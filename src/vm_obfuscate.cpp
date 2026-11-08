// vm_obfuscate.cpp — post-translation VM bytecode obfuscator
// ============================================================
// Emits two anti-analysis transforms on NovaProtect wire bytecode:
//
//   1. Dead-register junk emission (any complexity > 0)
//   2. Control-flow flattening (complexity >= 3, straight-line code only)
//
// Both transforms preserve semantics: junk never touches live registers
// and never modifies flags, and the flattening dispatcher reproduces the
// original block order through a state variable.
#include "vm_isa.h"
#include "wire_table.h"
#include <vector>
#include <random>

namespace np {

namespace {

// Instruction lengths and flag/register effects come from the shared wire
// table. A second, hand-maintained copy is how the memory and 32-bit opcodes
// would silently desync the obfuscator from the interpreter.
inline uint32_t wireInsnLen(uint8_t op) { return wireInsnLength(op); }
inline bool wireIsBranch(uint8_t op) { return wireIsBranchOp(op); }
inline bool wireSetsFlags(uint8_t op) { return wireWritesFlags(op); }

struct WI {
    uint8_t op;
    std::vector<uint8_t> ops;
    WI() : op(0) {}
    explicit WI(uint8_t o) : op(o) {}
    WI(uint8_t o, std::vector<uint8_t> v) : op(o), ops(std::move(v)) {}
    uint32_t size() const { return 1 + (uint32_t)ops.size(); }
};

WI mkNot(uint8_t reg) {
    return WI(WIRE_NOT, {reg});
}

WI mkMove(uint8_t dst, uint8_t src) {
    return WI(WIRE_MOVE, {dst, src});
}

WI mkLoadImm(uint8_t reg, uint64_t v) {
    std::vector<uint8_t> o = {reg};
    for (int k = 0; k < 8; k++) o.push_back((uint8_t)(v >> (k * 8)));
    return WI(WIRE_LOADIMM, std::move(o));
}

WI mkJmp(uint32_t target) {
    std::vector<uint8_t> o(4);
    for (int k = 0; k < 4; k++) o[k] = (uint8_t)(target >> (k * 8));
    return WI(WIRE_JMP, std::move(o));
}

WI mkCmpi(uint8_t reg, uint64_t v) {
    std::vector<uint8_t> o = {reg};
    for (int k = 0; k < 8; k++) o.push_back((uint8_t)(v >> (k * 8)));
    return WI(WIRE_CMPI, std::move(o));
}

WI mkJe(uint32_t target) {
    std::vector<uint8_t> o(4);
    for (int k = 0; k < 4; k++) o[k] = (uint8_t)(target >> (k * 8));
    return WI(WIRE_JE, std::move(o));
}

WI mkRegImm(uint8_t op, uint8_t reg, uint64_t v) {
    std::vector<uint8_t> o = {reg};
    for (int k = 0; k < 8; k++) o.push_back((uint8_t)(v >> (k * 8)));
    return WI(op, std::move(o));
}

void emitQword(std::vector<uint8_t>& v, uint64_t q) {
    for (int k = 0; k < 8; k++) v.push_back((uint8_t)(q >> (k * 8)));
}

} // namespace

std::vector<uint8_t> vmObfuscate(const std::vector<uint8_t>& bc,
                                  const uint8_t* reverse,
                                  const uint8_t* mapping,
                                  uint32_t reg_mask,
                                  uint8_t complexity) {
    if (bc.size() < 16 || complexity == 0) return bc;

    // ---- decode -------------------------------------------------------
    std::vector<WI> prog;
    {
        size_t ip = 0;
        while (ip < bc.size()) {
            uint8_t op = reverse[bc[ip]];
            uint32_t len = wireInsnLen(op);
            if (len == 0 || ip + len > bc.size()) return bc;
            std::vector<uint8_t> ops(bc.begin() + ip + 1,
                                     bc.begin() + ip + len);
            prog.push_back(WI(op, std::move(ops)));
            ip += len;
        }
    }
    if (prog.empty()) return bc;

    bool hasBranches = false;
    for (auto& wi : prog)
        if (wireIsBranch(wi.op)) { hasBranches = true; break; }

    // ---- dead register for junk / state -------------------------------
    int deadReg = -1;
    for (int r = 0; r < 16; r++) {
        if (!(reg_mask & (1u << r))) { deadReg = r; break; }
    }
    if (deadReg < 0) return bc;   // no dead register, stay safe

    std::mt19937 rng(0xA5A5u ^ (uint32_t)complexity ^ (uint32_t)bc.size());
    (void)rng; // silence unused in release

    std::vector<WI> body;
    std::vector<WI>* outStream = &body;

    const bool flatten = !hasBranches && complexity >= 3 && prog.size() >= 4;

    if (!flatten) {
        // ---------------------------------------------------------------
        // Junk + opaque-predicate fake jumps, with full target relocation
        // ---------------------------------------------------------------
        // Every insertion shifts the byte offsets that branch operands point
        // at, so this path cannot copy instructions verbatim: it records each
        // branch as a fixup against the *instruction index* it targets and
        // patches the final byte offsets once the layout is known. Before this,
        // junk emission silently corrupted any region that contained a branch.
        const size_t n = prog.size();

        // Original byte offset of every instruction, used to resolve the
        // absolute targets the translator emitted.
        std::vector<uint32_t> origOff(n);
        {
            uint32_t cur = 0;
            for (size_t i = 0; i < n; i++) { origOff[i] = cur; cur += prog[i].size(); }
        }

        // Flags are only ever read by branches, so an insertion point is safe
        // exactly when no branch can still observe an earlier comparison.
        std::vector<char> liveBefore(n, 0);
        {
            char live = 0;
            for (size_t i = 0; i < n; i++) {
                liveBefore[i] = live;
                if (wireIsBranch(prog[i].op)) live = 0;
                else if (wireSetsFlags(prog[i].op)) live = 1;
            }
        }

        std::vector<size_t> bodyIdxOf(n, 0);
        std::vector<std::pair<size_t, size_t>> instrFixups; // (body idx, prog idx)
        std::vector<std::pair<size_t, size_t>> bodyFixups;  // (body idx, body idx)

        auto emitJunk = [&](uint32_t count) {
            for (uint32_t j = 0; j < count; j++) {
                switch (rng() % 3) {
                case 0: body.push_back(mkNot((uint8_t)deadReg)); break;
                case 1: body.push_back(mkMove((uint8_t)deadReg, (uint8_t)deadReg)); break;
                default: {
                    uint64_t v = ((uint64_t)rng() << 32) ^ rng();
                    body.push_back(mkLoadImm((uint8_t)deadReg, v));
                    break;
                }
                }
            }
        };

        for (size_t i = 0; i < n; i++) {
            // ---- fake jump ------------------------------------------------
            // Opaque predicate on the dead register: (v >> 1) << 1 is even for
            // every v, so "& 1" is unconditionally zero and the branch is
            // always taken. A reader has to evaluate the shifts to see that;
            // the block after the branch is a plausible, harmless dead path
            // that falls through into the real continuation.
            if (complexity >= 2 && i > 0 && !liveBefore[i] &&
                !wireIsBranch(prog[i].op) && (rng() % 6) == 0) {
                body.push_back(mkRegImm(WIRE_SHRI, (uint8_t)deadReg, 1));
                body.push_back(mkRegImm(WIRE_SHLI, (uint8_t)deadReg, 1));
                body.push_back(mkRegImm(WIRE_ANDI, (uint8_t)deadReg, 1));
                body.push_back(mkCmpi((uint8_t)deadReg, 0));
                size_t jzAt = body.size();
                body.push_back(WI(WIRE_JZ, std::vector<uint8_t>(4, 0)));
                emitJunk(2 + (rng() % 3));
                // The dead block falls through into the continuation, so only
                // the branch itself needs a target.
                bodyFixups.emplace_back(jzAt, body.size());
            }

            // ---- junk -----------------------------------------------------
            emitJunk(rng() % 2);

            // ---- real instruction -----------------------------------------
            bodyIdxOf[i] = body.size();
            if (wireIsBranch(prog[i].op)) {
                uint32_t target = 0;
                for (int k = 0; k < 4; k++) target |= (uint32_t)prog[i].ops[k] << (k * 8);
                size_t targetIdx = n; // n == "past the end"
                for (size_t j = 0; j < n; j++) {
                    if (origOff[j] == target) { targetIdx = j; break; }
                }
                body.push_back(WI(prog[i].op, std::vector<uint8_t>(4, 0)));
                instrFixups.emplace_back(body.size() - 1, targetIdx);
            } else {
                body.push_back(prog[i]);
            }
        }

        // Concrete landing pad for branches that targeted the end of the stream.
        const size_t endIdx = body.size();
        body.push_back(WI(WIRE_HALT));

        std::vector<uint32_t> off(body.size() + 1, 0);
        {
            uint32_t cur = 0;
            for (size_t i = 0; i < body.size(); i++) { off[i] = cur; cur += body[i].size(); }
            off[body.size()] = cur;
        }
        auto patch = [&](size_t at, uint32_t tgt) {
            for (int k = 0; k < 4; k++) body[at].ops[k] = (uint8_t)(tgt >> (k * 8));
        };
        for (auto& f : instrFixups) {
            size_t bi = (f.second >= n) ? endIdx : bodyIdxOf[f.second];
            patch(f.first, off[bi]);
        }
        for (auto& f : bodyFixups) patch(f.first, off[f.second]);
    } else {
        // ---------------------------------------------------------------
        // Control-flow flattening
        // ---------------------------------------------------------------
        // Split into blocks of 1-3 instructions.
        std::vector<std::vector<WI>> blocks;
        {
            size_t i = 0;
            while (i < prog.size()) {
                uint32_t n = 1 + (rng() % 3);
                std::vector<WI> blk;
                for (uint32_t k = 0; k < n && i < prog.size(); k++, i++)
                    blk.push_back(prog[i]);
                blocks.push_back(std::move(blk));
            }
        }
        uint32_t nBlocks = (uint32_t)blocks.size();
        if (nBlocks < 2) {
            for (auto& wi : prog) body.push_back(wi);
            outStream = &body;
            // fall through to re-encode below
            std::vector<uint8_t> out;
            out.reserve(body.size() * 8);
            for (auto& wi : body) {
                out.push_back(mapping[wi.op]);
                out.insert(out.end(), wi.ops.begin(), wi.ops.end());
            }
            return out;
        }

        // Shuffle block order.
        std::vector<uint32_t> order(nBlocks);
        for (uint32_t i = 0; i < nBlocks; i++) order[i] = i;
        for (uint32_t i = nBlocks - 1; i > 0; i--) {
            uint32_t j = rng() % (i + 1);
            std::swap(order[i], order[j]);
        }

        // Layout:
        //   [0] LOADIMM state, 0
        //   [1] JMP dispatch            <- patch
        //   blocks in shuffled order:
        //     blockStart[b]
        //     <block instructions>
        //     LOADIMM state, b+1
        //     JMP dispatch              <- patch
        //   dispatch:
        //     CMPI state, 0; JE blockStart[0]
        //     ...
        //     CMPI state, nBlocks-1; JE blockStart[nBlocks-1]
        //     HALT

        size_t entryJmpIdx = 0;
        std::vector<size_t> blockJmpIdx;   // index of each block's JMP
        std::vector<size_t> blockStartIdx; // index of first insn of each block
        std::vector<size_t> jeIdx;         // index of each JE in dispatch
        size_t dispatchStart = 0;

        // prologue
        body.push_back(mkLoadImm((uint8_t)deadReg, 0));
        entryJmpIdx = body.size();
        body.push_back(mkJmp(0)); // patched later

        for (uint32_t pos = 0; pos < nBlocks; pos++) {
            uint32_t b = order[pos];
            blockStartIdx.push_back(body.size());
            for (auto& wi : blocks[b]) body.push_back(wi);
            // junk between blocks
            uint32_t junkCount = rng() % 2;
            for (uint32_t j = 0; j < junkCount; j++)
                body.push_back(mkNot((uint8_t)deadReg));
            // transition
            body.push_back(mkLoadImm((uint8_t)deadReg, b + 1));
            blockJmpIdx.push_back(body.size());
            body.push_back(mkJmp(0)); // patched later
        }

        dispatchStart = body.size();
        for (uint32_t b = 0; b < nBlocks; b++) {
            body.push_back(mkCmpi((uint8_t)deadReg, b));
            jeIdx.push_back(body.size());
            body.push_back(mkJe(0)); // patched later
        }
        body.push_back(WI(WIRE_HALT));

        // Assign offsets.
        std::vector<uint32_t> off(body.size(), 0);
        {
            uint32_t cur = 0;
            for (size_t i = 0; i < body.size(); i++) {
                off[i] = cur;
                cur += body[i].size();
            }
        }

        // Patch entry JMP -> dispatch
        {
            uint32_t tgt = off[dispatchStart];
            for (int k = 0; k < 4; k++)
                body[entryJmpIdx].ops[k] = (uint8_t)(tgt >> (k * 8));
        }
        // Patch block transition JMPs -> dispatch
        for (size_t i = 0; i < blockJmpIdx.size(); i++) {
            uint32_t tgt = off[dispatchStart];
            for (int k = 0; k < 4; k++)
                body[blockJmpIdx[i]].ops[k] = (uint8_t)(tgt >> (k * 8));
        }
        // Patch JE targets -> block starts.
        // blockStartIdx was filled in shuffled order; jeIdx[b] must jump to
        // the start of block with state == b.
        // blockStartIdx[pos] corresponds to the block whose original id is
        // order[pos], so the target for state b is the pos where order[pos]==b.
        std::vector<size_t> posOfState(nBlocks);
        for (uint32_t pos = 0; pos < nBlocks; pos++)
            posOfState[order[pos]] = (size_t)pos;
        for (uint32_t b = 0; b < nBlocks; b++) {
            uint32_t tgt = off[blockStartIdx[posOfState[b]]];
            for (int k = 0; k < 4; k++)
                body[jeIdx[b]].ops[k] = (uint8_t)(tgt >> (k * 8));
        }
    }

    // ---- re-encode ----------------------------------------------------
    std::vector<uint8_t> out;
    out.reserve(body.size() * 8);
    for (auto& wi : *outStream) {
        out.push_back(mapping[wi.op]);
        out.insert(out.end(), wi.ops.begin(), wi.ops.end());
    }
    return out;
}

} // namespace np