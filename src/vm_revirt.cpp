// vm_revirt.cpp 鈥?EnableRevirtualization: stage splitting + guest-block lifting
// =========================================================================
// Two independent transforms, applied in this order by the packer:
//
//   1. splitStages()   cuts the outer bytecode program into self-contained
//                      stage streams and gives every one its own opcode
//                      permutation and its own keystream key. This is the
//                      Themida "RelocateStages / MergeStages" idea: the
//                      interpreter only ever holds one stage at a time, and a
//                      dump of the running region yields bytes that decode to
//                      garbage under every other stage's key.
//
//   2. liftGuestBlocks() walks the arithmetic runs inside one stage and moves
//                      them into second-level blocks that are returned to a
//                      guest interpreter with their own register permutation,
//                      opcode permutation and key. The outer stream calls
//                      WIRE_GSTAGE <index> instead of executing them.
//
// Both transforms preserve observable semantics exactly: stages only break
// where no branch can leave the range, and a guest block is only cut out when
// the run it covers has no branch, no memory access and no WIRE_GSTAGE of its
// own (those would need an address space / outer descriptor index the guest
// interpreter does not have).
//
// The register permutation is a pure renaming: every VM register index operand
// in the block is rewritten through `perm`, so two runs lifted in the same
// region never agree on where a value lives. Registers the block neither reads
// nor writes are mapped onto a single shared scratch slot, which is what makes
// the guest state leak as little as possible.
#include "vm_isa.h"
#include "wire_table.h"
#include "vm_revirt.h"

#include <algorithm>
#include <cstring>
#include <random>
#include <vector>

namespace np {

namespace {

// A carrier must hold at least this many instructions before it is worth
// splitting. Stages are whole instruction ranges; guest blocks are short by
// construction, so they get a lower bound of their own. Using one bound for both
// is what silently capped revirtualization at level 1 on real images.
constexpr uint32_t kVmStageMinInsns = 6;
constexpr uint32_t kVmGuestMinInsns = 4;

uint32_t readU32(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

} // namespace

// ===========================================================================
// Stage splitting
// ===========================================================================
// Cuts `bc` into stage streams of roughly `targetStageBytes`, only ever at an
// instruction boundary that no branch jumps across. `reverse`/`mapping` are the
// region-wide tables used to decode and re-encode; every returned stage gets a
// fresh pair generated from `seed`.
//
// Branch targets are stream-relative, so a stage that starts at offset O has to
// have every target inside it rebased by -O. A target that points outside the
// stage disqualifies the cut.
bool vmSplitStages(const std::vector<uint8_t>& bc,
                   const uint8_t* reverse,
                   const uint8_t* /*mapping*/,
                   uint64_t seed,
                   uint32_t targetStageBytes,
                   std::vector<VmStage>& out) {
    out.clear();
    if (bc.size() < kMinStageBytes * 2) return false;
    if (targetStageBytes < kMinStageBytes) targetStageBytes = kMinStageBytes;

    // Instruction boundaries and branch edges.
    struct B { uint32_t off; uint32_t len; uint8_t logical; };
    std::vector<B> ins;
    {
        uint32_t off = 0;
        while (off < bc.size()) {
            uint8_t logical = reverse[bc[off]];
            uint32_t len = wireInsnLength(logical);
            if (len == 0 || off + len > bc.size()) return false;
            ins.push_back({ off, len, logical });
            off += len;
        }
        if (ins.size() < 4) return false;
    }

    // For every instruction that is a branch, which instruction index the
    // target lands on. A target that does not land on an instruction boundary
    // means the stream is not what we think it is: refuse to split it.
    std::vector<int64_t> targetIdx(ins.size(), -1);
    for (size_t i = 0; i < ins.size(); i++) {
        if (!wireIsBranchOp(ins[i].logical)) continue;
        uint32_t tgt = readU32(bc.data() + ins[i].off + 1);
        if (tgt == bc.size()) { targetIdx[i] = (int64_t)ins.size(); continue; }
        int64_t hit = -1;
        for (size_t j = 0; j < ins.size(); j++)
            if (ins[j].off == tgt) { hit = (int64_t)j; break; }
        if (hit < 0) return false;
        targetIdx[i] = hit;
    }

    // A cut in front of instruction k is legal when no branch straddles it.
    auto cutAllowed = [&](size_t k) -> bool {
        if (k == 0 || k >= ins.size()) return false;
        for (size_t i = 0; i < ins.size(); i++) {
            if (targetIdx[i] < 0) continue;
            int64_t t = targetIdx[i];
            int64_t from = (int64_t)i;
            // Straddles when the edge leaves one side and enters the other.
            if ((from < (int64_t)k && t >= (int64_t)k) || (from >= (int64_t)k && t < (int64_t)k))
                return false;
        }
        return true;
    };

    // Greedy fill towards the target size, falling back to the nearest legal
    // cut when the ideal one is not allowed.
    std::vector<size_t> cuts;   // instruction indices that start a stage
    cuts.push_back(0);
    {
        size_t i = 0;
        while (i < ins.size()) {
            uint32_t start = ins[i].off;
            size_t best = ins.size();
            for (size_t j = i + 1; j < ins.size(); j++) {
                if (ins[j].off - start < targetStageBytes) continue;
                if (cutAllowed(j)) { best = j; break; }
            }
            if (best >= ins.size()) break;
            cuts.push_back(best);
            i = best;
            if (cuts.size() > kMaxStagesPerRegion) return false;
        }
    }
    if (cuts.size() < 2) return false;   // nothing worth splitting

    std::mt19937_64 rng(seed ? seed : 0x5EED5EED5EED5EEDull);

    for (size_t s = 0; s < cuts.size(); s++) {
        size_t first = cuts[s];
        size_t last = (s + 1 < cuts.size()) ? cuts[s + 1] : ins.size();
        uint32_t base = ins[first].off;
        uint32_t end = (last < ins.size()) ? ins[last].off : (uint32_t)bc.size();

        VmStage st;
        st.base = base;
        st.rva = base;
        st.key = ((uint64_t)rng() << 32) ^ rng();
        memset(st.reverse, 0, sizeof(st.reverse));

        // Fresh permutation for this stage only.
        {
            uint8_t values[256];
            for (int i = 0; i < 256; i++) values[i] = (uint8_t)i;
            std::shuffle(values, values + 256, rng);
            std::memset(st.reverse, 0xFF, sizeof(st.reverse));
            for (int i = 0; i < NP_WIRE_OPCODE_SLOTS; i++)
                st.reverse[values[i]] = (uint8_t)i;
            for (int i = NP_WIRE_OPCODE_SLOTS; i < 256; i++)
                st.reverse[values[i]] = 0;
            for (int i = 0; i < 256; i++) st.mapping[i] = 0;
            for (int i = 0; i < NP_WIRE_OPCODE_SLOTS; i++) st.mapping[i] = values[i];
        }

        // Emit the stage with rebased branch targets and this stage's opcodes.
        for (size_t i = first; i < last; i++) {
            uint8_t logical = ins[i].logical;
            st.bc.push_back(st.mapping[logical]);
            uint32_t nops = kWireInfo[logical].len - 1;
            if (wireIsBranchOp(logical)) {
                uint32_t tgt = readU32(bc.data() + ins[i].off + 1);
                uint32_t rebased = tgt - base;
                for (int k = 0; k < 4; k++) st.bc.push_back((uint8_t)(rebased >> (k * 8)));
            } else {
                for (uint32_t k = 0; k < nops; k++)
                    st.bc.push_back(bc[ins[i].off + 1 + k]);
            }
        }
        // Non-final stages hand control to the next one explicitly, so the
        // runtime never has to guess where a stage ended.
        if (s + 1 < cuts.size())
            st.bc.push_back(st.mapping[WIRE_STAGEEND]);

        (void)end;
        out.push_back(std::move(st));
    }
    return out.size() >= 2;
}

// ===========================================================================
// Guest-block lifting
// ===========================================================================
namespace {

bool guestSafeOpcode(uint8_t logical) {
    switch (logical) {
    // Arithmetic / logic that only touches the register file and flags.
    case WIRE_LOADIMM:
    case WIRE_MOVE: case WIRE_MOVD: case WIRE_MOVZXB: case WIRE_MOVZXW:
    case WIRE_MOVSXB: case WIRE_MOVSXW: case WIRE_MOVSXD:
    case WIRE_ADD: case WIRE_SUB: case WIRE_MUL: case WIRE_AND:
    case WIRE_OR: case WIRE_XOR: case WIRE_SHL: case WIRE_SHR:
    case WIRE_SAR: case WIRE_ROL: case WIRE_ROR:
    case WIRE_ADDD: case WIRE_SUBD: case WIRE_ANDD: case WIRE_ORD:
    case WIRE_XORD: case WIRE_MULD:
    case WIRE_NOT: case WIRE_NEG: case WIRE_NOTD: case WIRE_NEGD:
    case WIRE_MULI: case WIRE_ADDI: case WIRE_SUBI: case WIRE_ANDI:
    case WIRE_ORI: case WIRE_XORI: case WIRE_SHRI: case WIRE_SHLI:
    case WIRE_SARI: case WIRE_RORI: case WIRE_ROLI:
    case WIRE_ADDID: case WIRE_SUBID: case WIRE_ANDID: case WIRE_ORID:
    case WIRE_XORID: case WIRE_SHLID: case WIRE_SHRID: case WIRE_SARID:
    case WIRE_CMP: case WIRE_TEST: case WIRE_CMPI:
    case WIRE_CMPD: case WIRE_TESTD: case WIRE_CMPID:
        return true;
    default:
        return false;
    }
}

// Operand slot kinds for the opcodes above, from the shared table, restricted
// to register / immediate / target shapes. The table already encodes this; the
// function exists so the rewrite below reads as intent.
void rewriteOperands(std::vector<uint8_t>& out,
                     uint8_t logical,
                     const uint8_t* ops,
                     const uint8_t* perm) {
    const WireInfo& info = kWireInfo[logical];
    uint32_t off = 0;
    for (uint8_t k = 0; k < info.nops; k++) {
        switch (info.op[k]) {
        case WireOperandKind::Reg: {
            uint8_t r = ops[off];
            out.push_back(r < 16 ? perm[r] : r);
            off += 1;
            break;
        }
        case WireOperandKind::Imm64:
            for (int b = 0; b < 8; b++) out.push_back(ops[off + b]);
            off += 8;
            break;
        case WireOperandKind::Imm32:
        case WireOperandKind::Target32:
        case WireOperandKind::Index32:
            for (int b = 0; b < 4; b++) out.push_back(ops[off + b]);
            off += 4;
            break;
        default:
            break;
        }
    }
}

} // namespace

// Lifts the arithmetic runs out of one *carrier* stream: either an outer stage
// or an already-lifted guest block. Both are the same thing to this function - a
// bytecode buffer with its own opcode tables - which is exactly what makes
// nesting possible: a level-2 block is produced by running this over a level-1
// block's bytes.
//
// `baseRva` only salts the child descriptors. The register permutation is
// applied against the carrier's own register numbering, so every level
// re-permutes the register space of the level above it.
//
// `minInsns` is the carrier's own lower bound, and it has to differ per level: a
// stage is normally dozens of instructions, while a guest block is a short
// straight-line run. Reusing the stage bound for guest carriers is what kept
// revirtualization at one level on real images - every candidate block was below
// the "worth splitting" threshold, so level 2 never found material.
static bool liftCarrier(std::vector<uint8_t>& bc,
                        const uint8_t* mapping,
                        const uint8_t* reverse,
                        uint32_t baseRva,
                        uint64_t seed,
                        uint32_t maxBlocks,
                        uint32_t firstGuestIndex,
                        uint32_t level,
                        uint32_t minInsns,
                        std::vector<VmGuestBlock>& out) {
    out.clear();
    if (bc.size() < kMinStageBytes / 2) return false;

    // Walk this carrier's own encoding back to logical instructions.
    struct B { uint32_t off; uint32_t len; uint8_t logical; };
    std::vector<B> ins;
    {
        uint32_t off = 0;
        while (off < bc.size()) {
            uint8_t logical = reverse[bc[off]];
            uint32_t len = wireInsnLength(logical);
            if (len == 0 || off + len > bc.size()) return false;
            ins.push_back({ off, len, logical });
            off += len;
        }
    }
    if (ins.size() < minInsns) return false;

    std::mt19937_64 rng(seed ? seed : 0xC0FFEE123456789ull);

    // Find maximal guest-safe runs. A run is lifted when it is long enough to
    // pay for the descriptor; runs are never allowed to contain a branch, a
    // memory access or another WIRE_GSTAGE of their own (a nested call site is
    // not a liftable instruction: the child index would be resolved against the
    // wrong table).
    std::vector<std::pair<size_t, size_t>> runs;
    size_t i = 0;
    while (i < ins.size()) {
        if (!guestSafeOpcode(ins[i].logical)) { i++; continue; }
        size_t j = i;
        while (j < ins.size() && guestSafeOpcode(ins[j].logical)) j++;
        if (j - i >= 3) runs.emplace_back(i, j);
        i = j;
    }
    if (runs.empty()) return false;

    for (auto& run : runs) {
        if (out.size() >= maxBlocks) break;
        VmGuestBlock g;
        g.level = level;
        g.key = ((uint64_t)rng() << 32) ^ rng();
        g.rva = baseRva + ins[run.first].off;

        // Register permutation.
        //
        // `regPerm` is indexed by outer register number and yields the slot the
        // block uses for it. It has to be a permutation of all sixteen slots,
        // not just of the touched ones: the runtime unpermutes by writing
        // slot -> outer for every slot, so two outer registers sharing a slot
        // would make one clobber the other on entry. Touched registers are
        // therefore given a shuffled subset and the untouched ones fill the
        // remaining slots in an arbitrary order - the block never names them, so
        // their placement only adds noise.
        {
            std::vector<uint8_t> touched;
            bool seen[16] = { false };
            for (size_t k = run.first; k < run.second; k++) {
                const WireInfo& info = kWireInfo[ins[k].logical];
                uint32_t off = 0;
                for (uint8_t s = 0; s < info.nops; s++) {
                    if (info.op[s] == WireOperandKind::Reg) {
                        uint8_t r = bc[ins[k].off + 1 + off];
                        if (r < 16 && !seen[r]) { seen[r] = true; touched.push_back(r); }
                    }
                    off += (info.op[s] == WireOperandKind::Reg) ? 1
                        : (info.op[s] == WireOperandKind::Imm64) ? 8
                        : (info.op[s] == WireOperandKind::None) ? 0 : 4;
                }
            }
            if (touched.empty()) return false;

            std::vector<uint8_t> slots;
            for (uint8_t r = 0; r < 16; r++) slots.push_back(r);
            std::shuffle(slots.begin(), slots.end(), rng);

            // First `touched.size()` slots go to the touched registers, the
            // rest to the untouched ones so the map stays a total bijection.
            for (size_t t = 0; t < touched.size(); t++)
                g.regPerm[touched[t]] = slots[t];
            size_t next = touched.size();
            for (uint8_t r = 0; r < 16; r++)
                if (!seen[r]) g.regPerm[r] = slots[next++];
        }

        // Guest opcode permutation.
        {
            uint8_t values[256];
            for (int k = 0; k < 256; k++) values[k] = (uint8_t)k;
            std::shuffle(values, values + 256, rng);
            std::memset(g.reverse, 0xFF, sizeof(g.reverse));
            for (int k = 0; k < NP_WIRE_OPCODE_SLOTS; k++) g.reverse[values[k]] = (uint8_t)k;
            for (int k = NP_WIRE_OPCODE_SLOTS; k < 256; k++) g.reverse[values[k]] = 0;
            for (int k = 0; k < 256; k++) g.mapping[k] = 0;
            for (int k = 0; k < NP_WIRE_OPCODE_SLOTS; k++) g.mapping[k] = values[k];
        }

        // Which registers the block assigns. Only these are copied back to the
        // outer register file on return; everything else must survive the guest
        // run untouched, including the registers whose slots were collapsed.
        for (size_t k = run.first; k < run.second; k++) {
            uint8_t logical = ins[k].logical;
            if (!wireWritesReg(logical)) continue;
            uint8_t outer = bc[ins[k].off + 1];      // first operand = destination
            if (outer < 16) g.writeMask |= (1u << outer);
        }

        for (size_t k = run.first; k < run.second; k++) {
            uint8_t logical = ins[k].logical;
            g.bc.push_back(g.mapping[logical]);
            rewriteOperands(g.bc, logical, bc.data() + ins[k].off + 1, g.regPerm);
        }
        // A guest block is straight-line by construction; the explicit stop is
        // what tells the guest dispatcher to return to its caller.
        g.bc.push_back(g.mapping[WIRE_HALT]);

        g.firstInsn = run.first;
        g.lastInsn = run.second;
        out.push_back(std::move(g));
    }
    if (out.empty()) return false;

    // ---- substitute the lifted runs in the carrier stream ----------------
    // The carrier must now call WIRE_GSTAGE <index> where the run used to live.
    // Nothing may be left behind: a run that is still present would execute
    // twice. Rebuild the stream and rebase every branch target, because the
    // instruction at any given offset just changed size.
    {
        // Old byte offset -> instruction index, for branch retargeting.
        std::vector<uint8_t> rebuilt;
        std::vector<uint32_t> oldOff(ins.size(), 0);
        for (size_t k = 0; k < ins.size(); k++) oldOff[k] = ins[k].off;

        // Index of the first instruction index >= k that begins a lifted run.
        auto runStartingAt = [&](size_t k) -> const VmGuestBlock* {
            for (auto& g : out)
                if (g.firstInsn == k) return &g;
            return nullptr;
        };
        // Which lifted run covers instruction k (k is inside a run's body but
        // not at its head) - those are skipped entirely.
        auto insideRun = [&](size_t k) -> bool {
            for (auto& g : out)
                if (k > g.firstInsn && k < g.lastInsn) return true;
            return false;
        };

        struct Fixup { size_t at; uint32_t oldTarget; };
        std::vector<Fixup> fixups;
        std::vector<uint32_t> newOffOfInsn(ins.size() + 1, 0);

        for (size_t k = 0; k < ins.size(); k++) {
            if (insideRun(k)) { newOffOfInsn[k] = (uint32_t)rebuilt.size(); continue; }
            newOffOfInsn[k] = (uint32_t)rebuilt.size();
            if (k == ins.size()) break;
            const VmGuestBlock* g = runStartingAt(k);
            if (g) {
                uint32_t idx = firstGuestIndex + (uint32_t)(g - out.data());
                rebuilt.push_back(mapping[WIRE_GSTAGE]);
                for (int b = 0; b < 4; b++) rebuilt.push_back((uint8_t)(idx >> (b * 8)));
                continue;
            }
            uint8_t logical = ins[k].logical;
            rebuilt.push_back(mapping[logical]);
            if (wireIsBranchOp(logical)) {
                uint32_t tgt = readU32(bc.data() + ins[k].off + 1);
                fixups.push_back({ rebuilt.size(), tgt });
                for (int b = 0; b < 4; b++) rebuilt.push_back(0);
            } else {
                uint32_t nops = kWireInfo[logical].len - 1;
                for (uint32_t b = 0; b < nops; b++)
                    rebuilt.push_back(bc[ins[k].off + 1 + b]);
            }
        }
        newOffOfInsn[ins.size()] = (uint32_t)rebuilt.size();

        for (auto& f : fixups) {
            // Resolve the old target to an instruction index, then to its new
            // offset. "Past the end" stays past the end.
            uint32_t resolved = (uint32_t)rebuilt.size();
            if (f.oldTarget != bc.size()) {
                resolved = 0;
                bool found = false;
                for (size_t k = 0; k < ins.size(); k++)
                    if (oldOff[k] == f.oldTarget) { resolved = newOffOfInsn[k]; found = true; break; }
                if (!found) return false;
            }
            for (int b = 0; b < 4; b++) rebuilt[f.at + b] = (uint8_t)(resolved >> (b * 8));
        }
        bc.swap(rebuilt);
    }
    return true;
}

bool vmLiftGuestBlocks(VmStage& stage,
                       uint64_t seed,
                       uint32_t maxBlocks,
                       uint32_t firstGuestIndex,
                       uint32_t level,
                       std::vector<VmGuestBlock>& out) {
    // An outer stage is a full instruction range, so it gets the strict bound.
    return liftCarrier(stage.bc, stage.mapping, stage.reverse, stage.rva,
                       seed, maxBlocks, firstGuestIndex, level ? level : 1u,
                       kVmStageMinInsns, out);
}

// ===========================================================================
// Nested revirtualization (revirtualization_level)
// ===========================================================================
// Level 1 is "every stage's arithmetic runs become guest blocks". Level N>1
// lifts runs out of the level N-1 blocks again, so the deepest blocks are
// reachable only through N successive WIRE_GSTAGE dispatches - each with its own
// key, its own opcode permutation and its own register permutation, and the
// register permutation of a level-k block is applied on top of the level k-1
// one.
//
// The transform is depth-first and appends to one flat guest table, so a
// descriptor's level is recorded in its flags and the runtime needs no per-level
// tables. Every step is fail-safe: a level that cannot be lifted simply does not
// exist, and the region keeps the depth that did work.
namespace {

// Build one stage that covers the whole program, used when the program is too
// short to split. Splitting is an optional strengthening: a region that cannot
// be cut still has liftable arithmetic, and refusing it here would silently
// downgrade every small region to the legacy single-level form.
bool makeWholeStage(const std::vector<uint8_t>& bc,
                    const uint8_t* reverse,
                    const uint8_t* mapping,
                    uint64_t seed,
                    VmStage& st) {
    if (bc.size() < kMinStageBytes) return false;

    // The stream still has to parse exactly - a bad reverse table must not be
    // papered over by wrapping it in a stage.
    uint32_t off = 0;
    while (off < bc.size()) {
        uint8_t logical = reverse[bc[off]];
        uint32_t len = wireInsnLength(logical);
        if (len == 0 || off + len > bc.size()) return false;
        off += len;
    }

    std::mt19937_64 rng(seed ? seed : 0x51A6E5EEDull);
    st = VmStage{};
    st.base = 0;
    st.rva = 0;
    st.key = ((uint64_t)rng() << 32) ^ rng();

    uint8_t values[256];
    for (int i = 0; i < 256; i++) values[i] = (uint8_t)i;
    std::shuffle(values, values + 256, rng);
    std::memset(st.reverse, 0xFF, sizeof(st.reverse));
    for (int i = 0; i < NP_WIRE_OPCODE_SLOTS; i++) st.reverse[values[i]] = (uint8_t)i;
    for (int i = NP_WIRE_OPCODE_SLOTS; i < 256; i++) st.reverse[values[i]] = 0;
    for (int i = 0; i < 256; i++) st.mapping[i] = 0;
    for (int i = 0; i < NP_WIRE_OPCODE_SLOTS; i++) st.mapping[i] = values[i];

    // Re-encode through the fresh permutation: the caller's bytes use `mapping`
    // from the region, this stage uses its own.
    st.bc.reserve(bc.size());
    off = 0;
    while (off < bc.size()) {
        uint8_t logical = reverse[bc[off]];
        uint32_t len = wireInsnLength(logical);
        st.bc.push_back(st.mapping[logical]);
        for (uint32_t k = 1; k < len; k++) st.bc.push_back(bc[off + k]);
        off += len;
    }
    return true;
}

} // namespace

uint32_t vmRevirtualize(std::vector<uint8_t>& bc,
                        const uint8_t* reverse,
                        const uint8_t* mapping,
                        uint64_t seed,
                        uint32_t targetStageBytes,
                        uint32_t levels,
                        uint32_t maxBlocks,
                        std::vector<VmStage>& stages,
                        std::vector<VmGuestBlock>& guests) {
    stages.clear();
    guests.clear();
    if (levels == 0) return 0;
    if (levels > kMaxGuestDepth) levels = kMaxGuestDepth;

    if (!vmSplitStages(bc, reverse, mapping, seed, targetStageBytes, stages)) {
        stages.clear();
        VmStage whole;
        if (!makeWholeStage(bc, reverse, mapping, seed ^ 0x9E3779B9u, whole))
            return 0;
        stages.push_back(std::move(whole));
    }

    if (levels == 1) {
        // Level 1: every stage contributes blocks directly.
        for (auto& st : stages) {
            if (guests.size() >= maxBlocks) break;
            std::vector<VmGuestBlock> gb;
            const uint32_t firstIdx = (uint32_t)guests.size();
            const uint32_t room = maxBlocks - firstIdx;
            if (vmLiftGuestBlocks(st, seed ^ (uint64_t)st.rva, room, firstIdx, 1, gb)) {
                for (auto& g : gb) guests.push_back(std::move(g));
            }
        }
        return 1;
    }

    // Level >= 2. Lift the outer layer first, then repeatedly lift the deepest
    // layer that exists. Lifting "the deepest layer" instead of every layer at
    // once keeps each new block's parent stream final: a parent whose bytes are
    // rewritten again would invalidate the child indices it already holds.
    for (auto& st : stages) {
        if (guests.size() >= maxBlocks) break;
        std::vector<VmGuestBlock> gb;
        const uint32_t firstIdx = (uint32_t)guests.size();
        const uint32_t room = maxBlocks - firstIdx;
        if (vmLiftGuestBlocks(st, seed ^ (uint64_t)st.rva, room, firstIdx, 1, gb)) {
            for (auto& g : gb) guests.push_back(std::move(g));
        }
    }
    if (guests.empty()) return stages.size() >= 2 ? 1u : 0u;

    uint32_t reached = 1;
    for (uint32_t want = 2; want <= levels; want++) {
        // Everything produced by this pass, appended after the current table so
        // indices stay stable for the parents already emitted.
        const size_t parentCount = guests.size();
        std::vector<VmGuestBlock> children;
        for (size_t p = 0; p < parentCount; p++) {
            if (guests.size() + children.size() >= maxBlocks) break;
            if (guests[p].level + 1 != want) continue;   // only lift the previous layer

            VmGuestBlock child = guests[p];   // carries mapping/reverse/rva/key
            std::vector<VmGuestBlock> made;
            const uint32_t firstIdx = (uint32_t)(guests.size() + children.size());
            const uint32_t room = maxBlocks - firstIdx;
            if (room == 0) break;
            if (!liftCarrier(child.bc, child.mapping, child.reverse, guests[p].rva,
                             seed ^ ((uint64_t)guests[p].rva << 16) ^ (uint64_t)want,
                             room, firstIdx, want, kVmGuestMinInsns, made)) {
                continue;
            }
            // The parent's own body changed (runs replaced by WIRE_GSTAGE), so
            // publish the rewritten bytes back into the table.
            guests[p].bc.swap(child.bc);
            for (auto& c : made) children.push_back(std::move(c));
        }
        if (children.empty()) break;
        for (auto& c : children) guests.push_back(std::move(c));
        reached = want;
    }
    return reached;
}

} // namespace np
