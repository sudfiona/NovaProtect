// NovaProtect VM Engine Implementation
// =================================
// Implements:
//   * VMOpcodeMapper  - per-build opcode permutation + reverse table
//   * VMTranslator    - real x86-64 -> wire bytecode lowering
//   * VMBytecodeGenerator - wire-level emit helpers
//
// The wire format is defined in include/vm_isa.h and consumed by
// runtime/prot64.c::np_vm_run.

#include "vm_isa.h"
#include "disasm.h"
#include <cstring>
#include <algorithm>
#include <random>
#include <string>

namespace np {

// ============================================================
// VMOpcodeMapper
// ============================================================
static void fillPermutation(uint8_t* mapping, uint8_t* reverse, uint64_t seed) {
    std::vector<uint8_t> values(256);
    for (int i = 0; i < 256; i++) values[i] = (uint8_t)i;

    std::mt19937_64 g(seed);
    std::shuffle(values.begin(), values.end(), g);

    std::memset(reverse, 0xFF, 256);
    for (int i = 0; i < NP_WIRE_OPCODE_SLOTS; i++) {
        mapping[i] = values[i];
        reverse[values[i]] = (uint8_t)i;
    }
    // Every other physical byte decodes to a no-op slot so stray bytes are inert.
    for (int i = NP_WIRE_OPCODE_SLOTS; i < 256; i++)
        reverse[values[i]] = (uint8_t)0;
}

void VMOpcodeMapper::generateMapping() {
    std::random_device rd;
    uint64_t seed = ((uint64_t)rd() << 32) ^ (uint64_t)rd();
    fillPermutation(mapping_, reverse_, seed ? seed : 0x9E3779B97F4A7C15ull);
}

void VMOpcodeMapper::generateMapping(uint64_t seed) {
    fillPermutation(mapping_, reverse_, seed ? seed : 0x9E3779B97F4A7C15ull);
}

// ============================================================
// VMTranslator
// ============================================================
namespace {

// Guest GPR i maps to register-file slot i. The translator's scratch slots
// sit *outside* the 16 guest slots: an address build that parked its temp in
// a guest slot would silently corrupt live guest state (the old layout used
// VM_R14/VM_R15, which made every guest use of r14/r15 a correctness hole).
struct RegMap {
    uint8_t guest_to_vm[16];
    uint8_t vmSp;
    bool used[NP_VM_SLOTS];

    void init(uint8_t sp) {
        std::memset(used, 0, sizeof(used));
        for (int i = 0; i < 16; i++) { guest_to_vm[i] = (uint8_t)i; used[i] = true; }
        used[NP_VM_SCRATCH_A] = true;
        used[NP_VM_SCRATCH_B] = true;
        vmSp = sp;
    }
    uint8_t g2v(Reg r) const {
        uint8_t i = (uint8_t)r;
        if (i > 15) return 0xFF;
        return guest_to_vm[i];
    }
};

// Scratch register-file slots (never aliased by guest registers).
static const uint8_t SCRATCH_A = (uint8_t)NP_VM_SCRATCH_A;
static const uint8_t SCRATCH_B = (uint8_t)NP_VM_SCRATCH_B;

// XMM scratch slots. Operands name xmm i as 20+i (outside the GPR slot range
// so a register permutation never rewrites them), so a "scratch xmm" has to be
// 20+15 / 20+14 - naming slot 15 directly would alias a GPR operand and the
// interpreter would reject it as not-an-xmm. `prefer` is the destination slot
// to avoid, expressed the same way.
static uint8_t XMM_TMP(uint8_t prefer) {
    return (prefer != (uint8_t)(20 + 15)) ? (uint8_t)(20 + 15) : (uint8_t)(20 + 14);
}

static bool isGPR(Reg r) { return (uint8_t)r <= 15; }

// Selector byte for WIRE_NALU: operand width in the high nibble, operation in
// the low one. The width is the *architectural* width of the x86 form being
// lowered, so the handler can compute the flags at that width and write the
// result back the way the original instruction does (splice for 8/16,
// zero-extend for 32).
static uint8_t naluSel(uint8_t width, uint8_t op) {
    uint8_t w = (width == 1) ? NP_NALU_W8 : (width == 2) ? NP_NALU_W16
              : (width == 4) ? NP_NALU_W32 : NP_NALU_W64;
    return (uint8_t)((w << 4) | (op & 0x0F));
}

// Map an x86 condition code (TTTTN of the Jcc opcode) to a wire Jcc opcode.
static uint8_t jccWire(uint8_t cc, uint8_t prefixes) {
    (void)prefixes;
    // x86 condition codes:
    //  0 O   1 NO  2 B/NAE  3 AE/NB  4 E/Z  5 NE/NZ  6 BE/NA  7 A/NBE
    //  8 S   9 NS  A P      B NP      C L/NGE D GE/NL E LE/NG F G/NLE
    //
    // The wire VM tracks zf/cf/sf/of/pf, so every condition code has an exact
    // opcode. The two "approximate" entries an earlier revision shipped were
    // correctness bugs: `jae` was lowered to JB and `jbe`/`ja` to JAE, which
    // silently inverted the branch in protected code.
    switch (cc) {
    case 0x0: return WIRE_JO;                            // O  (of)
    case 0x1: return WIRE_JNO;                           // NO (!of)
    case 0x2: return WIRE_JB;                            // B/NAE (cf)
    case 0x3: return WIRE_JAE;                           // AE/NB (!cf)
    case 0x4: return WIRE_JZ;                            // E/Z
    case 0x5: return WIRE_JNZ;                           // NE/NZ
    case 0x6: return WIRE_JBE;                           // BE/NA (cf || zf)
    case 0x7: return WIRE_JA;                            // A/NBE (!cf && !zf)
    case 0x8: return WIRE_JS;                            // S (sf)
    case 0x9: return WIRE_JNS;                           // NS (!sf)
    case 0xA: return WIRE_JP;                            // P (pf)
    case 0xB: return WIRE_JNP;                           // NP (!pf)
    case 0xC: return WIRE_JL;
    case 0xD: return WIRE_JGE;
    case 0xE: return WIRE_JLE;
    case 0xF: return WIRE_JG;
    default:  return 0;
    }
}

} // namespace

VMLoweredBlock VMTranslator::translate(const uint8_t* code, size_t size,
                                       uint64_t guestRip, uint64_t imageBase,
                                       uint8_t complexity, uint8_t mutationLevel,
                                       bool target64, uint64_t seed,
                                       bool allowIslands) {
    (void)imageBase;
    VMLoweredBlock out;
    out.vmSp = 4; // guest RSP lives in slot 4; the body rules bound its use

    RegMap regs;
    regs.init(out.vmSp);

    VMOpcodeMapper mapper;
    // A pinned seed makes the logical->physical opcode permutation part of the
    // build identity instead of fresh entropy, which is what lets a rebuild
    // reproduce byte for byte.
    // The region RVA folds into the seed, so every region gets its own
    // physical opcode layout: one region's dispatch bytes teach nothing
    // about another's, and a signature or breakpoint anchored on one
    // stream does not generalize (roadmap per-region handler salt, folded
    // into the reverse table as the salt carrier).
    const uint64_t regionSalt = (guestRip - imageBase) * 0x9E3779B97F4A7C15ull;
    if (seed) mapper.generateMapping(seed ^ 0x9E3779B97F4A7C15ull ^ regionSalt);
    else mapper.generateMapping();

    std::vector<uint8_t> bc;
    auto emit  = [&](uint8_t logical) { bc.push_back(mapper.encode(logical)); };
    auto b8    = [&](uint8_t v) { bc.push_back(v); };
    auto d32   = [&](uint32_t v) { bc.push_back(v & 0xFF); bc.push_back((v >> 8) & 0xFF);
                                   bc.push_back((v >> 16) & 0xFF); bc.push_back((v >> 24) & 0xFF); };
    auto q64   = [&](uint64_t v) { for (int k = 0; k < 8; k++) bc.push_back((uint8_t)(v >> (k * 8))); };

    // Guest offset -> bytecode offset, for internal branch fixups.
    std::unordered_map<uint32_t, uint32_t> offMap;
    std::vector<std::pair<size_t, uint32_t>> fixups; // (bc offset of target dword, guest target)

    // ================= pre-pass: prologue / islands / body rules =========
    // The wire VM owns no stack-pointer semantics and the trampoline parks its
    // register file just below the region's entry rsp (plus a 128-byte red-zone
    // gap), so a virtualized *body* must not write rsp and must not reach below
    // its entry rsp outside the x86-64 red zone. Everything that does touch rsp
    // natively - the frame prologue and every epilogue/ret - stays in the image
    // and is entered through WIRE_EXITJMP, which restores the real registers
    // and jumps to the original address. That is what makes ordinary frame
    // functions (the bulk of any compiled image) virtualizable at all.
    struct Decoded {
        uint32_t off = 0, len = 0;
        DisasmInsn insn;
    };
    std::vector<Decoded> insns;
    {
        Disassembler pdis;
        uint32_t po = 0;
        while (po < size) {
            Decoded d;
            d.off = po;
            uint32_t il = pdis.disassemble(code + po, size - po, d.insn);
            if (!il) {
                out.skipReason = "decode failed";
                return out;
            }
            d.len = il;
            insns.push_back(d);
            po += il;
        }
    }
    // Epilogue instructions restore rsp / callee-saved registers; a run of them
    // terminated by a ret (or by a jmp away) must execute natively.
    auto isEpilogue = [&](const DisasmInsn& in) -> bool {
        using C = InsnCategory;
        if (in.category == C::POP || in.category == C::LEAVE) return true;
        if (in.category == C::MOV || in.category == C::LEA)
            return in.dst.type == OperandType::Register && (uint8_t)in.dst.reg == 4;
        // ADD/SUB/AND to rsp are NOT epilogue markers: a body-level
        // `sub rsp, N ... add rsp, N` pair must both stay in the virtualized
        // body so the guest-rsp slot (VM slot 4) tracks the depth. Only the
        // frame-pointer restores above are true epilogue; the VM exit restores
        // real rsp from the register file, so the island sees exactly the
        // guest rsp value regardless of the body's net stack motion.
        return false;
    };

    int bodyIdx = 0;
    // The frame prologue is no longer trimmed out of the virtualized range.
    // Every prologue instruction - push, mov rbp/rsp, sub/and/lea rsp - lowers
    // through the guest stack-pointer slot exactly like body code, and the
    // trampoline's own `push rbp` writes the same slot with the same value the
    // virtualized `push rbp` would, so there is nothing left for the native
    // prelude to do. Keeping the prologue inside the range is also what makes
    // its bytes count as virtualized instead of staying native forever.
    // The frame-size tally (used to bound [rbp-X] accesses) is folded into the
    // body-rules pass below through the rsp delta.
    uint32_t frameBytes = 0;
    (void)frameBytes;
    uint32_t bodyStart = 0;

    std::vector<char> isIsland(insns.size(), 0);
    std::unordered_map<uint32_t, uint32_t> islandStart; // guest off -> rva
    // With islands disabled (the retry pass for functions the stub window
    // would swallow whole) every instruction - pops, leave, ret - becomes
    // body: ret lowers through the register-indirect exit and the other
    // epilogue pieces are ordinary pushes/pops.
    auto markIsland = [&](int from, int to) {
        if (!allowIslands) return;
        for (int k = from; k <= to; k++) isIsland[k] = 1;
        islandStart[insns[from].off] = 1;
    };
    auto runStart = [&](int termIdx) -> int {
        int k = termIdx;
        while (k > bodyIdx && isEpilogue(insns[k - 1].insn)) k--;
        return k;
    };
    for (size_t n = 0; n < insns.size(); n++) {
        if (insns[n].insn.category != InsnCategory::RET) continue;
        if ((int)n < bodyIdx) continue;
        markIsland(runStart((int)n), (int)n);
    }
    // INT3 (0xCC) is a trap: execution cannot continue past it. Function-end
    // alignment padding is a run of INT3s after the final ret (unreachable, so
    // it stays native exactly like an epilogue island and the trap bytes are
    // preserved); a reachable __debugbreak() traps before anything after it
    // runs either. Marking the run as an island keeps every byte before it
    // virtualizable instead of failing the whole region on "cat 0 op 204".
    for (size_t n = 0; n < insns.size(); n++) {
        if (insns[n].insn.opcode != 0xCC || (insns[n].insn.prefixes & PREFIX_0F)) continue;
        if ((int)n < bodyIdx) continue;
        size_t k = n;
        while (k < insns.size() && insns[k].insn.opcode == 0xCC &&
               !(insns[k].insn.prefixes & PREFIX_0F)) {
            isIsland[k] = 1;
            k++;
        }
        islandStart[insns[n].off] = 1;
        if (!allowIslands) isIsland[n] = 0;
    }
    for (size_t n = 0; n < insns.size(); n++) {
        const DisasmInsn& in = insns[n].insn;
        if (in.category != InsnCategory::JMP) continue;
        if ((int)n < bodyIdx) continue;
        bool leaves = false;
        if (in.opcode == 0xE9 || in.opcode == 0xEB) {
            int64_t tgt = (int64_t)insns[n].off + (int64_t)insns[n].len + (int64_t)in.rel_target;
            leaves = (tgt < (int64_t)bodyStart) || (tgt >= (int64_t)size) ||
                     islandStart.count((uint32_t)tgt) != 0;
        } else {
            leaves = true;   // indirect jmp: target unknown at build time
        }
        if (!leaves) continue;
        int k = runStart((int)n);
        if (k < (int)n) markIsland(k, (int)n);
        else if (!allowIslands) isIsland[n] = 0;
    }

    // Body safety rules.
    //
    // Guest RSP lives in VM slot 4 and is tracked through push/pop and
    // immediate rsp arithmetic; the VM exit restores real rsp from that
    // slot, so the body's stack depth is governed by the same address space
    // the original code used. The trampoline's register file sits a reserved
    // distance below the chunk's entry rsp and the reported stack depth
    // sizes that reservation, so guest stack motion and VM state can never
    // meet. Two things are refused instead of reserved for:
    //   - a stack-pointer write whose value is not statically knowable
    //     (alloca-style `sub rsp, reg`): it becomes a native bridge -
    //     translation stops just before it and the packer opens a new chunk
    //     after it, so the unbounded descent happens on the real stack
    //     between two VM regions;
    //   - ENTER / PUSHF / POPF, which have no wire translation.
    {
        int rspDelta = 0, minDelta = 0, maxRbpX = 0;
        uint32_t cutAt = 0;
        bool cut = false;
        for (size_t n = bodyIdx; n < insns.size(); n++) {
            if (isIsland[n]) continue;
            const DisasmInsn& in = insns[n].insn;
            using C = InsnCategory;
            if (in.category == C::PUSHF) {
                rspDelta -= 8;
            } else if (in.category == C::POPF) {
                rspDelta += 8;
            } else if (in.category == C::ENTER) {
                // enter imm16, n allocates imm16 bytes below the (new) frame
                // pointer; the nested-frame walk of n > 0 keeps the same final
                // depth, so the bound holds for both shapes.
                rspDelta -= 8 + (int)(in.src.immediate & 0xFFFFu);
            }
            // SSE/AVX/x87 decode their ModRM.reg field as a vector or
            // co-processor selector, not a GPR - `movaps [rsp+X], xmm4` must
            // not read as "writes rsp". CMP/TEST carry their first operand in
            // dst but write nothing at all.
            const bool gprDst = in.category != C::SSE && in.category != C::AVX &&
                                in.category != C::X87 &&
                                in.category != C::CMP && in.category != C::TEST;
            bool unbounded = false;
            if (in.category == C::PUSH || in.category == C::PUSH_IMM) {
                rspDelta -= 8;
            } else if (in.category == C::POP) {
                rspDelta += 8;
            } else if (gprDst && in.dst.type == OperandType::Register &&
                       (uint8_t)in.dst.reg == 4) {
                if ((in.category == C::ADD || in.category == C::SUB) &&
                    in.src.type == OperandType::Immediate) {
                    int64_t v = (in.category == C::SUB) ? (int64_t)in.src.immediate
                                                         : -(int64_t)in.src.immediate;
                    if (v > 0x40000 || v < -0x40000) {
                        out.skipReason = "body writes RSP";
                        return out;
                    }
                    rspDelta -= (int)v;
                } else if (in.category == C::AND && in.src.type == OperandType::Immediate) {
                    rspDelta -= 8;   // alignment can only push rsp down
                } else if (in.category == C::INC) {
                    rspDelta += 8;
                } else if (in.category == C::DEC) {
                    rspDelta -= 8;
                } else {
                    // reg-form add/sub or mov/lea/or/xor rsp: the resulting
                    // depth is only knowable at run time (the compiler's
                    // __chkstk handshake and alloca-sized frames both look
                    // like this). Native bridge.
                    unbounded = true;
                }
            }
            if (unbounded) {
                cut = true;
                cutAt = insns[n].off;
                break;
            }
            if (rspDelta < minDelta) minDelta = rspDelta;
            if (minDelta < -0x40000) {
                out.skipReason = "body writes RSP (depth outside the gap)";
                return out;
            }
            Operand ops[3] = { in.dst, in.src, in.extra };
            for (int k = 0; k < 3; k++) {
                if (ops[k].type == OperandType::MemoryRIP) continue;
                if (ops[k].type == OperandType::Memory ||
                    ops[k].type == OperandType::MemoryRegIndir) {
                    if ((uint8_t)ops[k].base == 5 && ops[k].displacement < 0) {
                        int x = (int)(-ops[k].displacement);
                        if (x > maxRbpX) maxRbpX = x;
                    }
                }
            }
        }
        // Stack depth below the chunk entry that the trampoline must reserve:
        // the deepest rsp motion, and any [rbp-X] local that reaches past the
        // 888-byte floor of the fixed part of the gap (rbp sits at entry-8 and
        // the register file starts 896 bytes below the entry).
        uint32_t rspDebt = (uint32_t)(-minDelta);
        uint32_t rbpDebt = (maxRbpX > 888) ? (uint32_t)(maxRbpX - 888) : 0;
        out.stackDepth = rspDebt > rbpDebt ? rspDebt : rbpDebt;
        if (cut) {
            out.cut = true;
            out.cutAt = cutAt;
            out.resumeOff = cutAt;   // + bridge length is added by the caller walk
            for (const Decoded& d : insns) {
                if (d.off == cutAt) { out.resumeOff = cutAt + d.len; break; }
            }
        }
    }
    // The trampoline's five-byte jump lands at bodyStart and overwrites the
    // bytes there. Two kinds of bytes must stay intact: the start of a native
    // epilogue island, and any instruction boundary another jump targets (a
    // jump into the stub's shadow would land on jump bytes). When one sits in
    // [bodyStart, bodyStart+5), move bodyStart to the conflicting boundary:
    // everything before it stays native - always semantically correct - and a
    // jump to that boundary now lands on the trampoline jump itself.
    {
        std::unordered_map<uint32_t, uint32_t> jumpTargets;
        for (auto& d : insns) {
            const DisasmInsn& in = d.insn;
            if (in.category == InsnCategory::JMP || in.category == InsnCategory::JCC ||
                in.category == InsnCategory::CALL) {
                if (in.opcode == 0xE8 || in.opcode == 0xE9 || in.opcode == 0xEB ||
                    in.category == InsnCategory::JCC) {
                    jumpTargets[(uint32_t)((int64_t)d.off + (int64_t)d.len + in.rel_target)] = 1;
                }
            }
        }
        auto islandEnd = [&](size_t idx) -> uint32_t {
            size_t k = idx;
            while (k + 1 < insns.size() && isIsland[k + 1]) k++;
            return insns[k].off + insns[k].len;
        };
        bool moved = true;
        while (moved && bodyStart + 5 <= (uint32_t)size) {
            moved = false;
            size_t startIdx = insns.size();
            for (size_t n = 0; n < insns.size(); n++)
                if (insns[n].off >= bodyStart) { startIdx = n; break; }
            if (startIdx < insns.size() && isIsland[startIdx] && insns[startIdx].off == bodyStart) {
                bodyStart = islandEnd(startIdx);
                moved = true;
                continue;
            }
            for (size_t n = 0; n < insns.size(); n++) {
                uint32_t o = insns[n].off;
                if (o <= bodyStart || o >= bodyStart + 5) continue;
                if (isIsland[n]) { bodyStart = islandEnd(n); moved = true; break; }
                if (jumpTargets.count(o)) { bodyStart = o; moved = true; break; }
            }
        }
    }
    if (bodyStart >= (uint32_t)size) {
        if (allowIslands)
            return translate(code, size, guestRip, imageBase, complexity,
                             mutationLevel, target64, seed, false);
        out.skipReason = "nothing to virtualize";
        return out;
    }
    bool hasBody = false;
    for (size_t n = bodyIdx; n < insns.size(); n++)
        if (!isIsland[n]) { hasBody = true; break; }
    if (!hasBody) {
        if (allowIslands)
            return translate(code, size, guestRip, imageBase, complexity,
                             mutationLevel, target64, seed, false);
        out.skipReason = "nothing to virtualize (native epilogues only)";
        return out;
    }

    Disassembler dis;
    size_t off = bodyStart;
    // With a native-bridge cut the chunk ends at the bridge; everything past
    // it belongs to the next chunk. Branches to the boundary resolve to the
    // end-of-stream halt, whose default exit lands exactly on the bridge.
    const uint32_t endPos = out.cut ? out.cutAt : (uint32_t)size;
    uint32_t translated = 0, skipped = 0;
    // imul defines CF/OF from the truncated product. The wire VM has no 128-bit
    // multiply, so those flags cannot be reproduced: an imul is translated only
    // while no branch can observe them, and a JCC that arrives before the next
    // flag-setting instruction ends the region instead of reading stale flags.
    bool mulFlagsPending = false;
    // Set by a lowered 8/16-bit ALU: the wire op wrote wide flags. Cleared by
    // any flag-setting op (those replace the flag file wholesale).
    bool byteFlagsPending = false;

    while (off < endPos) {
        // Native epilogue islands run at their original addresses: emit the
        // fall-through exit once and walk over their bytes. Branches that land
        // on an island start resolve to this same exit through offMap.
        {
            int ii = -1;
            for (size_t k = 0; k < insns.size(); k++)
                if (insns[k].off == (uint32_t)off) { ii = (int)k; break; }
            if (ii >= 0 && isIsland[ii]) {
                offMap[(uint32_t)off] = (uint32_t)bc.size();
                emit(WIRE_EXITJMP);
                d32((uint32_t)(guestRip - imageBase) + (uint32_t)off);
                while (ii < (int)insns.size() && isIsland[ii]) {
                    off += insns[ii].len;
                    ii++;
                }
                continue;
            }
        }
        // Stop at a terminator we cannot express; caller keeps the rest native.
        DisasmInsn insn;
        uint32_t len = dis.disassemble(code + off, size - off, insn);
        if (len == 0) { out.skipReason = "decode failed"; break; }

        uint32_t guestOff = (uint32_t)off;
        offMap[guestOff] = (uint32_t)bc.size();

        bool handled = true;
        uint8_t rexW = (insn.prefixes & PREFIX_REX_W) ? 1 : 0;

        // Operand width as the wire VM has to see it.
        //   8 = 64-bit form (REX.W)
        //   4 = 32-bit form: result is zero-extended into the full register and
        //       the flags come from 32-bit arithmetic, so the *D opcodes are
        //       required. Treating these as 64-bit would change both.
        //   2 / 1 = word / byte register writes. The wire register file has no
        //       partial-register access, so those still terminate translation.
        const uint8_t width = rexW ? 8u
                            : ((insn.prefixes & PREFIX_66) ? 2u
                            : ((insn.category == InsnCategory::MOVZX ||
                                insn.category == InsnCategory::MOVSX) ? 0u
                            : (insn.dst.size ? insn.dst.size : 4u)));
        const bool w32 = target64 && (width == 4);
        if (target64 && (width == 2 || width == 1) &&
            insn.category != InsnCategory::MOVZX &&
            insn.category != InsnCategory::MOVSX) {
            using C = InsnCategory;
            switch (insn.category) {
            // 8/16-bit forms lower through full-width ops plus the
            // INSB/INSW splice (the low byte/word of the wide result is the
            // byte/word result). The wide flags only match the narrow ones
            // when no branch can observe them, so a flag consumer arriving
            // before the next flag setter ends the region instead of reading
            // stale flags - the same discipline imul uses.
            default:
                break;
            }
        }
        const bool partial = (width == 2 || width == 1) &&
                             insn.category != InsnCategory::MOVZX &&
                             insn.category != InsnCategory::MOVSX;
        const uint8_t splice = (width == 2) ? (uint8_t)WIRE_INSW : (uint8_t)WIRE_INSB;

        // A memory operand has to be folded into [base(+index*scale)+disp].
        // The wire VM addresses memory through one base register plus a
        // displacement, so the index is folded into a scratch by hand; the only
        // forms rejected here are the ones with no register to fold into.
        bool memOk = true;
        auto foldMem = [&](Operand& m) -> bool {
            if (m.type != OperandType::Memory && m.type != OperandType::MemoryRegIndir) return true;
            // [index*scale + disp] with no base is legal for LEA (compilers emit
            // it constantly for array indexing). It is accepted here and folded
            // by the LEA case; every other instruction still rejects it in
            // memAddr(), which needs a real base register.
            if (m.base == Reg::NONE || m.base == Reg::RIP) return true; // [idx*scale+disp] / [disp32]
            if (m.index != Reg::NONE && m.index != Reg::RIP && !isGPR(m.index))
                return false;   // vector / non-GPR index
            if (m.scale != 1 && m.scale != 2 && m.scale != 4 && m.scale != 8) return false;
            return true;
        };
        memOk = foldMem(insn.dst) && foldMem(insn.src);

        // Emit code that materialises a memory operand's effective address into
        // `scratch`.
        //
        // Every instruction here must be flag-preserving. A memory operand is
        // flag-transparent in the original instruction, so `cmp a,b` /
        // `mov [rdi], rax` / `jne` has to still branch on the cmp. Using
        // WIRE_ADD/WIRE_ADDI here would replace the flags with the result of
        // the pointer sum and silently invert the branch - so this path uses
        // the ADDRADD/ADDRADDI pair, which are LEA's semantics.
        auto memAddr = [&](const Operand& m, uint8_t scratch,
                           uint32_t insnOff, uint32_t insnLen) -> bool {
            // [rip + disp]: the operand is position independent - the target
            // RVA is computed from the instruction and re-based at run time,
            // which is exactly what the original RIP-relative addressing did.
            if (m.type == OperandType::MemoryRIP) {
                uint32_t rva = (uint32_t)(guestRip - imageBase) + insnOff + insnLen +
                               (uint32_t)m.displacement;
                emit(WIRE_IMGADD); b8(scratch); d32(rva);
                return true;
            }
            if (!isGPR(m.base)) {
                // No base register: [index*scale + disp] (SIB with base=5,
                // mod=0) or [disp32] absolute. The decoder reports "no base"
                // as either Reg::NONE or Reg::RIP (its sentinel for the SIB
                // base=101 mod=0 form). LOADIMM / ADDRSHLI / ADDRADDI are
                // all flag-free, so an in-flight comparison survives.
                if (m.base != Reg::NONE && m.base != Reg::RIP) return false;
                if (m.index != Reg::NONE && m.index != Reg::RIP && isGPR(m.index)) {
                    uint8_t i = regs.g2v(m.index);
                    if (i == 0xFF) return false;
                    emit(WIRE_MOVE); b8(scratch); b8(i);
                    if (m.scale == 2 || m.scale == 4 || m.scale == 8) {
                        emit(WIRE_ADDRSHLI); b8(scratch);
                        q64((uint64_t)(m.scale == 2 ? 1 : m.scale == 4 ? 2 : 3));
                    }
                    if (m.displacement) {
                        emit(WIRE_ADDRADDI); b8(scratch);
                        q64((uint64_t)(int64_t)m.displacement);
                    }
                    return true;
                }
                if (m.index == Reg::NONE || m.index == Reg::RIP) {
                    emit(WIRE_LOADIMM); b8(scratch);
                    q64((uint64_t)(int64_t)m.displacement);
                    return true;
                }
                return false;
            }
            uint8_t b = regs.g2v(m.base);
            if (b == 0xFF) return false;

            // Reg::RIP is the decoder's sentinel for "SIB byte with no index";
            // it must not be folded in as a real register.
            if (m.index != Reg::NONE && m.index != Reg::RIP) {
                uint8_t i = regs.g2v(m.index);
                if (i == 0xFF) return false;

                // Index scaling: x86-64 has no lea-free way to express it in the
                // wire ISA, so synthesize index*scale. scale==1 needs nothing;
                // 2/4/8 become a left shift, which keeps the scaled value.
                if (m.scale == 2 || m.scale == 4 || m.scale == 8) {
                    // Scaling needs a disposable accumulator, and here the
                    // caller's scratch is the only register the block is not
                    // using for anything else. Both scratch VM registers are
                    // real guest registers, so aliasing the base or the index
                    // would corrupt a value still needed mid-build; in that case
                    // fall back to the other VM register if it is free.
                    uint8_t acc = scratch;
                    if (acc == b || acc == i) {
                        uint8_t other = (acc == SCRATCH_A) ? SCRATCH_B : SCRATCH_A;
                        if (other == b || other == i) return false;
                        acc = other;
                    }
                    emit(WIRE_MOVE); b8(acc); b8(i);
                    emit(WIRE_ADDRSHLI); b8(acc);
                    q64((uint64_t)(m.scale == 2 ? 1 : m.scale == 4 ? 2 : 3));
                    emit(WIRE_ADDRADD); b8(acc); b8(b);
                    // The caller expects the address in `scratch`.
                    if (acc != scratch) { emit(WIRE_MOVE); b8(scratch); b8(acc); }
                } else if (scratch == b) {
                    emit(WIRE_ADDRADD); b8(scratch); b8(i);
                } else if (scratch == i) {
                    emit(WIRE_ADDRADD); b8(scratch); b8(b);
                } else {
                    emit(WIRE_MOVE); b8(scratch); b8(b);
                    emit(WIRE_ADDRADD); b8(scratch); b8(i);
                }
            } else if (scratch != b) {
                emit(WIRE_MOVE); b8(scratch); b8(b);
            }
            if (m.displacement) {
                emit(WIRE_ADDRADDI); b8(scratch);
                q64((uint64_t)(int64_t)m.displacement);
            }
            return true;
        };

        // Helper for reg-reg / reg-imm binary ALU ops with a known wire op.
        auto needGPR = [&](Reg r) { return isGPR(r); };

        switch (insn.category) {
        case InsnCategory::MOV: {
            // mov dst, src
            if (insn.dst.type == OperandType::Register &&
                insn.src.type == OperandType::Register) {
                if (!needGPR(insn.dst.reg) || !needGPR(insn.src.reg)) { handled = false; break; }
                uint8_t d = regs.g2v(insn.dst.reg), s = regs.g2v(insn.src.reg);
                if (d == 0xFF || s == 0xFF) { handled = false; break; }
                // Braces matter here: `else emit(...); b8(d); b8(s);` used to
                // leave the two operand pushes outside the else, so every
                // partial-width reg/reg move emitted two stray operand bytes.
                // The interpreter read the first stray byte as an opcode and -
                // since an unknown logical opcode halts - silently dropped
                // everything after it. Whether that surfaced depended on which
                // physical byte the permutation happened to hand out.
                if (partial) { emit(splice); b8(d); b8(s); }
                else { emit(w32 ? WIRE_MOVD : WIRE_MOVE); b8(d); b8(s); }
            } else if (insn.dst.type == OperandType::Register &&
                       insn.src.type == OperandType::Immediate) {
                if (!needGPR(insn.dst.reg)) { handled = false; break; }
                uint8_t d = regs.g2v(insn.dst.reg);
                if (d == 0xFF) { handled = false; break; }
                // A 32-bit mov imm truncates and zero-extends exactly like the
                // immediate the decoder already masked.
                if (partial) {
                    emit(WIRE_LOADIMM); b8(SCRATCH_A);
                    q64((uint64_t)insn.src.immediate);
                    emit(splice); b8(d); b8(SCRATCH_A);
                } else {
                    emit(WIRE_LOADIMM); b8(d);
                    q64(w32 ? (uint64_t)(uint32_t)insn.src.immediate
                            : (uint64_t)insn.src.immediate);
                }
            } else if (insn.dst.type == OperandType::Register &&
                       (insn.src.type == OperandType::Memory ||
                        insn.src.type == OperandType::MemoryRegIndir ||
                        insn.src.type == OperandType::MemoryRIP)) {
                // mov reg, [base(+index)+disp] / [rip+disp]
                if (!memOk || !needGPR(insn.dst.reg)) { handled = false; break; }
                uint8_t d = regs.g2v(insn.dst.reg);
                if (d == 0xFF || !memAddr(insn.src, SCRATCH_A, (uint32_t)off, len)) { handled = false; break; }
                uint8_t loadOp;
                switch (insn.src.size ? insn.src.size : 8) {
                case 8: loadOp = WIRE_LOADQ; break;
                case 4: loadOp = WIRE_LOADD; break;
                case 2: loadOp = WIRE_LOADW; break;
                case 1: loadOp = WIRE_LOADB; break;
                default: handled = false; loadOp = 0; break;
                }
                if (!handled) break;
                if (partial) {
                    emit(loadOp); b8(SCRATCH_B); b8(SCRATCH_A); d32(0);
                    emit(splice); b8(d); b8(SCRATCH_B);
                } else {
                    emit(loadOp); b8(d); b8(SCRATCH_A); d32(0);
                }
            } else if ((insn.dst.type == OperandType::Memory ||
                        insn.dst.type == OperandType::MemoryRegIndir ||
                        insn.dst.type == OperandType::MemoryRIP) &&
                       insn.src.type == OperandType::Register) {
                // mov [base(+index)+disp], reg
                if (!memOk || !needGPR(insn.src.reg)) { handled = false; break; }
                uint8_t s = regs.g2v(insn.src.reg);
                if (s == 0xFF || !memAddr(insn.dst, SCRATCH_A, (uint32_t)off, len)) { handled = false; break; }
                uint8_t storeOp;
                switch (insn.dst.size ? insn.dst.size : 8) {
                case 8: storeOp = WIRE_STOREQ; break;
                case 4: storeOp = WIRE_STORED; break;
                case 2: storeOp = WIRE_STOREW; break;
                case 1: storeOp = WIRE_STOREB; break;
                default: handled = false; storeOp = 0; break;
                }
                if (!handled) break;
                emit(storeOp); b8(SCRATCH_A); d32(0); b8(s);
            } else if ((insn.dst.type == OperandType::Memory ||
                        insn.dst.type == OperandType::MemoryRegIndir ||
                        insn.dst.type == OperandType::MemoryRIP) &&
                       insn.src.type == OperandType::Immediate) {
                // mov [base+disp], imm - constant spills
                if (!memOk || !memAddr(insn.dst, SCRATCH_A, (uint32_t)off, len)) { handled = false; break; }
                emit(WIRE_LOADIMM); b8(SCRATCH_B);
                q64(w32 ? (uint64_t)(uint32_t)insn.src.immediate
                        : (uint64_t)insn.src.immediate);
                uint8_t storeOp;
                switch (insn.dst.size ? insn.dst.size : 8) {
                case 8: storeOp = WIRE_STOREQ; break;
                case 4: storeOp = WIRE_STORED; break;
                case 2: storeOp = WIRE_STOREW; break;
                case 1: storeOp = WIRE_STOREB; break;
                default: handled = false; storeOp = 0; break;
                }
                if (!handled) break;
                emit(storeOp); b8(SCRATCH_A); d32(0); b8(SCRATCH_B);
            } else {
                handled = false;
            }
            break;
        }
        case InsnCategory::MOVZX: case InsnCategory::MOVSX: {
            // 0F B6 / B7 / BE / BF. The source width is implied by the opcode,
            // the destination by REX.W.
            if (!needGPR(insn.dst.reg)) { handled = false; break; }
            uint8_t d = regs.g2v(insn.dst.reg);
            if (d == 0xFF) { handled = false; break; }
            uint8_t srcByte = insn.opcode2;
            uint8_t wire;
            if (insn.category == InsnCategory::MOVZX)
                wire = (srcByte == 0xB6) ? WIRE_MOVZXB : WIRE_MOVZXW;
            else
                wire = (srcByte == 0xBE) ? WIRE_MOVSXB :
                       (srcByte == 0xBF) ? WIRE_MOVSXW : WIRE_MOVSXD;

            if (insn.src.type == OperandType::Register) {
                if (!needGPR(insn.src.reg)) { handled = false; break; }
                uint8_t s = regs.g2v(insn.src.reg);
                if (s == 0xFF) { handled = false; break; }
                emit(wire); b8(d); b8(s);
            } else if (insn.src.type == OperandType::Memory ||
                       insn.src.type == OperandType::MemoryRegIndir ||
                       insn.src.type == OperandType::MemoryRIP) {
                if (!memOk || !memAddr(insn.src, SCRATCH_A, (uint32_t)off, len)) { handled = false; break; }
                switch (srcByte ? srcByte : 0x63) {
                case 0xB6: emit(WIRE_LOADB);  break;   // zero-extend
                case 0xB7: emit(WIRE_LOADW);  break;
                case 0xBE: emit(WIRE_LOADSB); break;   // sign-extend
                case 0xBF: emit(WIRE_LOADSW); break;
                case 0x63: emit(WIRE_LOADSD); break;
                default: handled = false; break;
                }
                if (!handled) break;
                b8(d); b8(SCRATCH_A); d32(0);
            } else {
                handled = false;
            }
            break;
        }
        case InsnCategory::LEA: {
            if (!needGPR(insn.dst.reg)) { handled = false; break; }
            if (insn.src.type != OperandType::Memory &&
                insn.src.type != OperandType::MemoryRegIndir &&
                insn.src.type != OperandType::MemoryRIP) { handled = false; break; }
            if (!memOk) { handled = false; break; }
            uint8_t d = regs.g2v(insn.dst.reg);
            if (d == 0xFF) { handled = false; break; }
            if (insn.src.type == OperandType::MemoryRIP) {
                if (partial) {
                    emit(WIRE_IMGADD); b8(SCRATCH_B); d32((uint32_t)(guestRip - imageBase) + (uint32_t)off + len + (uint32_t)insn.src.displacement);
                    emit(splice); b8(d); b8(SCRATCH_B);
                } else {
                    emit(WIRE_IMGADD); b8(d); d32((uint32_t)(guestRip - imageBase) + (uint32_t)off + len + (uint32_t)insn.src.displacement);
                }
                break;
            }
            // Build the address in a translator scratch slot first: it never
            // aliases a guest register, so even `lea rax,[rax+rbx*4]` is safe.
            // The helpers are flag-transparent, matching lea.
            //
            // The decoder reports the "no base" SIB form as Reg::RIP (so the
            // register-mask scan does not see a phantom RBP); has_sib tells it
            // apart from a genuine RIP-relative operand, which still stays
            // native because its address depends on the image base.
            uint8_t acc = SCRATCH_A;
            const bool indexOnly = (insn.src.base == Reg::NONE) ||
                                   (insn.src.base == Reg::RIP && insn.has_sib);
            if (indexOnly) {
                if (insn.src.index == Reg::NONE || insn.src.index == Reg::RIP) {
                    // [disp32] with neither base nor index: an absolute address.
                    if (partial) {
                        emit(WIRE_LOADIMM); b8(SCRATCH_B);
                        q64((uint64_t)insn.src.displacement);
                        emit(splice); b8(d); b8(SCRATCH_B);
                    } else {
                        emit(WIRE_LOADIMM); b8(d);
                        q64((uint64_t)insn.src.displacement);
                    }
                    break;
                }
                if (!isGPR(insn.src.index)) { handled = false; break; }
                uint8_t i = regs.g2v(insn.src.index);
                if (i == 0xFF) { handled = false; break; }
                emit(WIRE_MOVE); b8(acc); b8(i);
                if (insn.src.scale == 2 || insn.src.scale == 4 || insn.src.scale == 8) {
                    emit(WIRE_ADDRSHLI); b8(acc);
                    q64((uint64_t)(insn.src.scale == 2 ? 1 : insn.src.scale == 4 ? 2 : 3));
                }
                if (insn.src.displacement) {
                    emit(WIRE_ADDRADDI); b8(acc);
                    q64((uint64_t)(int64_t)insn.src.displacement);
                }
                if (partial) { emit(splice); b8(d); b8(acc); }
                else if (w32) { emit(WIRE_MOVD); b8(d); b8(acc); }
                else if (d != acc) { emit(WIRE_MOVE); b8(d); b8(acc); }
                break;
            }
            uint8_t b = regs.g2v(insn.src.base);
            if (b == 0xFF) { handled = false; break; }
            emit(WIRE_MOVE); b8(acc); b8(b);
            if (insn.src.index != Reg::NONE && insn.src.index != Reg::RIP) {
                if (!isGPR(insn.src.index)) { handled = false; break; }
                uint8_t i = regs.g2v(insn.src.index);
                if (i == 0xFF) { handled = false; break; }
                if (insn.src.scale == 2 || insn.src.scale == 4 || insn.src.scale == 8) {
                    emit(WIRE_MOVE); b8(SCRATCH_B); b8(i);
                    emit(WIRE_ADDRSHLI); b8(SCRATCH_B);
                    q64((uint64_t)(insn.src.scale == 2 ? 1 : insn.src.scale == 4 ? 2 : 3));
                    emit(WIRE_ADDRADD); b8(acc); b8(SCRATCH_B);
                } else {
                    emit(WIRE_ADDRADD); b8(acc); b8(i);
                }
            }
            if (insn.src.displacement) {
                emit(WIRE_ADDRADDI); b8(acc);
                q64((uint64_t)(int64_t)insn.src.displacement);
            }
            if (partial) { emit(splice); b8(d); b8(acc); }
            else if (w32) { emit(WIRE_MOVD); b8(d); b8(acc); }
            else if (d != acc) { emit(WIRE_MOVE); b8(d); b8(acc); }
            break;
        }
        case InsnCategory::IMUL: {
            // One-operand form (F7 /5): RDX:RAX = RAX * r/m, signed.
            if (insn.opcode == 0xF7 || insn.opcode == 0xF6) {
                if (insn.opcode == 0xF6) { handled = false; break; }
                uint8_t rax = regs.g2v(Reg::RAX), rdx = regs.g2v(Reg::RDX);
                if (rax == 0xFF || rdx == 0xFF) { handled = false; break; }
                uint8_t den = 0xFF;
                if (insn.dst.type == OperandType::Register) {
                    den = regs.g2v(insn.dst.reg);
                    if (den == 0xFF) { handled = false; break; }
                } else if (insn.dst.type == OperandType::Memory ||
                           insn.dst.type == OperandType::MemoryRegIndir ||
                           insn.dst.type == OperandType::MemoryRIP) {
                    if (!memOk || !memAddr(insn.dst, SCRATCH_A, (uint32_t)off, len)) { handled = false; break; }
                    emit((insn.dst.size >= 8) ? WIRE_LOADQ : WIRE_LOADD);
                    b8(SCRATCH_B); b8(SCRATCH_A); d32(0);
                    den = SCRATCH_B;
                } else { handled = false; break; }
                if (!rexW) {
                    emit(WIRE_MOVD); b8(rax); b8(rax);
                    emit(WIRE_MOVD); b8(den); b8(den);
                    emit(WIRE_MULQ); b8(1); b8(rax); b8(rdx); b8(den);
                    emit(WIRE_MOVE); b8(SCRATCH_B); b8(rax);
                    emit(WIRE_ADDRSHRI); b8(SCRATCH_B); q64(32);
                    emit(WIRE_MOVD); b8(rdx); b8(SCRATCH_B);
                    emit(WIRE_MOVD); b8(rax); b8(rax);
                } else {
                    emit(WIRE_MULQ); b8(1); b8(rax); b8(rdx); b8(den);
                }
                mulFlagsPending = true;
                break;
            }
            // Three-operand form (69 /r and 6B /r): dst = extra * imm.
            if (insn.extra.type == OperandType::Register ||
                insn.extra.type == OperandType::Memory ||
                insn.extra.type == OperandType::MemoryRegIndir ||
                insn.extra.type == OperandType::MemoryRIP) {
                if (!needGPR(insn.dst.reg)) { handled = false; break; }
                uint8_t d = regs.g2v(insn.dst.reg);
                if (d == 0xFF) { handled = false; break; }
                uint8_t base;
                if (insn.extra.type == OperandType::Register) {
                    if (!needGPR(insn.extra.reg)) { handled = false; break; }
                    base = regs.g2v(insn.extra.reg);
                    if (base == 0xFF) { handled = false; break; }
                } else {
                    if (!memOk || !memAddr(insn.extra, SCRATCH_A, (uint32_t)off, len)) { handled = false; break; }
                    uint8_t loadOp = insn.extra.size >= 8 ? WIRE_LOADQ :
                                     insn.extra.size == 4 ? WIRE_LOADD :
                                     insn.extra.size == 2 ? WIRE_LOADW : WIRE_LOADB;
                    emit(loadOp); b8(SCRATCH_B); b8(SCRATCH_A); d32(0);
                    base = SCRATCH_B;
                }
                if (partial) {
                    // 16-bit imul imm: the low half of the wide product is
                    // exactly the 16-bit product (the sign extension of the
                    // immediate only affects bits above it), so compute wide
                    // and splice the word back into the destination. The
                    // CF/OF story is imul's usual one: inexpressible in the
                    // wire VM, so a branch that can observe them ends the
                    // region instead of reading stale flags.
                    emit(WIRE_LOADIMM); b8(SCRATCH_A); q64((uint64_t)insn.src.immediate);
                    emit(WIRE_MULD); b8(base); b8(SCRATCH_A);
                    emit(splice); b8(d); b8(base);
                } else if (w32) {
                    emit(WIRE_LOADIMM); b8(SCRATCH_A); q64((uint64_t)(uint32_t)insn.src.immediate);
                    emit(WIRE_MULD); b8(base); b8(SCRATCH_A);
                    emit(WIRE_MOVD); b8(d); b8(base);
                } else {
                    emit(WIRE_MOVE); b8(SCRATCH_A); b8(base);
                    emit(WIRE_MULI); b8(SCRATCH_A);
                    q64((uint64_t)insn.src.immediate);
                    emit(WIRE_MOVE); b8(d); b8(SCRATCH_A);
                }
                mulFlagsPending = true;
                break;
            }
            // Two-operand form (0F AF /r). The decoder now parses its ModRM, so
            // dst is the reg field and src is the r/m operand.
            if (insn.dst.type != OperandType::Register) { handled = false; break; }
            if (!needGPR(insn.dst.reg)) { handled = false; break; }
            uint8_t d = regs.g2v(insn.dst.reg);
            if (d == 0xFF || d == out.vmSp) { handled = false; break; }
            if (insn.src.type == OperandType::Register && needGPR(insn.src.reg)) {
                uint8_t s = regs.g2v(insn.src.reg);
                if (s == 0xFF || s == out.vmSp) { handled = false; break; }
                emit(w32 ? WIRE_MULD : WIRE_MUL); b8(d); b8(s);
            } else if (insn.src.type == OperandType::Memory ||
                       insn.src.type == OperandType::MemoryRegIndir ||
                       insn.src.type == OperandType::MemoryRIP) {
                // memory source: read-modify-write through a scratch. The
                // product's low half is what the instruction writes, which is
                // exactly WIRE_MUL's semantics.
                if (!memOk || !memAddr(insn.src, SCRATCH_A, (uint32_t)off, len)) { handled = false; break; }
                uint8_t loadOp = insn.src.size >= 8 ? WIRE_LOADQ :
                                 insn.src.size == 4 ? WIRE_LOADD :
                                 insn.src.size == 2 ? WIRE_LOADW : WIRE_LOADB;
                emit(loadOp); b8(SCRATCH_B); b8(SCRATCH_A); d32(0);
                emit(w32 ? WIRE_MULD : WIRE_MUL); b8(d); b8(SCRATCH_B);
            } else {
                handled = false;
                break;
            }
            break;
        }
        case InsnCategory::ADD: case InsnCategory::SUB:
        case InsnCategory::SBB: case InsnCategory::ADC:
        case InsnCategory::AND: case InsnCategory::OR: case InsnCategory::XOR: {
            // The narrow (8/16-bit) forms go through WIRE_NALU, which computes
            // the flags at the operand width and writes the result back the way
            // the byte/word instruction does. The previous lowering ran the wide
            // op through a scratch and spliced, which left the *wide* flags
            // behind - every branch reading them afterwards was refused, which
            // is what kept whole functions native.
            const uint8_t naluOp = (insn.category == InsnCategory::ADD) ? NP_NALU_ADD :
                                   (insn.category == InsnCategory::SUB) ? NP_NALU_SUB :
                                   (insn.category == InsnCategory::SBB) ? NP_NALU_SBB :
                                   (insn.category == InsnCategory::ADC) ? NP_NALU_ADC :
                                   (insn.category == InsnCategory::AND) ? NP_NALU_AND :
                                   (insn.category == InsnCategory::OR)  ? NP_NALU_OR  :
                                                                          NP_NALU_XOR;
            uint8_t wire = (insn.category == InsnCategory::ADD) ? WIRE_ADD :
                           (insn.category == InsnCategory::SUB) ? WIRE_SUB :
                           (insn.category == InsnCategory::SBB) ? WIRE_SBB :
                           (insn.category == InsnCategory::ADC) ? WIRE_ADC :
                           (insn.category == InsnCategory::AND) ? WIRE_AND :
                           (insn.category == InsnCategory::OR)  ? WIRE_OR  : WIRE_XOR;
            uint8_t wireImm = (insn.category == InsnCategory::ADD) ? WIRE_ADDI :
                              (insn.category == InsnCategory::SUB) ? WIRE_SUBI :
                              (insn.category == InsnCategory::SBB) ? WIRE_SBBI :
                              (insn.category == InsnCategory::ADC) ? WIRE_ADCI :
                              (insn.category == InsnCategory::AND) ? WIRE_ANDI :
                              (insn.category == InsnCategory::OR)  ? WIRE_ORI  : WIRE_XORI;
            if (w32) {
                // SBB/ADC 32-bit forms use dedicated *D opcodes; the
                // immediate form has no *DI variant so lower it through a
                // scratch register with the reg-reg opcode.
                if (insn.category == InsnCategory::SBB) {
                    wire = WIRE_SBBD;
                } else if (insn.category == InsnCategory::ADC) {
                    wire = WIRE_ADCD;
                } else {
                wire = (insn.category == InsnCategory::ADD) ? WIRE_ADDD :
                       (insn.category == InsnCategory::SUB) ? WIRE_SUBD :
                       (insn.category == InsnCategory::AND) ? WIRE_ANDD :
                       (insn.category == InsnCategory::OR)  ? WIRE_ORD  : WIRE_XORD;
                wireImm = (insn.category == InsnCategory::ADD) ? WIRE_ADDID :
                          (insn.category == InsnCategory::SUB) ? WIRE_SUBID :
                          (insn.category == InsnCategory::AND) ? WIRE_ANDID :
                          (insn.category == InsnCategory::OR)  ? WIRE_ORID  : WIRE_XORID;
                }
            }
            const uint8_t nsel = naluSel(width, naluOp);

            // Operand order: `dst` is always the written operand here (the
            // decoder normalises rm,reg forms), so a memory destination shows
            // up as dst.type == Memory with src holding the register.
            if (insn.dst.type == OperandType::Register) {
                if (!needGPR(insn.dst.reg)) { handled = false; break; }
                uint8_t d = regs.g2v(insn.dst.reg);
                if (d == 0xFF) { handled = false; break; }
                if (insn.src.type == OperandType::Register && needGPR(insn.src.reg)) {
                    uint8_t s = regs.g2v(insn.src.reg);
                    if (s == 0xFF) { handled = false; break; }
                    if (partial) {
                        emit(WIRE_NALU); b8(nsel); b8(d); b8(s);
                    } else {
                        emit(wire); b8(d); b8(s);
                    }
                } else if (insn.src.type == OperandType::Immediate) {
                    if (partial) {
                        emit(WIRE_LOADIMM); b8(SCRATCH_B);
                        q64((uint64_t)insn.src.immediate);
                        emit(WIRE_NALU); b8(nsel); b8(d); b8(SCRATCH_B);
                    } else if (w32 && (insn.category == InsnCategory::SBB ||
                                       insn.category == InsnCategory::ADC)) {
                        // no *DI form for the 32-bit carry ops
                        emit(WIRE_LOADIMM); b8(SCRATCH_B);
                        q64((uint64_t)(uint32_t)insn.src.immediate);
                        emit(wire); b8(d); b8(SCRATCH_B);
                    } else {
                        emit(wireImm); b8(d);
                        q64(w32 ? (uint64_t)(uint32_t)insn.src.immediate
                                : (uint64_t)insn.src.immediate);
                    }
                } else if (insn.src.type == OperandType::Memory ||
                           insn.src.type == OperandType::MemoryRegIndir ||
                           insn.src.type == OperandType::MemoryRIP) {
                    // read-modify-write through a scratch register
                    if (!memOk || !memAddr(insn.src, SCRATCH_A, (uint32_t)off, len)) { handled = false; break; }
                    uint8_t loadOp = insn.src.size >= 8 ? WIRE_LOADQ :
                                     insn.src.size == 4 ? WIRE_LOADD :
                                     insn.src.size == 2 ? WIRE_LOADW : WIRE_LOADB;
                    emit(loadOp); b8(SCRATCH_B); b8(SCRATCH_A); d32(0);
                    if (partial) {
                        emit(WIRE_NALU); b8(nsel); b8(d); b8(SCRATCH_B);
                    } else {
                        emit(wire); b8(d); b8(SCRATCH_B);
                    }
                } else { handled = false; }
            } else if ((insn.dst.type == OperandType::Memory ||
                        insn.dst.type == OperandType::MemoryRegIndir ||
                        insn.dst.type == OperandType::MemoryRIP) &&
                       insn.src.type == OperandType::Immediate) {
                // add/sub/... [mem], imm - read-modify-write.
                // The address and the loaded value already occupy both
                // translator scratch slots, so the immediate is staged into
                // SCRATCH_A after the load and the address is rebuilt for the
                // store. memAddr is flag-transparent and deterministic, so the
                // rebuild is both safe and exact.
                if (!memOk) { handled = false; break; }
                if (!memAddr(insn.dst, SCRATCH_A, (uint32_t)off, len)) { handled = false; break; }
                uint8_t loadOp = insn.dst.size >= 8 ? WIRE_LOADQ :
                                 insn.dst.size == 4 ? WIRE_LOADD :
                                 insn.dst.size == 2 ? WIRE_LOADW : WIRE_LOADB;
                uint8_t storeOp = insn.dst.size >= 8 ? WIRE_STOREQ :
                                  insn.dst.size == 4 ? WIRE_STORED :
                                  insn.dst.size == 2 ? WIRE_STOREW : WIRE_STOREB;
                emit(loadOp); b8(SCRATCH_B); b8(SCRATCH_A); d32(0);
                if (partial) {
                    emit(WIRE_LOADIMM); b8(SCRATCH_A);
                    q64((uint64_t)insn.src.immediate);
                    emit(WIRE_NALU); b8(nsel); b8(SCRATCH_B); b8(SCRATCH_A);
                    if (!memAddr(insn.dst, SCRATCH_A, (uint32_t)off, len)) { handled = false; break; }
                } else {
                    emit(wireImm); b8(SCRATCH_B);
                    q64(w32 ? (uint64_t)(uint32_t)insn.src.immediate
                            : (uint64_t)insn.src.immediate);
                }
                emit(storeOp); b8(SCRATCH_A); d32(0); b8(SCRATCH_B);
            } else if ((insn.dst.type == OperandType::Memory ||
                        insn.dst.type == OperandType::MemoryRegIndir) &&
                       insn.src.type == OperandType::Register) {
                if (!memOk || !needGPR(insn.src.reg)) { handled = false; break; }
                uint8_t s = regs.g2v(insn.src.reg);
                if (s == 0xFF || !memAddr(insn.dst, SCRATCH_A, (uint32_t)off, len)) { handled = false; break; }
                uint8_t loadOp = insn.dst.size >= 8 ? WIRE_LOADQ :
                                 insn.dst.size == 4 ? WIRE_LOADD :
                                 insn.dst.size == 2 ? WIRE_LOADW : WIRE_LOADB;
                uint8_t storeOp = insn.dst.size >= 8 ? WIRE_STOREQ :
                                  insn.dst.size == 4 ? WIRE_STORED :
                                  insn.dst.size == 2 ? WIRE_STOREW : WIRE_STOREB;
                emit(loadOp); b8(SCRATCH_B); b8(SCRATCH_A); d32(0);
                if (partial) {
                    emit(WIRE_NALU); b8(nsel); b8(SCRATCH_B); b8(s);
                } else {
                    emit(wire); b8(SCRATCH_B); b8(s);
                }
                emit(storeOp); b8(SCRATCH_A); d32(0); b8(SCRATCH_B);
            } else { handled = false; }
            break;
        }
        case InsnCategory::CMP: case InsnCategory::TEST: {
            const bool isCmp = insn.category == InsnCategory::CMP;
            // Narrow forms use the byte/word flag computes: the wide op would
            // hand the next branch a stale sign/overflow from the high bits.
            uint8_t opRR = w32 ? (isCmp ? WIRE_CMPD : WIRE_TESTD)
                               : (isCmp ? WIRE_CMP : WIRE_TEST);
            uint8_t opImm = isCmp ? (w32 ? WIRE_CMPID : WIRE_CMPI) : 0;
            if (partial) {
                opRR = (width == 2) ? (isCmp ? WIRE_CMPW : WIRE_TESTW)
                                    : (isCmp ? WIRE_CMPB : WIRE_TESTB);
                opImm = 0;
            }
            auto loadMem = [&](Operand& m, uint8_t slot) -> bool {
                if (!memOk || !memAddr(m, SCRATCH_A, (uint32_t)off, len)) return false;
                uint8_t loadOp = (m.size >= 8) ? WIRE_LOADQ :
                                 (m.size == 4) ? WIRE_LOADD :
                                 (m.size == 2) ? WIRE_LOADW : WIRE_LOADB;
                emit(loadOp); b8(slot); b8(SCRATCH_A); d32(0);
                return true;
            };
            uint8_t d, s;
            if (insn.dst.type == OperandType::Register) {
                if (!needGPR(insn.dst.reg)) { handled = false; break; }
                d = regs.g2v(insn.dst.reg);
                if (d == 0xFF) { handled = false; break; }
                if (insn.src.type == OperandType::Register && needGPR(insn.src.reg)) {
                    s = regs.g2v(insn.src.reg);
                    if (s == 0xFF) { handled = false; break; }
                    emit(opRR); b8(d); b8(s);
                } else if (insn.src.type == OperandType::Immediate) {
                    if (opImm && !isCmp) {
                        // wide TEST reg, imm was lowered as `test d, d`, which
                        // tested the register against itself - a silent flag
                        // bug. Compare against the actual immediate instead.
                        emit(WIRE_LOADIMM); b8(SCRATCH_A);
                        q64(w32 ? (uint64_t)(uint32_t)insn.src.immediate
                                : (uint64_t)insn.src.immediate);
                        emit(opRR); b8(d); b8(SCRATCH_A);
                    } else if (opImm) {
                        emit(opImm); b8(d);
                        q64(w32 ? (uint64_t)(uint32_t)insn.src.immediate
                                : (uint64_t)insn.src.immediate);
                    } else {
                        emit(WIRE_LOADIMM); b8(SCRATCH_A);
                        q64((uint64_t)insn.src.immediate);
                        emit(opRR); b8(d); b8(SCRATCH_A);
                    }
                } else if (insn.src.type == OperandType::Memory ||
                           insn.src.type == OperandType::MemoryRegIndir ||
                           insn.src.type == OperandType::MemoryRIP) {
                    if (!loadMem(insn.src, SCRATCH_B)) { handled = false; break; }
                    emit(opRR); b8(d); b8(SCRATCH_B);
                } else { handled = false; }
            } else if ((insn.dst.type == OperandType::Memory ||
                        insn.dst.type == OperandType::MemoryRegIndir ||
                        insn.dst.type == OperandType::MemoryRIP)) {
                // cmp/test [mem], reg | imm
                if (!loadMem(insn.dst, SCRATCH_B)) { handled = false; break; }
                if (insn.src.type == OperandType::Register && needGPR(insn.src.reg)) {
                    s = regs.g2v(insn.src.reg);
                    if (s == 0xFF) { handled = false; break; }
                    emit(opRR); b8(SCRATCH_B); b8(s);
                } else if (insn.src.type == OperandType::Immediate) {
                    emit(WIRE_LOADIMM); b8(SCRATCH_A);
                    q64((uint64_t)insn.src.immediate);
                    emit(opRR); b8(SCRATCH_B); b8(SCRATCH_A);
                } else { handled = false; }
            } else { handled = false; }
            break;
        }
        case InsnCategory::INC: case InsnCategory::DEC: case InsnCategory::NEG: case InsnCategory::NOT: {
            // INC/DEC/NEG go through WIRE_NALU at every width: x86 INC/DEC
            // never write CF, and the old ADDI/SUBI lowering did - a following
            // adc/sbb/jb read a carry the original instruction never produced.
            // NOT sets no flags at all, so it keeps its own path.
            const uint8_t naluOp = (insn.category == InsnCategory::INC) ? NP_NALU_INC :
                                   (insn.category == InsnCategory::DEC) ? NP_NALU_DEC :
                                                                          NP_NALU_NEG;
            if (insn.category == InsnCategory::NOT) {
                if (insn.dst.type == OperandType::Memory ||
                    insn.dst.type == OperandType::MemoryRegIndir ||
                    insn.dst.type == OperandType::MemoryRIP) {
                    if (!memOk || !memAddr(insn.dst, SCRATCH_A, (uint32_t)off, len)) { handled = false; break; }
                    uint8_t loadOp = insn.dst.size >= 8 ? WIRE_LOADQ :
                                     insn.dst.size == 4 ? WIRE_LOADD :
                                     insn.dst.size == 2 ? WIRE_LOADW : WIRE_LOADB;
                    uint8_t storeOp = insn.dst.size >= 8 ? WIRE_STOREQ :
                                      insn.dst.size == 4 ? WIRE_STORED :
                                      insn.dst.size == 2 ? WIRE_STOREW : WIRE_STOREB;
                    emit(loadOp); b8(SCRATCH_B); b8(SCRATCH_A); d32(0);
                    emit(WIRE_NOT); b8(SCRATCH_B);
                    emit(storeOp); b8(SCRATCH_A); d32(0); b8(SCRATCH_B);
                    break;
                }
                Reg r = insn.dst.reg;
                if (!needGPR(r)) { handled = false; break; }
                uint8_t v = regs.g2v(r);
                if (v == 0xFF) { handled = false; break; }
                if (partial) {
                    emit(WIRE_MOVE); b8(SCRATCH_A); b8(v);
                    emit(WIRE_NOT); b8(SCRATCH_A);
                    emit(splice); b8(v); b8(SCRATCH_A);
                } else if (w32) {
                    emit(WIRE_NOTD); b8(v);
                } else {
                    emit(WIRE_NOT); b8(v);
                }
                break;
            }
            if (insn.dst.type == OperandType::Memory ||
                insn.dst.type == OperandType::MemoryRegIndir ||
                insn.dst.type == OperandType::MemoryRIP) {
                // inc/dec/neg [mem]
                if (!memOk || !memAddr(insn.dst, SCRATCH_A, (uint32_t)off, len)) { handled = false; break; }
                uint8_t loadOp = insn.dst.size >= 8 ? WIRE_LOADQ :
                                 insn.dst.size == 4 ? WIRE_LOADD :
                                 insn.dst.size == 2 ? WIRE_LOADW : WIRE_LOADB;
                uint8_t storeOp = insn.dst.size >= 8 ? WIRE_STOREQ :
                                  insn.dst.size == 4 ? WIRE_STORED :
                                  insn.dst.size == 2 ? WIRE_STOREW : WIRE_STOREB;
                emit(loadOp); b8(SCRATCH_B); b8(SCRATCH_A); d32(0);
                emit(WIRE_NALU); b8(naluSel(insn.dst.size ? insn.dst.size : 8, naluOp));
                b8(SCRATCH_B); b8(SCRATCH_B);
                emit(storeOp); b8(SCRATCH_A); d32(0); b8(SCRATCH_B);
                break;
            }
            Reg r = insn.dst.reg;
            if (!needGPR(r)) { handled = false; break; }
            uint8_t v = regs.g2v(r);
            if (v == 0xFF) { handled = false; break; }
            emit(WIRE_NALU); b8(naluSel(width, naluOp)); b8(v); b8(v);
            break;
        }
        case InsnCategory::SHL: case InsnCategory::SHR: case InsnCategory::SAR:
        case InsnCategory::ROL: case InsnCategory::ROR: {
            const uint8_t shOp = insn.category == InsnCategory::SHL ? NP_NALU_SHL :
                                 insn.category == InsnCategory::SHR ? NP_NALU_SHR :
                                 insn.category == InsnCategory::SAR ? NP_NALU_SAR :
                                 insn.category == InsnCategory::ROL ? NP_NALU_ROL : NP_NALU_ROR;
            // Everything except a plain 64-bit register destination goes
            // through WIRE_NALU: that covers the 8/16-bit forms (which shift
            // bits in from outside the register half), the 32-bit forms (whose
            // result must be zero-extended and whose flags are 32-bit) and
            // memory destinations. The old path rejected all of those.
            auto shiftViaNalu = [&](uint8_t v) -> bool {
                if (insn.src.type == OperandType::Immediate) {
                    emit(WIRE_LOADIMM); b8(SCRATCH_B); q64((uint64_t)insn.src.immediate);
                    emit(WIRE_NALU); b8(naluSel(width, shOp)); b8(v); b8(SCRATCH_B);
                    return true;
                }
                if (insn.src.type == OperandType::Register) {
                    uint8_t s = regs.g2v(insn.src.reg);
                    if (s == 0xFF) return false;
                    emit(WIRE_NALU); b8(naluSel(width, shOp)); b8(v); b8(s);
                    return true;
                }
                return false;
            };
            if (insn.dst.type == OperandType::Memory ||
                insn.dst.type == OperandType::MemoryRegIndir ||
                insn.dst.type == OperandType::MemoryRIP) {
                if (!memOk || !memAddr(insn.dst, SCRATCH_A, (uint32_t)off, len)) { handled = false; break; }
                uint8_t loadOp = insn.dst.size >= 8 ? WIRE_LOADQ :
                                 insn.dst.size == 4 ? WIRE_LOADD :
                                 insn.dst.size == 2 ? WIRE_LOADW : WIRE_LOADB;
                uint8_t storeOp = insn.dst.size >= 8 ? WIRE_STOREQ :
                                  insn.dst.size == 4 ? WIRE_STORED :
                                  insn.dst.size == 2 ? WIRE_STOREW : WIRE_STOREB;
                emit(loadOp); b8(SCRATCH_B); b8(SCRATCH_A); d32(0);
                // shift the value in place, then write it back
                if (insn.src.type == OperandType::Immediate) {
                    emit(WIRE_LOADIMM); b8(SCRATCH_A); q64((uint64_t)insn.src.immediate);
                    emit(WIRE_NALU); b8(naluSel(width, shOp)); b8(SCRATCH_B); b8(SCRATCH_A);
                    if (!memAddr(insn.dst, SCRATCH_A, (uint32_t)off, len)) { handled = false; break; }
                } else {
                    uint8_t s = regs.g2v(insn.src.reg);
                    if (s == 0xFF) { handled = false; break; }
                    emit(WIRE_NALU); b8(naluSel(width, shOp)); b8(SCRATCH_B); b8(s);
                }
                emit(storeOp); b8(SCRATCH_A); d32(0); b8(SCRATCH_B);
                break;
            }
            if (!needGPR(insn.dst.reg)) { handled = false; break; }
            uint8_t v = regs.g2v(insn.dst.reg);
            if (v == 0xFF) { handled = false; break; }
            if (!rexW || partial) {
                if (!shiftViaNalu(v)) { handled = false; }
                break;
            }
            // From here the form is a plain 64-bit register shift/rotate: the
            // dedicated wide opcodes cover it. (32-bit and narrower already
            // left through the NALU path above, so `w32` cannot be true here -
            // an earlier revision kept a dead "32-bit rotate stays native"
            // branch that was unreachable and read as a live limitation.)
            if (insn.src.type == OperandType::Immediate) {
                uint64_t sh = (uint64_t)insn.src.immediate;
                if (insn.category == InsnCategory::SHL && sh == 1) { emit(WIRE_ADD); b8(v); b8(v); }
                else if (insn.category == InsnCategory::SHL) { emit(WIRE_SHLI); b8(v); q64(sh); }
                else if (insn.category == InsnCategory::SHR) { emit(WIRE_SHRI); b8(v); q64(sh); }
                else if (insn.category == InsnCategory::SAR) { emit(WIRE_SARI); b8(v); q64(sh); }
                else if (insn.category == InsnCategory::ROL) { emit(WIRE_ROLI); b8(v); q64(sh); }
                else { emit(WIRE_RORI); b8(v); q64(sh); }
            } else if (insn.src.type == OperandType::Register) {
                uint8_t s = regs.g2v(insn.src.reg);
                if (s == 0xFF) { handled = false; break; }
                // CL-forms: the shift count register is the low byte of the
                // source, which the identity mapping already carries.
                uint8_t wire = insn.category == InsnCategory::SHL ? WIRE_SHL :
                               insn.category == InsnCategory::SHR ? WIRE_SHR :
                               insn.category == InsnCategory::SAR ? WIRE_SAR :
                               insn.category == InsnCategory::ROL ? WIRE_ROL : WIRE_ROR;
                emit(wire); b8(v); b8(s);
            } else { handled = false; }
            break;
        }
        case InsnCategory::PUSH: case InsnCategory::PUSH_IMM: {
            // Guest RSP lives in VM slot 4. Push = slot4 -= 8; [slot4] = value.
            // ADDRADDI is flag-free so the push does not disturb an in-flight
            // comparison (PUSH is architecturally flag-transparent).
            // fixupOperands keeps the pushed value in *dst* for every form -
            // push reg (0x50+r), push imm (68/6A) and push r/m (FF /6). The
            // old src-based read fell through to "store src.immediate", which
            // is always zero for these forms: every translated push stored 0
            // and the lowered leave/pop of the same frame restored it.
            if (insn.prefixes & PREFIX_66) { handled = false; break; } // 16-bit push
            uint8_t sp = regs.vmSp;
            emit(WIRE_ADDRADDI); b8(sp); q64((uint64_t)-8);
            if (insn.dst.type == OperandType::Immediate) {
                emit(WIRE_LOADIMM); b8(SCRATCH_A); q64(insn.dst.immediate);
                emit(WIRE_STOREQ); b8(sp); d32(0); b8(SCRATCH_A);
            } else if (insn.dst.type == OperandType::Register) {
                if (!needGPR(insn.dst.reg)) { handled = false; break; }
                uint8_t s = regs.g2v(insn.dst.reg);
                if (s == 0xFF) { handled = false; break; }
                emit(WIRE_STOREQ); b8(sp); d32(0); b8(s);
            } else if (insn.dst.type == OperandType::Memory ||
                       insn.dst.type == OperandType::MemoryRegIndir ||
                       insn.dst.type == OperandType::MemoryRIP) {
                if (!memOk || !memAddr(insn.dst, SCRATCH_A, (uint32_t)off, len)) {
                    handled = false; break;
                }
                emit(WIRE_LOADQ); b8(SCRATCH_B); b8(SCRATCH_A); d32(0);
                emit(WIRE_STOREQ); b8(sp); d32(0); b8(SCRATCH_B);
            } else {
                handled = false;
            }
            break;
        }
        case InsnCategory::POP: {
            // Pop = value = [slot4]; slot4 += 8. LOADQ then ADDRADDI in that
            // order so the load reads the slot the push wrote.
            if (insn.prefixes & PREFIX_66) { handled = false; break; } // 16-bit pop
            uint8_t sp = regs.vmSp;
            if (insn.dst.type == OperandType::Register) {
                if (!needGPR(insn.dst.reg)) { handled = false; break; }
                uint8_t d = regs.g2v(insn.dst.reg);
                if (d == 0xFF) { handled = false; break; }
                emit(WIRE_LOADQ); b8(d); b8(sp); d32(0);
                emit(WIRE_ADDRADDI); b8(sp); q64(8);
            } else if (insn.dst.type == OperandType::Memory ||
                       insn.dst.type == OperandType::MemoryRegIndir ||
                       insn.dst.type == OperandType::MemoryRIP) {
                if (!memOk || !memAddr(insn.dst, SCRATCH_A, (uint32_t)off, len)) {
                    handled = false; break;
                }
                emit(WIRE_LOADQ); b8(SCRATCH_B); b8(sp); d32(0);
                emit(WIRE_STOREQ); b8(SCRATCH_A); d32(0); b8(SCRATCH_B);
                emit(WIRE_ADDRADDI); b8(sp); q64(8);
            } else {
                handled = false;
            }
            break;
        }
        case InsnCategory::JMP: {
            if (insn.opcode == 0xE9 || insn.opcode == 0xEB) {
                uint32_t target = (uint32_t)((int64_t)off + (int32_t)len + insn.rel_target);
                if (target >= bodyStart && target < endPos) {
                    emit(WIRE_JMP); fixups.push_back({ bc.size(), target }); d32(0);
                } else {
                    // Direct jump out of the body: leave to the target itself.
                    emit(WIRE_EXITJMP);
                    d32((uint32_t)(guestRip - imageBase) + target);
                }
            } else {
                // Indirect jump: the target is only known at run time, so exit
                // with that value and let the trampoline jump to it. Exiting
                // through the jump's own bytes would race the five-byte
                // trampoline stub when the jump sits at the region head; the
                // register form depends on no native byte surviving.
                if (((insn.modrm >> 3) & 7) == 5) { handled = false; break; } // jmpf
                uint8_t slot;
                if (insn.dst.type == OperandType::Register) {
                    slot = regs.g2v(insn.dst.reg);
                    if (slot == 0xFF) { handled = false; break; }
                } else if (insn.dst.type == OperandType::Memory ||
                           insn.dst.type == OperandType::MemoryRegIndir ||
                           insn.dst.type == OperandType::MemoryRIP) {
                    if (!memOk || !memAddr(insn.dst, SCRATCH_A, (uint32_t)off, len)) { handled = false; break; }
                    emit(WIRE_LOADQ); b8(SCRATCH_B); b8(SCRATCH_A); d32(0);
                    slot = SCRATCH_B;
                } else {
                    handled = false; break;
                }
                emit(WIRE_EXITJMP);
                d32(0x80000000u | (uint32_t)slot);
            }
            break;
        }
        case InsnCategory::JCC: {
            // A branch reached while imul's CF/OF or a wide-lowered byte ALU
            // flags are still live would read flags the wire VM never produced.
            // IMUL's ZF/SF/PF are exact (computed from the low 64 bits), so
            // branches that read only those flags are safe; byte-ALU flags are
            // wrong for every condition and always reject.
            if (byteFlagsPending) { handled = false; break; }
            if (mulFlagsPending) {
                // cc: 0=O 1=NO 2=B 3=AE 4=E 5=NE 6=BE 7=A 8=S 9=NS A=P B=NP
                //     C=L D=GE E=LE F=G. O/NO read OF; B/AE/BE/A read CF;
                //     L/GE/LE/G read SF!=OF (OF is stale).
                uint8_t cc = insn.condition;
                if (cc <= 0x3 || cc == 0x6 || cc == 0x7 || cc >= 0xC) {
                    handled = false; break;
                }
            }
            uint8_t wire = jccWire(insn.condition, insn.prefixes);
            if (!wire) { handled = false; break; }
            uint32_t target = (uint32_t)((int64_t)off + (int32_t)len + insn.rel_target);
            if (target >= bodyStart && target < endPos) {
                emit(wire); fixups.push_back({ bc.size(), target }); d32(0);
            } else {
                // Condition jumps out of the body (native epilogue, tail call,
                // another function). Invert it over a native exit so the taken
                // path leaves the VM exactly where the original branch went.
                uint8_t inv = jccWire(insn.condition ^ 1u, insn.prefixes);
                if (!inv) { handled = false; break; }
                emit(inv); fixups.push_back({ bc.size(), (uint32_t)off + len }); d32(0);
                emit(WIRE_EXITJMP);
                d32((uint32_t)(guestRip - imageBase) + target);
            }
            break;
        }
        case InsnCategory::CALL: {
            if (insn.opcode == 0xE8) {
                uint32_t target = (uint32_t)((int64_t)off + (int32_t)len + insn.rel_target);
                emit(WIRE_CALL);
                d32((uint32_t)(guestRip - imageBase) + target);
            } else if (insn.dst.type == OperandType::Register) {
                uint8_t s = regs.g2v(insn.dst.reg);
                if (s == 0xFF) { handled = false; break; }
                emit(WIRE_CALL);
                d32(0x80000000u | (uint32_t)s);
            } else if (insn.dst.type == OperandType::Memory ||
                       insn.dst.type == OperandType::MemoryRegIndir ||
                       insn.dst.type == OperandType::MemoryRIP) {
                if (!memOk || !memAddr(insn.dst, SCRATCH_A, (uint32_t)off, len)) { handled = false; break; }
                emit(WIRE_LOADQ); b8(SCRATCH_B); b8(SCRATCH_A); d32(0);
                emit(WIRE_CALL);
                d32(0x80000000u | (uint32_t)SCRATCH_B);
            } else {
                handled = false;
            }
            break;
        }
        case InsnCategory::SETcc: {
            // setcc r8 -> 0/1 computed in a scratch, spliced into the low byte.
            if (mulFlagsPending || byteFlagsPending) { handled = false; break; }
            if (!needGPR(insn.dst.reg)) { handled = false; break; }
            uint8_t d = regs.g2v(insn.dst.reg);
            if (d == 0xFF) { handled = false; break; }
            uint8_t inv = jccWire(insn.condition ^ 1u, insn.prefixes);
            if (!inv) { handled = false; break; }
            emit(WIRE_LOADIMM); b8(SCRATCH_A); q64(0);
            emit(inv); fixups.push_back({ bc.size(), (uint32_t)off + len }); d32(0);
            emit(WIRE_LOADIMM); b8(SCRATCH_A); q64(1);
            emit(WIRE_INSB); b8(d); b8(SCRATCH_A);
            break;
        }
        case InsnCategory::CMOVcc: {
            if (mulFlagsPending || byteFlagsPending) { handled = false; break; }
            if (!needGPR(insn.dst.reg)) { handled = false; break; }
            uint8_t d = regs.g2v(insn.dst.reg);
            if (d == 0xFF) { handled = false; break; }
            uint8_t inv = jccWire(insn.condition ^ 1u, insn.prefixes);
            if (!inv) { handled = false; break; }
            // Invert over the move: the destination is only written when the
            // original cmov's condition holds.
            size_t fixSlot = 0;
            emit(inv); fixSlot = bc.size(); fixups.push_back({ bc.size(), (uint32_t)off + len }); d32(0);
            if (insn.src.type == OperandType::Register) {
                uint8_t s = regs.g2v(insn.src.reg);
                if (s == 0xFF) { handled = false; break; }
                emit(w32 ? WIRE_MOVD : WIRE_MOVE); b8(d); b8(s);
            } else if (insn.src.type == OperandType::Memory ||
                       insn.src.type == OperandType::MemoryRegIndir) {
                if (!memOk || !memAddr(insn.src, SCRATCH_A, (uint32_t)off, len)) { handled = false; break; }
                uint8_t loadOp;
                switch (insn.src.size ? insn.src.size : 8) {
                case 8: loadOp = WIRE_LOADQ; break;
                case 4: loadOp = WIRE_LOADD; break;
                case 2: loadOp = WIRE_LOADW; break;
                case 1: loadOp = WIRE_LOADB; break;
                default: handled = false; loadOp = 0; break;
                }
                if (!handled) break;
                emit(loadOp); b8(d); b8(SCRATCH_A); d32(0);
            } else {
                handled = false;
            }
            (void)fixSlot;
            break;
        }
        case InsnCategory::XCHG: {
            if (insn.dst.type == OperandType::Register &&
                insn.src.type == OperandType::Register) {
                if (!needGPR(insn.dst.reg) || !needGPR(insn.src.reg)) { handled = false; break; }
                uint8_t d = regs.g2v(insn.dst.reg), s = regs.g2v(insn.src.reg);
                if (d == 0xFF || s == 0xFF) { handled = false; break; }
                if (d == s) break;
                emit(WIRE_MOVE); b8(SCRATCH_A); b8(d);
                if (partial) {
                    emit(splice); b8(d); b8(s);
                    emit(splice); b8(s); b8(SCRATCH_A);
                } else if (w32) {
                    emit(WIRE_MOVD); b8(d); b8(s);
                    emit(WIRE_MOVD); b8(s); b8(SCRATCH_A);
                } else {
                    emit(WIRE_MOVE); b8(d); b8(s);
                    emit(WIRE_MOVE); b8(s); b8(SCRATCH_A);
                }
            } else if (insn.dst.type == OperandType::Register &&
                       (insn.src.type == OperandType::Memory ||
                        insn.src.type == OperandType::MemoryRegIndir ||
                        insn.src.type == OperandType::MemoryRIP)) {
                if (!memOk || !needGPR(insn.dst.reg)) { handled = false; break; }
                uint8_t d = regs.g2v(insn.dst.reg);
                if (d == 0xFF || !memAddr(insn.src, SCRATCH_A, (uint32_t)off, len)) { handled = false; break; }
                uint8_t loadOp, storeOp;
                switch (insn.src.size ? insn.src.size : 8) {
                case 8: loadOp = WIRE_LOADQ; storeOp = WIRE_STOREQ; break;
                case 4: loadOp = WIRE_LOADD; storeOp = WIRE_STORED; break;
                case 2: loadOp = WIRE_LOADW; storeOp = WIRE_STOREW; break;
                case 1: loadOp = WIRE_LOADB; storeOp = WIRE_STOREB; break;
                default: handled = false; loadOp = storeOp = 0; break;
                }
                if (!handled) break;
                emit(loadOp); b8(SCRATCH_B); b8(SCRATCH_A); d32(0);
                emit(storeOp); b8(SCRATCH_A); d32(0); b8(d);
                // Braces: the operand pushes must belong to the chosen arm,
                // not run for both (same defect as the mov case above).
                if (partial) { emit(splice); b8(d); b8(SCRATCH_B); }
                else { emit(WIRE_MOVE); b8(d); b8(SCRATCH_B); }
            } else {
                handled = false;
            }
            break;
        }
        case InsnCategory::XADD: {
            // xadd r/m, r: tmp = dst; dst = dst + src; src = tmp. The decoder
            // leaves the reg field (the *source*) in dst, so swap first.
            Operand tdst = insn.src, tsrc = insn.dst;
            if (tdst.type == OperandType::Register &&
                tsrc.type == OperandType::Register) {
                if (!needGPR(tdst.reg) || !needGPR(tsrc.reg)) { handled = false; break; }
                uint8_t d = regs.g2v(tdst.reg), s = regs.g2v(tsrc.reg);
                if (d == 0xFF || s == 0xFF) { handled = false; break; }
                emit(WIRE_MOVE); b8(SCRATCH_A); b8(d);
                if (partial) emit(WIRE_NALU); else emit(w32 ? WIRE_ADDD : WIRE_ADD);
                if (partial) { b8(naluSel(width, NP_NALU_ADD)); b8(d); b8(s); }
                else { b8(d); b8(s); }
                emit(WIRE_MOVE); b8(s); b8(SCRATCH_A);
            } else if ((tdst.type == OperandType::Memory ||
                        tdst.type == OperandType::MemoryRegIndir ||
                        tdst.type == OperandType::MemoryRIP) &&
                       tsrc.type == OperandType::Register) {
                if (!memOk || !needGPR(tsrc.reg)) { handled = false; break; }
                uint8_t s = regs.g2v(tsrc.reg);
                if (s == 0xFF || !memAddr(tdst, SCRATCH_A, (uint32_t)off, len)) { handled = false; break; }
                uint8_t loadOp = tdst.size >= 8 ? WIRE_LOADQ :
                                 tdst.size == 4 ? WIRE_LOADD :
                                 tdst.size == 2 ? WIRE_LOADW : WIRE_LOADB;
                uint8_t storeOp = tdst.size >= 8 ? WIRE_STOREQ :
                                  tdst.size == 4 ? WIRE_STORED :
                                  tdst.size == 2 ? WIRE_STOREW : WIRE_STOREB;
                // Use `s` as the accumulator so SCRATCH_A (the address)
                // survives to the store. The add sets the flags exactly as
                // XADD requires (old + src) at the operand width; the final
                // MOVE is flag-free.
                emit(loadOp); b8(SCRATCH_B); b8(SCRATCH_A); d32(0);
                if (partial) {
                    emit(WIRE_NALU); b8(naluSel(width, NP_NALU_ADD)); b8(s); b8(SCRATCH_B);
                } else {
                    emit(w32 ? WIRE_ADDD : WIRE_ADD); b8(s); b8(SCRATCH_B);
                }
                emit(storeOp); b8(SCRATCH_A); d32(0); b8(s);
                emit(WIRE_MOVE); b8(s); b8(SCRATCH_B);
            } else { handled = false; }
            mulFlagsPending = false;
            byteFlagsPending = false;
            break;
        }
        case InsnCategory::SSE: {
            // XMM data movement only: memcpy tails, spill fills and the
            // pxor zeroing idiom. SSE arithmetic keeps the function native.
            // Operands carry xmm i as register XMM0+i; the wire names them
            // 20+i (the file behind the GPR slots).
            auto xmmSlot = [&](Reg rr) -> uint8_t {
                uint8_t v = (uint8_t)rr;
                // The decoder maps SSE reg/rm fields to GPR indices 0..15
                // (it does not know the instruction is SSE at parse time).
                // Accept those as XMM0..XMM15 alongside the explicit XMM
                // enum values (17..32).
                if (v <= 15) return (uint8_t)(20 + v);
                if (v < (uint8_t)Reg::XMM0 || v > (uint8_t)Reg::XMM15) return 0xFF;
                return (uint8_t)(20 + (v - (uint8_t)Reg::XMM0));
            };
            uint8_t op2 = insn.opcode2;

            // ---- conversions (int <-> fp <-> fp) ------------------------
            // These have a GPR on one side and an xmm on the other, so they
            // cannot share the reg/reg path below. The fmt nibble of the
            // selector is the conversion code (see include/vm_isa.h).
            if (op2 == 0x2A || op2 == 0x2C || op2 == 0x2D ||
                op2 == 0x5A || op2 == 0x5B || op2 == 0xE6) {
                const bool p66 = (insn.prefixes & PREFIX_66) != 0;
                const bool pF3 = (insn.prefixes & PREFIX_F3) != 0;
                const bool pF2 = (insn.prefixes & PREFIX_F2) != 0;
                const bool round = (op2 == 0x2D) ||
                                   (op2 == 0x5B && p66) ||
                                   (op2 == 0xE6 && p66);
                uint8_t code = 0xFF;
                if (op2 == 0x2A) {
                    // cvtsi2ss/cvtsi2sd xmm, r/m - the integer width follows REX.W
                    if (pF2) code = rexW ? 2 : 1;
                    else code = rexW ? 3 : 0;
                } else if (op2 == 0x2C || op2 == 0x2D) {
                    // cvt(t)ss2si / cvt(t)sd2si r, xmm - integer width follows REX.W
                    if (pF2) code = rexW ? 6 : 5;
                    else code = rexW ? 7 : 4;
                } else if (op2 == 0x5A) {
                    code = pF3 ? 8 : pF2 ? 9 : p66 ? 15 : 14;
                } else if (op2 == 0x5B) {
                    code = (p66 || pF3) ? 11 : 10;
                } else { // 0xE6
                    code = pF2 ? 12 : 13;
                }
                // fp -> int forms truncate (cvtt*) or round (cvt*); the
                // int -> fp and fp -> fp forms have no such distinction.
                const bool fpToInt = (op2 == 0x2C || op2 == 0x2D) ||
                                     (op2 == 0x5B && (p66 || pF3)) ||
                                     (op2 == 0xE6 && !pF2);
                const uint8_t cop = !fpToInt ? NP_XALU_CVT2F
                                    : round ? NP_XALU_CVT2F2 : NP_XALU_CVT2I;
                const uint8_t sel = cop;   /* encoding: op byte then fmt byte */
                if (op2 == 0x2A) {
                    // int -> fp: the integer comes from a GPR or memory and
                    // goes through an xmm scratch.
                    uint8_t d = xmmSlot(insn.dst.reg);
                    uint8_t tmp = XMM_TMP(d);
                    if (d == 0xFF) { handled = false; break; }
                    if (insn.src.type == OperandType::Register) {
                        if (!needGPR(insn.src.reg)) { handled = false; break; }
                        uint8_t g = regs.g2v(insn.src.reg);
                        if (g == 0xFF) { handled = false; break; }
                        emit(WIRE_XLOADD); b8(tmp); b8(g);
                    } else if (insn.src.type == OperandType::Memory ||
                               insn.src.type == OperandType::MemoryRegIndir ||
                               insn.src.type == OperandType::MemoryRIP) {
                        if (!memOk || !memAddr(insn.src, SCRATCH_A, (uint32_t)off, len)) { handled = false; break; }
                        emit((insn.src.size == 4) ? WIRE_LOADD : WIRE_LOADQ);
                        b8(SCRATCH_B); b8(SCRATCH_A); d32(0);
                        emit(WIRE_XLOADD); b8(tmp); b8(SCRATCH_B);
                    } else { handled = false; break; }
                    emit(WIRE_XALU); b8(sel); b8(code); b8(d); b8(tmp);
                } else if (op2 == 0x2C || op2 == 0x2D) {
                    // fp -> int: the result goes to a GPR.
                    uint8_t tmp = XMM_TMP(0);
                    if (insn.src.type == OperandType::Register) {
                        uint8_t s2 = xmmSlot(insn.src.reg);
                        if (s2 == 0xFF) { handled = false; break; }
                        emit(WIRE_XALU); b8(sel); b8(code); b8(tmp); b8(s2);
                    } else if (insn.src.type == OperandType::Memory ||
                               insn.src.type == OperandType::MemoryRegIndir ||
                               insn.src.type == OperandType::MemoryRIP) {
                        if (!memOk || !memAddr(insn.src, SCRATCH_A, (uint32_t)off, len)) { handled = false; break; }
                        uint8_t s2 = XMM_TMP(tmp);
                        emit(WIRE_XLOAD); b8(s2); b8(SCRATCH_A); d32(0);
                        emit(WIRE_XALU); b8(sel); b8(code); b8(tmp); b8(s2);
                    } else { handled = false; break; }
                    if (insn.dst.type != OperandType::Register || !needGPR(insn.dst.reg)) { handled = false; break; }
                    uint8_t g = regs.g2v(insn.dst.reg);
                    if (g == 0xFF) { handled = false; break; }
                    emit(WIRE_XSTORED); b8(g); b8(tmp);
                } else {
                    // fp <-> fp: xmm <- xmm/m
                    if (insn.dst.type != OperandType::Register) { handled = false; break; }
                    uint8_t d = xmmSlot(insn.dst.reg);
                    uint8_t s2;
                    if (insn.src.type == OperandType::Register) {
                        s2 = xmmSlot(insn.src.reg);
                    } else if (insn.src.type == OperandType::Memory ||
                               insn.src.type == OperandType::MemoryRegIndir ||
                               insn.src.type == OperandType::MemoryRIP) {
                        if (!memOk || !memAddr(insn.src, SCRATCH_A, (uint32_t)off, len)) { handled = false; break; }
                        s2 = XMM_TMP(d);
                        emit(WIRE_XLOAD); b8(s2); b8(SCRATCH_A); d32(0);
                    } else { handled = false; break; }
                    if (d == 0xFF || s2 == 0xFF) { handled = false; break; }
                    emit(WIRE_XALU); b8(sel); b8(code); b8(d); b8(s2);
                }
                out.usesXmm = true;
                break;
            }

            // ---- XMM arithmetic / SIMD ---------------------------------
            // sel = (fmt << 4) | op. The prefix picks the lane type: bare is
            // packed single, 66 is packed double, F3 is scalar single and F2
            // is scalar double. Scalar forms touch only lane 0 and leave the
            // rest of the destination alone, exactly like addss/addsd.
            {
                const bool p66 = (insn.prefixes & PREFIX_66) != 0;
                const bool pF3 = (insn.prefixes & PREFIX_F3) != 0;
                const bool pF2 = (insn.prefixes & PREFIX_F2) != 0;
                uint8_t fmt = pF2 ? NP_XALU_FMT_SD : pF3 ? NP_XALU_FMT_SS
                             : p66 ? NP_XALU_FMT_PD : NP_XALU_FMT_PS;
                uint8_t xop = 0xFF;
                bool binary = true;      // dst <- dst OP src
                bool unary = false;      // dst <- OP src (sqrt)
                bool cmpImm = false;     // needs a trailing predicate
                switch (op2) {
                case 0x58: xop = NP_XALU_ADD; break;
                case 0x5C: xop = NP_XALU_SUB; break;
                case 0x59: xop = NP_XALU_MUL; break;
                case 0x5E: xop = NP_XALU_DIV; break;
                case 0x5D: xop = NP_XALU_MIN; break;
                case 0x5F: xop = NP_XALU_MAX; break;
                case 0x51: xop = NP_XALU_SQRT; unary = true; break;
                case 0x54: xop = NP_XALU_AND;  fmt = p66 ? NP_XALU_FMT_PD : NP_XALU_FMT_PS; break;
                case 0x55: xop = NP_XALU_ANDN; fmt = p66 ? NP_XALU_FMT_PD : NP_XALU_FMT_PS; break;
                case 0x56: xop = NP_XALU_OR;   fmt = p66 ? NP_XALU_FMT_PD : NP_XALU_FMT_PS; break;
                case 0x57: xop = NP_XALU_XOR;  fmt = p66 ? NP_XALU_FMT_PD : NP_XALU_FMT_PS; break;
                case 0x2E: case 0x2F:
                    // ucomiss/ucomisd/comiss/comisd: compare and set the
                    // integer flags, no xmm write beyond the compare masks.
                    xop = NP_XALU_CMPORD; fmt = (op2 == 0x2F && p66) ? NP_XALU_FMT_SD
                                               : (op2 == 0x2F) ? NP_XALU_FMT_SS
                                               : (p66 || pF2) ? NP_XALU_FMT_SD : NP_XALU_FMT_SS;
                    break;
                case 0xC2: xop = NP_XALU_CMPEQ; cmpImm = true; break;
                case 0xC6: xop = NP_XALU_PSHUF;
                    fmt = p66 ? NP_XALU_FMT_PD : NP_XALU_FMT_PS;
                    cmpImm = true; break;
                default: break;
                }
                // Packed integer SIMD: the prefix selects the data width.
                if (xop == 0xFF) {
                    switch (op2) {
                    case 0x74: xop = NP_XALU_CMPEQ; fmt = p66 ? NP_XALU_FMT_B : NP_XALU_FMT_B; break;
                    case 0x75: xop = NP_XALU_CMPEQ; fmt = NP_XALU_FMT_W; break;
                    case 0x76: xop = NP_XALU_CMPEQ; fmt = p66 ? NP_XALU_FMT_D : NP_XALU_FMT_D; break;
                    case 0x64: xop = NP_XALU_CMPGT; fmt = NP_XALU_FMT_B; break;
                    case 0x65: xop = NP_XALU_CMPGT; fmt = NP_XALU_FMT_W; break;
                    case 0x66: xop = NP_XALU_CMPGT; fmt = p66 ? NP_XALU_FMT_D : NP_XALU_FMT_D; break;
                    case 0x60: xop = NP_XALU_UNPCKL; fmt = NP_XALU_FMT_B; break;
                    case 0x61: xop = NP_XALU_UNPCKL; fmt = NP_XALU_FMT_W; break;
                    case 0x62: xop = NP_XALU_UNPCKL; fmt = NP_XALU_FMT_D; break;
                    case 0x6C: xop = NP_XALU_UNPCKL; fmt = p66 ? NP_XALU_FMT_Q : NP_XALU_FMT_D; break;
                    case 0x68: xop = NP_XALU_UNPCKH; fmt = NP_XALU_FMT_B; break;
                    case 0x69: xop = NP_XALU_UNPCKH; fmt = NP_XALU_FMT_W; break;
                    case 0x6A: xop = NP_XALU_UNPCKH; fmt = NP_XALU_FMT_D; break;
                    case 0x6D: xop = NP_XALU_UNPCKH; fmt = p66 ? NP_XALU_FMT_Q : NP_XALU_FMT_D; break;
                    case 0x63: xop = NP_XALU_PACK; fmt = NP_XALU_FMT_B; break;   // packsswb
                    case 0x67: xop = NP_XALU_PACK; fmt = NP_XALU_FMT_D; break;   // packuswb
                    case 0x6B: xop = NP_XALU_PACK; fmt = NP_XALU_FMT_W; break;   // packssdw
                    case 0xFC: xop = NP_XALU_ADD; fmt = NP_XALU_FMT_B; break;    // paddb
                    case 0xFD: xop = NP_XALU_ADD; fmt = NP_XALU_FMT_W; break;
                    case 0xFE: xop = NP_XALU_ADD; fmt = NP_XALU_FMT_D; break;
                    case 0xD4: xop = NP_XALU_ADD; fmt = NP_XALU_FMT_Q; break;
                    case 0xF8: xop = NP_XALU_SUB; fmt = NP_XALU_FMT_B; break;    // psubb
                    case 0xF9: xop = NP_XALU_SUB; fmt = NP_XALU_FMT_W; break;
                    case 0xFA: xop = NP_XALU_SUB; fmt = NP_XALU_FMT_D; break;
                    case 0xFB: xop = NP_XALU_SUB; fmt = NP_XALU_FMT_Q; break;
                    case 0xDB: xop = NP_XALU_AND;  fmt = NP_XALU_FMT_Q; break;   // pand
                    case 0xDF: xop = NP_XALU_ANDN; fmt = NP_XALU_FMT_Q; break;   // pandn
                    case 0xEB: xop = NP_XALU_OR;   fmt = NP_XALU_FMT_Q; break;   // por
                    case 0xEF: xop = NP_XALU_XOR;  fmt = NP_XALU_FMT_Q; break;   // pxor
                    case 0xD5: xop = NP_XALU_MUL;  fmt = NP_XALU_FMT_W; break;   // pmullw
                    case 0x70: xop = NP_XALU_PSHUF;
                        fmt = pF3 ? NP_XALU_FMT_W : pF2 ? NP_XALU_FMT_B : NP_XALU_FMT_D;
                        cmpImm = true; break;
                    case 0x71: case 0x72: case 0x73: {
                        // imm8 shift groups: the /digit picks the operation
                        uint8_t ext = (insn.modrm >> 3) & 7;
                        if (op2 == 0x73) {
                            if (ext == 2) { xop = NP_XALU_SHRI; fmt = NP_XALU_FMT_Q; }
                            else if (ext == 3) { xop = NP_XALU_SHRI; fmt = NP_XALU_FMT_B; }
                            else if (ext == 6) { xop = NP_XALU_SHLI; fmt = NP_XALU_FMT_Q; }
                            else if (ext == 7) { xop = NP_XALU_SHLI; fmt = NP_XALU_FMT_B; }
                        } else {
                            fmt = (op2 == 0x71) ? NP_XALU_FMT_W : (op2 == 0x72) ? NP_XALU_FMT_D : NP_XALU_FMT_Q;
                            if (ext == 2) xop = NP_XALU_SHRI;
                            else if (ext == 4) xop = NP_XALU_SARI;
                            else if (ext == 6) xop = NP_XALU_SHLI;
                        }
                        if (xop != 0xFF) cmpImm = true;
                        break;
                    }
                    case 0xD7: xop = NP_XALU_MOVMSK; break;   // pmovmskb
                    default: break;
                    }
                }
                if (xop != 0xFF) {
                    /* encoding: op byte then fmt byte */
                    // 0F 71/72/73 are group forms: the reg field is an opcode
                    // extension and the only operand is the rm. Everything else
                    // has reg = dst and rm = src. The trailing imm8 lands in
                    // insn.src.immediate for both shapes.
                    const bool groupForm = (op2 == 0x71 || op2 == 0x72 || op2 == 0x73);
                    uint8_t d = 0xFF, s2 = 0xFF;
                    if (groupForm) {
                        d = xmmSlot(insn.src.reg);
                        s2 = d;
                    } else {
                        d = xmmSlot(insn.dst.reg);
                        bool srcIsMem = insn.src.type == OperandType::Memory ||
                                        insn.src.type == OperandType::MemoryRegIndir ||
                                        insn.src.type == OperandType::MemoryRIP;
                        if (srcIsMem) {
                            if (!memOk || !memAddr(insn.src, SCRATCH_A, (uint32_t)off, len)) { handled = false; break; }
                            s2 = XMM_TMP(d);
                            emit(WIRE_XLOAD); b8(s2); b8(SCRATCH_A); d32(0);
                        } else {
                            s2 = xmmSlot(insn.src.reg);
                        }
                    }
                    if (d == 0xFF || s2 == 0xFF) { handled = false; break; }
                    if (unary) {
                        // sqrt: dst = OP src (nothing is read from dst).
                        emit(WIRE_XALU); b8(xop); b8(fmt); b8(d); b8(s2);
                    } else if (cmpImm) {
                        uint8_t imm = (uint8_t)insn.src.immediate;
                        emit(WIRE_XALUI); b8(xop); b8(fmt); b8(d); b8(s2); b8(imm);
                    } else {
                        emit(WIRE_XALU); b8(xop); b8(fmt); b8(d); b8(s2);
                    }
                    out.usesXmm = true;
                    break;
                }
            }

            const bool scalarMove = (insn.prefixes & (PREFIX_F2 | PREFIX_F3)) != 0;
            // 0F 6F/7F: F3 = movdqu, 66 = movdqa - both 16 bytes (REX.W is
            // ignored for them); bare = MMX movq which has no xmm semantics,
            // so reject. The 8-byte MOVQ forms are separate opcodes and are
            // handled further down.
            const bool wideDq = (op2 == 0x6F || op2 == 0x7F)
                ? ((insn.prefixes & (PREFIX_F3 | PREFIX_66)) != 0)
                : true;
            if (op2 == 0xEF || op2 == 0x57) {
                // pxor / xorps: the zeroing idiom (same register) lowers to
                // XZERO; a general two-register form lowers to XXOR. Bit-level
                // semantics are identical for pxor and xorps.
                if (insn.dst.type != OperandType::Register) { handled = false; break; }
                uint8_t d = xmmSlot(insn.dst.reg);
                if (d == 0xFF) { handled = false; break; }
                if (insn.src.type == OperandType::Register) {
                    uint8_t s2 = xmmSlot(insn.src.reg);
                    if (s2 == 0xFF) { handled = false; break; }
                    if (d == s2) { emit(WIRE_XZERO); b8(d); }
                    else { emit(WIRE_XXOR); b8(d); b8(s2); }
                } else {
                    // xorps xmm, m128: load into a temp xmm via the scratch
                    // pair, XOR, done. The scratch slots are GPRs so we need
                    // the XMM temp; use xmm slot 15 as a working register when
                    // the destination is not 15.
                    uint8_t tmp = XMM_TMP(d);
                    if (insn.src.type == OperandType::Memory ||
                        insn.src.type == OperandType::MemoryRegIndir ||
                        insn.src.type == OperandType::MemoryRIP) {
                        if (!memOk || !memAddr(insn.src, SCRATCH_A, (uint32_t)off, len)) { handled = false; break; }
                        emit(WIRE_XLOAD); b8(tmp); b8(SCRATCH_A); d32(0);
                        emit(WIRE_XXOR); b8(d); b8(tmp);
                    } else { handled = false; break; }
                }
                out.usesXmm = true;
            } else if (op2 == 0x6F || op2 == 0x28) {
                // movdqu/movdqa/movaps/movups xmm <- xmm/m128. Always 16 bytes:
                // REX.W is ignored for these (a `F3 REX.W 0F 6F` is still MOVDQU),
                // and the 8-byte MOVQ forms are handled by the 0xD6 / F3 0F 7E
                // branches below.
                if (insn.dst.type != OperandType::Register) { handled = false; break; }
                uint8_t d = xmmSlot(insn.dst.reg);
                if (d == 0xFF) { handled = false; break; }
                if (!wideDq) { handled = false; break; }               // MMX movq
                if (insn.src.type == OperandType::Register) {
                    uint8_t s2 = xmmSlot(insn.src.reg);
                    if (s2 == 0xFF) { handled = false; break; }
                    emit(WIRE_XMOV); b8(d); b8(s2);
                } else if (insn.src.type == OperandType::Memory ||
                           insn.src.type == OperandType::MemoryRegIndir ||
                           insn.src.type == OperandType::MemoryRIP) {
                    if (!memOk || !memAddr(insn.src, SCRATCH_A, (uint32_t)off, len)) { handled = false; break; }
                    emit(WIRE_XLOAD); b8(d); b8(SCRATCH_A); d32(0);
                } else { handled = false; }
                out.usesXmm = true;
            } else if (op2 == 0x10) {
                // movups/movss/movsd/movaps xmm <- xmm/m. The scalar forms
                // write only the low 4/8 bytes of the destination and leave
                // the rest alone (register form) or zero it (memory form).
                if (insn.dst.type != OperandType::Register) { handled = false; break; }
                uint8_t d = xmmSlot(insn.dst.reg);
                if (d == 0xFF) { handled = false; break; }
                if (scalarMove) {
                    const uint8_t sfmt = (insn.prefixes & PREFIX_F2) ? NP_XALU_FMT_SD
                                                                       : NP_XALU_FMT_SS;
                    if (insn.src.type == OperandType::Register) {
                        uint8_t s2 = xmmSlot(insn.src.reg);
                        if (s2 == 0xFF) { handled = false; break; }
                        emit(WIRE_XALU); b8(NP_XALU_SPLICE); b8(sfmt);
                        b8(d); b8(s2);
                    } else if (insn.src.type == OperandType::Memory ||
                               insn.src.type == OperandType::MemoryRegIndir ||
                               insn.src.type == OperandType::MemoryRIP) {
                        if (!memOk || !memAddr(insn.src, SCRATCH_A, (uint32_t)off, len)) { handled = false; break; }
                        if (sfmt == NP_XALU_FMT_SD) {
                            emit(WIRE_XLOADQ); b8(d); b8(SCRATCH_A); d32(0);
                        } else {
                            emit(WIRE_LOADD); b8(SCRATCH_B); b8(SCRATCH_A); d32(0);
                            emit(WIRE_XLOADD); b8(d); b8(SCRATCH_B);
                        }
                    } else { handled = false; break; }
                    out.usesXmm = true;
                    break;
                }
                if (insn.src.type == OperandType::Register) {
                    uint8_t s2 = xmmSlot(insn.src.reg);
                    if (s2 == 0xFF) { handled = false; break; }
                    emit(WIRE_XMOV); b8(d); b8(s2);
                } else if (insn.src.type == OperandType::Memory ||
                           insn.src.type == OperandType::MemoryRegIndir ||
                           insn.src.type == OperandType::MemoryRIP) {
                    if (!memOk || !memAddr(insn.src, SCRATCH_A, (uint32_t)off, len)) { handled = false; break; }
                    emit(WIRE_XLOAD); b8(d); b8(SCRATCH_A); d32(0);
                } else { handled = false; }
                out.usesXmm = true;
            } else if (op2 == 0x7F || op2 == 0x29 || op2 == 0x11 || op2 == 0x17) {
                // stores: parseModRM put the xmm (reg field) in dst, the
                // destination operand in src - the roles are inverted here.
                // 0F 11 with a scalar prefix is movss/movsd m/xmm, xmm; the
                // register form of that splices the low half and leaves the
                // rest of the destination alone. 0F 17 is movhps m64, xmm.
                uint8_t s2 = xmmSlot(insn.dst.reg);
                if (s2 == 0xFF) { handled = false; break; }
                if (op2 == 0x11 && scalarMove) {
                    const uint8_t sfmt = (insn.prefixes & PREFIX_F2) ? NP_XALU_FMT_SD
                                                                       : NP_XALU_FMT_SS;
                    if (insn.src.type == OperandType::Register) {
                        uint8_t d = xmmSlot(insn.src.reg);
                        if (d == 0xFF) { handled = false; break; }
                        emit(WIRE_XALU); b8(NP_XALU_SPLICE); b8(sfmt);
                        b8(d); b8(s2);
                    } else if (insn.src.type == OperandType::Memory ||
                               insn.src.type == OperandType::MemoryRegIndir ||
                               insn.src.type == OperandType::MemoryRIP) {
                        if (!memOk || !memAddr(insn.src, SCRATCH_A, (uint32_t)off, len)) { handled = false; break; }
                        if (sfmt == NP_XALU_FMT_SD) {
                            emit(WIRE_XSTOREQ); b8(SCRATCH_A); d32(0); b8(s2);
                        } else {
                            emit(WIRE_XSTORED); b8(SCRATCH_B); b8(s2);
                            emit(WIRE_STORED); b8(SCRATCH_A); d32(0); b8(SCRATCH_B);
                        }
                    } else { handled = false; break; }
                    out.usesXmm = true;
                    break;
                }
                if (op2 == 0x17) {
                    // movhps m64, xmm: the high 64 bits of the xmm go to memory.
                    // XMOVHL copies the source's high half into a scratch's low
                    // half, which is exactly the value the store needs.
                    if (insn.src.type != OperandType::Memory &&
                        insn.src.type != OperandType::MemoryRegIndir &&
                        insn.src.type != OperandType::MemoryRIP) { handled = false; break; }
                    if (!memOk || !memAddr(insn.src, SCRATCH_A, (uint32_t)off, len)) { handled = false; break; }
                    uint8_t tmp = (s2 != 15) ? 15 : 14;
                    emit(WIRE_XMOVHL); b8(tmp); b8(s2);
                    emit(WIRE_XSTORED); b8(SCRATCH_B); b8(tmp);
                    emit(WIRE_XSTOREQ); b8(SCRATCH_A); d32(0); b8(SCRATCH_B);
                    out.usesXmm = true;
                    break;
                }
                if (!wideDq) { handled = false; break; }
                if (insn.src.type == OperandType::Register) {
                    uint8_t d = xmmSlot(insn.src.reg);
                    if (d == 0xFF) { handled = false; break; }
                    emit(WIRE_XMOV); b8(d); b8(s2);
                } else if (insn.src.type == OperandType::Memory ||
                           insn.src.type == OperandType::MemoryRegIndir ||
                           insn.src.type == OperandType::MemoryRIP) {
                    if (!memOk || !memAddr(insn.src, SCRATCH_A, (uint32_t)off, len)) { handled = false; break; }
                    emit(WIRE_XSTORE); b8(SCRATCH_A); d32(0); b8(s2);
                } else { handled = false; }
                out.usesXmm = true;
            } else if (op2 == 0x6E) {
                // movd/movq xmm <- gpr/m
                if (insn.dst.type != OperandType::Register) { handled = false; break; }
                uint8_t d = xmmSlot(insn.dst.reg);
                if (d == 0xFF) { handled = false; break; }
                if (insn.src.type == OperandType::Register) {
                    if (!needGPR(insn.src.reg)) { handled = false; break; }
                    uint8_t s2 = regs.g2v(insn.src.reg);
                    if (s2 == 0xFF) { handled = false; break; }
                    emit(WIRE_XLOADD); b8(d); b8(s2);
                } else if (insn.src.type == OperandType::Memory ||
                           insn.src.type == OperandType::MemoryRegIndir ||
                           insn.src.type == OperandType::MemoryRIP) {
                    if (!memOk || !memAddr(insn.src, SCRATCH_A, (uint32_t)off, len)) { handled = false; break; }
                    uint8_t loadOp = insn.src.size == 4 ? WIRE_LOADD : WIRE_LOADQ;
                    emit(loadOp); b8(SCRATCH_B); b8(SCRATCH_A); d32(0);
                    emit(WIRE_XLOADD); b8(d); b8(SCRATCH_B);
                } else { handled = false; }
                out.usesXmm = true;
            } else if (op2 == 0x7E && (insn.prefixes & PREFIX_F3)) {
                // F3 0F 7E = MOVQ xmm, xmm/m64. Here parseModRM put the
                // *destination* in dst and the source in src - the opposite of
                // the store forms. The upper 64 bits of the destination are
                // zeroed, which XLOADQ does for memory and a store/load pair
                // through a GPR scratch does for the register form.
                if (insn.dst.type != OperandType::Register) { handled = false; break; }
                uint8_t d = xmmSlot(insn.dst.reg);
                if (d == 0xFF) { handled = false; break; }
                if (insn.src.type == OperandType::Register) {
                    uint8_t s2 = xmmSlot(insn.src.reg);
                    if (s2 == 0xFF) { handled = false; break; }
                    emit(WIRE_XSTORED); b8(SCRATCH_B); b8(s2);
                    emit(WIRE_XLOADD); b8(d); b8(SCRATCH_B);
                } else if (insn.src.type == OperandType::Memory ||
                           insn.src.type == OperandType::MemoryRegIndir ||
                           insn.src.type == OperandType::MemoryRIP) {
                    if (!memOk || !memAddr(insn.src, SCRATCH_A, (uint32_t)off, len)) { handled = false; break; }
                    emit(WIRE_XLOADQ); b8(d); b8(SCRATCH_A); d32(0);
                } else { handled = false; }
                out.usesXmm = true;
            } else if (op2 == 0x7E || op2 == 0xD6) {
                // Store forms where parseModRM put the xmm *source* in dst and
                // the destination in src:
                //   66 REX.W 0F 7E = MOVQ r/m64, xmm
                //   66        0F D6 = MOVQ xmm/m64, xmm
                // The register form of MOVQ writes the low 64 bits and zeroes
                // the high half of the destination xmm, exactly like the load.
                uint8_t s2 = xmmSlot(insn.dst.reg);
                if (s2 == 0xFF) { handled = false; break; }
                if (insn.src.type == OperandType::Memory ||
                    insn.src.type == OperandType::MemoryRegIndir ||
                    insn.src.type == OperandType::MemoryRIP) {
                    if (!memOk || !memAddr(insn.src, SCRATCH_A, (uint32_t)off, len)) { handled = false; break; }
                    emit(WIRE_XSTOREQ); b8(SCRATCH_A); d32(0); b8(s2);
                } else if (insn.src.type == OperandType::Register) {
                    if (op2 == 0xD6) {
                        // 66 0F D6 with a register rm is `movq xmm, xmm`:
                        // write the low half and zero the upper half of the
                        // destination. (66 REX.W 0F 7E with a register rm is
                        // the *GPR* store below - the 66 prefix does not
                        // decide the shape, the opcode does.)
                        uint8_t d = xmmSlot(insn.src.reg);
                        if (d == 0xFF) { handled = false; break; }
                        emit(WIRE_XSTORED); b8(SCRATCH_B); b8(s2);
                        emit(WIRE_XLOADD); b8(d); b8(SCRATCH_B);
                    } else {
                        // movq r/m64, xmm into a GPR
                        if (!needGPR(insn.src.reg)) { handled = false; break; }
                        uint8_t d = regs.g2v(insn.src.reg);
                        if (d == 0xFF) { handled = false; break; }
                        emit(WIRE_XSTORED); b8(d); b8(s2);
                    }
                } else { handled = false; }
                out.usesXmm = true;
            } else if (op2 == 0x6C) {
                // unpcklps xmm1, xmm2/m128
                if (insn.dst.type != OperandType::Register) { handled = false; break; }
                uint8_t d = xmmSlot(insn.dst.reg);
                if (d == 0xFF) { handled = false; break; }
                if (insn.src.type == OperandType::Register) {
                    uint8_t s2 = xmmSlot(insn.src.reg);
                    if (s2 == 0xFF) { handled = false; break; }
                    emit(WIRE_XUNPCKL); b8(d); b8(s2);
                } else if (insn.src.type == OperandType::Memory ||
                           insn.src.type == OperandType::MemoryRegIndir ||
                           insn.src.type == OperandType::MemoryRIP) {
                    if (!memOk || !memAddr(insn.src, SCRATCH_A, (uint32_t)off, len)) { handled = false; break; }
                    uint8_t tmp = XMM_TMP(d);
                    emit(WIRE_XLOAD); b8(tmp); b8(SCRATCH_A); d32(0);
                    emit(WIRE_XUNPCKL); b8(d); b8(tmp);
                } else { handled = false; break; }
                out.usesXmm = true;
            } else if (op2 == 0x12) {
                // movhlps xmm1, xmm2: dst[0:8] = src[8:16]
                if (insn.dst.type != OperandType::Register ||
                    insn.src.type != OperandType::Register) { handled = false; break; }
                uint8_t d = xmmSlot(insn.dst.reg), s2 = xmmSlot(insn.src.reg);
                if (d == 0xFF || s2 == 0xFF) { handled = false; break; }
                emit(WIRE_XMOVHL); b8(d); b8(s2);
                out.usesXmm = true;
            } else if (op2 == 0x16) {
                // movhps xmm, m64 (load high from memory)
                if (insn.dst.type != OperandType::Register) { handled = false; break; }
                uint8_t d = xmmSlot(insn.dst.reg);
                if (d == 0xFF) { handled = false; break; }
                if (insn.src.type == OperandType::Memory ||
                    insn.src.type == OperandType::MemoryRegIndir ||
                    insn.src.type == OperandType::MemoryRIP) {
                    if (!memOk || !memAddr(insn.src, SCRATCH_A, (uint32_t)off, len)) { handled = false; break; }
                    emit(WIRE_LOADQ); b8(SCRATCH_B); b8(SCRATCH_A); d32(0);
                    emit(WIRE_XMOUNTH); b8(d); b8(SCRATCH_B);
                } else if (insn.src.type == OperandType::Register) {
                    // movhlps xmm, xmm (high-to-low move) - copy high half
                    uint8_t s2 = xmmSlot(insn.src.reg);
                    if (s2 == 0xFF) { handled = false; break; }
                    // xmounth from src high to dst low is not the same as
                    // movhlps; reject for now.
                    handled = false; break;
                } else { handled = false; break; }
                out.usesXmm = true;
            } else {
                handled = false;
            }
            break;
        }
        case InsnCategory::ENTER: {
            // enter imm16, 0 == push rbp ; mov rbp, rsp ; sub rsp, imm16.
            // The nesting walk of a level > 0 frame has no wire form and goes
            // to the native bridge instead. The packed immediate is
            // imm16 | (level << 16) - see disasm's 3-byte immediate case.
            uint32_t imm16 = (uint32_t)(insn.src.immediate & 0xFFFFu);
            uint32_t level = (uint32_t)((insn.src.immediate >> 16) & 0xFFu);
            if (level != 0) { handled = false; break; }
            uint8_t sp = regs.vmSp, bp = regs.g2v(Reg::RBP);
            if (bp == 0xFF) { handled = false; break; }
            emit(WIRE_ADDRADDI); b8(sp); q64((uint64_t)-8);
            emit(WIRE_STOREQ); b8(sp); d32(0); b8(bp);
            emit(WIRE_MOVE); b8(bp); b8(sp);
            if (imm16) { emit(WIRE_ADDRADDI); b8(sp); q64((uint64_t)(-(int64_t)imm16)); }
            break;
        }
        case InsnCategory::PUSHF:
            // pushfq: the flag file as a qword on the guest stack.
            emit(WIRE_PUSHF); b8(regs.vmSp);
            break;
        case InsnCategory::POPF:
            emit(WIRE_POPF); b8(regs.vmSp);
            break;
        case InsnCategory::LEAVE:
            // leave = mov rsp, rbp ; pop rbp
            emit(WIRE_MOVE); b8(regs.vmSp); b8(regs.g2v(Reg::RBP));
            emit(WIRE_LOADQ); b8(regs.g2v(Reg::RBP)); b8(regs.vmSp); d32(0);
            emit(WIRE_ADDRADDI); b8(regs.vmSp); q64(8);
            break;
        case InsnCategory::NOP:
            // WIRE_ENDBR is the wire no-op. Emitting logical opcode 0 instead
            // (as this used to) produced a byte with no handler, which made the
            // interpreter treat it as the end of the program and silently drop
            // every following instruction of the region.
            emit(WIRE_ENDBR);
            break;
        case InsnCategory::SAHF:
            // sahf: the flag byte lives in AH, which is bits 8..15 of RAX.
            emit(WIRE_SAHF); b8(regs.g2v(Reg::RAX));
            break;
        case InsnCategory::LAHF:
            emit(WIRE_LAHF); b8(regs.g2v(Reg::RAX));
            break;
        case InsnCategory::CDQ: {
            // cdq / cqo: RDX = sign extension of the accumulator. Both
            // instructions write no flags, so the shift has to be flag-free -
            // WIRE_ADDRSHRI is the LEA-style partner WIRE_SARI is not.
            // The 32-bit form must sign-extend EAX first: shifting the raw
            // register would drag in whatever is sitting above bit 31.
            uint8_t d = regs.g2v(Reg::RDX), a = regs.g2v(Reg::RAX);
            if (d == 0xFF || a == 0xFF) { handled = false; break; }
            if (rexW) {
                emit(WIRE_MOVE); b8(d); b8(a);
                emit(WIRE_ADDRSHRI); b8(d); q64(63u);
            } else {
                emit(WIRE_MOVSXD); b8(d); b8(a);
                emit(WIRE_ADDRSHRI); b8(d); q64(31u);
                emit(WIRE_MOVD); b8(d); b8(d);
            }
            break;
        }
        case InsnCategory::MUL: case InsnCategory::DIV: case InsnCategory::IDIV: {
            // One-operand mul/div over the implicit RDX:RAX pair.
            //   mul  r/m   -> RDX:RAX = RAX * r/m        (unsigned)
            //   div  r/m   -> RAX = RDX:RAX / r/m, RDX = remainder
            //   idiv r/m   -> the signed form
            // The 32-bit encodings use EDX:EAX as a 64-bit pair: model them by
            // building that pair in the 64-bit form and splitting the result
            // back afterwards. x86 leaves every flag undefined after div, and
            // only CF/OF defined after mul, so the extra moves may use the
            // flag-free address opcodes without losing anything real.
            if (insn.opcode == 0xF6) {
                // 8-bit pair forms (AX = AL * r/m8, or AL=quot / AH=rem of
                // AX / r/m8) lower through WIRE_MULB / WIRE_DIVB, which own
                // the AX splice and the AH-driven CF/OF pair.
                uint8_t ext = (insn.modrm >> 3) & 7;
                if (ext < 4 || ext > 7) { handled = false; break; }
                uint8_t sel = (uint8_t)(((ext & 1) ? 1u : 0u));   // 5=imul 7=idiv
                uint8_t rax = regs.g2v(Reg::RAX);
                if (rax == 0xFF) { handled = false; break; }
                uint8_t den = 0xFF;
                if (insn.dst.type == OperandType::Register) {
                    den = regs.g2v(insn.dst.reg);
                    if (den == 0xFF) { handled = false; break; }
                } else if (insn.dst.type == OperandType::Memory ||
                           insn.dst.type == OperandType::MemoryRegIndir ||
                           insn.dst.type == OperandType::MemoryRIP) {
                    if (!memOk || !memAddr(insn.dst, SCRATCH_A, (uint32_t)off, len)) { handled = false; break; }
                    emit(WIRE_LOADB); b8(SCRATCH_B); b8(SCRATCH_A); d32(0);
                    den = SCRATCH_B;
                } else { handled = false; break; }
                emit((ext == 4 || ext == 5) ? WIRE_MULB : WIRE_DIVB);
                b8(sel); b8(rax); b8(den);
                break;
            }
            uint8_t rax = regs.g2v(Reg::RAX), rdx = regs.g2v(Reg::RDX);
            if (rax == 0xFF || rdx == 0xFF) { handled = false; break; }
            uint8_t den = 0xFF;
            bool denIsMem = insn.dst.type == OperandType::Memory ||
                            insn.dst.type == OperandType::MemoryRegIndir ||
                            insn.dst.type == OperandType::MemoryRIP;
            if (insn.dst.type == OperandType::Register) {
                den = regs.g2v(insn.dst.reg);
                if (den == 0xFF) { handled = false; break; }
            } else if (denIsMem) {
                if (!memOk || !memAddr(insn.dst, SCRATCH_A, (uint32_t)off, len)) { handled = false; break; }
                uint8_t loadOp = (insn.dst.size >= 8) ? WIRE_LOADQ : WIRE_LOADD;
                emit(loadOp); b8(SCRATCH_B); b8(SCRATCH_A); d32(0);
                den = SCRATCH_B;
            } else { handled = false; break; }
            const bool w32op = !rexW;
            if (w32op && insn.category == InsnCategory::MUL) {
                // EDX:EAX = EAX * r/m32. The 64-bit product already holds the
                // whole answer; split it into the two 32-bit halves.
                emit(WIRE_MOVD); b8(rax); b8(rax);
                emit(WIRE_MOVD); b8(den); b8(den);
                emit(WIRE_MULQ); b8(0); b8(rax); b8(rdx); b8(den);
                emit(WIRE_MOVE); b8(SCRATCH_B); b8(rax);
                emit(WIRE_ADDRSHRI); b8(SCRATCH_B); q64(32);
                emit(WIRE_MOVD); b8(rdx); b8(SCRATCH_B);
                emit(WIRE_MOVD); b8(rax); b8(rax);
            } else if (w32op) {
                // EDX:EAX / r/m32: build the 64-bit numerator, divide, split.
                emit(WIRE_MOVD); b8(den); b8(den);
                emit(WIRE_MOVE); b8(SCRATCH_B); b8(rdx);
                emit(WIRE_ADDRSHLI); b8(SCRATCH_B); q64(32);
                emit(WIRE_ADDRADD); b8(SCRATCH_B); b8(rax);
                emit(WIRE_MOVE); b8(rax); b8(SCRATCH_B);
                emit(WIRE_LOADIMM); b8(rdx); q64(0);
                emit(insn.category == InsnCategory::DIV ? WIRE_DIVQ : WIRE_IDIVQ);
                b8(rax); b8(rdx); b8(den);
                emit(WIRE_MOVD); b8(rax); b8(rax);
                emit(WIRE_MOVD); b8(rdx); b8(rdx);
            } else if (insn.category == InsnCategory::MUL) {
                emit(WIRE_MULQ); b8(0); b8(rax); b8(rdx); b8(den);
            } else {
                emit(insn.category == InsnCategory::DIV ? WIRE_DIVQ : WIRE_IDIVQ);
                b8(rax); b8(rdx); b8(den);
            }
            break;
        }
        case InsnCategory::BT: {
            // bt/bts/btr/btc. For 0F A3/AB/B3/BB the reg field is the *index*
            // register and the rm is the bit-string operand. For the 0F BA
            // group the reg field is an opcode extension and the index is the
            // trailing imm8. fixupOperands orients both forms as dst <- rm
            // (the bit string) and src <- index (register or immediate).
            const bool groupImm = (insn.opcode2 == 0xBA);
            uint8_t op = 0;
            if (insn.opcode2 == 0xA3) op = 0;
            else if (insn.opcode2 == 0xAB) op = 1;
            else if (insn.opcode2 == 0xB3) op = 2;
            else if (insn.opcode2 == 0xBB) op = 3;
            else if (groupImm) op = (uint8_t)(((insn.modrm >> 3) & 7) - 4);
            else { handled = false; break; }
            const bool is32 = !rexW;
            const Operand& bits = insn.dst;
            uint8_t idxSlot = 0xFF;
            if (groupImm) {
                emit(WIRE_LOADIMM); b8(SCRATCH_B); q64((uint64_t)insn.src.immediate);
                idxSlot = SCRATCH_B;
            } else {
                idxSlot = regs.g2v(insn.src.reg);     // reg field = index register
                if (idxSlot == 0xFF) { handled = false; break; }
            }
            if (bits.type == OperandType::Register) {
                uint8_t base = regs.g2v(bits.reg);
                if (base == 0xFF) { handled = false; break; }
                emit(WIRE_BITOP);
                b8((uint8_t)((is32 ? 8 : 0) | op));
                b8(base); b8(idxSlot);
            } else if (bits.type == OperandType::Memory ||
                       bits.type == OperandType::MemoryRegIndir ||
                       bits.type == OperandType::MemoryRIP) {
                // memory form: the index is a plain bit offset, so the
                // interpreter walks bytes; `base` must be the address.
                if (!memOk || !memAddr(bits, SCRATCH_A, (uint32_t)off, len)) { handled = false; break; }
                emit(WIRE_BITOP);
                b8((uint8_t)(4 | op));
                b8(SCRATCH_A); b8(idxSlot);
            } else { handled = false; }
            break;
        }
        case InsnCategory::FLAGOP: {
            // clc (F8) / stc (F9) / cmc (F5) / cld (FC) / std (FD).
            // F8 is CLC and F9 is STC - the order is easy to get backwards and
            // the two tests that pin this are "clc/adc" and "stc/sbb".
            // CLD/STD set the VM's own direction flag, which the string
            // primitives read - since strings became translatable, DF is
            // real VM state and a no-op here would silently walk them the
            // wrong way.
            if (insn.opcode == 0xFC || insn.opcode == 0xFD) {
                emit(WIRE_SETDF); b8(insn.opcode == 0xFD ? 1u : 0u);
                break;
            }
            if (insn.opcode == 0xF8 || insn.opcode == 0xF9) {
                emit(WIRE_LOADIMM); b8(SCRATCH_A); q64(insn.opcode == 0xF9 ? 1u : 0u);
                emit(WIRE_SETCF); b8(SCRATCH_A);
                break;
            }
            // cmc: flip cf. LAHF parks it in AH; move it to bit 0, flip that
            // bit with a bit-op (which leaves cf itself untouched), write it
            // back.
            emit(WIRE_LAHF); b8(SCRATCH_A);
            emit(WIRE_MOVE); b8(SCRATCH_B); b8(SCRATCH_A);
            emit(WIRE_ADDRSHRI); b8(SCRATCH_B); q64(8);
            emit(WIRE_LOADIMM); b8(SCRATCH_A); q64(0);      // bit index 0
            emit(WIRE_BITOP); b8(3); b8(SCRATCH_B); b8(SCRATCH_A);   // btc
            emit(WIRE_SETCF); b8(SCRATCH_B);
            break;
        }
        // ================= coverage round: residual reject buckets =======
        case InsnCategory::BITSCAN: {
            // 0F BC = bsf / F3 tzcnt; 0F BD = bsr / F3 lzcnt.
            uint8_t op = (insn.prefixes & PREFIX_F3)
                ? (uint8_t)((insn.opcode2 == 0xBC) ? 2u : 3u)
                : (uint8_t)((insn.opcode2 == 0xBC) ? 0u : 1u);
            if (width == 1) { handled = false; break; }   // no 8-bit bsf
            uint8_t wsel = (width == 2) ? 0u : (width == 4) ? 1u : 2u;
            if (insn.dst.type != OperandType::Register || !needGPR(insn.dst.reg)) {
                handled = false; break;
            }
            uint8_t d = regs.g2v(insn.dst.reg);
            if (d == 0xFF) { handled = false; break; }
            uint8_t sv;
            if (insn.src.type == OperandType::Register) {
                if (!needGPR(insn.src.reg)) { handled = false; break; }
                sv = regs.g2v(insn.src.reg);
                if (sv == 0xFF) { handled = false; break; }
            } else if (insn.src.type == OperandType::Memory ||
                       insn.src.type == OperandType::MemoryRegIndir ||
                       insn.src.type == OperandType::MemoryRIP) {
                if (!memOk || !memAddr(insn.src, SCRATCH_A, (uint32_t)off, len)) {
                    handled = false; break;
                }
                uint8_t loadOp = (width == 2) ? WIRE_LOADW : (width == 4) ? WIRE_LOADD
                                                                           : WIRE_LOADQ;
                emit(loadOp); b8(SCRATCH_B); b8(SCRATCH_A); d32(0);
                sv = SCRATCH_B;
            } else { handled = false; break; }
            emit(WIRE_BITSCAN); b8((uint8_t)((op << 2) | wsel)); b8(d); b8(sv);
            break;
        }
        case InsnCategory::X87: {
            // The handler re-decodes the raw (escape, modrm) pair against the
            // real FPU stack; `ea` carries the folded effective address for
            // memory forms and the rax slot for FNSTSW AX.
            uint8_t esc = insn.opcode;
            uint8_t modrm = insn.modrm;
            uint8_t eaSlot = SCRATCH_A;
            if ((modrm >> 6) != 3) {
                if (!memOk || !memAddr(insn.src, SCRATCH_A, (uint32_t)off, len)) {
                    handled = false; break;
                }
            } else if (esc == 0xDF && modrm == 0xE0) {
                eaSlot = regs.g2v(Reg::RAX);
                if (eaSlot == 0xFF) { handled = false; break; }
            }
            emit(WIRE_X87); b8(esc); b8(modrm); b8(eaSlot);
            break;
        }
        case InsnCategory::MOVS: case InsnCategory::STOS:
        case InsnCategory::LODS: case InsnCategory::CMPS:
        case InsnCategory::SCAS: {
            uint8_t sop = (insn.category == InsnCategory::MOVS) ? 0u
                        : (insn.category == InsnCategory::STOS) ? 1u
                        : (insn.category == InsnCategory::LODS) ? 2u
                        : (insn.category == InsnCategory::CMPS) ? 3u : 4u;
            uint8_t rep = (insn.prefixes & PREFIX_F3) ? 1u
                        : (insn.prefixes & PREFIX_F2) ? 2u : 0u;
            // A4/A6/AA/AC/AE are the byte forms; the odd opcodes widen with
            // 66 / REX.W exactly like every other operand pair.
            uint8_t wcode = ((insn.opcode & 1) == 0) ? 0u
                          : (insn.prefixes & PREFIX_REX_W) ? 3u
                          : (insn.prefixes & PREFIX_66) ? 1u : 2u;
            uint8_t srsi = regs.g2v(Reg::RSI), srdi = regs.g2v(Reg::RDI);
            uint8_t srcx = regs.g2v(Reg::RCX), sacc = regs.g2v(Reg::RAX);
            if (srsi == 0xFF || srdi == 0xFF || srcx == 0xFF || sacc == 0xFF) {
                handled = false; break;
            }
            emit(WIRE_STR);
            b8((uint8_t)((rep << 5) | (sop << 2) | wcode));
            b8(srsi); b8(srdi); b8(srcx); b8(sacc);
            break;
        }
        case InsnCategory::CMPXCHG: {
            if (insn.opcode2 == 0xC7) {
                // 0F C7: /6 /7 with mod == 3 are rdrand / rdseed; the
                // memory forms (cmpxchg8b / cmpxchg16b) keep their native
                // atomicity and are not lowered (no compiled form of them
                // appears where the VM is asked to virtualize).
                if ((insn.modrm >> 6) != 3) { handled = false; break; }
                uint8_t ext = (insn.modrm >> 3) & 7u;
                // RDRAND is /6 and RDSEED /7; the F3 prefix some assemblers
                // add to RDSEED is accepted but not required (the encodings
                // in real binaries vary).
                bool isSeed = (ext == 7);
                if (!isSeed && ext != 6) { handled = false; break; }
                if (insn.src.type != OperandType::Register || !needGPR(insn.src.reg)) {
                    handled = false; break;
                }
                uint8_t d = regs.g2v(insn.src.reg);
                if (d == 0xFF) { handled = false; break; }
                uint8_t sel = (uint8_t)(isSeed ? 1u : 0u);
                if (width == 4) sel |= 2u;
                emit(WIRE_RDRAND); b8(sel); b8(d);
                break;
            }
            // 0F B0 / 0F B1: cmpxchg r/m, r with rax as the implicit
            // accumulator. Register-register forms are left native - the
            // handler's compare-and-swap runs against memory, which is where
            // every compiler emits this instruction for atomics.
            if ((insn.modrm >> 6) == 3) { handled = false; break; }
            if (width == 1 && insn.opcode2 != 0xB0) { handled = false; break; }
            if (width == 8 && insn.opcode2 != 0xB1) { handled = false; break; }
            if (insn.dst.type != OperandType::Register || !needGPR(insn.dst.reg)) {
                handled = false; break;
            }
            uint8_t srcR = regs.g2v(insn.dst.reg);
            uint8_t accR = regs.g2v(Reg::RAX);
            if (srcR == 0xFF || accR == 0xFF) { handled = false; break; }
            if (!memOk || !memAddr(insn.src, SCRATCH_A, (uint32_t)off, len)) {
                handled = false; break;
            }
            uint8_t wsel = (width == 1) ? 0u : (width == 2) ? 1u : (width == 4) ? 2u : 3u;
            if (insn.prefixes & PREFIX_LOCK) wsel |= 4u;
            emit(WIRE_CMPXCHG); b8(wsel); b8(SCRATCH_A); b8(accR); b8(srcR);
            break;
        }
        case InsnCategory::CPUID: {
            uint8_t a = regs.g2v(Reg::RAX), b = regs.g2v(Reg::RBX);
            uint8_t c = regs.g2v(Reg::RCX), d = regs.g2v(Reg::RDX);
            if (a == 0xFF || b == 0xFF || c == 0xFF || d == 0xFF) {
                handled = false; break;
            }
            emit(WIRE_CPUID); b8(a); b8(b); b8(c); b8(d);
            break;
        }
        case InsnCategory::RDTSC: {
            uint8_t lo = regs.g2v(Reg::RAX), hi = regs.g2v(Reg::RDX);
            if (lo == 0xFF || hi == 0xFF) { handled = false; break; }
            emit(WIRE_RDTSC); b8(lo); b8(hi);
            break;
        }
        case InsnCategory::RET: {
            // `ret` lowers to a load of the return address from the guest
            // stack plus the register-indirect exit the trampoline already
            // supports - used when the five-byte stub would swallow the
            // native epilogue island whole (tiny thunk functions).
            uint8_t sp = regs.vmSp;
            emit(WIRE_LOADQ); b8(SCRATCH_A); b8(sp); d32(0);
            emit(WIRE_ADDRADDI); b8(sp);
            q64((uint64_t)(8 + (uint64_t)(insn.opcode == 0xC2 ? (uint16_t)insn.src.immediate : 0)));
            emit(WIRE_EXITJMP); d32(0x80000000u | (uint32_t)SCRATCH_A);
            break;
        }
        case InsnCategory::UD2:
            emit(WIRE_UD2);
            break;
        case InsnCategory::SHLD: {
            // 0F A4/A5 = shld r/m, r, imm8/cl; 0F AC/AD = shrd. The decoder
            // leaves the rm (the read-modify-write destination) in src and
            // the donor register in dst.
            bool right = (insn.opcode2 == 0xAC || insn.opcode2 == 0xAD);
            bool clForm = (insn.opcode2 == 0xA5 || insn.opcode2 == 0xAD);
            if (width == 1) { handled = false; break; }   // no 8-bit form
            uint8_t wcode = (width == 2) ? 1u : (width == 4) ? 2u : 3u;
            if (insn.src.type != OperandType::Register || !needGPR(insn.src.reg) ||
                insn.dst.type != OperandType::Register || !needGPR(insn.dst.reg)) {
                handled = false; break;
            }
            uint8_t d = regs.g2v(insn.src.reg), dn = regs.g2v(insn.dst.reg);
            if (d == 0xFF || dn == 0xFF) { handled = false; break; }
            uint8_t cntSlot;
            if (clForm) {
                cntSlot = regs.g2v(Reg::RCX);
                if (cntSlot == 0xFF) { handled = false; break; }
            } else {
                emit(WIRE_LOADIMM); b8(SCRATCH_A); q64(insn.src.immediate & 0x3Fu);
                cntSlot = SCRATCH_A;
            }
            emit(WIRE_SHLD);
            b8((uint8_t)((wcode << 2) | (right ? 1u : 0u)));
            b8(d); b8(dn); b8(cntSlot);
            break;
        }
        default:
            handled = false;
            break;
        }

        if (!handled) {
            // Native bridge: end the VM chunk just before this instruction and
            // let the packer execute it natively between two VM regions (the
            // same mechanism as the sub-rsp bridge). The chunk loop resumes
            // after it, so one unhandled form - AVX, cmpxchg16b, 16-bit
            // push/pop, enter with nesting - costs exactly its own bytes
            // instead of the rest of the function.
            bc.resize(offMap[guestOff]); // roll back partial emission for this insn
            out.cut = true;
            out.cutAt = guestOff;
            out.resumeOff = guestOff + len;
            out.skipReason = "native bridge (cat " + std::to_string((int)insn.category) + " op " + std::to_string((int)insn.opcode) + "/" + std::to_string((int)insn.opcode2) + ")";
            out.skipOffset = guestOff;
            out.skipCat = (uint8_t)insn.category; out.skipOp = insn.opcode; out.skipOp2 = insn.opcode2;
            break;
        }

        // Track whether imul's inexpressible CF/OF could still be observed.
        switch (insn.category) {
        case InsnCategory::IMUL:
            mulFlagsPending = true;
            byteFlagsPending = false;
            break;
        case InsnCategory::CMP: case InsnCategory::TEST:
            // Narrow compares compute exact narrow flags; both pendants die
            // and none is armed.
            mulFlagsPending = false;
            byteFlagsPending = false;
            break;
        case InsnCategory::CMPS: case InsnCategory::SCAS:
        case InsnCategory::CMPXCHG:
            // Full-width flag replacements: the comparison flags land in the
            // VM file exactly as the hardware computes them, so an armed
            // pendant (imul's CF/OF, wide flags after a narrow ALU) is gone.
            mulFlagsPending = false;
            byteFlagsPending = false;
            break;
        case InsnCategory::ADD: case InsnCategory::SUB: case InsnCategory::AND:
        case InsnCategory::OR: case InsnCategory::XOR:
        case InsnCategory::INC: case InsnCategory::DEC:
        case InsnCategory::NEG: case InsnCategory::SHL: case InsnCategory::SHR:
        case InsnCategory::SAR: case InsnCategory::ROL: case InsnCategory::ROR:
        case InsnCategory::SBB: case InsnCategory::ADC:
            // A full-width setter replaces the flag file outright; a narrow
            // one goes through WIRE_NALU, which writes flags *at that width*,
            // so nothing wide is ever left behind and no pendant is armed.
            mulFlagsPending = false;
            byteFlagsPending = false;
            break;
        default:
            break;
        }

        translated++;
        off += len;
    }

    if (skipped && translated == 0) {
        out.ok = false;
        out.skipReason = out.skipReason.empty() ? "no translatable instruction" : out.skipReason;
        return out;
    }

    // Terminator: halt at end of block. Record it as the landing site for
    // branches whose fall-through runs off the end of the range (inverted
    // condition jumps around a native exit). With a bridge cut discovered
    // mid-loop the effective end is the bridge, not the range end.
    uint32_t endP = out.cut ? out.cutAt : (uint32_t)size;
    if (endP > (uint32_t)size) endP = (uint32_t)size;
    offMap[endP] = (uint32_t)bc.size();
    emit(WIRE_HALT);

    if (skipped) {
        out.ok = false;
        if (out.skipReason.empty()) out.skipReason = "unsupported instruction";
        return out;
    }

    // Resolve internal branch targets.
    for (auto& fx : fixups) {
        size_t bcOff = fx.first;
        uint32_t guestTarget = fx.second;
        uint32_t dst;
        auto it = offMap.find(guestTarget);
        if (it != offMap.end()) {
            dst = it->second;
        } else {
            // Target outside the translated range: cannot represent.
            out.ok = false;
            out.skipReason = "branch target outside translated range";
            return out;
        }
        bc[bcOff + 0] = (uint8_t)(dst & 0xFF);
        bc[bcOff + 1] = (uint8_t)((dst >> 8) & 0xFF);
        bc[bcOff + 2] = (uint8_t)((dst >> 16) & 0xFF);
        bc[bcOff + 3] = (uint8_t)((dst >> 24) & 0xFF);
    }

    out.bytecode = std::move(bc);
    out.reverse = mapper.reverseTable();
    for (int i = 0; i < 16; i++) out.guestReg[i] = regs.guest_to_vm[i];
    out.insnsTranslated = translated;
    out.insnsSkipped = skipped;
    out.ok = (skipped == 0);
    out.bodyOff = bodyStart;
    (void)complexity; (void)mutationLevel;
    return out;
}

// ============================================================
// VMBytecodeGenerator (wire-level emit helpers)
// ============================================================
VMBytecodeGenerator::VMBytecodeGenerator() { output_.reserve(4096); }

void VMBytecodeGenerator::emitByte(uint8_t b) { output_.push_back(b); }
void VMBytecodeGenerator::emitDword(uint32_t d) {
    emitByte(d & 0xFF); emitByte((d >> 8) & 0xFF);
    emitByte((d >> 16) & 0xFF); emitByte((d >> 24) & 0xFF);
}
void VMBytecodeGenerator::emitQword(uint64_t q) {
    for (int k = 0; k < 8; k++) emitByte((uint8_t)(q >> (k * 8)));
}
void VMBytecodeGenerator::emitOp(uint8_t logical) { emitByte(mapper_.encode(logical)); }
void VMBytecodeGenerator::padForAlignment() { while (output_.size() & 7) emitByte(0x00); }

void VMBytecodeGenerator::emitLoadImm(uint8_t reg, uint64_t value) {
    emitOp(WIRE_LOADIMM); emitByte(reg); emitQword(value); instrCount_++;
}
void VMBytecodeGenerator::emitLoadReg(uint8_t dst, uint8_t src) {
    emitOp(WIRE_MOVE); emitByte(dst); emitByte(src); instrCount_++;
}
void VMBytecodeGenerator::emitMemLoad(uint8_t dst, uint8_t base, uint32_t disp) {
    emitOp(WIRE_LOADQ); emitByte(dst); emitByte(base); emitDword(disp); instrCount_++;
}
void VMBytecodeGenerator::emitMemStore(uint8_t base, uint32_t disp, uint8_t src) {
    emitOp(WIRE_STOREQ); emitByte(base); emitDword(disp); emitByte(src); instrCount_++;
}
void VMBytecodeGenerator::emitArith(uint8_t wireOp, uint8_t dst, uint8_t src) {
    emitOp(wireOp); emitByte(dst); emitByte(src); instrCount_++;
}
void VMBytecodeGenerator::emitArithImm(uint8_t wireOp, uint8_t dst, uint64_t imm) {
    emitOp(wireOp); emitByte(dst); emitQword(imm); instrCount_++;
}
void VMBytecodeGenerator::emitCmp(uint8_t a, uint8_t b) {
    emitOp(WIRE_CMP); emitByte(a); emitByte(b); instrCount_++;
}
void VMBytecodeGenerator::emitTest(uint8_t a, uint8_t b) {
    emitOp(WIRE_TEST); emitByte(a); emitByte(b); instrCount_++;
}
void VMBytecodeGenerator::emitJmp(uint32_t target) {
    emitOp(WIRE_JMP); emitDword(target); instrCount_++;
}
void VMBytecodeGenerator::emitJcc(uint8_t wireOp, uint32_t target) {
    emitOp(wireOp); emitDword(target); instrCount_++;
}
void VMBytecodeGenerator::emitPush(uint8_t reg) {
    emitArithImm(WIRE_SUBI, 15, 8);
    emitOp(WIRE_STOREQ); emitByte(15); emitDword(0); emitByte(reg);
    instrCount_++;
}
void VMBytecodeGenerator::emitPop(uint8_t reg) {
    emitOp(WIRE_LOADQ); emitByte(reg); emitByte(15); emitDword(0);
    emitArithImm(WIRE_ADDI, 15, 8);
    instrCount_++;
}
void VMBytecodeGenerator::emitHalt() { emitOp(WIRE_HALT); instrCount_++; }
void VMBytecodeGenerator::emitEnter() { instrCount_++; }
void VMBytecodeGenerator::emitLeave() { instrCount_++; }

std::vector<uint8_t> VMBytecodeGenerator::generate(const std::vector<uint8_t>& x86_code,
                                                   uint32_t code_rva,
                                                   uint8_t complexity,
                                                   uint8_t mutation_level) {
    VMTranslator tr;
    VMLoweredBlock blk = tr.translate(x86_code.data(), x86_code.size(),
                                      code_rva, 0, complexity, mutation_level);
    if (blk.ok) {
        mapper_.generateMapping();
        output_ = blk.bytecode;
    }
    return output_;
}

} // namespace np
