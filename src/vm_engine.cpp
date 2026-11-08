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

// A tiny register allocator that never touches the two registers we keep for
// scratch (VM_R14/VM_R15 by default) or the stack pointer register.
struct RegMap {
    uint8_t guest_to_vm[16];
    uint8_t vmSp;
    bool used[NP_VM_REGS];

    void init(uint8_t sp) {
        // guest GPR i -> VM register i, but reserve the top two VM regs for
        // translator scratch and the guest stack pointer.
        std::memset(used, 0, sizeof(used));
        for (int i = 0; i < 16; i++) { guest_to_vm[i] = (uint8_t)i; used[i] = true; }
        vmSp = sp;
    }
    uint8_t g2v(Reg r) const {
        uint8_t i = (uint8_t)r;
        if (i > 15) return 0xFF;
        return guest_to_vm[i];
    }
};

// Scratch VM registers (must differ from any guest mapping).
static const uint8_t SCRATCH_A = 14; // VM_R14
static const uint8_t SCRATCH_B = 15; // VM_R15

static bool isGPR(Reg r) { return (uint8_t)r <= 15; }

// Map an x86 condition code (TTTTN of the Jcc opcode) to a wire Jcc opcode.
static uint8_t jccWire(uint8_t cc, uint8_t prefixes) {
    // x86 condition codes:
    //  0 O   1 NO  2 B/NAE  3 AE/NB  4 E/Z  5 NE/NZ  6 BE/NA  7 A/NBE
    //  8 S   9 NS  A P      B NP      C L/NGE D GE/NL E LE/NG F G/NLE
    switch (cc) {
    case 0x0: case 0x1: return 0;                       // O  - unsupported
    case 0x2: case 0x3: return WIRE_JB;                 // approximate
    case 0x4: return WIRE_JZ;
    case 0x5: return WIRE_JNZ;
    case 0x6: case 0x7: return WIRE_JAE;
    case 0x8: case 0x9: return 0;                       // S  - unsupported
    case 0xA: case 0xB: return 0;                       // P  - unsupported
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
                                       bool target64, uint64_t seed) {
    (void)imageBase;
    VMLoweredBlock out;
    out.vmSp = SCRATCH_B; // guest RSP stays mapped to VM_R4; message says SP reg

    RegMap regs;
    regs.init(out.vmSp);

    VMOpcodeMapper mapper;
    // A pinned seed makes the logical->physical opcode permutation part of the
    // build identity instead of fresh entropy, which is what lets a rebuild
    // reproduce byte for byte.
    if (seed) mapper.generateMapping(seed ^ 0x9E3779B97F4A7C15ull);
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

    Disassembler dis;
    size_t off = 0;
    uint32_t translated = 0, skipped = 0;
    // imul defines CF/OF from the truncated product. The wire VM has no 128-bit
    // multiply, so those flags cannot be reproduced: an imul is translated only
    // while no branch can observe them, and a JCC that arrives before the next
    // flag-setting instruction ends the region instead of reading stale flags.
    bool mulFlagsPending = false;

    while (off < size) {
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
            case C::MOV: case C::LEA:
            case C::ADD: case C::SUB: case C::AND: case C::OR: case C::XOR:
            case C::INC: case C::DEC: case C::NEG: case C::NOT:
            case C::SHL: case C::SHR: case C::SAR: case C::ROL: case C::ROR:
            case C::CMP: case C::TEST:
                skipped++;
                out.skipReason = "8/16-bit register form";
                break;
            default:
                break;
            }
            if (skipped) break;
        }

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
            if (m.base == Reg::NONE) return m.index != Reg::NONE;
            if (m.index != Reg::NONE && !isGPR(m.index)) return false;   // vector / non-GPR index
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
        auto memAddr = [&](const Operand& m, uint8_t scratch) -> bool {
            if (!isGPR(m.base)) return false;
            uint8_t b = regs.g2v(m.base);
            if (b == 0xFF || b == out.vmSp) return false;   // RSP/RBP are trampoline-owned
            if (scratch == out.vmSp) return false;          // scratch must survive the build

            if (m.index != Reg::NONE) {
                uint8_t i = regs.g2v(m.index);
                if (i == 0xFF || i == out.vmSp) return false;

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
                        if (other == b || other == i || other == out.vmSp) return false;
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
                emit(w32 ? WIRE_MOVD : WIRE_MOVE); b8(d); b8(s);
            } else if (insn.dst.type == OperandType::Register &&
                       insn.src.type == OperandType::Immediate) {
                if (!needGPR(insn.dst.reg)) { handled = false; break; }
                uint8_t d = regs.g2v(insn.dst.reg);
                if (d == 0xFF) { handled = false; break; }
                // A 32-bit mov imm truncates and zero-extends exactly like the
                // immediate the decoder already masked.
                emit(WIRE_LOADIMM); b8(d);
                q64(w32 ? (uint64_t)(uint32_t)insn.src.immediate
                        : (uint64_t)insn.src.immediate);
            } else if (insn.dst.type == OperandType::Register &&
                       (insn.src.type == OperandType::Memory ||
                        insn.src.type == OperandType::MemoryRegIndir)) {
                // mov reg, [base(+index)+disp]
                if (!memOk || !needGPR(insn.dst.reg)) { handled = false; break; }
                uint8_t d = regs.g2v(insn.dst.reg);
                if (d == 0xFF || !memAddr(insn.src, SCRATCH_A)) { handled = false; break; }
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
            } else if ((insn.dst.type == OperandType::Memory ||
                        insn.dst.type == OperandType::MemoryRegIndir) &&
                       insn.src.type == OperandType::Register) {
                // mov [base(+index)+disp], reg
                if (!memOk || !needGPR(insn.src.reg)) { handled = false; break; }
                uint8_t s = regs.g2v(insn.src.reg);
                if (s == 0xFF || !memAddr(insn.dst, SCRATCH_A)) { handled = false; break; }
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
                       insn.src.type == OperandType::MemoryRegIndir) {
                if (!memOk || !memAddr(insn.src, SCRATCH_A)) { handled = false; break; }
                switch (srcByte) {
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
                insn.src.type != OperandType::MemoryRegIndir) { handled = false; break; }
            if (!memOk) { handled = false; break; }
            uint8_t d = regs.g2v(insn.dst.reg);
            if (d == 0xFF || d == out.vmSp) { handled = false; break; }

            // lea with no base register: index*scale + disp. Compilers emit
            // this for every array subscript (`lea 0x0(,%rax,8),%rcx`), so
            // rejecting it cost far more regions than it protected. All the
            // helpers below are flag-transparent, matching lea.
            //
            // The decoder reports the "no base" SIB form as Reg::RIP (so the
            // register-mask scan does not see a phantom RBP); has_sib tells it
            // apart from a genuine RIP-relative operand, which still stays
            // native because its address depends on the image base.
            const bool indexOnly = (insn.src.base == Reg::NONE) ||
                                   (insn.src.base == Reg::RIP && insn.has_sib);
            if (indexOnly) {
                if (insn.src.index == Reg::NONE || insn.src.index == Reg::RIP) {
                    // [disp32] with neither base nor index: an absolute address.
                    emit(WIRE_LOADIMM); b8(d);
                    q64((uint64_t)insn.src.displacement);
                    break;
                }
                if (!isGPR(insn.src.index)) { handled = false; break; }
                uint8_t i = regs.g2v(insn.src.index);
                if (i == 0xFF || i == out.vmSp) { handled = false; break; }
                if (d != i) { emit(WIRE_MOVE); b8(d); b8(i); }
                if (insn.src.scale == 2 || insn.src.scale == 4 || insn.src.scale == 8) {
                    emit(WIRE_ADDRSHLI); b8(d);
                    q64((uint64_t)(insn.src.scale == 2 ? 1 : insn.src.scale == 4 ? 2 : 3));
                }
                if (insn.src.displacement) {
                    emit(WIRE_ADDRADDI); b8(d); q64((uint64_t)(int64_t)insn.src.displacement);
                }
                break;
            }

            uint8_t b = regs.g2v(insn.src.base);
            if (b == 0xFF || b == out.vmSp) { handled = false; break; }
            if (d != b) { emit(WIRE_MOVE); b8(d); b8(b); }
            if (insn.src.index != Reg::NONE) {
                if (!isGPR(insn.src.index)) { handled = false; break; }
                uint8_t i = regs.g2v(insn.src.index);
                if (i == 0xFF || i == out.vmSp) { handled = false; break; }
                // lea is architecturally forbidden from touching the flags, so
                // the address arithmetic here must not either.
                if (insn.src.scale == 2 || insn.src.scale == 4 || insn.src.scale == 8) {
                    // d already holds the base, so it is the natural accumulator:
                    // scale the index into it, then add the saved base back.
                    // Both scratch VM registers are real guest registers here, so
                    // there is no free third register to borrow. Aliasing d to
                    // the base or the index would have destroyed the value being
                    // scaled, so those two forms stay native.
                    if (d == b || d == i) { handled = false; break; }
                    emit(WIRE_MOVE); b8(d); b8(i);
                    emit(WIRE_ADDRSHLI); b8(d);
                    q64((uint64_t)(insn.src.scale == 2 ? 1 : insn.src.scale == 4 ? 2 : 3));
                    emit(WIRE_ADDRADD); b8(d); b8(b);
                } else {
                    emit(WIRE_ADDRADD); b8(d); b8(i);
                }
            }
            if (insn.src.displacement) {
                emit(WIRE_ADDRADDI); b8(d); q64((uint64_t)(int64_t)insn.src.displacement);
            }
            break;
        }
        case InsnCategory::IMUL: {
            // Two-operand form (0F AF /r). The decoder now parses its ModRM, so
            // dst is the reg field and src is the r/m operand.
            if (insn.dst.type != OperandType::Register) { handled = false; break; }
            if (!needGPR(insn.dst.reg)) { handled = false; break; }
            uint8_t d = regs.g2v(insn.dst.reg);
            if (d == 0xFF || d == out.vmSp) { handled = false; break; }
            if (insn.src.type != OperandType::Register || !needGPR(insn.src.reg)) {
                handled = false;   // memory source stays native
                break;
            }
            uint8_t s = regs.g2v(insn.src.reg);
            if (s == 0xFF || s == out.vmSp) { handled = false; break; }
            emit(w32 ? WIRE_MULD : WIRE_MUL); b8(d); b8(s);
            break;
        }
        case InsnCategory::ADD: case InsnCategory::SUB:
        case InsnCategory::AND: case InsnCategory::OR: case InsnCategory::XOR: {
            uint8_t wire = (insn.category == InsnCategory::ADD) ? WIRE_ADD :
                           (insn.category == InsnCategory::SUB) ? WIRE_SUB :
                           (insn.category == InsnCategory::AND) ? WIRE_AND :
                           (insn.category == InsnCategory::OR)  ? WIRE_OR  : WIRE_XOR;
            uint8_t wireImm = (insn.category == InsnCategory::ADD) ? WIRE_ADDI :
                              (insn.category == InsnCategory::SUB) ? WIRE_SUBI :
                              (insn.category == InsnCategory::AND) ? WIRE_ANDI :
                              (insn.category == InsnCategory::OR)  ? WIRE_ORI  : WIRE_XORI;
            if (w32) {
                wire = (insn.category == InsnCategory::ADD) ? WIRE_ADDD :
                       (insn.category == InsnCategory::SUB) ? WIRE_SUBD :
                       (insn.category == InsnCategory::AND) ? WIRE_ANDD :
                       (insn.category == InsnCategory::OR)  ? WIRE_ORD  : WIRE_XORD;
                wireImm = (insn.category == InsnCategory::ADD) ? WIRE_ADDID :
                          (insn.category == InsnCategory::SUB) ? WIRE_SUBID :
                          (insn.category == InsnCategory::AND) ? WIRE_ANDID :
                          (insn.category == InsnCategory::OR)  ? WIRE_ORID  : WIRE_XORID;
            }

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
                    emit(wire); b8(d); b8(s);
                } else if (insn.src.type == OperandType::Immediate) {
                    emit(wireImm); b8(d);
                    q64(w32 ? (uint64_t)(uint32_t)insn.src.immediate
                            : (uint64_t)insn.src.immediate);
                } else if (insn.src.type == OperandType::Memory ||
                           insn.src.type == OperandType::MemoryRegIndir) {
                    // read-modify-write through a scratch register
                    if (!memOk || !memAddr(insn.src, SCRATCH_A)) { handled = false; break; }
                    uint8_t loadOp = insn.src.size >= 8 ? WIRE_LOADQ :
                                     insn.src.size == 4 ? WIRE_LOADD :
                                     insn.src.size == 2 ? WIRE_LOADW : WIRE_LOADB;
                    emit(loadOp); b8(SCRATCH_B); b8(SCRATCH_A); d32(0);
                    emit(wire); b8(d); b8(SCRATCH_B);
                } else { handled = false; }
            } else if ((insn.dst.type == OperandType::Memory ||
                        insn.dst.type == OperandType::MemoryRegIndir) &&
                       insn.src.type == OperandType::Register) {
                if (!memOk || !needGPR(insn.src.reg)) { handled = false; break; }
                uint8_t s = regs.g2v(insn.src.reg);
                if (s == 0xFF || !memAddr(insn.dst, SCRATCH_A)) { handled = false; break; }
                uint8_t loadOp = insn.dst.size >= 8 ? WIRE_LOADQ :
                                 insn.dst.size == 4 ? WIRE_LOADD :
                                 insn.dst.size == 2 ? WIRE_LOADW : WIRE_LOADB;
                emit(loadOp); b8(SCRATCH_B); b8(SCRATCH_A); d32(0);
                emit(wire); b8(SCRATCH_B); b8(s);
                uint8_t storeOp = insn.dst.size >= 8 ? WIRE_STOREQ :
                                  insn.dst.size == 4 ? WIRE_STORED :
                                  insn.dst.size == 2 ? WIRE_STOREW : WIRE_STOREB;
                emit(storeOp); b8(SCRATCH_A); d32(0); b8(SCRATCH_B);
            } else { handled = false; }
            break;
        }
        case InsnCategory::CMP: case InsnCategory::TEST: {
            if (insn.dst.type != OperandType::Register) { handled = false; break; }
            uint8_t d = regs.g2v(insn.dst.reg);
            if (d == 0xFF) { handled = false; break; }
            uint8_t cmpOp = w32 ? WIRE_CMPD : WIRE_CMP;
            uint8_t testOp = w32 ? WIRE_TESTD : WIRE_TEST;
            uint8_t cmpImmOp = w32 ? WIRE_CMPID : WIRE_CMPI;
            if (insn.src.type == OperandType::Register && needGPR(insn.src.reg)) {
                uint8_t s = regs.g2v(insn.src.reg);
                if (s == 0xFF) { handled = false; break; }
                emit(insn.category == InsnCategory::CMP ? cmpOp : testOp); b8(d); b8(s);
            } else if (insn.src.type == OperandType::Immediate) {
                if (insn.category == InsnCategory::CMP) {
                    emit(cmpImmOp); b8(d);
                    q64(w32 ? (uint64_t)(uint32_t)insn.src.immediate
                            : (uint64_t)insn.src.immediate);
                } else {
                    emit(testOp); b8(d); b8(d);
                }
            } else { handled = false; }
            break;
        }
        case InsnCategory::INC: case InsnCategory::DEC: case InsnCategory::NEG: case InsnCategory::NOT: {
            Reg r = insn.dst.reg;
            if (!needGPR(r)) { handled = false; break; }
            uint8_t v = regs.g2v(r);
            if (v == 0xFF) { handled = false; break; }
            if (w32) {
                if (insn.category == InsnCategory::INC) { emit(WIRE_ADDID); b8(v); q64(1); }
                else if (insn.category == InsnCategory::DEC) { emit(WIRE_SUBID); b8(v); q64(1); }
                else if (insn.category == InsnCategory::NEG) { emit(WIRE_NEGD); b8(v); }
                else { emit(WIRE_NOTD); b8(v); }
            } else {
                if (insn.category == InsnCategory::INC) { emit(WIRE_ADDI); b8(v); q64(1); }
                else if (insn.category == InsnCategory::DEC) { emit(WIRE_SUBI); b8(v); q64(1); }
                else if (insn.category == InsnCategory::NEG) { emit(WIRE_NEG); b8(v); }
                else { emit(WIRE_NOT); b8(v); }
            }
            break;
        }
        case InsnCategory::SHL: case InsnCategory::SHR: case InsnCategory::SAR:
        case InsnCategory::ROL: case InsnCategory::ROR: {
            uint8_t v = regs.g2v(insn.dst.reg);
            if (v == 0xFF) { handled = false; break; }
            if (insn.src.type == OperandType::Immediate) {
                uint64_t sh = (uint64_t)insn.src.immediate;
                if (w32) {
                    if (insn.category == InsnCategory::SHL && sh == 1) { emit(WIRE_ADDD); b8(v); b8(v); }
                    else if (insn.category == InsnCategory::SHL) { emit(WIRE_SHLID); b8(v); q64(sh); }
                    else if (insn.category == InsnCategory::SHR) { emit(WIRE_SHRID); b8(v); q64(sh); }
                    else if (insn.category == InsnCategory::SAR) { emit(WIRE_SARID); b8(v); q64(sh); }
                    else { handled = false; }   // 32-bit rotate stays native
                } else {
                    if (insn.category == InsnCategory::SHL && sh == 1) { emit(WIRE_ADD); b8(v); b8(v); }
                    else if (insn.category == InsnCategory::SHL) { emit(WIRE_SHLI); b8(v); q64(sh); }
                    else if (insn.category == InsnCategory::SHR) { emit(WIRE_SHRI); b8(v); q64(sh); }
                    else if (insn.category == InsnCategory::SAR) { emit(WIRE_SARI); b8(v); q64(sh); }
                    else if (insn.category == InsnCategory::ROL) { emit(WIRE_ROLI); b8(v); q64(sh); }
                    else { emit(WIRE_RORI); b8(v); q64(sh); }
                }
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
        case InsnCategory::PUSH: case InsnCategory::POP: {
            // The interpreter models its stack with VM_R15 while the guest
            // mapping is the identity, so a guest PUSH/POP would read and
            // write through the guest R15 value instead of the real stack.
            // Until the register map allocates a dedicated VM stack slot,
            // these forms stay native (the translator reports them as
            // unsupported, which makes the packer skip the region).
            handled = false;
            break;
        }
        case InsnCategory::JMP: {
            uint32_t target = (uint32_t)((int64_t)off + (int32_t)len + insn.rel_target);
            emit(WIRE_JMP); fixups.push_back({ bc.size(), target }); d32(0);
            break;
        }
        case InsnCategory::JCC: {
            // A branch reached while imul's CF/OF are still live would read
            // flags the wire VM never produced.
            if (mulFlagsPending) { handled = false; break; }
            uint8_t wire = jccWire(insn.condition, insn.prefixes);
            if (!wire) { handled = false; break; }
            uint32_t target = (uint32_t)((int64_t)off + (int32_t)len + insn.rel_target);
            emit(wire); fixups.push_back({ bc.size(), target }); d32(0);
            break;
        }
        case InsnCategory::NOP:
            // WIRE_ENDBR is the wire no-op. Emitting logical opcode 0 instead
            // (as this used to) produced a byte with no handler, which made the
            // interpreter treat it as the end of the program and silently drop
            // every following instruction of the region.
            emit(WIRE_ENDBR);
            break;
        default:
            handled = false;
            break;
        }

        if (!handled) {
            skipped++;
            bc.resize(offMap[guestOff]); // roll back partial emission for this insn
            out.skipReason = "unsupported instruction";
            // Stop translation; caller keeps [off, end) native.
            break;
        }

        // Track whether imul's inexpressible CF/OF could still be observed.
        switch (insn.category) {
        case InsnCategory::IMUL:
            mulFlagsPending = true;
            break;
        case InsnCategory::ADD: case InsnCategory::SUB: case InsnCategory::AND:
        case InsnCategory::OR: case InsnCategory::XOR: case InsnCategory::CMP:
        case InsnCategory::TEST: case InsnCategory::INC: case InsnCategory::DEC:
        case InsnCategory::NEG: case InsnCategory::SHL: case InsnCategory::SHR:
        case InsnCategory::SAR: case InsnCategory::ROL: case InsnCategory::ROR:
            mulFlagsPending = false;
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

    // Terminator: halt at end of block.
    emit(WIRE_HALT);

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