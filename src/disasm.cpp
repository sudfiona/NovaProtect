// NovaProtect x86-64 Disassembler Implementation
#include "disasm.h"
#include <cstring>
#include <cstdio>
#include <cctype>
#include <utility>
#include <cstdint>

namespace np {

// ============================================================
// Register names
// ============================================================
namespace reg_util {

static const char* reg64_names[] = {
    "rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi",
    "r8","r9","r10","r11","r12","r13","r14","r15"
};
static const char* reg32_names[] = {
    "eax","ecx","edx","ebx","esp","ebp","esi","edi",
    "r8d","r9d","r10d","r11d","r12d","r13d","r14d","r15d"
};
static const char* reg16_names[] = {
    "ax","cx","dx","bx","sp","bp","si","di",
    "r8w","r9w","r10w","r11w","r12w","r13w","r14w","r15w"
};
static const char* reg8_names[] = {
    "al","cl","dl","bl","spl","bpl","sil","dil",
    "r8b","r9b","r10b","r11b","r12b","r13b","r14b","r15b"
};
static const char* xmm_names[] = {
    "xmm0","xmm1","xmm2","xmm3","xmm4","xmm5","xmm6","xmm7",
    "xmm8","xmm9","xmm10","xmm11","xmm12","xmm13","xmm14","xmm15"
};

const char* regName(Reg r) {
    uint8_t idx = (uint8_t)r & 0x0F;
    switch (r) {
    case Reg::RIP: return "rip";
    default:
        if ((uint8_t)r >= (uint8_t)Reg::XMM0 && (uint8_t)r <= (uint8_t)Reg::XMM15)
            return xmm_names[idx];
        return reg64_names[idx & 0x0F];
    }
}

uint8_t regSize(Reg r) {
    if ((uint8_t)r >= (uint8_t)Reg::XMM0 && (uint8_t)r <= (uint8_t)Reg::XMM15) return 16;
    if (r == Reg::NONE) return 0;
    return 8; // default 64-bit
}

Reg regFromIndex(uint8_t index, bool extended, bool is64) {
    uint8_t actual = index | (extended ? 8 : 0);
    return (Reg)actual;
}

bool isGPR(Reg r) {
    return (uint8_t)r <= 15;
}

bool isXMM(Reg r) {
    return (uint8_t)r >= (uint8_t)Reg::XMM0 && (uint8_t)r <= (uint8_t)Reg::XMM15;
}

} // namespace reg_util

// ============================================================
// Instruction string representation
// ============================================================
std::string DisasmInsn::toString() const {
    char buf[256];
    const char* cat = Disassembler::categoryToString(category);
    snprintf(buf, sizeof(buf), "%s", cat);
    return buf;
}

const char* Disassembler::categoryToString(InsnCategory cat) {
    switch (cat) {
    case InsnCategory::MOV:    return "mov";
    case InsnCategory::MOVZX:  return "movzx";
    case InsnCategory::MOVSX:  return "movsx";
    case InsnCategory::LEA:    return "lea";
    case InsnCategory::XCHG:   return "xchg";
    case InsnCategory::XADD:   return "xadd";
    case InsnCategory::PUSH:   return "push";
    case InsnCategory::POP:    return "pop";
    case InsnCategory::ADD:    return "add";
    case InsnCategory::SUB:    return "sub";
    case InsnCategory::MUL:    return "mul";
    case InsnCategory::IMUL:   return "imul";
    case InsnCategory::DIV:    return "div";
    case InsnCategory::IDIV:   return "idiv";
    case InsnCategory::INC:    return "inc";
    case InsnCategory::DEC:    return "dec";
    case InsnCategory::NEG:    return "neg";
    case InsnCategory::AND:    return "and";
    case InsnCategory::OR:     return "or";
    case InsnCategory::XOR:    return "xor";
    case InsnCategory::NOT:    return "not";
    case InsnCategory::TEST:   return "test";
    case InsnCategory::CMP:    return "cmp";
    case InsnCategory::SHL:    return "shl";
    case InsnCategory::SHR:    return "shr";
    case InsnCategory::SAR:    return "sar";
    case InsnCategory::ROL:    return "rol";
    case InsnCategory::ROR:    return "ror";
    case InsnCategory::JMP:    return "jmp";
    case InsnCategory::JCC:    return "jcc";
    case InsnCategory::CALL:   return "call";
    case InsnCategory::RET:    return "ret";
    case InsnCategory::LEAVE:  return "leave";
    case InsnCategory::ENTER:  return "enter";
    case InsnCategory::SETcc:  return "setcc";
    case InsnCategory::CMOVcc: return "cmovcc";
    case InsnCategory::CPUID:  return "cpuid";
    case InsnCategory::RDTSC:  return "rdtsc";
    case InsnCategory::NOP:    return "nop";
    case InsnCategory::SSE:    return "sse";
    case InsnCategory::AVX:    return "avx";
    case InsnCategory::SAHF:   return "sahf";
    case InsnCategory::LAHF:   return "lahf";
    case InsnCategory::BT:     return "bt";
    case InsnCategory::CDQ:    return "cdq";
    case InsnCategory::FLAGOP: return "flagop";
    default: return "???";
    }
}

// ============================================================
// Prefix parsing
// ============================================================
uint32_t Disassembler::parsePrefixes(const uint8_t* code, size_t max_len, size_t& offset) {
    uint32_t prefixes = PREFIX_NONE;
    bool done = false;
    
    while (offset < max_len && !done) {
        switch (code[offset]) {
        case 0x66: prefixes |= PREFIX_66; offset++; break;
        case 0x67: prefixes |= PREFIX_67; offset++; break;
        case 0xF2: prefixes |= PREFIX_F2; offset++; break;
        case 0xF3: prefixes |= PREFIX_F3; offset++; break;
        case 0xF0: prefixes |= PREFIX_LOCK; offset++; break;
        case 0x2E: case 0x36: case 0x3E: case 0x26: case 0x64: case 0x65:
            // Segment prefixes
            switch (code[offset]) {
            case 0x64: prefixes |= PREFIX_FS; break;
            case 0x65: prefixes |= PREFIX_GS; break;
            }
            offset++;
            break;
        default:
            // Check for REX prefix (0x40-0x4F)
            if (code[offset] >= 0x40 && code[offset] <= 0x4F) {
                uint8_t rex = code[offset];
                if (rex & 0x08) prefixes |= PREFIX_REX_W;
                if (rex & 0x04) prefixes |= PREFIX_REX_R;
                if (rex & 0x02) prefixes |= PREFIX_REX_X;
                if (rex & 0x01) prefixes |= PREFIX_REX_B;
                offset++;
            } else {
                done = true;
            }
            break;
        }
    }
    return prefixes;
}

// Static variable for REX byte (need to make this a member)
// ============================================================
// ModRM parsing
// ============================================================
bool Disassembler::parseModRM(const uint8_t* code, size_t max_len, size_t& offset,
                               DisasmInsn& insn, uint32_t prefixes) {
    if (offset >= max_len) return false;
    
    uint8_t modrm = code[offset++];
    insn.modrm = modrm;
    insn.has_modrm = true;
    
    uint8_t mod = (modrm >> 6) & 3;
    uint8_t reg = (modrm >> 3) & 7;
    uint8_t rm  = modrm & 7;
    
    bool rex_r = (prefixes & PREFIX_REX_R) != 0;
    bool rex_x = (prefixes & PREFIX_REX_X) != 0;
    bool rex_b = (prefixes & PREFIX_REX_B) != 0;
    bool is64  = (prefixes & PREFIX_REX_W) != 0;
    
    // Determine operand size
    uint8_t opsize = 4;
    if (is64) opsize = 8;
    else if (prefixes & PREFIX_66) opsize = 2;
    // Byte-operand opcodes (W bit clear in the legacy rows, plus the explicit
    // byte forms) size their operands at one byte regardless of REX.W/66:
    // `mov al, bl` must not masquerade as a 32-bit move.
    if (!(prefixes & PREFIX_0F)) {
        uint8_t o = insn.opcode;
        bool byteOp =
            o == 0x80 || o == 0x82 || o == 0x84 || o == 0x86 || o == 0x88 ||
            o == 0x8A || o == 0xC0 || o == 0xC6 || o == 0xD0 || o == 0xD2 ||
            o == 0xF6 || o == 0xFE ||
            (o >= 0xB0 && o <= 0xB7) ||
            (o < 0x40 && (o & 1) == 0);
        if (byteOp) opsize = 1;
    }
    
    // Handle register operand (reg field). Category is assigned later by
    // categorizeInstruction(), so decode the reg field unconditionally here;
    // fixupOperands() re-orients dst/src once the category is known.
    insn.dst.type = OperandType::Register;
    insn.dst.reg = reg_util::regFromIndex(reg, rex_r, is64);
    insn.dst.size = opsize;
    
    // Handle rm field
    if (mod == 3) {
        // Register to register
        insn.src.type = OperandType::Register;
        insn.src.reg = reg_util::regFromIndex(rm, rex_b, is64);
        insn.src.size = opsize;
    } else {
        // Memory operand
        insn.src.type = OperandType::Memory;
        insn.src.size = opsize;
        
        // Parse SIB byte if needed
        uint8_t base_reg = rm;
        bool has_sib = false;
        uint8_t sib = 0;
        if (rm == 4 && mod != 3) {
            // SIB byte follows for every mod except 3, including mod == 0
            // (the [index*scale + disp32] encoding - lea 0x0(,%rdx,8)).
            if (offset >= max_len) return false;
            sib = code[offset++];
            insn.sib = sib;
            insn.has_sib = true;
            has_sib = true;
            base_reg = sib & 7;
            uint8_t index_reg = (sib >> 3) & 7;
            uint8_t scale_bits = (sib >> 6) & 3;

            // index == 4 (100b) means "no index register". Report it as RIP
            // so the register-mask scan (which only looks at GPR 0..15)
            // skips it instead of seeing a phantom RSP.
            insn.src.index = (index_reg == 4 && !rex_x)
                ? Reg::RIP
                : reg_util::regFromIndex(index_reg, rex_x, is64);
            insn.src.scale = 1 << scale_bits;
        }

        if (rm == 5 && mod == 0) {
            // RIP-relative addressing
            insn.src.type = OperandType::MemoryRIP;
            insn.src.base = Reg::RIP;
        } else if (has_sib && base_reg == 5 && mod == 0) {
            // [index*scale + disp32]: the SIB base field 101 with mod == 0
            // means there is no base register, only a 32-bit displacement.
            // Report RIP so the mask scan skips a phantom RBP.
            insn.src.base = Reg::RIP;
        } else {
            insn.src.base = reg_util::regFromIndex(base_reg, rex_b, is64);
        }

        // Parse displacement
        int disp_size = 0;
        switch (mod) {
        case 0:
            if (rm == 5) disp_size = 4;                        // RIP-relative
            else if (has_sib && base_reg == 5) disp_size = 4;  // SIB no-base
            break;
        case 1: disp_size = 1; break;
        case 2: disp_size = 4; break;
        }
        
        if (disp_size > 0) {
            insn.has_displacement = true;
            if (disp_size == 1) {
                insn.src.displacement = (int8_t)code[offset++];
            } else {
                int32_t disp = 0;
                memcpy(&disp, &code[offset], 4);
                insn.src.displacement = disp;
                offset += 4;
            }
        }
    }
    
    return true;
}

// ============================================================
// Displacement and immediate parsing
// ============================================================
bool Disassembler::parseDisplacement(const uint8_t* code, size_t max_len, size_t& offset,
                                     DisasmInsn& insn, int disp_size) {
    if (offset + disp_size > max_len) return false;
    if (disp_size == 1) {
        insn.src.displacement = (int8_t)code[offset++];
    } else if (disp_size == 2) {
        int16_t d; memcpy(&d, &code[offset], 2);
        insn.src.displacement = d; offset += 2;
    } else if (disp_size == 4) {
        int32_t d; memcpy(&d, &code[offset], 4);
        insn.src.displacement = d; offset += 4;
    }
    insn.has_displacement = true;
    return true;
}

bool Disassembler::parseImmediate(const uint8_t* code, size_t max_len, size_t& offset,
                                   DisasmInsn& insn, int imm_size) {
    if (offset + imm_size > max_len) return false;
    insn.has_immediate = true;
    // In 64-bit mode (REX.W) every immediate shorter than 64 bits is
    // sign-extended by the CPU.  Store the sign-extended value so the VM
    // translator emits the same constant the hardware would use; without
    // this, mutated forms such as "add rax,imm -> sub rax,-imm" would be
    // lowered with a zero-extended (positive) immediate and compute the
    // wrong result.
    bool is64 = (insn.prefixes & PREFIX_REX_W) != 0;
    if (imm_size == 1) {
        // The x86 imm8 forms sign-extend to the operand size in every mode;
        // the zero-extend shortcut here turned `add/sub/cmp r32, -1` into
        // `+255`. Byte moves splice only the low byte anyway.
        insn.src.immediate = (uint64_t)(int64_t)(int8_t)code[offset];
        offset++;
    } else if (imm_size == 2) {
        uint16_t i; memcpy(&i, &code[offset], 2);
        insn.src.immediate = is64 ? (uint64_t)(int64_t)(int16_t)i : (uint64_t)i;
        offset += 2;
    } else if (imm_size == 3) {
        // enter imm16, imm8 - keep both parts in one value: the low 16 bits
        // are the frame allocation size, the third byte the nesting level.
        uint16_t i; memcpy(&i, &code[offset], 2);
        insn.src.immediate = (uint64_t)i | ((uint64_t)code[offset + 2] << 16);
        offset += 3;
    } else if (imm_size == 4) {
        uint32_t i; memcpy(&i, &code[offset], 4);
        insn.src.immediate = is64 ? (uint64_t)(int64_t)(int32_t)i : (uint64_t)i;
        offset += 4;
    } else if (imm_size == 8) {
        uint64_t i; memcpy(&i, &code[offset], 8);
        insn.src.immediate = i; offset += 8;
    }
    return true;
}

// ============================================================
// Operand-direction fixup
// ============================================================
// parseModRM assigns dst <- ModRM.reg and src <- ModRM.rm for the ALU/MOV
// families.  That is only correct for the "reg is destination" encodings.
// Here we normalise every encoding to the canonical form
//     dst = the operand that is written
//     src = the other operand (register / memory / immediate)
void Disassembler::fixupOperands(DisasmInsn& insn) {
    uint8_t op = insn.opcode;
    if (insn.prefixes & PREFIX_0F) {
        // BT/BTS/BTR/BTC (0F A3/AB/B3/BB and the 0F BA imm8 group): the
        // ModRM.reg field is the bit index or an opcode extension, not a
        // destination. parseModRM decoded it as a register regardless - the
        // group's /4 fabricated a phantom RSP that the stack-depth guard
        // read as an unbounded rsp write, so `bt rax, imm8` cut the region
        // and translated to a bare HALT (the interpreter then ran nothing
        // and left every register untouched). Orient dst <- rm (the bit
        // string - the only operand BT* may write) and src <- index
        // (register form) or the trailing imm8 (group form).
        uint8_t op2 = insn.opcode2;
        if (op2 == 0xA3 || op2 == 0xAB || op2 == 0xB3 || op2 == 0xBB) {
            std::swap(insn.dst, insn.src);
        } else if (op2 == 0xBA && insn.has_modrm) {
            uint64_t imm = insn.src.immediate;
            Operand rm = insn.src;
            rm.immediate = 0;
            insn.dst = rm;
            insn.src.type = OperandType::Immediate;
            insn.src.reg = Reg::NONE;
            insn.src.base = Reg::NONE;
            insn.src.index = Reg::NONE;
            insn.src.immediate = imm;
        }
        return;   // other two-byte forms already oriented
    }

    bool haveRm = insn.has_modrm;
    switch (op) {
    // (r/m, r): rm is destination -> swap
    case 0x00: case 0x08: case 0x20: case 0x28: case 0x30: case 0x38:
    case 0x01: case 0x09: case 0x21: case 0x29: case 0x31: case 0x39:
    case 0x88: case 0x89:
        if (haveRm) std::swap(insn.dst, insn.src);
        break;

    // LEA: dst = reg field, src = memory operand
    case 0x8D: {
        uint8_t rf = (insn.modrm >> 3) & 7;
        bool is64 = (insn.prefixes & PREFIX_REX_W) != 0;
        insn.dst.type = OperandType::Register;
        insn.dst.reg = reg_util::regFromIndex(rf, (insn.prefixes & PREFIX_REX_R) != 0, is64);
        break;
    }
    // (r, r/m): reg is destination -> already correct
    case 0x02: case 0x03: case 0x0A: case 0x0B:
    case 0x22: case 0x23: case 0x2A: case 0x2B:
    case 0x32: case 0x33: case 0x3A: case 0x3B:
    case 0x8A: case 0x8B:
        break;

    // ALU r/m, imm: reg field is an opcode extension; rm is the destination
    case 0x80: case 0x81: case 0x82: case 0x83:
    case 0xC6: case 0xC7: {
        Operand rm = insn.src;
        insn.dst = rm;
        insn.src.type = OperandType::Immediate;
        insn.src.reg = Reg::NONE;
        insn.src.base = Reg::NONE;
        break;
    }
    // imul r64, r/m64, imm: dst stays the reg field, rm goes to extra.
    case 0x69: case 0x6B: {
        insn.extra = insn.src;
        insn.src.type = OperandType::Immediate;
        insn.src.reg = Reg::NONE;
        insn.src.base = Reg::NONE;
        break;
    }
    // moffs: the parsed "immediate" is the absolute memory address. Orient as
    // a plain MOV with an absolute memory operand on the correct side.
    case 0xA0: case 0xA1: case 0xA2: case 0xA3: {
        bool toReg = (op == 0xA0 || op == 0xA1);
        bool byteAcc = (op == 0xA0 || op == 0xA2);
        uint8_t sz = byteAcc ? 1
                   : (insn.prefixes & PREFIX_REX_W) ? 8
                   : (insn.prefixes & PREFIX_66) ? 2 : 4;
        Operand mem;
        mem.type = OperandType::Memory;
        mem.base = Reg::NONE;
        mem.index = Reg::NONE;
        mem.displacement = (int64_t)insn.src.immediate;
        mem.size = sz;
        Operand acc;
        acc.type = OperandType::Register;
        acc.reg = Reg::RAX;
        acc.size = sz;
        if (toReg) { insn.dst = acc; insn.src = mem; }
        else       { insn.dst = mem; insn.src = acc; }
        insn.has_immediate = false;
        break;
    }
    // String ops: name the implicit registers so the packer's register-mask
    // scan preserves them across the interpreter (rax/rcx are in the
    // always-save set; rsi/rdi are not).
    case 0xA4: case 0xA5: case 0xA6: case 0xA7:
    case 0xAA: case 0xAB: case 0xAC: case 0xAD:
    case 0xAE: case 0xAF: {
        auto o = [](Reg r) {
            Operand x;
            x.type = OperandType::Register;
            x.reg = r;
            return x;
        };
        switch (insn.category) {
        case InsnCategory::MOVS:
        case InsnCategory::CMPS:
            insn.dst = o(Reg::RDI); insn.src = o(Reg::RSI); insn.extra = o(Reg::RCX);
            break;
        case InsnCategory::STOS:
            insn.dst = o(Reg::RDI); insn.src = o(Reg::RAX); insn.extra = o(Reg::RCX);
            break;
        case InsnCategory::LODS:
            insn.dst = o(Reg::RAX); insn.src = o(Reg::RSI); insn.extra = o(Reg::RCX);
            break;
        default: // SCAS
            insn.dst = o(Reg::RDI); insn.src = o(Reg::RAX); insn.extra = o(Reg::RCX);
            break;
        }
        break;
    }

    // ALU accumulator, imm: implicit AL/AX/EAX/RAX destination, no ModRM.
    case 0x04: case 0x05: case 0x0C: case 0x0D:
    case 0x14: case 0x15: case 0x1C: case 0x1D:
    case 0x24: case 0x25: case 0x2C: case 0x2D:
    case 0x34: case 0x35: case 0x3C: case 0x3D: {
        bool is64 = (insn.prefixes & PREFIX_REX_W) != 0;
        insn.dst.type = OperandType::Register;
        insn.dst.reg = Reg::RAX;
        insn.dst.size = (insn.opcode & 1) ? (is64 ? 8 : 4) : 1;
        insn.src.type = OperandType::Immediate;
        insn.src.reg = Reg::NONE;
        insn.src.base = Reg::NONE;
        break;
    }

    // MOV reg, imm
    case 0xB0: case 0xB1: case 0xB2: case 0xB3:
    case 0xB4: case 0xB5: case 0xB6: case 0xB7:
    case 0xB8: case 0xB9: case 0xBA: case 0xBB:
    case 0xBC: case 0xBD: case 0xBE: case 0xBF: {
        uint8_t ri = (op & 7) | ((insn.prefixes & PREFIX_REX_B) ? 8 : 0);
        bool is64 = (insn.prefixes & PREFIX_REX_W) != 0;
        insn.dst.type = OperandType::Register;
        insn.dst.reg = reg_util::regFromIndex(ri, false, is64);
        insn.dst.size = (op <= 0xB7) ? 1 : (is64 ? 8 : 4);
        insn.src.type = OperandType::Immediate;
        insn.src.reg = Reg::NONE;
        break;
    }

    // shifts r/m, imm8 or CL
    case 0xC0: case 0xC1:
    case 0xD0: case 0xD1:
    case 0xD2: case 0xD3: {
        Operand rm = insn.src;
        insn.dst = rm;
        if (op == 0xD2 || op == 0xD3) {
            insn.src = Operand{};
            insn.src.type = OperandType::Register;
            insn.src.reg = Reg::RCX;
        } else if (op == 0xD0 || op == 0xD1) {
            insn.src = Operand{};
            insn.src.type = OperandType::Immediate;
            insn.src.immediate = 1;
        } else {
            uint64_t imm = insn.src.immediate;
            insn.src = Operand{};
            insn.src.type = OperandType::Immediate;
            insn.src.immediate = imm;
        }
        break;
    }

    // group 3: F6/F7
    case 0xF6: case 0xF7: {
        Operand rm = insn.src;
        uint64_t imm = insn.src.immediate;
        insn.dst = rm;
        insn.src = Operand{};
        if (insn.category == InsnCategory::TEST) {
            insn.src.type = OperandType::Immediate;
            insn.src.immediate = imm;
        }
        break;
    }

    // inc/dec/group5 (FE/FF)
    case 0xFE: case 0xFF: {
        Operand rm = insn.src;
        insn.dst = rm;
        insn.src = Operand{};
        break;
    }
    case 0x8F: {
        Operand rm = insn.src;
        insn.dst = rm;
        insn.src = Operand{};
        insn.category = InsnCategory::POP;
        break;
    }

    // push/pop reg
    case 0x50: case 0x51: case 0x52: case 0x53:
    case 0x54: case 0x55: case 0x56: case 0x57:
    case 0x58: case 0x59: case 0x5A: case 0x5B:
    case 0x5C: case 0x5D: case 0x5E: case 0x5F: {
        uint8_t ri = (op & 7) | ((insn.prefixes & PREFIX_REX_B) ? 8 : 0);
        insn.dst.type = OperandType::Register;
        insn.dst.reg = reg_util::regFromIndex(ri, false, true);
        insn.src = Operand{};
        break;
    }
    case 0x68: case 0x6A: {
        uint64_t imm = insn.src.immediate;
        insn.dst = Operand{};
        insn.dst.type = OperandType::Immediate;
        insn.dst.immediate = imm;
        insn.src = Operand{};
        break;
    }

    // test eAX, imm
    case 0xA8: case 0xA9: {
        uint64_t imm = insn.src.immediate;
        insn.dst = Operand{};
        insn.dst.type = OperandType::Register;
        insn.dst.reg = Reg::RAX;
        insn.src = Operand{};
        insn.src.type = OperandType::Immediate;
        insn.src.immediate = imm;
        break;
    }
    default:
        break;
    }
}
// ============================================================
// Instruction categorization
// ============================================================
void Disassembler::categorizeInstruction(DisasmInsn& insn) {
    if (insn.prefixes & PREFIX_0F) {
        // Two-byte opcodes
        switch (insn.opcode2) {
        case 0x05: insn.category = InsnCategory::Unknown; break; // syscall
        case 0x0B: insn.category = InsnCategory::UD2; break;
        case 0x1E: insn.category = InsnCategory::NOP; break; // endbr64
        case 0x1F: insn.category = InsnCategory::NOP; break; // multi-byte nop
        case 0x31: insn.category = InsnCategory::RDTSC; break;
        case 0xA2:
            // cpuid: rax/rbx/rcx/rdx are implicit. rbx is not in the
            // packer's always-save set, so it is named here for the register
            // mask scan (rax/rcx/rdx are forced in unconditionally).
            insn.category = InsnCategory::CPUID;
            insn.dst.type = OperandType::Register; insn.dst.reg = Reg::RAX;
            insn.src.type = OperandType::Register; insn.src.reg = Reg::RBX;
            insn.extra.type = OperandType::Register; insn.extra.reg = Reg::RCX;
            break;
        case 0xC0: case 0xC1: insn.category = InsnCategory::XADD; break;
        // cmpxchg r/m, r (0F B0 / B1). F3-prefixed forms do not exist, so the
        // prefix never changes the meaning here.
        case 0xB0: case 0xB1: insn.category = InsnCategory::CMPXCHG; break;
        // bsf / bsr; the F3 prefix upgrades them to tzcnt / lzcnt at
        // lowering time (the decoder keeps the prefix in insn.prefixes).
        case 0xBC: case 0xBD: insn.category = InsnCategory::BITSCAN; break;
        // shld (A4/A5) and shrd (AC/AD); the trailing count is imm8 for the
        // even opcodes and CL for the odd ones.
        case 0xA4: case 0xA5: case 0xAC: case 0xAD:
            insn.category = InsnCategory::SHLD; break;
        // Group 0F C7: /6 cmpxchg8b / rdrand / rdseed, /7 cmpxchg16b.
        // mod==3 turns /6 into the register forms rdrand / rdseed.
        case 0xC7:
            if (insn.has_modrm) {
                uint8_t ext = (insn.modrm >> 3) & 7;
                insn.category = (ext == 6 || ext == 7) ? InsnCategory::CMPXCHG
                                                       : InsnCategory::Unknown;
            }
            break;
        // ---- SSE / SSE2 data movement, arithmetic and integer SIMD -------
        // Every 0F form the translator understands is classified here; the
        // prefix (66/F2/F3) picks the flavour at lowering time.
        case 0x10: case 0x11: case 0x12: case 0x13: case 0x14: case 0x15:
        case 0x16: case 0x17: case 0x28: case 0x29: case 0x2A: case 0x2B:
        case 0x2C: case 0x2D: case 0x2E: case 0x2F:
        case 0x50: case 0x51: case 0x52: case 0x53: case 0x54: case 0x55:
        case 0x56: case 0x57: case 0x58: case 0x59: case 0x5A: case 0x5B:
        case 0x5C: case 0x5D: case 0x5E: case 0x5F:
        case 0x60: case 0x61: case 0x62: case 0x63: case 0x64: case 0x65:
        case 0x66: case 0x67: case 0x68: case 0x69: case 0x6A: case 0x6B:
        case 0x6C: case 0x6D: case 0x6E: case 0x6F:
        case 0x70: case 0x71: case 0x72: case 0x73: case 0x74: case 0x75:
        case 0x76: case 0x77: case 0x78: case 0x79: case 0x7A: case 0x7B:
        case 0x7C: case 0x7D: case 0x7E: case 0x7F:
        case 0xC2: case 0xC6:
        case 0xD0: case 0xD1: case 0xD2: case 0xD3: case 0xD4: case 0xD5:
        case 0xD6: case 0xD7: case 0xD8: case 0xD9: case 0xDA: case 0xDB:
        case 0xDC: case 0xDD: case 0xDE: case 0xDF:
        case 0xE0: case 0xE1: case 0xE2: case 0xE3: case 0xE4: case 0xE5:
        case 0xE6: case 0xE7: case 0xE8: case 0xE9: case 0xEA: case 0xEB:
        case 0xEC: case 0xED: case 0xEE: case 0xEF: case 0xF0: case 0xF1:
        case 0xF2: case 0xF3: case 0xF4: case 0xF5: case 0xF6: case 0xF7:
        case 0xF8: case 0xF9: case 0xFA: case 0xFB: case 0xFC: case 0xFD:
        case 0xFE:
            insn.category = InsnCategory::SSE; break;
        // ---- BT / BTS / BTR / BTC ---------------------------------------
        case 0xA3: case 0xAB: case 0xB3: case 0xBB:
            insn.category = InsnCategory::BT; break;
        case 0xBA:
            // group BT: /4 bt /5 bts /6 btr /7 btc with an imm8
            if (insn.has_modrm) {
                uint8_t ext = (insn.modrm >> 3) & 7;
                insn.category = (ext >= 4) ? InsnCategory::BT : InsnCategory::Unknown;
            }
            break;
        case 0xAF: insn.category = InsnCategory::IMUL; break;
        case 0x80: case 0x81: case 0x82: case 0x83: case 0x84: case 0x85:
        case 0x86: case 0x87: case 0x88: case 0x89: case 0x8A: case 0x8B:
        case 0x8C: case 0x8D: case 0x8E: case 0x8F:
            insn.category = InsnCategory::JCC;
            insn.condition = insn.opcode2 & 0x0F;
            break;
        case 0x90: case 0x91: case 0x92: case 0x93: case 0x94: case 0x95:
        case 0x96: case 0x97: case 0x98: case 0x99: case 0x9A: case 0x9B:
        case 0x9C: case 0x9D: case 0x9E: case 0x9F:
            insn.category = InsnCategory::SETcc;
            insn.condition = insn.opcode2 & 0x0F;
            break;
        case 0x40: case 0x41: case 0x42: case 0x43: case 0x44: case 0x45:
        case 0x46: case 0x47: case 0x48: case 0x49: case 0x4A: case 0x4B:
        case 0x4C: case 0x4D: case 0x4E: case 0x4F:
            insn.category = InsnCategory::CMOVcc;
            insn.condition = insn.opcode2 & 0x0F;
            break;
        case 0xB6: insn.category = InsnCategory::MOVZX; break;
        case 0xB7: insn.category = InsnCategory::MOVZX; break;
        case 0xBE: insn.category = InsnCategory::MOVSX; break;
        case 0xBF: insn.category = InsnCategory::MOVSX; break;
        default:
            insn.category = InsnCategory::Unknown;
            break;
        }
    } else {
        // One-byte opcodes
        switch (insn.opcode) {
        case 0x00: case 0x01: case 0x02: case 0x03:
        case 0x04: case 0x05:
            insn.category = InsnCategory::ADD; break;
        case 0x08: case 0x09: case 0x0A: case 0x0B:
        case 0x0C: case 0x0D:
            insn.category = InsnCategory::OR; break;
        case 0x10: case 0x11: case 0x12: case 0x13:
        case 0x14: case 0x15:
            insn.category = InsnCategory::ADC; break;
        case 0x18: case 0x19: case 0x1A: case 0x1B:
        case 0x1C: case 0x1D:
            insn.category = InsnCategory::SBB; break;
        case 0x20: case 0x21: case 0x22: case 0x23:
        case 0x24: case 0x25:
            insn.category = InsnCategory::AND; break;
        case 0x28: case 0x29: case 0x2A: case 0x2B:
        case 0x2C: case 0x2D:
            insn.category = InsnCategory::SUB; break;
        case 0x30: case 0x31: case 0x32: case 0x33:
        case 0x34: case 0x35:
            insn.category = InsnCategory::XOR; break;
        case 0x38: case 0x39: case 0x3A: case 0x3B:
        case 0x3C: case 0x3D:
            insn.category = InsnCategory::CMP; break;
        case 0x50: case 0x51: case 0x52: case 0x53:
        case 0x54: case 0x55: case 0x56: case 0x57:
            insn.category = InsnCategory::PUSH; break;
        case 0x58: case 0x59: case 0x5A: case 0x5B:
        case 0x5C: case 0x5D: case 0x5E: case 0x5F:
            insn.category = InsnCategory::POP; break;
        case 0x68: insn.category = InsnCategory::PUSH; break; // push imm
        case 0x69: insn.category = InsnCategory::IMUL; break; // imul r, r/m, imm32
        case 0x6A: insn.category = InsnCategory::PUSH; break; // push imm8
        case 0x6B: insn.category = InsnCategory::IMUL; break; // imul r, r/m, imm8
        case 0x70: case 0x71: case 0x72: case 0x73: case 0x74: case 0x75:
        case 0x76: case 0x77: case 0x78: case 0x79: case 0x7A: case 0x7B:
        case 0x7C: case 0x7D: case 0x7E: case 0x7F:
            insn.category = InsnCategory::JCC;
            insn.condition = insn.opcode & 0x0F;
            break;
        case 0x80: case 0x81: case 0x82: case 0x83:
            // Group 1: ADD/OR/ADC/SBB/AND/SUB/XOR/CMP with imm
            if (insn.has_modrm) {
                uint8_t ext = (insn.modrm >> 3) & 7;
                switch (ext) {
                case 0: insn.category = InsnCategory::ADD; break;
                case 1: insn.category = InsnCategory::OR; break;
                case 2: insn.category = InsnCategory::ADC; break;
                case 3: insn.category = InsnCategory::SBB; break;
                case 4: insn.category = InsnCategory::AND; break;
                case 5: insn.category = InsnCategory::SUB; break;
                case 6: insn.category = InsnCategory::XOR; break;
                case 7: insn.category = InsnCategory::CMP; break;
                default: insn.category = InsnCategory::Unknown; break;
                }
            }
            break;
        case 0x84: case 0x85:
            insn.category = InsnCategory::TEST; break;
        case 0x86: case 0x87:
            insn.category = InsnCategory::XCHG; break;
        case 0x88: case 0x89: case 0x8A: case 0x8B:
        case 0x8C: case 0x8E:
            insn.category = InsnCategory::MOV; break;
        case 0x8D:
            insn.category = InsnCategory::LEA; break;
        case 0x63:
            insn.category = InsnCategory::MOVSX; break;   // movsxd
        case 0x90:
            insn.category = InsnCategory::NOP; break;
        case 0x91: case 0x92: case 0x93: case 0x94: case 0x95:
        case 0x96: case 0x97:
            insn.category = InsnCategory::XCHG; break;   // xchg rax, r64
        case 0x98:
            // cwde (eax = sign-extend ax) / cdqe (rax = sign-extend eax).
            insn.category = InsnCategory::MOVSX;
            insn.dst.type = OperandType::Register;
            insn.dst.reg = Reg::RAX;
            insn.src.type = OperandType::Register;
            insn.src.reg = Reg::RAX;
            insn.opcode2 = (insn.prefixes & PREFIX_REX_W) ? 0x63 : 0xBF;
            break;
        case 0x99: insn.category = InsnCategory::CDQ; break;  // cdq / cqo
        case 0x9C: insn.category = InsnCategory::PUSHF; break; // pushfq
        case 0x9D: insn.category = InsnCategory::POPF; break;  // popfq
        case 0x9E: insn.category = InsnCategory::SAHF; break;
        case 0x9F: insn.category = InsnCategory::LAHF; break;
        case 0xA8: case 0xA9:
            insn.category = InsnCategory::TEST; break;
        case 0xB0: case 0xB1: case 0xB2: case 0xB3:
        case 0xB4: case 0xB5: case 0xB6: case 0xB7:
            insn.category = InsnCategory::MOV; break; // mov reg8, imm8
        case 0xB8: case 0xB9: case 0xBA: case 0xBB:
        case 0xBC: case 0xBD: case 0xBE: case 0xBF:
            insn.category = InsnCategory::MOV; break; // mov reg, imm
        case 0xC0: case 0xC1:
            // Shift group 2 with imm8
            if (insn.has_modrm) {
                uint8_t ext = (insn.modrm >> 3) & 7;
                switch (ext) {
                case 0: insn.category = InsnCategory::ROL; break;
                case 1: insn.category = InsnCategory::ROR; break;
                case 4: case 6: insn.category = InsnCategory::SHL; break;
                case 5: insn.category = InsnCategory::SHR; break;
                case 7: insn.category = InsnCategory::SAR; break;
                }
            }
            break;
        case 0xC6: case 0xC7:
            insn.category = InsnCategory::MOV; break;   // mov r/m, imm
        case 0xC2:
            insn.category = InsnCategory::RET; break;   // ret imm16
        case 0xC3:
            insn.category = InsnCategory::RET; break;
        case 0xC8:
            insn.category = InsnCategory::ENTER; break;
        case 0xC9:
            insn.category = InsnCategory::LEAVE; break;
        case 0xE8:
            insn.category = InsnCategory::CALL; break;
        case 0xE9:
            insn.category = InsnCategory::JMP; break;
        case 0xEB:
            insn.category = InsnCategory::JMP; break;
        case 0xFE:
            if (insn.has_modrm) {
                uint8_t ext = (insn.modrm >> 3) & 7;
                insn.category = (ext == 1) ? InsnCategory::DEC : InsnCategory::INC;
            }
            break;
        case 0xFF:
            if (insn.has_modrm) {
                uint8_t ext = (insn.modrm >> 3) & 7;
                switch (ext) {
                case 0: insn.category = InsnCategory::INC; break;
                case 1: insn.category = InsnCategory::DEC; break;
                case 2: case 3: insn.category = InsnCategory::CALL; break;
                case 4: case 5: insn.category = InsnCategory::JMP; break;
                case 6: insn.category = InsnCategory::PUSH; break;
                default: insn.category = InsnCategory::Unknown; break;
                }
            }
            break;
        case 0x8F:
            insn.category = InsnCategory::POP; break;
        case 0xF6: case 0xF7:
            // Group 3: TEST/NOT/NEG/MUL/IMUL/DIV/IDIV
            if (insn.has_modrm) {
                uint8_t ext = (insn.modrm >> 3) & 7;
                switch (ext) {
                case 0: case 1: insn.category = InsnCategory::TEST; break;
                case 2: insn.category = InsnCategory::NOT; break;
                case 3: insn.category = InsnCategory::NEG; break;
                case 4: insn.category = InsnCategory::MUL; break;
                case 5: insn.category = InsnCategory::IMUL; break;
                case 6: insn.category = InsnCategory::DIV; break;
                case 7: insn.category = InsnCategory::IDIV; break;
                }
            }
            break;
        case 0xD0: case 0xD1: case 0xD2: case 0xD3:
            // Shift group 2 by 1 or CL
            if (insn.has_modrm) {
                uint8_t ext = (insn.modrm >> 3) & 7;
                switch (ext) {
                case 0: insn.category = InsnCategory::ROL; break;
                case 1: insn.category = InsnCategory::ROR; break;
                case 4: case 6: insn.category = InsnCategory::SHL; break;
                case 5: insn.category = InsnCategory::SHR; break;
                case 7: insn.category = InsnCategory::SAR; break;
                }
            }
            break;
        case 0xA0: case 0xA1: case 0xA2: case 0xA3:
            // moffs: mov acc <-> [abs64]. (One-byte 0xA2 is *not* cpuid -
            // cpuid is 0F A2. Labelling it cpuid here once masked the
            // nine-byte moffs encoding as a one-byte instruction.)
            insn.category = InsnCategory::MOV; break;
        // String ops. The REP/REPNE prefixes are in insn.prefixes; the
        // operand/address width comes from 66 / REX.W at lowering time. The
        // implicit registers are named in the operand fields so the packer's
        // register-mask scan includes them - without this the trampoline
        // would not preserve rsi/rdi across the interpreter.
        case 0xA4: case 0xA5: insn.category = InsnCategory::MOVS; break;
        case 0xA6: case 0xA7: insn.category = InsnCategory::CMPS; break;
        case 0xAA: case 0xAB: insn.category = InsnCategory::STOS; break;
        case 0xAC: case 0xAD: insn.category = InsnCategory::LODS; break;
        case 0xAE: case 0xAF: insn.category = InsnCategory::SCAS; break;
        case 0xD8: case 0xD9: case 0xDA: case 0xDB:
        case 0xDC: case 0xDD: case 0xDE: case 0xDF:
            insn.category = InsnCategory::X87; break;
        case 0xF4: insn.category = InsnCategory::Unknown; break; // HLT
        // stc/clc/cmc/clc/std - single-flag instructions. The wire VM tracks
        // only the arithmetic flags, so the direction-flag pair lowers to a
        // no-op (nothing the VM executes reads DF) and the carry trio to a
        // carry write.
        case 0xF8: case 0xF9: case 0xF5: case 0xFC: case 0xFD:
            insn.category = InsnCategory::FLAGOP; break;
        default:
            insn.category = InsnCategory::Unknown;
            break;
        }
    }
}

// ============================================================
// Main disassemble function
// ============================================================
uint32_t Disassembler::disassemble(const uint8_t* code, size_t max_len, DisasmInsn& insn) {
    insn = DisasmInsn{};
    insn.category = InsnCategory::Unknown;
    size_t start = 0;
    size_t offset = 0;
    
    if (max_len < 1) return 0;
    
    // Save the start
    size_t start_offset = 0;
    
    // Parse prefixes
    insn.prefixes = parsePrefixes(code, max_len, offset);
    if (offset >= max_len) return 0;

    // VEX (C4/C5) and EVEX (62) forms: consume the instruction at its real
    // shape so every later boundary stays exact. These never lower to wire -
    // they execute on the native bridge - but a wrong length here would cut
    // mid-instruction and hand the bridge half a command. The shape is
    // prefix(2-3/4) + opcode + [modrm/sib/disp] + [imm8]:
    //   C5: VEX.128.0F - opcode 77 (vzeroupper) carries no ModRM;
    //   C4: VEX.2/3-byte, map in the first byte's low 5 (1=0F 2=0F38 3=0F3A);
    //   62: EVEX, map in P0's low 2.
    if (code[offset] == 0xC5 || code[offset] == 0xC4 || code[offset] == 0x62) {
        uint8_t kind = code[offset++];
        uint8_t map = 1;
        if (kind == 0xC5) {
            if (offset >= max_len) return 0;
            offset++;                                    // R vvvv L pp
        } else if (kind == 0xC4) {
            if (offset + 1 >= max_len) return 0;
            map = code[offset] & 0x1F;
            offset += 2;                                 // RXBmmmmm / WvvvvLpp
        } else {
            if (offset + 2 >= max_len) return 0;
            map = code[offset] & 0x03;
            offset += 3;                                 // P0 / P1 / P2
        }
        if (offset >= max_len) return 0;
        insn.opcode2 = code[offset++];
        insn.category = InsnCategory::AVX;
        bool needs_modrm = !(kind == 0xC5 && insn.opcode2 == 0x77);
        int imm_size = 0;
        if (map == 3) {
            imm_size = 1;                                // 0F3A: trailing imm8
        } else if (map == 1) {
            switch (insn.opcode2) {
            case 0x70: case 0x71: case 0x72: case 0x73:
            case 0xC2: case 0xC4: case 0xC5: case 0xC6:
                imm_size = 1;
                break;
            default:
                break;
            }
        }
        if (needs_modrm) {
            if (!parseModRM(code, max_len, offset, insn, 0)) return 0;
        }
        if (imm_size > 0 && !parseImmediate(code, max_len, offset, insn, imm_size)) return 0;
        insn.length = (uint32_t)(offset - start_offset);
        insn.bytes.assign(code, code + insn.length);
        insn.can_mutate = false;
        insn.writes_flags = false;
        insn.reads_flags = false;
        return insn.length;
    }

    // Check for 0x0F escape (two-byte opcode)
    if (code[offset] == 0x0F) {
        insn.prefixes |= PREFIX_0F;
        offset++;
        if (offset >= max_len) return 0;
        
        // Check for 0F38/0F3A
        if (code[offset] == 0x38) { insn.prefixes |= PREFIX_0F38; offset++; }
        else if (code[offset] == 0x3A) { insn.prefixes |= PREFIX_0F3A; offset++; }
        
        insn.opcode2 = code[offset++];
    } else {
        // Get opcode (one-byte form)
        insn.opcode = code[offset++];
    }
    
    // Check if we need ModRM byte
    bool needs_modrm = false;
    int imm_size = 0;
    int disp_size = 0;
    
    if (!(insn.prefixes & PREFIX_0F)) {
        switch (insn.opcode) {
        // Instructions with ModRM
        case 0x00: case 0x01: case 0x02: case 0x03:
        case 0x08: case 0x09: case 0x0A: case 0x0B:
        case 0x10: case 0x11: case 0x12: case 0x13:
        case 0x18: case 0x19: case 0x1A: case 0x1B:
        case 0x20: case 0x21: case 0x22: case 0x23:
        case 0x28: case 0x29: case 0x2A: case 0x2B:
        case 0x30: case 0x31: case 0x32: case 0x33:
        case 0x38: case 0x39: case 0x3A: case 0x3B:
        case 0x63:
        case 0x84: case 0x85: case 0x86: case 0x87:
        case 0x88: case 0x89: case 0x8A: case 0x8B:
        case 0x8C: case 0x8D: case 0x8E: case 0x8F:
        case 0xD0: case 0xD1: case 0xD2: case 0xD3:
        case 0xD8: case 0xD9: case 0xDA: case 0xDB:
        case 0xDC: case 0xDD: case 0xDE: case 0xDF:
        case 0xF6: case 0xF7:
        case 0xFE: case 0xFF:
            needs_modrm = true;
            break;
        // Group 1 with immediate (needs ModRM *and* an immediate).
        // The immediate width follows the operand size: REX.W keeps the 32-bit
        // form (sign-extended to 64), a 66 prefix narrows it to 16 bits. Getting
        // this wrong desynchronises the whole instruction stream, because the
        // decoder consumes two bytes too many and every later boundary is off.
        case 0x80: needs_modrm = true; imm_size = 1; break;
        case 0x81: needs_modrm = true;
            imm_size = (insn.prefixes & PREFIX_REX_W) ? 4 :
                       ((insn.prefixes & PREFIX_66) ? 2 : 4); break;
        case 0x82: needs_modrm = true; imm_size = 1; break;
        case 0x83: needs_modrm = true; imm_size = 1; break;
        // shift group with immediate
        case 0xC0: needs_modrm = true; imm_size = 1; break;
        case 0xC1: needs_modrm = true; imm_size = 1; break;
        // mov with immediate
        case 0xC6: needs_modrm = true; imm_size = 1; break;
        case 0xC7: needs_modrm = true;
            imm_size = (insn.prefixes & PREFIX_REX_W) ? 4 :
                       ((insn.prefixes & PREFIX_66) ? 2 : 4); break;
        // imul with immediate
        case 0x69: needs_modrm = true;
            imm_size = (insn.prefixes & PREFIX_REX_W) ? 4 :
                       ((insn.prefixes & PREFIX_66) ? 2 : 4); break;
        case 0x6B: needs_modrm = true; imm_size = 1; break;
        // Instructions with immediate
        case 0x04: case 0x05: case 0x0C: case 0x0D:
        case 0x14: case 0x15: case 0x1C: case 0x1D:
        case 0x24: case 0x25: case 0x2C: case 0x2D:
        case 0x34: case 0x35: case 0x3C: case 0x3D:
        case 0xA8: case 0xA9:
            imm_size = (insn.prefixes & PREFIX_REX_W) ? 4 :
                       ((insn.prefixes & PREFIX_66) ? 2 :
                       ((insn.opcode & 1) ? 4 : 1));
            if (insn.prefixes & PREFIX_REX_W) imm_size = 4; // sign-extended to 64
            break;
        // moffs: mov al/ax/eax/rax <-> [abs64]. The 64-bit offset always
        // follows the opcode regardless of operand size - decoding it as a
        // one-byte instruction desynchronises the whole stream.
        case 0xA0: case 0xA1: case 0xA2: case 0xA3:
            imm_size = 8;
            break;
        case 0x68: imm_size = 4; break; // push imm32
        case 0x6A: imm_size = 1; break; // push imm8
        // ret imm16: the trailing count pops the argument area on return.
        case 0xC2: imm_size = 2; break;
        // enter imm16, imm8: three trailing bytes packed as
        // imm16 | (imm8 << 16) - see parseImmediate's 3-byte case.
        case 0xC8: imm_size = 3; break;
        case 0xB0: case 0xB1: case 0xB2: case 0xB3:
        case 0xB4: case 0xB5: case 0xB6: case 0xB7:
            imm_size = 1;
            break;
        case 0xB8: case 0xB9: case 0xBA: case 0xBB:
        case 0xBC: case 0xBD: case 0xBE: case 0xBF:
            imm_size = (insn.prefixes & PREFIX_REX_W) ? 8 :
                       ((insn.prefixes & PREFIX_66) ? 2 : 4);
            break;
        // Relative jumps/calls
        case 0x70: case 0x71: case 0x72: case 0x73:
        case 0x74: case 0x75: case 0x76: case 0x77:
        case 0x78: case 0x79: case 0x7A: case 0x7B:
        case 0x7C: case 0x7D: case 0x7E: case 0x7F:
        case 0xEB:
            disp_size = 1;
            break;
        case 0xE8: case 0xE9:
            disp_size = 4;
            break;
        }
    } else {
        // Two-byte opcodes
        switch (insn.opcode2) {
        case 0x80: case 0x81: case 0x82: case 0x83:
        case 0x84: case 0x85: case 0x86: case 0x87:
        case 0x88: case 0x89: case 0x8A: case 0x8B:
        case 0x8C: case 0x8D: case 0x8E: case 0x8F:
            disp_size = 4;
            break;
        case 0x05: // syscall
            break;
        case 0x0B: // ud2
            break;
        case 0x1E: // endbr
            break;
        default:
            // Most 0F opcodes need ModRM
            if (insn.opcode2 >= 0x00 && insn.opcode2 <= 0x3F) {
                needs_modrm = true;
                // The zero-to-3F band is mostly groups, but a handful of
                // system instructions are single-byte: parsing a phantom
                // ModRM for them shifts every following boundary. (This is
                // what left rdtsc regions desynchronised - 0F 31 ate the
                // next instruction's first byte as its ModRM.)
                switch (insn.opcode2) {
                case 0x06: case 0x07: case 0x08: case 0x09: case 0x0E:
                case 0x30: case 0x31: case 0x32: case 0x33: case 0x34:
                case 0x35: case 0x37:
                    needs_modrm = false;
                    break;
                default:
                    break;
                }
            } else if (insn.opcode2 >= 0x40 && insn.opcode2 <= 0x4F) {
                needs_modrm = true; // CMOV
            } else if (insn.opcode2 >= 0x90 && insn.opcode2 <= 0x9F) {
                needs_modrm = true; // SETcc
            } else if (insn.opcode2 >= 0xB0 && insn.opcode2 <= 0xBF) {
                needs_modrm = true; // MOVZX/MOVSX/cmpxchg/bsf/bsr
            } else if (insn.opcode2 == 0xAF) {
                // 0F AF is the two-operand imul. It sits just below the
                // MOVZX/MOVSX block, so the range above never covered it and
                // the ModRM byte was skipped: the operands stayed empty and the
                // decoded length was two bytes short.
                needs_modrm = true;
            } else if (insn.opcode2 >= 0x10 && insn.opcode2 <= 0x7F) {
                // SSE band. 0F 77 (EMMS) is the one form here with no ModRM;
                // parsing one would over-read and desynchronise the stream.
                if (insn.opcode2 != 0x77) needs_modrm = true;
            } else if (insn.opcode2 == 0xEF) {
                needs_modrm = true; // pxor (outside the 0x10-0x7F SSE band)
            } else if (insn.opcode2 == 0xC0 || insn.opcode2 == 0xC1) {
                needs_modrm = true; // xadd
            } else if (insn.opcode2 == 0xC2 || insn.opcode2 == 0xC4 ||
                       insn.opcode2 == 0xC5 || insn.opcode2 == 0xC6) {
                // cmpps/cmpss/cmpsd/cmppd, pinsrw, pshufd, shufps/shufpd:
                // all ModRM + trailing imm8.
                needs_modrm = true;
            } else if (insn.opcode2 == 0xC3 || insn.opcode2 == 0xC7) {
                needs_modrm = true; // movnti / cmpxchg8b / rdrand family
            } else if (insn.opcode2 == 0xA4 || insn.opcode2 == 0xA5 ||
                       insn.opcode2 == 0xAC || insn.opcode2 == 0xAD) {
                needs_modrm = true; // shld / shrd
            } else if (insn.opcode2 == 0xAE) {
                needs_modrm = true; // fxsave/lfence/mfence/sfence group
            } else if (insn.opcode2 == 0xA3 || insn.opcode2 == 0xAB ||
                       insn.opcode2 == 0xB3 || insn.opcode2 == 0xBB ||
                       insn.opcode2 == 0xBA) {
                needs_modrm = true; // bt/bts/btr/btc (+ 0F BA group with imm8)
            } else if (insn.opcode2 >= 0xD0) {
                // SSE/integer-SIMD tail (movq, packss*, padd*, pcmpeq*, ...)
                needs_modrm = true;
            }
            break;
        }
    }
    
    // Parse ModRM
    if (needs_modrm) {
        if (!parseModRM(code, max_len, offset, insn, insn.prefixes)) {
            return 0;
        }
        // Note: parseModRM may have already consumed displacement
    }
    
    // F6/F7 with modrm extension /0 or /1 (TEST) carry an immediate. The
    // width follows the operand size: F7 + 66 prefix is imm16 (not imm32) -
    // reading two bytes too many desynchronises the stream and every later
    // boundary lands mid-instruction (the phantom "VEX" / "moffs" rejects
    // were this bug's shadow).
    if (!(insn.prefixes & PREFIX_0F) &&
        (insn.opcode == 0xF6 || insn.opcode == 0xF7) && insn.has_modrm) {
        uint8_t ext = (insn.modrm >> 3) & 7;
        if (ext == 0 || ext == 1) {
            if (insn.opcode == 0xF6) imm_size = 1;
            else imm_size = (insn.prefixes & PREFIX_66) ? 2 : 4;
        }
    }

    // 0F-prefixed forms that carry a trailing imm8. Missing one of these makes
    // the decoded length one byte short, which desynchronises every following
    // instruction - exactly the class of bug that turns one unknown opcode into
    // a whole function staying native.
    if ((insn.prefixes & PREFIX_0F) && needs_modrm && imm_size == 0) {
        if ((insn.prefixes & PREFIX_0F3A) != 0) {
            imm_size = 1;                       // 0F3A forms all end in imm8
        } else {
            switch (insn.opcode2) {
            case 0x70: case 0x71: case 0x72: case 0x73:
            case 0xC2: case 0xC4: case 0xC5: case 0xC6:
            case 0xBA: case 0xA4: case 0xAC:
                imm_size = 1;
                break;
            default:
                break;
            }
        }
    }

    // Parse additional immediate
    if (imm_size > 0) {
        if (!parseImmediate(code, max_len, offset, insn, imm_size)) {
            return 0;
        }
    }
    
    // Parse relative target for branches
    if (disp_size > 0 && !needs_modrm) {
        // This is a relative branch, not a memory displacement
        if (disp_size == 1) {
            insn.rel_target = (int8_t)code[offset];
            insn.length = offset + 1;
        } else {
            int32_t rel;
            memcpy(&rel, &code[offset], 4);
            insn.rel_target = rel;
            insn.length = offset + 4;
        }
        insn.has_displacement = true;
    } else {
        insn.length = offset;
    }
    
    // Categorize
    categorizeInstruction(insn);
    fixupOperands(insn);
    
    // Copy bytes
    insn.bytes.assign(code, code + insn.length);
    
    // Determine if instruction can be mutated/virtualized
    insn.can_mutate = canMutate(insn);
    insn.writes_flags = (insn.category == InsnCategory::ADD || 
                        insn.category == InsnCategory::SUB ||
                        insn.category == InsnCategory::AND ||
                        insn.category == InsnCategory::OR ||
                        insn.category == InsnCategory::XOR ||
                        insn.category == InsnCategory::CMP ||
                        insn.category == InsnCategory::TEST ||
                        insn.category == InsnCategory::SHL ||
                        insn.category == InsnCategory::SHR);
    insn.reads_flags = (insn.category == InsnCategory::JCC ||
                       insn.category == InsnCategory::SETcc ||
                       insn.category == InsnCategory::CMOVcc);
    
    return insn.length;
}

// ============================================================
// Disassemble a block
// ============================================================
std::vector<DisasmInsn> Disassembler::disassembleBlock(const uint8_t* code, size_t size, uint32_t base_rva) {
    std::vector<DisasmInsn> result;
    size_t offset = 0;
    
    while (offset < size) {
        DisasmInsn insn;
        uint32_t len = disassemble(code + offset, size - offset, insn);
        if (len == 0) break;
        
        insn.rva = base_rva + (uint32_t)offset;
        
        // Calculate absolute target for branches
        if (insn.has_displacement && (insn.category == InsnCategory::JCC ||
            insn.category == InsnCategory::JMP || insn.category == InsnCategory::CALL)) {
            insn.abs_target = insn.rva + insn.length + (uint32_t)insn.rel_target;
        }
        
        result.push_back(insn);
        offset += len;
    }
    
    return result;
}

// ============================================================
// Can virtualize/mutate checks
// ============================================================
bool Disassembler::canVirtualize(const DisasmInsn& insn) const {
    // These instruction types can be virtualized
    switch (insn.category) {
    case InsnCategory::MOV:
    case InsnCategory::MOVZX:
    case InsnCategory::MOVSX:
    case InsnCategory::LEA:
    case InsnCategory::ADD:
    case InsnCategory::SUB:
    case InsnCategory::XOR:
    case InsnCategory::AND:
    case InsnCategory::OR:
    case InsnCategory::NOT:
    case InsnCategory::NEG:
    case InsnCategory::SHL:
    case InsnCategory::SHR:
    case InsnCategory::SAR:
    case InsnCategory::ROL:
    case InsnCategory::ROR:
    case InsnCategory::CMP:
    case InsnCategory::TEST:
    case InsnCategory::PUSH:
    case InsnCategory::POP:
    case InsnCategory::INC:
    case InsnCategory::DEC:
    case InsnCategory::MUL:
    case InsnCategory::IMUL:
    case InsnCategory::JCC:
    case InsnCategory::JMP:
    case InsnCategory::CALL:
    case InsnCategory::RET:
        return true;
    default:
        return false;
    }
}

bool Disassembler::canMutate(const DisasmInsn& insn) const {
    switch (insn.category) {
    case InsnCategory::MOV:
    case InsnCategory::ADD:
    case InsnCategory::SUB:
    case InsnCategory::XOR:
    case InsnCategory::AND:
    case InsnCategory::OR:
    case InsnCategory::SHL:
    case InsnCategory::SHR:
    case InsnCategory::TEST:
        return true;
    default:
        return false;
    }
}

// Get instruction length without full decode
uint32_t Disassembler::getLength(const uint8_t* code, size_t max_len) {
    DisasmInsn insn;
    Disassembler dis;
    return dis.disassemble(code, max_len, insn);
}

} // namespace np


