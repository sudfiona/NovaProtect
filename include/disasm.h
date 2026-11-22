#pragma once
// NovaProtect x86-64 Disassembler
// Lightweight disassembler for instruction parsing (VM translation)
// Supports common x86-64 instruction encodings

#include <cstdint>
#include <vector>
#include <string>
#include <optional>

namespace np {

// x86-64 registers
enum class Reg : uint8_t {
    RAX=0, RCX, RDX, RBX, RSP, RBP, RSI, RDI,
    R8, R9, R10, R11, R12, R13, R14, R15,
    RIP,
    XMM0, XMM1, XMM2, XMM3, XMM4, XMM5, XMM6, XMM7,
    XMM8, XMM9, XMM10, XMM11, XMM12, XMM13, XMM14, XMM15,
    NONE = 0xFF
};

// Instruction prefix flags
enum PrefixFlags : uint32_t {
    PREFIX_NONE      = 0x0000,
    PREFIX_REX_W     = 0x0001,   // REX.W (64-bit operand)
    PREFIX_REX_R     = 0x0002,   // REX.R (extended reg)
    PREFIX_REX_X     = 0x0004,   // REX.X (extended index)
    PREFIX_REX_B     = 0x0008,   // REX.B (extended rm)
    PREFIX_66        = 0x0010,   // Operand size override
    PREFIX_67        = 0x0020,   // Address size override
    PREFIX_F2        = 0x0040,   // REPNE
    PREFIX_F3        = 0x0080,   // REP/REPE
    PREFIX_LOCK      = 0x0100,   // LOCK prefix
    PREFIX_ES        = 0x0200,
    PREFIX_CS        = 0x0400,
    PREFIX_SS        = 0x0800,
    PREFIX_DS        = 0x1000,
    PREFIX_FS        = 0x2000,
    PREFIX_GS        = 0x4000,
    PREFIX_0F        = 0x8000,   // Two-byte opcode (0x0F prefix)
    PREFIX_0F38      = 0x10000,
    PREFIX_0F3A      = 0x20000,
};

// Instruction categories (for mutation/VM translation)
enum class InsnCategory : uint8_t {
    Unknown,
    // Data movement
    MOV, MOVZX, MOVSX, LEA, XCHG, PUSH, POP,
    // Arithmetic
    ADD, SUB, MUL, IMUL, DIV, IDIV, INC, DEC, NEG,
    // Logic
    AND, OR, XOR, NOT, TEST, CMP,
    // Shift/Rotate
    SHL, SHR, SAR, ROL, ROR, RCL, RCR,
    // Control flow
    JMP, JCC, CALL, RET, LEAVE, ENTER,
    // Stack
    PUSHF, POPF, PUSH_IMM,
    // String ops
    MOVS, STOS, LODS, CMPS, SCAS,
    // Flags
    SETcc, CMOVcc,
    // System
    XADD, CPUID, RDTSC, SYSCALL, NOP,
    // SSE/AVX (treated as black box)
    SSE, AVX,
    SBB, ADC,
    // Marker instructions (SDK)
    MARKER,
    // Flag transfer and bit-test families (appended so existing values stay
    // stable - the diagnostic output prints these numbers).
    SAHF, LAHF, BT, CDQ, FLAGOP,
    // Coverage rounds 2026-11: the residual reject buckets. Appended like the
    // rows above so every existing numeric category keeps its value.
    X87,        // x87 escape D8-DF (translated through WIRE_X87)
    BITSCAN,    // 0F BC / 0F BD (bsf/bsr + F3 tzcnt/lzcnt)
    CMPXCHG,    // 0F B0 / 0F B1 / 0F C7 /6 /7
    UD2,        // 0F 0B
    SHLD,       // 0F A4 / A5 (shld) and 0F AC / AD (shrd)
};

// Operand types
enum class OperandType : uint8_t {
    None,
    Register,
    Immediate,
    Memory,          // [reg + disp]
    MemoryRegIndir,  // [reg]
    MemoryRIP,       // [rip + disp]
    FarAddress,
};

// Operand structure
struct Operand {
    OperandType type = OperandType::None;
    Reg reg = Reg::NONE;
    Reg base = Reg::NONE;       // for memory: base register
    Reg index = Reg::NONE;      // for memory: index register
    uint8_t scale = 1;          // for memory: scale (1,2,4,8)
    int64_t displacement = 0;   // for memory: displacement
    uint64_t immediate = 0;     // for immediate
    uint8_t size = 0;           // operand size in bytes (1,2,4,8)
};

// Parsed instruction
struct DisasmInsn {
    // Raw encoding
    std::vector<uint8_t> bytes;
    uint32_t length;
    uint32_t rva;
    
    // Decoded info
    InsnCategory category;
    uint32_t prefixes;          // prefix flags
    uint8_t opcode;             // primary opcode byte
    uint8_t opcode2;            // second opcode byte (for 0F XX)
    uint8_t modrm;              // modrm byte if present
    uint8_t sib;                // sib byte if present
    
    // Operands
    Operand dst;                // destination
    Operand src;                // source
    Operand extra;              // third operand (for some instructions)
    
    // Control flow
    int64_t rel_target;         // relative target offset
    uint32_t abs_target;        // absolute target (calls/jumps with direct address)
    uint8_t condition;          // condition code for JCC (0-15)
    
    // Metadata
    bool has_modrm;
    bool has_sib;
    bool has_displacement;
    bool has_immediate;
    bool writes_flags;
    bool reads_flags;
    bool is_privileged;
    bool can_mutate;            // safe to mutate
    
    // String representation (for debugging)
    std::string toString() const;
};

// Disassembler class
class Disassembler {
public:
    Disassembler() = default;
    
    // Disassemble a single instruction
    // Returns instruction length (0 if error)
    uint32_t disassemble(const uint8_t* code, size_t max_len, DisasmInsn& insn);
    
    // Disassemble a block of code
    std::vector<DisasmInsn> disassembleBlock(const uint8_t* code, size_t size, uint32_t base_rva);
    
    // Check if instruction can be safely virtualized
    bool canVirtualize(const DisasmInsn& insn) const;
    
    // Check if instruction can be mutated
    bool canMutate(const DisasmInsn& insn) const;
    
    // Get instruction length without full decode (for iteration)
    static uint32_t getLength(const uint8_t* code, size_t max_len);
    
private:
    // Prefix parsing
    uint32_t parsePrefixes(const uint8_t* code, size_t max_len, size_t& offset);
    
    // ModRM/SIB parsing
    bool parseModRM(const uint8_t* code, size_t max_len, size_t& offset,
                    DisasmInsn& insn, uint32_t prefixes);
    
    // Displacement/Immediate parsing
    bool parseDisplacement(const uint8_t* code, size_t max_len, size_t& offset,
                          DisasmInsn& insn, int disp_size);
    bool parseImmediate(const uint8_t* code, size_t max_len, size_t& offset,
                       DisasmInsn& insn, int imm_size);
    
    // Instruction categorization
    void categorizeInstruction(DisasmInsn& insn);
    void fixupOperands(DisasmInsn& insn);
    
public:
    static const char* categoryToString(InsnCategory cat);
    
private:
};

// Register utility functions
namespace reg_util {
    const char* regName(Reg r);
    uint8_t regSize(Reg r);
    Reg regFromIndex(uint8_t index, bool extended, bool is64);
    bool isGPR(Reg r);
    bool isXMM(Reg r);
}

} // namespace np




