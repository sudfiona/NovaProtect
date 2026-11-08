#pragma once
// NovaProtect VM Instruction Set Architecture
// =========================================
// Two layers live in this header:
//
//   * the *wire* ISA   - the concrete opcodes understood by the runtime
//                        interpreter (runtime/prot64.c: np_vm_run).  These
//                        constants are the single source of truth and must
//                        stay in sync with that interpreter.
//   * the *guest* view - the register file / helper classes used by the
//                        packer when lowering x86-64 code into wire bytecode.
//
// Wire encoding (all little endian, no alignment padding):
//
//   [phys_op]                one byte = opcode_mapping[logical_op]
//   operands depend on op, see the WireOp enum below.
//
// The interpreter translates physical bytes back to logical ops through a
// 256-entry `reverse` table so every build can use a distinct opcode mapping.

#include <cstdint>
#include <vector>
#include <unordered_map>
#include <string>

namespace np {

// ============================================================
// Wire ISA - opcodes understood by runtime/prot64.c
// ============================================================
enum WireOp : uint8_t {
    WIRE_LOADIMM = 0x01,  // reg u8, imm u64
    WIRE_LOADB   = 0x02,  // reg u8, base u8, disp u32   -> zero-extended byte
    WIRE_XOREQ   = 0x03,  // dst u8, src u8
    WIRE_MULI    = 0x04,  // reg u8, imm u64
    WIRE_ADDI    = 0x05,  // reg u8, imm u64
    WIRE_SUBI    = 0x06,  // reg u8, imm u64
    WIRE_ANDI    = 0x07,  // reg u8, imm u64
    WIRE_RORI    = 0x08,  // reg u8, imm u64
    WIRE_CMPI    = 0x09,  // reg u8, imm u64   -> sets flags
    WIRE_JE      = 0x0A,  // target u32 (jump if zf)
    WIRE_JNE     = 0x0B,  // target u32 (jump if !zf)
    WIRE_JMP     = 0x0C,  // target u32
    WIRE_MOVE    = 0x0D,  // dst u8, src u8
    WIRE_XORI    = 0x0E,  // reg u8, imm u64
    WIRE_HALT    = 0x0F,
    WIRE_LOADQ   = 0x10,  // reg u8, base u8, disp u32
    WIRE_STOREB  = 0x11,  // base u8, disp u32, src u8
    WIRE_STOREQ  = 0x12,  // base u8, disp u32, src u8
    WIRE_ADD     = 0x13,  // dst u8, src u8
    WIRE_SUB     = 0x14,  // dst u8, src u8
    WIRE_MUL     = 0x15,  // dst u8, src u8
    WIRE_AND     = 0x16,  // dst u8, src u8
    WIRE_OR      = 0x17,  // dst u8, src u8
    WIRE_XOR     = 0x18,  // dst u8, src u8
    WIRE_SHL     = 0x19,  // dst u8, src u8
    WIRE_SHR     = 0x1A,  // dst u8, src u8 (logical)
    WIRE_SAR     = 0x1B,  // dst u8, src u8 (arithmetic)
    WIRE_SHRI    = 0x1C,  // reg u8, imm u64
    WIRE_ORI     = 0x1D,  // reg u8, imm u64
    WIRE_NOT     = 0x1E,  // reg u8
    WIRE_NEG     = 0x1F,  // reg u8
    WIRE_CMP     = 0x20,  // a u8, b u8  -> sets zf/sf/cf/of
    WIRE_TEST    = 0x21,  // a u8, b u8  -> sets zf/sf
    WIRE_JNZ     = 0x22,  // target u32 (jump if !zf)
    WIRE_JZ      = 0x23,  // target u32 (jump if zf)
    WIRE_JAE     = 0x24,  // target u32 (jump if !cf)
    WIRE_JB      = 0x25,  // target u32 (jump if cf)
    WIRE_JGE     = 0x26,  // target u32 (jump if sf==of)
    WIRE_JL      = 0x27,  // target u32 (jump if sf!=of)
    WIRE_JG      = 0x28,  // target u32 (jump if !zf && sf==of)
    WIRE_JLE     = 0x29,  // target u32 (jump if zf || sf!=of)
    WIRE_ENDBR   = 0x2A,  // region boundary marker (no-op)
    WIRE_SHLI    = 0x2B,  // reg u8, imm u64 (shift left)
    WIRE_SARI    = 0x2C,  // reg u8, imm u64 (shift right arithmetic)

    // ---- memory-operand micro-ops (macro-instruction expansion) --------
    // The original ISA could only move whole qwords through [base+disp32],
    // which forced the translator to abandon every region that touched a
    // byte/word/dword field. These six loads and two stores close that gap;
    // the sign-extending loads are what movsx/movsxd from memory need.
    WIRE_LOADW   = 0x2D,  // reg u8, base u8, disp u32 -> zero-extended u16
    WIRE_LOADD   = 0x2E,  // reg u8, base u8, disp u32 -> zero-extended u32
    WIRE_LOADSB  = 0x2F,  // reg u8, base u8, disp u32 -> sign-extended i8
    WIRE_LOADSW  = 0x30,  // reg u8, base u8, disp u32 -> sign-extended i16
    WIRE_LOADSD  = 0x31,  // reg u8, base u8, disp u32 -> sign-extended i32
    WIRE_STOREW  = 0x32,  // base u8, disp u32, src u8
    WIRE_STORED  = 0x33,  // base u8, disp u32, src u8

    // ---- rotates (ROL/ROR were missing entirely) -----------------------
    WIRE_ROL     = 0x34,  // dst u8, src u8
    WIRE_ROR     = 0x35,  // dst u8, src u8
    WIRE_ROLI    = 0x36,  // reg u8, imm u64

    // ---- 32-bit operand forms ------------------------------------------
    // In a 64-bit stream `add eax, ecx` zero-extends the result and computes
    // its flags on 32 bits. Widening it to the 64-bit op would silently change
    // both, which is why these used to terminate translation. The *D opcodes
    // reproduce the truncation and the 32-bit flag arithmetic exactly.
    WIRE_ADDD    = 0x37,  // dst u8, src u8
    WIRE_SUBD    = 0x38,
    WIRE_ANDD    = 0x39,
    WIRE_ORD     = 0x3A,
    WIRE_XORD    = 0x3B,
    WIRE_MULD    = 0x3C,
    WIRE_CMPD    = 0x3D,  // a u8, b u8 -> 32-bit flags
    WIRE_TESTD   = 0x3E,  // a u8, b u8 -> 32-bit flags
    WIRE_ADDID   = 0x3F,  // reg u8, imm u64
    WIRE_SUBID   = 0x40,
    WIRE_ANDID   = 0x41,
    WIRE_ORID    = 0x42,
    WIRE_XORID   = 0x43,
    WIRE_CMPID   = 0x44,
    WIRE_SHLID   = 0x45,
    WIRE_SHRID   = 0x46,
    WIRE_SARID   = 0x47,
    WIRE_NEGD    = 0x48,  // reg u8
    WIRE_NOTD    = 0x49,  // reg u8

    // ---- explicit-width register moves ---------------------------------
    WIRE_MOVD    = 0x4A,  // dst u8, src u8  (dst = zero-extended low 32)
    WIRE_MOVZXB  = 0x4B,  // dst u8, src u8
    WIRE_MOVZXW  = 0x4C,
    WIRE_MOVSXB  = 0x4D,
    WIRE_MOVSXW  = 0x4E,
    WIRE_MOVSXD  = 0x4F,

    // ---- secondary virtual machine (revirtualization) -------------------
    // Hands the guest interpreter one straight-line block that is stored and
    // decoded with its own key, opcode permutation and register permutation.
    // See include/vm_revirt.h for the descriptor layout.
    WIRE_GSTAGE  = 0x50,  // desc_index u32

    // Emitted as the last instruction of every outer stage except the final
    // one: "continue at the first instruction of the next stage". The final
    // stage uses WIRE_HALT instead, so a caller that ignores stages still sees
    // a well-formed program.
    WIRE_STAGEEND = 0x51, // no operands

    // ---- flag-preserving address arithmetic ------------------------------
    // Lowering a memory operand needs scratch registers, and builder-provided
    // ADD/ADDI clobber cf/of/zf/sf. That is wrong whenever the original
    // instruction was flag-transparent: `cmp a, b` / `mov [rdi], rax` / `jne`
    // must still branch on the cmp, but the address build would have replaced
    // the flags with the result of the pointer sum. Emitting a flag save and
    // restore around every memory operand instead would add two instructions
    // and twelve bytes per access, so the address arithmetic itself is what
    // moves: these two are exactly LEA's semantics.
    //
    // LEA needs them for a second reason - it is architecturally forbidden from
    // touching the flags, so it could not be translated at all without them.
    WIRE_ADDRADD  = 0x52, // d = a + b, flags untouched
    WIRE_ADDRADDI = 0x53, // d = d + imm64, flags untouched
    // Scaling a scaled index needs a shift, and the ordinary SHLI writes
    // zf/sf - which would put the flag corruption straight back. This is the
    // flag-free form, so an in-flight comparison survives index*scale too.
    WIRE_ADDRSHLI = 0x54, // d = d << imm64, flags untouched

    WIRE_COUNT   = 0x55,
};

// Highest logical opcode value the mapper permutes.
#define NP_WIRE_OPCODE_SLOTS 0x55

// ============================================================
// Guest register file (virtual registers seen by the translator)
// ============================================================
enum VMReg : uint8_t {
    VM_R0, VM_R1, VM_R2, VM_R3,
    VM_R4, VM_R5, VM_R6, VM_R7,
    VM_R8, VM_R9, VM_R10, VM_R11,
    VM_R12, VM_R13, VM_R14, VM_R15,
    VM_COUNT
};

#define NP_VM_REGS 16

// ============================================================
// Randomized opcode mapping
// ============================================================
class VMOpcodeMapper {
public:
    VMOpcodeMapper() { generateMapping(); }

    uint8_t encode(uint8_t logical) const {
        if (logical >= NP_WIRE_OPCODE_SLOTS) return logical;
        return mapping_[logical];
    }
    uint8_t decode(uint8_t byte) const { return reverse_[byte]; }

    void generateMapping();
    void generateMapping(uint64_t seed);

    // Build a 256-byte reverse table compatible with np_vm_run.
    std::vector<uint8_t> reverseTable() const {
        return std::vector<uint8_t>(reverse_, reverse_ + 256);
    }

    const uint8_t* mapping() const { return mapping_; }

private:
    uint8_t mapping_[NP_WIRE_OPCODE_SLOTS] = {0};
    uint8_t reverse_[256] = {0};
};

// ============================================================
// Lowering result produced by VMTranslator
// ============================================================
struct VMLoweredBlock {
    bool ok = false;                 // whole input covered by virtualized code
    std::vector<uint8_t> bytecode;   // wire bytecode
    std::vector<uint8_t> reverse;    // 256-byte reverse table
    uint8_t guestReg[16] = {0};      // guest GPR index -> VM register
    uint8_t vmSp = 15;               // VM register used as a guest stack pointer
    uint32_t insnsTranslated = 0;
    uint32_t insnsSkipped = 0;
    std::string skipReason;
};

// ============================================================
// x86-64 -> VM bytecode translator
// ============================================================
class VMTranslator {
public:
    // Translate a straight-line (or internally-branching) x86-64 block.
    //
    //   code        raw x86 bytes starting at the guest entry
    //   size        number of bytes available
    //   guestRip    guest virtual address of the first byte
    //   imageBase   guest image base (for absolute/RIP-relative rewrites)
    //   complexity  1..10, controls extra obfuscation (opaque nops, padding)
    //   mutationLevel 0..3, reserved for mutation cooperation
    //   target64    true for x64 images.  The wire VM is a 64-bit
    //               machine, so in a 64-bit stream a non-REX.W (32-bit)
    //               register-writing or flag-affecting form cannot be
    //               reproduced faithfully -- zero-extension of the upper
    //               half and 32-bit carry/sign flags differ -- and
    //               terminates translation (the packer then keeps the
    //               region native).  In a 32-bit image every instruction
    //               is 32-bit by definition, so callers pass false.
    static VMLoweredBlock translate(const uint8_t* code, size_t size,
                             uint64_t guestRip, uint64_t imageBase,
                             uint8_t complexity = 5,
                             uint8_t mutationLevel = 1,
                             bool target64 = true,
                             uint64_t seed = 0);
};

// ============================================================
// Bytecode generator (low-level emit helpers; used by translator)
// ============================================================
// ============================================================
// Post-translation obfuscation (vm_obfuscate.cpp)
// ============================================================

// Applies dead-register junk emission and (for straight-line code)
// control-flow flattening to a translated wire bytecode stream.
// `reverse` is the 256-entry physical->logical opcode table used by the
// interpreter; `mapping` is the logical->physical table used to re-encode.
std::vector<uint8_t> vmObfuscate(const std::vector<uint8_t>& bc,
                                  const uint8_t* reverse,
                                  const uint8_t* mapping,
                                  uint32_t reg_mask,
                                  uint8_t complexity);
class VMBytecodeGenerator {
public:
    VMBytecodeGenerator();

    std::vector<uint8_t> generate(const std::vector<uint8_t>& x86_code,
                                  uint32_t code_rva,
                                  uint8_t complexity = 5,
                                  uint8_t mutation_level = 1);

    // Wire-level emitters.
    void emitOp(uint8_t logical);
    void emitByte(uint8_t b);
    void emitDword(uint32_t d);
    void emitQword(uint64_t q);

    void emitLoadImm(uint8_t reg, uint64_t value);
    void emitLoadReg(uint8_t dst, uint8_t src);
    void emitMemLoad(uint8_t dst, uint8_t base, uint32_t disp);
    void emitMemStore(uint8_t base, uint32_t disp, uint8_t src);
    void emitArith(uint8_t wireOp, uint8_t dst, uint8_t src);
    void emitArithImm(uint8_t wireOp, uint8_t dst, uint64_t imm);
    void emitCmp(uint8_t a, uint8_t b);
    void emitTest(uint8_t a, uint8_t b);
    void emitJmp(uint32_t target);
    void emitJcc(uint8_t wireOp, uint32_t target);
    void emitPush(uint8_t reg);
    void emitPop(uint8_t reg);
    void emitHalt();
    void emitEnter();
    void emitLeave();

    const std::vector<uint8_t>& bytecode() const { return output_; }
    const VMOpcodeMapper& mapper() const { return mapper_; }
    void setMapper(const VMOpcodeMapper& m) { mapper_ = m; }
    size_t instructionCount() const { return instrCount_; }

private:
    void padForAlignment();

    VMOpcodeMapper mapper_;
    std::vector<uint8_t> output_;
    size_t instrCount_ = 0;
};

} // namespace np