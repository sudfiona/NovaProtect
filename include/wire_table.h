#pragma once
// NovaProtect —wire instruction table
// ===================================
// One row per logical wire opcode describing its encoded length and the kind of
// each operand slot. Three consumers depend on this single table:
//
//   * vm_obfuscate.cpp   - instruction lengths while walking / rebuilding the
//                          bytecode stream (junk insertion, flattening)
//   * vm_revirt.cpp      - register-operand rewriting when a stage is lifted
//                          into a second-level block with a permuted register
//                          file, and stage-boundary safety analysis
//   * tests              - a stream walker that verifies a produced program
//                          parses exactly, with no trailing bytes
//
// Keeping it in one place is what makes the new memory / 32-bit / rotate
// opcodes safe to add: a missing length in a second copy is precisely the kind
// of silent desync that corrupts a protected program.
//
// The runtime (runtime/prot64.c) cannot include this header - it is freestanding
// C compiled into a position-independent blob - so it carries its own decoders.
// The unit tests cross-check the two against each other through the shipped
// interpreter, which is why a mismatch fails the build instead of a shipped
// binary.

#include "vm_isa.h"
#include <cstdint>

namespace np {

// The packer/obfuscator remap `logical < WIRE_COUNT` into physical opcodes, so
// WIRE_COUNT has to be one past the highest defined opcode - the same bound as
// the kWireInfo row count. If these two drift apart the last opcode silently
// re-encodes as physical 0 and the stream dies there. This assertion is what
// keeps them together.
static_assert((int)WIRE_COUNT == (int)NP_WIRE_OPCODE_SLOTS,
              "WIRE_COUNT must equal NP_WIRE_OPCODE_SLOTS (one past the highest opcode)");


enum class WireOperandKind : uint8_t {
    None = 0,
    Reg,        // u8 VM register index (rewritable by a register permutation)
    Imm64,      // u64 immediate
    Imm32,      // u32 displacement
    Target32,   // u32 bytecode-relative branch target
    Index32,    // u32 guest-stage index (not a register, not a branch target)
    OpSel,      // u8 operation selector (NALU/XALU) - never a register
};

struct WireInfo {
    uint8_t len = 1;               // total encoded size, opcode byte included
    uint8_t nops = 0;              // operand slots
    WireOperandKind op[5] = { WireOperandKind::None, WireOperandKind::None,
                              WireOperandKind::None, WireOperandKind::None,
                              WireOperandKind::None };
};

// Row index is the logical opcode value. Entries left at {1,0,...} are
// one-byte no-operand instructions (HALT, ENDBR) or unassigned slots.
inline constexpr WireInfo kWireInfo[NP_WIRE_OPCODE_SLOTS] = {
    /* 0x00 unused      */ { 1, 0, {} },
    /* 0x01 LOADIMM    */ { 10, 2, { WireOperandKind::Reg, WireOperandKind::Imm64, WireOperandKind::None } },
    /* 0x02 LOADB      */ { 7, 3, { WireOperandKind::Reg, WireOperandKind::Reg, WireOperandKind::Imm32 } },
    /* 0x03 XOREQ      */ { 3, 2, { WireOperandKind::Reg, WireOperandKind::Reg, WireOperandKind::None } },
    /* 0x04 MULI       */ { 10, 2, { WireOperandKind::Reg, WireOperandKind::Imm64, WireOperandKind::None } },
    /* 0x05 ADDI       */ { 10, 2, { WireOperandKind::Reg, WireOperandKind::Imm64, WireOperandKind::None } },
    /* 0x06 SUBI       */ { 10, 2, { WireOperandKind::Reg, WireOperandKind::Imm64, WireOperandKind::None } },
    /* 0x07 ANDI       */ { 10, 2, { WireOperandKind::Reg, WireOperandKind::Imm64, WireOperandKind::None } },
    /* 0x08 RORI       */ { 10, 2, { WireOperandKind::Reg, WireOperandKind::Imm64, WireOperandKind::None } },
    /* 0x09 CMPI       */ { 10, 2, { WireOperandKind::Reg, WireOperandKind::Imm64, WireOperandKind::None } },
    /* 0x0A JE         */ { 5, 1, { WireOperandKind::Target32, WireOperandKind::None, WireOperandKind::None } },
    /* 0x0B JNE        */ { 5, 1, { WireOperandKind::Target32, WireOperandKind::None, WireOperandKind::None } },
    /* 0x0C JMP        */ { 5, 1, { WireOperandKind::Target32, WireOperandKind::None, WireOperandKind::None } },
    /* 0x0D MOVE       */ { 3, 2, { WireOperandKind::Reg, WireOperandKind::Reg, WireOperandKind::None } },
    /* 0x0E XORI       */ { 10, 2, { WireOperandKind::Reg, WireOperandKind::Imm64, WireOperandKind::None } },
    /* 0x0F HALT       */ { 1, 0, {} },
    /* 0x10 LOADQ      */ { 7, 3, { WireOperandKind::Reg, WireOperandKind::Reg, WireOperandKind::Imm32 } },
    /* 0x11 STOREB     */ { 7, 3, { WireOperandKind::Reg, WireOperandKind::Imm32, WireOperandKind::Reg } },
    /* 0x12 STOREQ     */ { 7, 3, { WireOperandKind::Reg, WireOperandKind::Imm32, WireOperandKind::Reg } },
    /* 0x13 ADD        */ { 3, 2, { WireOperandKind::Reg, WireOperandKind::Reg, WireOperandKind::None } },
    /* 0x14 SUB        */ { 3, 2, { WireOperandKind::Reg, WireOperandKind::Reg, WireOperandKind::None } },
    /* 0x15 MUL        */ { 3, 2, { WireOperandKind::Reg, WireOperandKind::Reg, WireOperandKind::None } },
    /* 0x16 AND        */ { 3, 2, { WireOperandKind::Reg, WireOperandKind::Reg, WireOperandKind::None } },
    /* 0x17 OR         */ { 3, 2, { WireOperandKind::Reg, WireOperandKind::Reg, WireOperandKind::None } },
    /* 0x18 XOR        */ { 3, 2, { WireOperandKind::Reg, WireOperandKind::Reg, WireOperandKind::None } },
    /* 0x19 SHL        */ { 3, 2, { WireOperandKind::Reg, WireOperandKind::Reg, WireOperandKind::None } },
    /* 0x1A SHR        */ { 3, 2, { WireOperandKind::Reg, WireOperandKind::Reg, WireOperandKind::None } },
    /* 0x1B SAR        */ { 3, 2, { WireOperandKind::Reg, WireOperandKind::Reg, WireOperandKind::None } },
    /* 0x1C SHRI       */ { 10, 2, { WireOperandKind::Reg, WireOperandKind::Imm64, WireOperandKind::None } },
    /* 0x1D ORI        */ { 10, 2, { WireOperandKind::Reg, WireOperandKind::Imm64, WireOperandKind::None } },
    /* 0x1E NOT        */ { 2, 1, { WireOperandKind::Reg, WireOperandKind::None, WireOperandKind::None } },
    /* 0x1F NEG        */ { 2, 1, { WireOperandKind::Reg, WireOperandKind::None, WireOperandKind::None } },
    /* 0x20 CMP        */ { 3, 2, { WireOperandKind::Reg, WireOperandKind::Reg, WireOperandKind::None } },
    /* 0x21 TEST       */ { 3, 2, { WireOperandKind::Reg, WireOperandKind::Reg, WireOperandKind::None } },
    /* 0x22 JNZ        */ { 5, 1, { WireOperandKind::Target32, WireOperandKind::None, WireOperandKind::None } },
    /* 0x23 JZ         */ { 5, 1, { WireOperandKind::Target32, WireOperandKind::None, WireOperandKind::None } },
    /* 0x24 JAE        */ { 5, 1, { WireOperandKind::Target32, WireOperandKind::None, WireOperandKind::None } },
    /* 0x25 JB         */ { 5, 1, { WireOperandKind::Target32, WireOperandKind::None, WireOperandKind::None } },
    /* 0x26 JGE        */ { 5, 1, { WireOperandKind::Target32, WireOperandKind::None, WireOperandKind::None } },
    /* 0x27 JL         */ { 5, 1, { WireOperandKind::Target32, WireOperandKind::None, WireOperandKind::None } },
    /* 0x28 JG         */ { 5, 1, { WireOperandKind::Target32, WireOperandKind::None, WireOperandKind::None } },
    /* 0x29 JLE        */ { 5, 1, { WireOperandKind::Target32, WireOperandKind::None, WireOperandKind::None } },
    /* 0x2A ENDBR      */ { 1, 0, {} },
    /* 0x2B SHLI       */ { 10, 2, { WireOperandKind::Reg, WireOperandKind::Imm64, WireOperandKind::None } },
    /* 0x2C SARI       */ { 10, 2, { WireOperandKind::Reg, WireOperandKind::Imm64, WireOperandKind::None } },
    /* 0x2D LOADW      */ { 7, 3, { WireOperandKind::Reg, WireOperandKind::Reg, WireOperandKind::Imm32 } },
    /* 0x2E LOADD      */ { 7, 3, { WireOperandKind::Reg, WireOperandKind::Reg, WireOperandKind::Imm32 } },
    /* 0x2F LOADSB     */ { 7, 3, { WireOperandKind::Reg, WireOperandKind::Reg, WireOperandKind::Imm32 } },
    /* 0x30 LOADSW     */ { 7, 3, { WireOperandKind::Reg, WireOperandKind::Reg, WireOperandKind::Imm32 } },
    /* 0x31 LOADSD     */ { 7, 3, { WireOperandKind::Reg, WireOperandKind::Reg, WireOperandKind::Imm32 } },
    /* 0x32 STOREW     */ { 7, 3, { WireOperandKind::Reg, WireOperandKind::Imm32, WireOperandKind::Reg } },
    /* 0x33 STORED     */ { 7, 3, { WireOperandKind::Reg, WireOperandKind::Imm32, WireOperandKind::Reg } },
    /* 0x34 ROL        */ { 3, 2, { WireOperandKind::Reg, WireOperandKind::Reg, WireOperandKind::None } },
    /* 0x35 ROR        */ { 3, 2, { WireOperandKind::Reg, WireOperandKind::Reg, WireOperandKind::None } },
    /* 0x36 ROLI       */ { 10, 2, { WireOperandKind::Reg, WireOperandKind::Imm64, WireOperandKind::None } },
    /* 0x37 ADDD       */ { 3, 2, { WireOperandKind::Reg, WireOperandKind::Reg, WireOperandKind::None } },
    /* 0x38 SUBD       */ { 3, 2, { WireOperandKind::Reg, WireOperandKind::Reg, WireOperandKind::None } },
    /* 0x39 ANDD       */ { 3, 2, { WireOperandKind::Reg, WireOperandKind::Reg, WireOperandKind::None } },
    /* 0x3A ORD        */ { 3, 2, { WireOperandKind::Reg, WireOperandKind::Reg, WireOperandKind::None } },
    /* 0x3B XORD       */ { 3, 2, { WireOperandKind::Reg, WireOperandKind::Reg, WireOperandKind::None } },
    /* 0x3C MULD       */ { 3, 2, { WireOperandKind::Reg, WireOperandKind::Reg, WireOperandKind::None } },
    /* 0x3D CMPD       */ { 3, 2, { WireOperandKind::Reg, WireOperandKind::Reg, WireOperandKind::None } },
    /* 0x3E TESTD      */ { 3, 2, { WireOperandKind::Reg, WireOperandKind::Reg, WireOperandKind::None } },
    /* 0x3F ADDID      */ { 10, 2, { WireOperandKind::Reg, WireOperandKind::Imm64, WireOperandKind::None } },
    /* 0x40 SUBID      */ { 10, 2, { WireOperandKind::Reg, WireOperandKind::Imm64, WireOperandKind::None } },
    /* 0x41 ANDID      */ { 10, 2, { WireOperandKind::Reg, WireOperandKind::Imm64, WireOperandKind::None } },
    /* 0x42 ORID       */ { 10, 2, { WireOperandKind::Reg, WireOperandKind::Imm64, WireOperandKind::None } },
    /* 0x43 XORID      */ { 10, 2, { WireOperandKind::Reg, WireOperandKind::Imm64, WireOperandKind::None } },
    /* 0x44 CMPID      */ { 10, 2, { WireOperandKind::Reg, WireOperandKind::Imm64, WireOperandKind::None } },
    /* 0x45 SHLID      */ { 10, 2, { WireOperandKind::Reg, WireOperandKind::Imm64, WireOperandKind::None } },
    /* 0x46 SHRID      */ { 10, 2, { WireOperandKind::Reg, WireOperandKind::Imm64, WireOperandKind::None } },
    /* 0x47 SARID      */ { 10, 2, { WireOperandKind::Reg, WireOperandKind::Imm64, WireOperandKind::None } },
    /* 0x48 NEGD       */ { 2, 1, { WireOperandKind::Reg, WireOperandKind::None, WireOperandKind::None } },
    /* 0x49 NOTD       */ { 2, 1, { WireOperandKind::Reg, WireOperandKind::None, WireOperandKind::None } },
    /* 0x4A MOVD       */ { 3, 2, { WireOperandKind::Reg, WireOperandKind::Reg, WireOperandKind::None } },
    /* 0x4B MOVZXB     */ { 3, 2, { WireOperandKind::Reg, WireOperandKind::Reg, WireOperandKind::None } },
    /* 0x4C MOVZXW     */ { 3, 2, { WireOperandKind::Reg, WireOperandKind::Reg, WireOperandKind::None } },
    /* 0x4D MOVSXB     */ { 3, 2, { WireOperandKind::Reg, WireOperandKind::Reg, WireOperandKind::None } },
    /* 0x4E MOVSXW     */ { 3, 2, { WireOperandKind::Reg, WireOperandKind::Reg, WireOperandKind::None } },
    /* 0x4F MOVSXD     */ { 3, 2, { WireOperandKind::Reg, WireOperandKind::Reg, WireOperandKind::None } },
    /* 0x50 GSTAGE     */ { 5, 1, { WireOperandKind::Index32, WireOperandKind::None, WireOperandKind::None } },
    /* 0x51 STAGEEND   */ { 1, 0, {} },
    /* 0x52 ADDRADD    */ { 3, 2, { WireOperandKind::Reg, WireOperandKind::Reg, WireOperandKind::None } },
    /* 0x53 ADDRADDI   */ { 10, 2, { WireOperandKind::Reg, WireOperandKind::Imm64, WireOperandKind::None } },
    /* 0x54 ADDRSHLI   */ { 10, 2, { WireOperandKind::Reg, WireOperandKind::Imm64, WireOperandKind::None } },
    /* 0x55 JA         */ { 5, 1, { WireOperandKind::Target32, WireOperandKind::None, WireOperandKind::None } },
    /* 0x56 JBE        */ { 5, 1, { WireOperandKind::Target32, WireOperandKind::None, WireOperandKind::None } },
    /* 0x57 JS         */ { 5, 1, { WireOperandKind::Target32, WireOperandKind::None, WireOperandKind::None } },
    /* 0x58 JNS        */ { 5, 1, { WireOperandKind::Target32, WireOperandKind::None, WireOperandKind::None } },
    /* 0x59 JO         */ { 5, 1, { WireOperandKind::Target32, WireOperandKind::None, WireOperandKind::None } },
    /* 0x5A JNO        */ { 5, 1, { WireOperandKind::Target32, WireOperandKind::None, WireOperandKind::None } },
    /* 0x5B JP         */ { 5, 1, { WireOperandKind::Target32, WireOperandKind::None, WireOperandKind::None } },
    /* 0x5C JNP        */ { 5, 1, { WireOperandKind::Target32, WireOperandKind::None, WireOperandKind::None } },
    /* 0x5D INSB       */ { 3, 2, { WireOperandKind::Reg, WireOperandKind::Reg, WireOperandKind::None } },
    /* 0x5E INSW       */ { 3, 2, { WireOperandKind::Reg, WireOperandKind::Reg, WireOperandKind::None } },
    /* 0x5F EXITJMP    */ { 5, 1, { WireOperandKind::Index32, WireOperandKind::None, WireOperandKind::None } },
    /* 0x60 CALL       */ { 5, 1, { WireOperandKind::Index32, WireOperandKind::None, WireOperandKind::None } },
    /* 0x61 IMGADD     */ { 6, 2, { WireOperandKind::Reg, WireOperandKind::Index32, WireOperandKind::None } },
    /* 0x62 CMPB       */ { 3, 2, { WireOperandKind::Reg, WireOperandKind::Reg, WireOperandKind::None } },
    /* 0x63 CMPW       */ { 3, 2, { WireOperandKind::Reg, WireOperandKind::Reg, WireOperandKind::None } },
    /* 0x64 TESTB      */ { 3, 2, { WireOperandKind::Reg, WireOperandKind::Reg, WireOperandKind::None } },
    /* 0x65 TESTW      */ { 3, 2, { WireOperandKind::Reg, WireOperandKind::Reg, WireOperandKind::None } },
    /* 0x66 XLOAD      */ { 7, 3, { WireOperandKind::Reg, WireOperandKind::Reg, WireOperandKind::Imm32 } },
    /* 0x67 XSTORE     */ { 7, 3, { WireOperandKind::Reg, WireOperandKind::Imm32, WireOperandKind::Reg } },
    /* 0x68 XMOV       */ { 3, 2, { WireOperandKind::Reg, WireOperandKind::Reg, WireOperandKind::None } },
    /* 0x69 XLOADQ     */ { 7, 3, { WireOperandKind::Reg, WireOperandKind::Reg, WireOperandKind::Imm32 } },
    /* 0x6A XSTOREQ    */ { 7, 3, { WireOperandKind::Reg, WireOperandKind::Imm32, WireOperandKind::Reg } },
    /* 0x6B XLOADD     */ { 3, 2, { WireOperandKind::Reg, WireOperandKind::Reg, WireOperandKind::None } },
    /* 0x6C XSTORED    */ { 3, 2, { WireOperandKind::Reg, WireOperandKind::Reg, WireOperandKind::None } },
    /* 0x6D XZERO      */ { 2, 1, { WireOperandKind::Reg, WireOperandKind::None, WireOperandKind::None } },
    /* 0x6E XXOR       */ { 3, 2, { WireOperandKind::Reg, WireOperandKind::Reg, WireOperandKind::None } },
    /* 0x6F SBB        */ { 3, 2, { WireOperandKind::Reg, WireOperandKind::Reg, WireOperandKind::None } },
    /* 0x70 SBBI       */ { 10, 2, { WireOperandKind::Reg, WireOperandKind::Imm64, WireOperandKind::None } },
    /* 0x71 ADC        */ { 3, 2, { WireOperandKind::Reg, WireOperandKind::Reg, WireOperandKind::None } },
    /* 0x72 ADCI       */ { 10, 2, { WireOperandKind::Reg, WireOperandKind::Imm64, WireOperandKind::None } },
    /* 0x73 SBBD       */ { 3, 2, { WireOperandKind::Reg, WireOperandKind::Reg, WireOperandKind::None } },
    /* 0x74 ADCD       */ { 3, 2, { WireOperandKind::Reg, WireOperandKind::Reg, WireOperandKind::None } },
    /* 0x75 XUNPCKL    */ { 3, 2, { WireOperandKind::Reg, WireOperandKind::Reg, WireOperandKind::None } },
    /* 0x76 XMOUNTH    */ { 3, 2, { WireOperandKind::Reg, WireOperandKind::Reg, WireOperandKind::None } },
    /* 0x77 XMOVHL     */ { 3, 2, { WireOperandKind::Reg, WireOperandKind::Reg, WireOperandKind::None } },
    /* 0x78 NALU       */ { 4, 3, { WireOperandKind::OpSel, WireOperandKind::Reg, WireOperandKind::Reg } },
    /* 0x79 XALU       */ { 5, 4, { WireOperandKind::OpSel, WireOperandKind::OpSel, WireOperandKind::Reg, WireOperandKind::Reg } },
    /* 0x7A XALUI      */ { 6, 5, { WireOperandKind::OpSel, WireOperandKind::OpSel, WireOperandKind::Reg, WireOperandKind::Reg, WireOperandKind::Imm32 } },
    /* 0x7B SAHF       */ { 2, 1, { WireOperandKind::Reg, WireOperandKind::None, WireOperandKind::None } },
    /* 0x7C LAHF       */ { 2, 1, { WireOperandKind::Reg, WireOperandKind::None, WireOperandKind::None } },
    /* 0x7D MULQ       */ { 5, 4, { WireOperandKind::OpSel, WireOperandKind::Reg, WireOperandKind::Reg, WireOperandKind::Reg } },
    /* 0x7E DIVQ       */ { 4, 3, { WireOperandKind::Reg, WireOperandKind::Reg, WireOperandKind::Reg } },
    /* 0x7F IDIVQ      */ { 4, 3, { WireOperandKind::Reg, WireOperandKind::Reg, WireOperandKind::Reg } },
    /* 0x80 SETCF      */ { 2, 1, { WireOperandKind::Reg, WireOperandKind::None, WireOperandKind::None } },
    /* 0x81 BITOP      */ { 4, 3, { WireOperandKind::OpSel, WireOperandKind::Reg, WireOperandKind::Reg } },
    /* 0x82 ADDRSHRI   */ { 10, 2, { WireOperandKind::Reg, WireOperandKind::Imm64, WireOperandKind::None } },
    /* 0x83 BITSCAN    */ { 4, 3, { WireOperandKind::OpSel, WireOperandKind::Reg, WireOperandKind::Reg } },
    /* 0x84 X87        */ { 4, 3, { WireOperandKind::OpSel, WireOperandKind::OpSel, WireOperandKind::Reg } },
    /* 0x85 STR        */ { 6, 5, { WireOperandKind::OpSel, WireOperandKind::Reg, WireOperandKind::Reg, WireOperandKind::Reg, WireOperandKind::Reg } },
    /* 0x86 CMPXCHG    */ { 5, 4, { WireOperandKind::OpSel, WireOperandKind::Reg, WireOperandKind::Reg, WireOperandKind::Reg } },
    /* 0x87 CPUID      */ { 5, 4, { WireOperandKind::Reg, WireOperandKind::Reg, WireOperandKind::Reg, WireOperandKind::Reg } },
    /* 0x88 RDTSC      */ { 3, 2, { WireOperandKind::Reg, WireOperandKind::Reg, WireOperandKind::None } },
    /* 0x89 UD2        */ { 1, 0, {} },
    /* 0x8A RDRAND     */ { 3, 2, { WireOperandKind::OpSel, WireOperandKind::Reg, WireOperandKind::None } },
    /* 0x8B SETDF      */ { 2, 1, { WireOperandKind::OpSel, WireOperandKind::None, WireOperandKind::None } },
    /* 0x8C SHLD       */ { 5, 4, { WireOperandKind::OpSel, WireOperandKind::Reg, WireOperandKind::Reg, WireOperandKind::Reg } },
    /* 0x8D PUSHF      */ { 2, 1, { WireOperandKind::Reg, WireOperandKind::None, WireOperandKind::None } },
    /* 0x8E POPF       */ { 2, 1, { WireOperandKind::Reg, WireOperandKind::None, WireOperandKind::None } },
    /* 0x8F MULB       */ { 4, 3, { WireOperandKind::OpSel, WireOperandKind::Reg, WireOperandKind::Reg } },
    /* 0x90 DIVB       */ { 4, 3, { WireOperandKind::OpSel, WireOperandKind::Reg, WireOperandKind::Reg } },
};

// Encoded size of one instruction, or 0 when the opcode byte is not a defined
// logical opcode (the translator never emits those, but a corrupted stream or a
// bad reverse table can produce one - callers must treat 0 as a hard stop).
inline uint32_t wireInsnLength(uint8_t logical) {
    if (logical >= NP_WIRE_OPCODE_SLOTS) return 0;
    const WireInfo& w = kWireInfo[logical];
    return w.len ? w.len : 0;
}

// True when `logical` is a branch that carries a bytecode-relative target.
inline bool wireIsBranchOp(uint8_t logical) {
    switch (logical) {
    case WIRE_JE: case WIRE_JNE: case WIRE_JMP: case WIRE_JNZ: case WIRE_JZ:
    case WIRE_JAE: case WIRE_JB: case WIRE_JGE: case WIRE_JL: case WIRE_JG:
    case WIRE_JLE: case WIRE_JA: case WIRE_JBE: case WIRE_JS: case WIRE_JNS:
    case WIRE_JO: case WIRE_JNO: case WIRE_JP: case WIRE_JNP:
        return true;
    default:
        return false;
    }
}

// True when the instruction reads the flag state produced by an earlier
// comparison. Nothing may be inserted between the producer and these.
// NALU is listed because its ADC/SBB forms consume cf; the helper only sees the
// opcode byte, so it has to be conservative for the whole family.
inline bool wireReadsFlags(uint8_t logical) {
    return wireIsBranchOp(logical) || logical == WIRE_NALU || logical == WIRE_SBB ||
           logical == WIRE_SBBI || logical == WIRE_ADC || logical == WIRE_ADCI ||
           logical == WIRE_SBBD || logical == WIRE_ADCD || logical == WIRE_LAHF;
}

// True when the instruction leaves a defined zf/sf/cf/of behind.
inline bool wireWritesFlags(uint8_t logical) {
    switch (logical) {
    case WIRE_CMPI: case WIRE_CMP: case WIRE_TEST:
    case WIRE_ADD: case WIRE_SUB: case WIRE_AND: case WIRE_OR:
    case WIRE_XOR: case WIRE_SHL: case WIRE_SHR: case WIRE_SAR:
    case WIRE_NEG:
    case WIRE_ADDI: case WIRE_SUBI: case WIRE_ANDI: case WIRE_ORI:
    case WIRE_XORI: case WIRE_SHRI: case WIRE_SHLI: case WIRE_SARI:
    // 32-bit forms compute their flags on the low half; they still clobber
    // the shared flag state, so junk insertion must treat them as producers.
    case WIRE_ROL: case WIRE_ROR: case WIRE_ROLI:
    case WIRE_ADDD: case WIRE_SUBD: case WIRE_ANDD: case WIRE_ORD:
    case WIRE_XORD: case WIRE_CMPD: case WIRE_TESTD:
    case WIRE_ADDID: case WIRE_SUBID: case WIRE_ANDID: case WIRE_ORID:
    case WIRE_XORID: case WIRE_CMPID: case WIRE_SHLID: case WIRE_SHRID:
    case WIRE_SARID: case WIRE_NEGD:
    case WIRE_CMPB: case WIRE_CMPW: case WIRE_TESTB: case WIRE_TESTW:
    case WIRE_SBB: case WIRE_SBBI: case WIRE_ADC: case WIRE_ADCI:
    case WIRE_SBBD: case WIRE_ADCD: case WIRE_SAHF: case WIRE_MULQ:
    case WIRE_DIVQ: case WIRE_IDIVQ: case WIRE_SETCF:
        return true;
    // NALU's NOT form leaves flags alone, but the selector byte is not visible
    // here; treat the family as a producer so junk is never inserted between a
    // comparison and a branch it feeds.
    case WIRE_NALU:
        return true;
    // XALU compares write the integer flags; the selector is not visible here
    // either, so the whole family is a producer.
    case WIRE_XALU: case WIRE_XALUI:
        return true;
    // Coverage-round opcodes: BITSCAN writes zf (and cf for tzcnt/lzcnt),
    // CMPXCHG writes the subtraction flags, RDRAND sets cf and clears the
    // rest, STR's cmps/scas forms write the comparison flags (the selector is
    // not visible here, so the family counts as a producer), and X87's
    // fucomi/fcomip write the integer flags.
    case WIRE_BITSCAN: case WIRE_CMPXCHG: case WIRE_RDRAND:
    case WIRE_STR: case WIRE_X87: case WIRE_SHLD:
    case WIRE_POPF: case WIRE_MULB: case WIRE_DIVB:
        return true;
    // ADDRADD/ADDRADDI/ADDRSHLI are deliberately absent: they exist so address
    // arithmetic can happen without disturbing a pending comparison.
    default:
        return false;
    }
}

// True when the destination register slot is written (for liveness tracking).
inline bool wireWritesReg(uint8_t logical) {
    switch (logical) {
    case WIRE_LOADIMM: case WIRE_LOADB: case WIRE_LOADQ:
    case WIRE_LOADW: case WIRE_LOADD: case WIRE_LOADSB:
    case WIRE_LOADSW: case WIRE_LOADSD:
    case WIRE_MOVE: case WIRE_MOVD: case WIRE_MOVZXB: case WIRE_MOVZXW:
    case WIRE_MOVSXB: case WIRE_MOVSXW: case WIRE_MOVSXD:
    case WIRE_XOREQ:
    case WIRE_ADD: case WIRE_SUB: case WIRE_MUL: case WIRE_AND:
    case WIRE_OR: case WIRE_XOR: case WIRE_SHL: case WIRE_SHR:
    case WIRE_SAR: case WIRE_ROL: case WIRE_ROR:
    case WIRE_NOT: case WIRE_NEG:
    case WIRE_MULI: case WIRE_ADDI: case WIRE_SUBI: case WIRE_ANDI:
    case WIRE_ORI: case WIRE_XORI: case WIRE_SHRI: case WIRE_SHLI:
    case WIRE_SARI: case WIRE_RORI: case WIRE_ROLI:
    case WIRE_ADDD: case WIRE_SUBD: case WIRE_ANDD: case WIRE_ORD:
    case WIRE_XORD: case WIRE_MULD:
    case WIRE_ADDID: case WIRE_SUBID: case WIRE_ANDID: case WIRE_ORID:
    case WIRE_XORID: case WIRE_SHLID: case WIRE_SHRID: case WIRE_SARID:
    case WIRE_NEGD: case WIRE_NOTD:
    case WIRE_ADDRADD: case WIRE_ADDRADDI: case WIRE_ADDRSHLI:
    case WIRE_SBB: case WIRE_SBBI: case WIRE_ADC: case WIRE_ADCI:
    case WIRE_SBBD: case WIRE_ADCD:
    case WIRE_INSB: case WIRE_INSW:
    // NALU / XALU / XALUI write their dst slot; the unary forms share the same
    // encoding so a single entry covers the family. LAHF writes dst. MULQ /
    // DIVQ / IDIVQ write both members of the (lo,hi) pair - counted once here
    // because the helper only answers "does this opcode write a register".
    case WIRE_NALU: case WIRE_XALU: case WIRE_XALUI: case WIRE_LAHF:
    case WIRE_MULQ: case WIRE_DIVQ: case WIRE_IDIVQ:
        return true;
    // Coverage-round opcodes that write register slots: BITSCAN (dst),
    // STR (lods writes acc; the family counts as a writer), CMPXCHG (acc is
    // rewritten on mismatch), CPUID (all four), RDTSC (lo/hi), RDRAND (dst),
    // X87 (FNSTSW writes the acc slot through `ea`).
    case WIRE_BITSCAN: case WIRE_STR: case WIRE_CMPXCHG: case WIRE_CPUID:
    case WIRE_RDTSC: case WIRE_RDRAND: case WIRE_X87: case WIRE_SHLD:
    case WIRE_PUSHF: case WIRE_POPF: case WIRE_MULB: case WIRE_DIVB:
        return true;
    default:
        return false;
    }
}

} // namespace np
