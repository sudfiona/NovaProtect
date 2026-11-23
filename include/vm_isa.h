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

    // ---- unsigned / signed / overflow conditional branches -----------------
    // The original branch set covered only jz/jnz/jae/jb and the four signed
    // orders. `ja`/`jbe` need both carry and zero, and `js`/`jns`/`jo`/`jno`
    // need sf/of which the flag file already carries - these six close the
    // condition-code gap so the translator no longer has to approximate (or,
    // worse, silently invert) those branches.
    WIRE_JA      = 0x55, // target u32 (jump if !cf && !zf)
    WIRE_JBE     = 0x56, // target u32 (jump if cf || zf)
    WIRE_JS      = 0x57, // target u32 (jump if sf)
    WIRE_JNS     = 0x58, // target u32 (jump if !sf)
    WIRE_JO      = 0x59, // target u32 (jump if of)
    WIRE_JNO     = 0x5A, // target u32 (jump if !of)
    // Parity pair: the runtime now carries pf (even parity of the result's
    // low byte), so jp/jnp no longer have to be rejected.
    WIRE_JP      = 0x5B, // target u32 (jump if pf)
    WIRE_JNP     = 0x5C, // target u32 (jump if !pf)

    // ---- partial-register inserts + native exits --------------------------
    // The register file has no partial-register access: writing AL must keep
    // RAX's high 56 bits. INSB/INSW splice a byte/word into the low end of a
    // register and leave the rest untouched, which is what makes the 8/16-bit
    // mov forms translatable.
    //   INSB dst u8, src u8   -> r[d] = (r[d] & ~0xFF) | (r[s] & 0xFF)
    //   INSW dst u8, src u8   -> r[d] = (r[d] & ~0xFFFF) | (r[s] & 0xFFFF)
    WIRE_INSB    = 0x5D, // dst u8, src u8
    WIRE_INSW    = 0x5E, // dst u8, src u8

    // EXITJMP leaves the VM and continues natively at an address inside the
    // image. It is how a virtualized function body hands control back to a
    // native epilogue (leave/ret), a tail jmp, or any other code that must run
    // with the real registers. The operand is an image *RVA*, not a bytecode
    // offset: the handler re-adds the runtime image base. Value 0 means
    // "leave through the region's normal exit" (fall through to region end).
    //   EXITJMP target_rva u32
    WIRE_EXITJMP = 0x5F, // target_rva u32

    // CALL performs a real x86-64 call from inside the interpreter. The
    // callee runs on the interpreter's own stack (never the guest stack, which
    // the trampoline owns) with the guest's register values loaded per the ABI
    // convention; stack arguments are copied from the guest frame. The operand
    // is an image RVA of the target, re-based at run time like EXITJMP.
    //   CALL target_rva u32
    WIRE_CALL    = 0x60, // target_rva u32

    // IMGADD re-bases an image RVA at run time: r[d] = imgBase + rva. It is
    // how RIP-relative addressing survives virtualization - the operand is
    // position independent (an RVA), and the handler adds the load address
    // the trampoline parked in the control slots. LEA/mov through [rip+disp]
    // lower to IMGADD plus the ordinary load/store micro-ops.
    //   IMGADD dst u8, rva u32
    WIRE_IMGADD  = 0x61, // dst u8, rva u32

    // Narrow compares: the flag file is computed at byte/word width, which is
    // what `cmp al, bl` / `test ax, 1` need. A wide CMP would hand the next
    // branch a stale sign/overflow from the high bits.
    WIRE_CMPB    = 0x62, // a u8, b u8 -> 8-bit flags
    WIRE_CMPW    = 0x63, // a u8, b u8 -> 16-bit flags
    WIRE_TESTB   = 0x64, // a u8, b u8 -> 8-bit flags (and)
    WIRE_TESTW   = 0x65, // a u8, b u8 -> 16-bit flags (and)

    // XMM data movement (memcpy tails, spill fills, the pxor zeroing idiom).
    // Operand values 20+i name xmm i; the register file behind the GPR slots
    // holds 16x16 bytes of xmm state. Only moves are supported: SSE
    // arithmetic is still native (a virtualized function may move xmm data
    // but not compute on it).
    WIRE_XLOAD   = 0x66, // xmm u8, base u8, disp u32 -> 16B load
    WIRE_XSTORE  = 0x67, // base u8, disp u32, xmm u8 -> 16B store
    WIRE_XMOV    = 0x68, // dst u8, src u8 -> 16B register move
    WIRE_XLOADQ  = 0x69, // xmm u8, base u8, disp u32 -> 8B load, upper zeroed
    WIRE_XSTOREQ = 0x6A, // base u8, disp u32, xmm u8 -> 8B store
    WIRE_XLOADD  = 0x6B, // xmm u8, gpr u8 -> gpr zero-extended into xmm
    WIRE_XSTORED = 0x6C, // gpr u8, xmm u8 -> low 64 of xmm into gpr
    WIRE_XZERO   = 0x6D, // xmm u8 -> zero 16B (pxor xmm, xmm idiom)
    WIRE_XXOR    = 0x6E, // dst u8, src u8 -> 128-bit XOR of two xmm slots
    WIRE_SBB     = 0x6F, // dst u8, src u8 -> dst = dst - src - cf
    WIRE_SBBI    = 0x70, // reg u8, imm u64 -> reg = reg - imm - cf
    WIRE_ADC     = 0x71, // dst u8, src u8 -> dst = dst + src + cf
    WIRE_ADCI    = 0x72, // reg u8, imm u64 -> reg = reg + imm + cf
    WIRE_SBBD    = 0x73, // dst u8, src u8 -> 32-bit dst - src - cf
    WIRE_ADCD    = 0x74, // dst u8, src u8 -> 32-bit dst + src + cf
    WIRE_XUNPCKL = 0x75, // dst u8, src u8 -> UNPCKLPS interleave
    WIRE_XMOUNTH = 0x76, // xmm u8, gpr u8 -> store gpr to xmm high 64
    WIRE_XMOVHL  = 0x77, // dst u8, src u8 -> MOVHLPS: dst[0:8]=src[8:16]
    // Narrow ALU with exact operand-width flags. sel = (width<<4)|op where
    // width is 0=8, 1=16, 2=32, 3=64 bits and op is NALU_* below. The result is
    // written back at the chosen width - 8/16 splice into the low half (upper
    // bits preserved), 32 zero-extends, 64 overwrites - and the flags come from
    // that width, which is what the x86 byte/word forms produce. INC/DEC leave
    // cf alone (x86 INC/DEC never touch CF; the old ADDI/SUBI lowering did).
    WIRE_NALU    = 0x78, // sel u8, dst u8, src u8
    // XMM arithmetic. Operand layout is `op u8, fmt u8, dst u8, src u8`: the
    // operation and the lane type get a full byte each because the family has
    // more than 16 operations and the conversion codes need the whole range
    // 0..15. dst/src name xmm slots as 20+i. Compares write the integer flags
    // too; WIRE_XALUI carries a trailing imm8 for shuffles and predicates.
    WIRE_XALU    = 0x79, // op u8, fmt u8, dst u8, src u8
    WIRE_XALUI   = 0x7A, // op u8, fmt u8, dst u8, src u8, imm8 u8
    // Move the integer flags into / out of a register's low byte (SAHF/LAHF).
    WIRE_SAHF    = 0x7B, // src u8 -> flags from bits 8..15 of src (AH)
    WIRE_LAHF    = 0x7C, // dst u8 -> dst low byte = flags (AH layout)
    // 64x64->128 multiply and 128/64 division over a (lo,hi) register pair.
    // MULQ's sel byte picks the operand signedness (0 = unsigned, 1 = signed);
    // the low half of the product is identical either way, only the high half
    // differs.
    WIRE_MULQ    = 0x7D, // sel u8, lo u8, hi u8, src u8
    WIRE_DIVQ    = 0x7E, // lo u8, hi u8, den u8  (unsigned; lo=quot hi=rem)
    WIRE_IDIVQ   = 0x7F, // lo u8, hi u8, den u8  (signed)
    // CF = bit 0 of the register, every other flag left alone. This is the one
    // primitive the BT/BTS/BTC/BTR family needs - they move a single bit of a
    // register or memory word into CF and otherwise leave the flag file be.
    WIRE_SETCF   = 0x80, // src u8
    // Bit test / test-and-set / test-and-reset / test-and-complement. sel =
    // (isMem << 2) | op with op 0=bt 1=bts 2=btr 3=btc. In register mode `base`
    // is the value to read/modify and `idx` is masked to 5/6 bits; in memory
    // mode `base` is the address and `idx` is a full bit offset (the bit may
    // lie outside the addressed word). Only cf is written.
    WIRE_BITOP   = 0x81, // sel u8, base u8, idx u8
    // Flag-free arithmetic shift right by an immediate - LEA's partner for
    // right shifts, so `cqo`/`cdq` can replicate the sign without disturbing a
    // live comparison.
    WIRE_ADDRSHRI = 0x82, // d u8, imm u64
    // ---- coverage round: the residual reject buckets --------------------
    // Bit scan. sel = (op << 2) | width with op 0=bsf 1=bsr 2=tzcnt 3=lzcnt
    // and width 0=16 1=32 2=64. bsf/bsr write only zf (undefined elsewhere);
    // tzcnt/lzcnt write zf and cf. A zero source leaves dst unchanged for
    // bsf/bsr and yields the operand width for tzcnt/lzcnt.
    WIRE_BITSCAN  = 0x83, // sel u8, dst u8, src u8
    // x87 co-processor escape. The operands are the raw x87 opcode bytes:
    // `esc` is the D8-DF escape and `modrm` the following ModRM byte, so the
    // handler decodes (and executes) exactly the form the guest encoded. `ea`
    // carries the pre-computed effective address for memory forms and the rax
    // slot for FNSTSW. The x87 stack is real machine state the VM never
    // models - the handler operates on it directly, which is what keeps the
    // semantics bit-exact for the 80-bit tbyte forms compiled code uses for
    // long double.
    WIRE_X87      = 0x84, // esc u8, modrm u8, ea u8
    // String primitive. sel = (rep << 5) | (op << 2) | width where
    // rep 0=plain 1=rep/repe (F3) 2=repne (F2), op 0=movs 1=stos 2=lods
    // 3=cmps 4=scas, width 0=b 1=w 2=d 3=q. `rsi`/`rdi`/`rcx` name the
    // source index, destination index and count slots; `acc` names the
    // accumulator slot (stos reads it, lods writes it, cmps/scas compare
    // against it). Direction comes from the VM's df flag (CLD/STD set it).
    WIRE_STR      = 0x85, // sel u8, rsi u8, rdi u8, rcx u8, acc u8
    // cmpxchg family. sel bits [1:0]=width (0=b 1=w 2=d 3=q), bit 2=lock,
    // sel 4=cmpxchg8b (edx:eax vs [ea]), 5=cmpxchg16b. `ea` is the computed
    // address slot, `acc` the rax slot, `src` the r/m-source register slot.
    // ZF follows the comparison; the other flags move with the subtraction.
    WIRE_CMPXCHG  = 0x86, // sel u8, ea u8, acc u8, src u8
    // cpuid: a/b/c/d name the slots holding rax/rbx/rcx/rdx in and out.
    WIRE_CPUID    = 0x87, // a u8, b u8, c u8, d u8
    // rdtsc: edx:eax -> (hi, lo) slots.
    WIRE_RDTSC    = 0x88, // lo u8, hi u8
    // ud2: raises #UD exactly like the native instruction. The guest binary
    // emits it for __assume(0)/unreachable - it is a trap, not a recoverable
    // condition, and the crash is the intended semantics.
    WIRE_UD2      = 0x89,
    // rdrand / rdseed: sel 0=rdrand 1=rdseed. dst gets the random value, cf
    // reports success and the other arithmetic flags are cleared, matching
    // the hardware.
    WIRE_RDRAND   = 0x8A, // sel u8, dst u8
    // Set the VM's direction flag (CLD/STD). String primitives read it; it
    // survives across instructions exactly like the hardware flag.
    WIRE_SETDF    = 0x8B, // sel u8 (0=cld, 1=std)
    // Double-precision shift (shld / shrd). sel bit 0 picks the direction
    // (0 = shld, 1 = shrd) and bits 2..3 the width (1=16 2=32 3=64); `cnt`
    // holds the shift count (masked like the hardware), `src` the donor
    // register and `dst` the read-modify-write destination. cf comes from
    // the last bit shifted out of dst, of from a one-bit sign change, and
    // zf/sf/pf from the result; a zero count leaves everything untouched.
    WIRE_SHLD     = 0x8C, // sel u8, dst u8, src u8, cnt u8
    // Push / pop the flag file as a qword on the guest stack. RFLAGS layout:
    // cf=bit0, pf=bit2, zf=bit6, sf=bit7, of=bit11, df=bit10 (bit1 reads 1).
    // Only the modelled bits round-trip; everything else is reserved-0.
    WIRE_PUSHF    = 0x8D, // sp u8
    WIRE_POPF     = 0x8E, // sp u8
    // 8-bit one-operand pair arithmetic (mul/div r/m8): AX = AL * den8,
    // or AL=quotient / AH=remainder of AX / den8. sel bit 0 picks the
    // signed form. The result is spliced into bits 0..15 of acc; CF/OF
    // come from AH exactly like the hardware.
    WIRE_MULB     = 0x8F, // sel u8, acc u8, den u8
    WIRE_DIVB     = 0x90, // sel u8, acc u8, den u8
    // One past the highest defined opcode: the packer/obfuscator build their
    // logical->physical map for `logical < WIRE_COUNT`, so leaving this at the
    // highest opcode would silently drop that last instruction's remapping and
    // re-encode it as physical opcode 0.
    WIRE_COUNT   = 0x91,
};

// Highest logical opcode value the mapper permutes.
#define NP_WIRE_OPCODE_SLOTS 0x91

// WIRE_BITSCAN selector: (op << 2) | width
#define NP_BITSCAN_BSF    0
#define NP_BITSCAN_BSR    1
#define NP_BITSCAN_TZCNT  2
#define NP_BITSCAN_LZCNT  3
#define NP_BITSCAN_W16    0
#define NP_BITSCAN_W32    1
#define NP_BITSCAN_W64    2

// WIRE_STR selector: (rep << 5) | (op << 2) | width
#define NP_STR_REP    1
#define NP_STR_REPNE  2
#define NP_STR_MOVS   0
#define NP_STR_STOS   1
#define NP_STR_LODS   2
#define NP_STR_CMPS   3
#define NP_STR_SCAS   4

// WIRE_CMPXCHG selector
#define NP_CX_WIDTH(w) ((uint8_t)((w) & 3u))      // 0=b 1=w 2=d 3=q
#define NP_CX_LOCK     4u
#define NP_CX_8B       8u                          // cmpxchg8b (edx:eax)
#define NP_CX_16B      9u                          // cmpxchg16b (rdx:rax vs rbx:rcx)

// WIRE_NALU selector: (width << 4) | op
#define NP_NALU_W8   0x0
#define NP_NALU_W16  0x1
#define NP_NALU_W32  0x2
#define NP_NALU_W64  0x3
#define NP_NALU_ADD  0
#define NP_NALU_SUB  1
#define NP_NALU_ADC  2
#define NP_NALU_SBB  3
#define NP_NALU_AND  4
#define NP_NALU_OR   5
#define NP_NALU_XOR  6
#define NP_NALU_NOT  7
#define NP_NALU_INC  8
#define NP_NALU_DEC  9
#define NP_NALU_NEG  10
#define NP_NALU_SHL  11
#define NP_NALU_SHR  12
#define NP_NALU_SAR  13
#define NP_NALU_ROL  14
#define NP_NALU_ROR  15

// WIRE_XALU / WIRE_XALUI operands: op first, then fmt. They are separate bytes
// because the operation space runs past 16 entries and the conversion code
// below needs 0..15 of its own.
// fmt: 0=ps (4xf32), 1=pd (2xf64), 2=ss (xf32), 3=sd (xf64),
//      4=pb (16xi8), 5=pw (8xi16), 6=pdq (4xi32), 7=pq (2xi64)
#define NP_XALU_FMT_PS  0x0
#define NP_XALU_FMT_PD  0x1
#define NP_XALU_FMT_SS  0x2
#define NP_XALU_FMT_SD  0x3
#define NP_XALU_FMT_B   0x4
#define NP_XALU_FMT_W   0x5
#define NP_XALU_FMT_D   0x6
#define NP_XALU_FMT_Q   0x7
#define NP_XALU_ADD    0
#define NP_XALU_SUB    1
#define NP_XALU_MUL    2
#define NP_XALU_DIV    3
#define NP_XALU_MIN    4
#define NP_XALU_MAX    5
#define NP_XALU_SQRT   6
#define NP_XALU_AND    7
#define NP_XALU_OR     8
#define NP_XALU_XOR    9
#define NP_XALU_ANDN   10
#define NP_XALU_CMPEQ  11
#define NP_XALU_CMPGT  12
#define NP_XALU_CMPLE  13   // ordered <= (scalar fp compare, imm form)
#define NP_XALU_CMPLT  14
#define NP_XALU_CMPORD 15
#define NP_XALU_CVT2F  16   // int lane -> fp lane (signed)
#define NP_XALU_CVT2I  17   // fp lane -> int lane (truncate toward zero)
#define NP_XALU_CVT2F2 18   // fp lane -> fp lane (narrow/widen)
#define NP_XALU_UNPCKL 19
#define NP_XALU_UNPCKH 20
#define NP_XALU_PACK   21
#define NP_XALU_PSHUF  22   // imm8 shuffle (WIRE_XALUI)
#define NP_XALU_SHLI   23   // imm8 lane shift left
#define NP_XALU_SHRI   24   // imm8 lane shift right (logical)
#define NP_XALU_SARI   25   // imm8 lane shift right (arithmetic)
#define NP_XALU_MOVMSK 26   // dst is a GPR slot: sign bits -> mask
#define NP_XALU_SPLICE 27   // dst low 4 (fmt=ss) / 8 (fmt=sd) bytes <- src, rest kept

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
// Translator scratch slots inside the register file. They sit outside the 16
// guest registers on purpose: the address builder clobbers them freely, so
// aliasing a guest register there would silently corrupt live state.
#define NP_VM_SCRATCH_A 16
#define NP_VM_SCRATCH_B 17
// Total register-file slots: 16 guest + 2 scratch + 2 control (native exit
// address, runtime image base).
#define NP_VM_SLOTS 20

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
    // Input offset of the first instruction that ended translation (diagnostic).
    uint32_t skipOffset = 0;
    // Category/opcode of that instruction (diagnostic, matches the reason text).
    uint8_t skipCat = 0, skipOp = 0, skipOp2 = 0;
    // Offset of the virtualized body inside the input range: everything before
    // it is the native frame prologue the caller must leave in place. The
    // region descriptor's RVA is the input base plus this value.
    uint32_t bodyOff = 0;
    // The stream performs xmm data movement: the trampoline must save and
    // restore the real xmm registers around the interpreter.
    bool usesXmm = false;
    // Deepest stack motion below the body's entry rsp, in bytes. The
    // installer sizes the trampoline gap from this (and probes the pages it
    // spans) so the guest frame can never land on the register file.
    uint32_t stackDepth = 0;
    // Set when translation stopped at a native bridge (an rsp write whose
    // depth is only knowable at run time). cutAt is the bridge instruction's
    // offset in the input and resumeOff the offset just after it: the packer
    // emits a region for [bodyOff, cutAt) and opens the next chunk at
    // resumeOff. The bridge itself runs on the real stack between the two
    // VM regions; entry/exit flag synchronisation keeps its effects visible
    // to the next chunk.
    bool cut = false;
    uint32_t cutAt = 0;
    uint32_t resumeOff = 0;
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
                             uint64_t seed = 0,
                             bool allowIslands = true);
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
                                  uint8_t complexity,
                                  int junk_override = -1);
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