// NovaProtect Anti-Debug Module Implementation
//
// Emits self contained x64 machine code. Nothing here depends on the packer,
// on an import table or on any external symbol: modules are found through the
// PEB loader lists and exports are resolved by walking the PE export directory
// with a ROR13 name hash. Every block is position independent, so the packer
// can drop it into a freshly built section without generating relocations.
//
// ABI of every emitted block:
//     uint32_t fn(void);       // 0 = clean, 1 = detected, 2 = unavailable
// Non volatile registers (rbx, rbp, rsi, rdi, r12-r15) are preserved, only
// rax/rcx/rdx/r8-r11 are clobbered. The stack stays 16 byte aligned across
// calls into Windows APIs (the prologue lands on rsp % 16 == 8).
//
// The detection logic mirrors runtime/prot64.c (np_chk_peb, np_chk_ntglobal,
// np_chk_heap, np_chk_ntquery, np_chk_dr, np_chk_timing, np_chk_cpuid,
// np_chk_integrity) so the generator and the runtime agree on "clean".

#include "anti_debug.h"
#include <cstring>

namespace np {

// ===========================================================================
// ROR13 hashes of the exported names, computed over the raw ASCII bytes the
// way runtime/prot64.c folds them (no case conversion: export names are used
// verbatim). The resolver walks every module's export directory.
// ===========================================================================
static constexpr uint32_t H_NtQueryInformationProcess = 0xB10FD839u;
static constexpr uint32_t H_GetThreadContext          = 0x68A7C7D2u;
static constexpr uint32_t H_ExitProcess               = 0x73E2D87Eu;

namespace {

enum Reg { RAX = 0, RCX = 1, RDX = 2, RBX = 3, RSP = 4, RBP = 5, RSI = 6, RDI = 7,
           R8 = 8, R9 = 9, R10 = 10, R11 = 11, R12 = 12, R13 = 13, R14 = 14, R15 = 15 };

// ---------------------------------------------------------------------------
// assembler with a label based relocation pass
// ---------------------------------------------------------------------------
struct Asm {
    std::vector<uint8_t> b;
    std::vector<size_t> relSite;
    std::vector<size_t> relNext;
    std::vector<int>    relLabel;
    std::vector<size_t> labelOff;

    size_t n() const { return b.size(); }
    void u8(uint8_t v)   { b.push_back(v); }
    void u32(uint32_t v) { for (int i = 0; i < 4; i++) b.push_back((uint8_t)(v >> (8 * i))); }
    void u64(uint64_t v) { for (int i = 0; i < 8; i++) b.push_back((uint8_t)(v >> (8 * i))); }

    int newLabel() { labelOff.push_back(0); return (int)labelOff.size() - 1; }
    void mark(int id) { labelOff[(size_t)id] = b.size(); }
    void addRel(size_t site, int id) { relSite.push_back(site); relNext.push_back(b.size()); relLabel.push_back(id); }
    void resolve() {
        for (size_t i = 0; i < relSite.size(); i++) {
            int64_t d = (int64_t)labelOff[(size_t)relLabel[i]] - (int64_t)relNext[i];
            uint32_t v = (uint32_t)(int32_t)d;
            for (int k = 0; k < 4; k++) b[relSite[i] + (size_t)k] = (uint8_t)(v >> (8 * k));
        }
    }
};

// ---------------------------------------------------------------------------
// encoding helpers
// ---------------------------------------------------------------------------
uint8_t rexW(int regf, int rm) { return (uint8_t)(0x48 | (((regf >> 3) & 1) << 2) | ((rm >> 3) & 1)); }

// modrm for mod=10 (disp32) with no SIB (base must not be rsp/r12)
void modrmMem32(Asm& a, int regf, int base) { a.u8((uint8_t)(0x80 | ((regf & 7) << 3) | (base & 7))); }
// modrm for mod=10 with SIB, index = none, base = rsp/r12
void sibMem32(Asm& a, int regf, int base) {
    a.u8((uint8_t)(0x84 | ((regf & 7) << 3)));
    a.u8((uint8_t)(0x24 | (((base >> 3) & 1) << 3)));
}
void mem32(Asm& a, int regf, int base) {
    if ((base & 7) == 4) sibMem32(a, regf, base); else modrmMem32(a, regf, base);
}

// REX prefix (0x40 | R | B) emitted only when a high register is involved.
void rexIf(Asm& a, int regf, int rm) {
    uint8_t r = (uint8_t)(0x40 | (((regf >> 3) & 1) << 2) | ((rm >> 3) & 1));
    if (r != 0x40) a.u8(r);
}

// REX for an instruction with a SIB byte: W | R(dst) | X(index) | B(base).
uint8_t rexSIB(int w, int dst, int index, int base) {
    return (uint8_t)(0x40 | (w << 3) | (((dst   >> 3) & 1) << 2)
                          | (((index >> 3) & 1) << 1) | ((base >> 3) & 1));
}
void emitRexSIB(Asm& a, int w, int dst, int index, int base) {
    uint8_t r = rexSIB(w, dst, index, base);
    if (r != 0x40) a.u8(r);
}

// --- data movement ---------------------------------------------------------
void movRI32(Asm& a, int reg, uint32_t v) { if (reg >= 8) a.u8(0x41); a.u8((uint8_t)(0xB8 + (reg & 7))); a.u32(v); }
void movRI64(Asm& a, int reg, uint64_t v) { a.u8(rexW(0, reg)); a.u8((uint8_t)(0xB8 + (reg & 7))); a.u64(v); }
void movRR64(Asm& a, int dst, int src) { a.u8(rexW(src, dst)); a.u8(0x89); a.u8((uint8_t)(0xC0 | ((src & 7) << 3) | (dst & 7))); }
void movRR32(Asm& a, int dst, int src) { rexIf(a, src, dst); a.u8(0x89); a.u8((uint8_t)(0xC0 | ((src & 7) << 3) | (dst & 7))); }
void movR64BaseDisp(Asm& a, int dst, int base, int32_t d) {
    a.u8(rexW(dst, base)); a.u8(0x8B); mem32(a, dst, base); a.u32((uint32_t)d);
}
void movR32BaseDisp(Asm& a, int dst, int base, int32_t d) {
    rexIf(a, dst, base); a.u8(0x8B); mem32(a, dst, base); a.u32((uint32_t)d);
}
void movzxR32ByteBaseDisp(Asm& a, int dst, int base, int32_t d) {
    rexIf(a, dst, base); a.u8(0x0F); a.u8(0xB6); mem32(a, dst, base); a.u32((uint32_t)d);
}
void leaR64BaseDisp(Asm& a, int dst, int base, int32_t d) {
    a.u8(rexW(dst, base)); a.u8(0x8D); mem32(a, dst, base); a.u32((uint32_t)d);
}
// lea dst64, [base + index*1]   (mod = 00, disp = 0; scale 1 for byte offsets)
void leaR64BaseIndex1(Asm& a, int dst, int base, int index) {
    emitRexSIB(a, 1, dst, index, base);
    a.u8(0x8D);
    a.u8((uint8_t)(0x04 | ((dst & 7) << 3)));
    a.u8((uint8_t)((0 << 6) | ((index & 7) << 3) | (base & 7)));
}
// mov dst64, [base + index*4]   (mod = 00, disp = 0)
[[maybe_unused]] void movR64BaseIndex4(Asm& a, int dst, int base, int index) {
    emitRexSIB(a, 1, dst, index, base);
    a.u8(0x8B);
    a.u8((uint8_t)(0x04 | ((dst & 7) << 3)));
    a.u8((uint8_t)((2 << 6) | ((index & 7) << 3) | (base & 7)));
}
// mov dst32, [base + index*4]   (mod = 00, disp = 0)
void movR32BaseIndex4(Asm& a, int dst, int base, int index) {
    emitRexSIB(a, 0, dst, index, base);
    a.u8(0x8B);
    a.u8((uint8_t)(0x04 | ((dst & 7) << 3)));
    a.u8((uint8_t)((2 << 6) | ((index & 7) << 3) | (base & 7)));
}
// movzx dst32, word ptr [base + index*2]   (mod = 00, disp = 0)
void movR32BaseIndex2(Asm& a, int dst, int base, int index) {
    emitRexSIB(a, 0, dst, index, base);
    a.u8(0x0F); a.u8(0xB7);
    a.u8((uint8_t)(0x04 | ((dst & 7) << 3)));
    a.u8((uint8_t)((1 << 6) | ((index & 7) << 3) | (base & 7)));
}
// --- rsp relative ----------------------------------------------------------
// All rsp relative forms use SIB with base = 100b (rsp/r12). The base is rsp,
// so only the register field (R bit) can need a REX prefix; getting this wrong
// silently turns "lea r8, [rsp+x]" into "lea rax, [rsp+x]".
void movR64RspDisp(Asm& a, int dst, int32_t d) { a.u8((uint8_t)(0x48 | (((dst >> 3) & 1) << 2))); a.u8(0x8B); a.u8((uint8_t)(0x84 | ((dst & 7) << 3))); a.u8(0x24); a.u32((uint32_t)d); }
void movR32RspDisp(Asm& a, int dst, int32_t d) { if (dst >= 8) a.u8(0x44); a.u8(0x8B); a.u8((uint8_t)(0x84 | ((dst & 7) << 3))); a.u8(0x24); a.u32((uint32_t)d); }
void movRspDispR64(Asm& a, int32_t d, int src) { a.u8((uint8_t)(0x48 | (((src >> 3) & 1) << 2))); a.u8(0x89); a.u8((uint8_t)(0x84 | ((src & 7) << 3))); a.u8(0x24); a.u32((uint32_t)d); }
void movRspDispR32(Asm& a, int32_t d, int src) { if (src >= 8) a.u8(0x44); a.u8(0x89); a.u8((uint8_t)(0x84 | ((src & 7) << 3))); a.u8(0x24); a.u32((uint32_t)d); }
void movRspDispImm64(Asm& a, int32_t d, uint64_t v) { a.u8(0x48); a.u8(0xC7); a.u8(0x84); a.u8(0x24); a.u32((uint32_t)d); a.u32((uint32_t)v); }
void movRspDisp32Imm32(Asm& a, int32_t d, uint32_t v) { a.u8(0xC7); a.u8(0x84); a.u8(0x24); a.u32((uint32_t)d); a.u32(v); }
void leaR64RspDisp(Asm& a, int dst, int32_t d) { a.u8((uint8_t)(0x48 | (((dst >> 3) & 1) << 2))); a.u8(0x8D); a.u8((uint8_t)(0x84 | ((dst & 7) << 3))); a.u8(0x24); a.u32((uint32_t)d); }

// --- stack -----------------------------------------------------------------
void pushR64(Asm& a, int reg) { if (reg >= 8) a.u8(0x41); a.u8((uint8_t)(0x50 + (reg & 7))); }
void popR64(Asm& a, int reg)  { if (reg >= 8) a.u8(0x41); a.u8((uint8_t)(0x58 + (reg & 7))); }
void subRspImm(Asm& a, uint32_t v) { a.u8(0x48); a.u8(0x81); a.u8(0xEC); a.u32(v); }
void addRspImm(Asm& a, uint32_t v) { a.u8(0x48); a.u8(0x81); a.u8(0xC4); a.u32(v); }

// --- alu -------------------------------------------------------------------
void xorRR32(Asm& a, int dst, int src) { rexIf(a, src, dst); a.u8(0x31); a.u8((uint8_t)(0xC0 | ((src & 7) << 3) | (dst & 7))); }
void xorRR64(Asm& a, int dst, int src) { a.u8(rexW(src, dst)); a.u8(0x31); a.u8((uint8_t)(0xC0 | ((src & 7) << 3) | (dst & 7))); }
void addRR64(Asm& a, int dst, int src) { a.u8(rexW(src, dst)); a.u8(0x01); a.u8((uint8_t)(0xC0 | ((src & 7) << 3) | (dst & 7))); }
void subRR64(Asm& a, int dst, int src) { a.u8(rexW(src, dst)); a.u8(0x29); a.u8((uint8_t)(0xC0 | ((src & 7) << 3) | (dst & 7))); }
void orRR32(Asm& a, int dst, int src) { rexIf(a, src, dst); a.u8(0x09); a.u8((uint8_t)(0xC0 | ((src & 7) << 3) | (dst & 7))); }
void orRR64(Asm& a, int dst, int src) { a.u8(rexW(src, dst)); a.u8(0x09); a.u8((uint8_t)(0xC0 | ((src & 7) << 3) | (dst & 7))); }
void andRI32(Asm& a, int dst, uint32_t v) { a.u8(0x81); a.u8((uint8_t)(0xE0 | (dst & 7))); a.u32(v); }
[[maybe_unused]] void andRI64(Asm& a, int dst, uint32_t v) { a.u8(0x48); a.u8(0x81); a.u8((uint8_t)(0xE0 | (dst & 7))); a.u32(v); }
void testRR32(Asm& a, int r1, int r2) { rexIf(a, r2, r1); a.u8(0x85); a.u8((uint8_t)(0xC0 | ((r2 & 7) << 3) | (r1 & 7))); }
void testRR64(Asm& a, int r1, int r2) { a.u8(rexW(r2, r1)); a.u8(0x85); a.u8((uint8_t)(0xC0 | ((r2 & 7) << 3) | (r1 & 7))); }
void cmpRI32(Asm& a, int reg, uint32_t v) { a.u8(0x81); a.u8((uint8_t)(0xF8 | (reg & 7))); a.u32(v); }
void cmpRI8(Asm& a, int reg, uint8_t v) { a.u8(0x83); a.u8((uint8_t)(0xF8 | (reg & 7))); a.u8(v); }
void cmpRR32(Asm& a, int dst, int src) { rexIf(a, src, dst); a.u8(0x39); a.u8((uint8_t)(0xC0 | ((src & 7) << 3) | (dst & 7))); }
void cmpRR64(Asm& a, int dst, int src) { a.u8(rexW(src, dst)); a.u8(0x39); a.u8((uint8_t)(0xC0 | ((src & 7) << 3) | (dst & 7))); }
[[maybe_unused]] void imulRR32(Asm& a, int dst, int src) { rexIf(a, dst, src); a.u8(0x0F); a.u8(0xAF); a.u8((uint8_t)(0xC0 | ((dst & 7) << 3) | (src & 7))); }
void imulRR64(Asm& a, int dst, int src) { a.u8(rexW(dst, src)); a.u8(0x0F); a.u8(0xAF); a.u8((uint8_t)(0xC0 | ((dst & 7) << 3) | (src & 7))); }
void shlRI64(Asm& a, int reg, uint8_t v) { a.u8(0x48); a.u8(0xC1); a.u8((uint8_t)(0xE0 | (reg & 7))); a.u8(v); }
void shlRI32(Asm& a, int reg, uint8_t v) { a.u8(0xC1); a.u8((uint8_t)(0xE0 | (reg & 7))); a.u8(v); }
void shrRI32(Asm& a, int reg, uint8_t v) { a.u8(0xC1); a.u8((uint8_t)(0xE8 | (reg & 7))); a.u8(v); }
void shrRI64(Asm& a, int reg, uint8_t v) { a.u8(0x48); a.u8(0xC1); a.u8((uint8_t)(0xE8 | (reg & 7))); a.u8(v); }
void incR64(Asm& a, int reg) { a.u8(rexW(0, reg)); a.u8(0xFF); a.u8((uint8_t)(0xC0 | (reg & 7))); }
void decR32(Asm& a, int reg) { if (reg >= 8) a.u8(0x41); a.u8(0xFF); a.u8((uint8_t)(0xC8 | (reg & 7))); }
[[maybe_unused]] void movzxRR32(Asm& a, int dst, int src) { rexIf(a, dst, src); a.u8(0x0F); a.u8(0xB7); a.u8((uint8_t)(0xC0 | ((dst & 7) << 3) | (src & 7))); }
[[maybe_unused]] void movsxdRR64(Asm& a, int dst, int src) { a.u8(rexW(dst, src)); a.u8(0x63); a.u8((uint8_t)(0xC0 | ((dst & 7) << 3) | (src & 7))); }
[[maybe_unused]] void movdXmmR32(Asm& a, int dstX, int src) { a.u8(0x66); rexIf(a, dstX, src); a.u8(0x0F); a.u8(0x6E); a.u8((uint8_t)(0xC0 | ((dstX & 7) << 3) | (src & 7))); }
[[maybe_unused]] void movdR32Xmm(Asm& a, int dst, int srcX) { a.u8(0x66); rexIf(a, srcX, dst); a.u8(0x0F); a.u8(0x7E); a.u8((uint8_t)(0xC0 | ((srcX & 7) << 3) | (dst & 7))); }
void rdtsc(Asm& a) { a.u8(0x0F); a.u8(0x31); }
void cpuid(Asm& a) { a.u8(0x0F); a.u8(0xA2); }
void repStosq(Asm& a) { a.u8(0xF3); a.u8(0x48); a.u8(0xAB); }
void callR64(Asm& a, int reg) { if (reg >= 8) a.u8(0x41); a.u8(0xFF); a.u8((uint8_t)(0xD0 | (reg & 7))); }
void ret(Asm& a) { a.u8(0xC3); }

// --- control flow (label based) --------------------------------------------
int callL(Asm& a) { a.u8(0xE8); size_t s = a.n(); a.u32(0); int id = a.newLabel(); a.addRel(s, id); return id; }
int jmpL(Asm& a)  { a.u8(0xE9); size_t s = a.n(); a.u32(0); int id = a.newLabel(); a.addRel(s, id); return id; }
int jzL(Asm& a)   { a.u8(0x0F); a.u8(0x84); size_t s = a.n(); a.u32(0); int id = a.newLabel(); a.addRel(s, id); return id; }
int jnzL(Asm& a)  { a.u8(0x0F); a.u8(0x85); size_t s = a.n(); a.u32(0); int id = a.newLabel(); a.addRel(s, id); return id; }
[[maybe_unused]] int jbL(Asm& a)   { a.u8(0x0F); a.u8(0x82); size_t s = a.n(); a.u32(0); int id = a.newLabel(); a.addRel(s, id); return id; }
int jaeL(Asm& a)  { a.u8(0x0F); a.u8(0x83); size_t s = a.n(); a.u32(0); int id = a.newLabel(); a.addRel(s, id); return id; }
[[maybe_unused]] int jaL(Asm& a)   { a.u8(0x0F); a.u8(0x87); size_t s = a.n(); a.u32(0); int id = a.newLabel(); a.addRel(s, id); return id; }
int jbeL(Asm& a)  { a.u8(0x0F); a.u8(0x86); size_t s = a.n(); a.u32(0); int id = a.newLabel(); a.addRel(s, id); return id; }

// --- standard block frame --------------------------------------------------
// push rbx/rbp/rsi/rdi then sub rsp,frame. frame % 16 == 8 keeps rsp 16 byte
// aligned for calls into the OS.
enum { FRAME_DEFAULT = 0x68, FRAME_BIG = 0x528 };
void prologue(Asm& a, uint32_t frame) { pushR64(a, RBX); pushR64(a, RBP); pushR64(a, RSI); pushR64(a, RDI); subRspImm(a, frame); }
void prologue(Asm& a) { prologue(a, FRAME_DEFAULT); }
void epilogue(Asm& a, uint32_t frame) { addRspImm(a, frame); popR64(a, RDI); popR64(a, RSI); popR64(a, RBP); popR64(a, RBX); ret(a); }
void epilogue(Asm& a) { epilogue(a, FRAME_DEFAULT); }
void retVal(Asm& a, uint32_t v) { movRI32(a, RAX, v); epilogue(a); }
void retValBig(Asm& a, uint32_t v) { movRI32(a, RAX, v); epilogue(a, FRAME_BIG); }

// frame slots
// Stack slots below the four pushed non-volatiles. SL_ARG5 is the 5th
// *argument* slot at a call site: by the Windows x64 ABI the caller places
// arg5 at [rsp+0x20] and arg6 at [rsp+0x28] (verified against GCC output).
// It lived at 0x28 for a while - one slot too high - so NtQueryInformationProcess
// read its ReturnLength pointer from the uninitialized 0x20 slot instead: the
// kernel then wrote through whatever stale stack value it found there. When
// that value was a bad pointer the API call silently failed (every debug-port
// check read its zero-initialized result and reported "clean"); when it was a
// writable leftover the write corrupted the caller's frame and the process
// crashed later in unrelated code.
enum { SL_A = 0x00, SL_B = 0x08, SL_C = 0x10, SL_D = 0x18, SL_CTX = 0x20, SL_ARG5 = 0x20 };
enum { CTX_SIZE = 0x4D0, CTX_CONTEXTFLAGS = 0x30, CTX_DR0 = 0x48 };
enum { CONTEXT_DEBUG_REGISTERS = 0x00100010 };

// ---------------------------------------------------------------------------
// export resolver
// uintptr_t np_resolve(uint32_t ror13_hash)   (arg in ecx, result in rax)
//
// Walks PEB->Ldr->InLoadOrderModuleList, then each module's export directory
// (IMAGE_DIRECTORY_ENTRY_EXPORT = optional header + 0x70 in PE32+). Exported
// names are folded with ROR13 and compared against the requested hash.
// Returns 0 when nothing matches. Preserves every non volatile register.
//
// register plan:
//   r10 = requested hash      r11 = PEB->Ldr        r13 = &InLoadOrderModuleList
//   rsi = current entry       r14 = module base     r15 = export directory VA
//   r12 = names left          rdi = names array     rbx = name RVA
//   rbp = folded hash         rax/rcx/rdx = scratch
// ---------------------------------------------------------------------------
void emitResolver(Asm& a) {
    pushR64(a, RBX); pushR64(a, RBP); pushR64(a, RSI); pushR64(a, RDI);
    pushR64(a, R12); pushR64(a, R13); pushR64(a, R14); pushR64(a, R15);

    movRR32(a, R10, RCX);                                     // r10d = requested hash
    a.u8(0x65); a.u8(0x48); a.u8(0x8B); a.u8(0x04); a.u8(0x25); a.u32(0x60);   // mov rax, gs:[0x60]
    movR64BaseDisp(a, R11, RAX, 0x18);                        // r11 = PEB->Ldr
    leaR64BaseDisp(a, R13, R11, 0x10);                        // r13 = &InLoadOrderModuleList
    movR64BaseDisp(a, RSI, R13, 0);                           // rsi = first Flink

    int l_loop     = a.newLabel();
    int l_nameloop = a.newLabel();
    int l_hashloop = a.newLabel();
    int l_hashdone = a.newLabel();
    int l_found    = a.newLabel();
    int l_nextname = a.newLabel();
    int l_nextmod  = a.newLabel();
    int l_done     = a.newLabel();
    int l_end      = a.newLabel();

    a.mark(l_loop);
    cmpRR64(a, RSI, R13);                                     // wrapped back to the head?
    { int b = jzL(a); a.relLabel.back() = l_done; (void)b; }
    movR64BaseDisp(a, R14, RSI, 0x30);                        // r14 = DllBase
    testRR64(a, R14, R14);
    { int b = jzL(a); a.relLabel.back() = l_nextmod; (void)b; }

    movR32BaseDisp(a, RDX, R14, 0x3C);                        // e_lfanew
    leaR64BaseIndex1(a, R15, R14, RDX);                       // r15 = NT headers
    movR32BaseDisp(a, RAX, R15, 0x18);                        // OptionalHeader.Magic
    andRI32(a, RAX, 0xFFFF);                                  // field is a WORD
    cmpRI32(a, RAX, 0x20B);                                   // PE32+ only
    { int b = jnzL(a); a.relLabel.back() = l_nextmod; (void)b; }
    movR32BaseDisp(a, R15, R15, 0x88);                        // DataDirectory[0].VirtualAddress
    testRR32(a, R15, R15);
    { int b = jzL(a); a.relLabel.back() = l_nextmod; (void)b; }
    addRR64(a, R15, R14);                                     // r15 = export directory VA
    movR32BaseDisp(a, R12, R15, 0x18);                        // NumberOfNames
    testRR32(a, R12, R12);
    { int b = jzL(a); a.relLabel.back() = l_nextmod; (void)b; }
    movR32BaseDisp(a, RDI, R15, 0x20);                        // AddressOfNames RVA
    addRR64(a, RDI, R14);                                     // rdi = names array

    a.mark(l_nameloop);
    movR32BaseDisp(a, RBX, RDI, 0);                           // ebx = name RVA
    a.u8(0x48); a.u8(0x83); a.u8(0xC7); a.u8(0x04);           // add rdi, 4
    testRR32(a, RBX, RBX);
    { int b = jzL(a); a.relLabel.back() = l_nextname; (void)b; }
    leaR64BaseIndex1(a, RDX, R14, RBX);                       // rdx = image + name
    xorRR32(a, RBP, RBP);                                     // ebp = 0

    a.mark(l_hashloop);
    movzxR32ByteBaseDisp(a, RAX, RDX, 0);                     // eax = *name
    testRR32(a, RAX, RAX);
    { int b = jzL(a); a.relLabel.back() = l_hashdone; (void)b; }
    incR64(a, RDX);
    movRR32(a, RCX, RBP);
    shrRI32(a, RCX, 13);
    shlRI32(a, RBP, 19);
    orRR32(a, RBP, RCX);
    a.u8(0x01); a.u8(0xC5);                                   // add ebp, eax
    { int b = jmpL(a); a.relLabel.back() = l_hashloop; (void)b; }

    a.mark(l_hashdone);
    cmpRR32(a, RBP, R10);
    { int b = jzL(a); a.relLabel.back() = l_found; (void)b; }

    a.mark(l_nextname);
    decR32(a, R12);
    { int b = jnzL(a); a.relLabel.back() = l_nameloop; (void)b; }

    a.mark(l_nextmod);
    movR64BaseDisp(a, RSI, RSI, 0);                           // rsi = rsi->Flink
    { int b = jmpL(a); a.relLabel.back() = l_loop; (void)b; }

    // ---- found: AddressOfFunctions[AddressOfNameOrdinals[i]] ----
    a.mark(l_found);
    movR32BaseDisp(a, RCX, R15, 0x20);                        // AddressOfNames RVA
    addRR64(a, RCX, R14);                                     // rcx = names base
    a.u8(0x48); a.u8(0x8D); a.u8(0x47); a.u8(0xFC);           // lea rax, [rdi-4]
    subRR64(a, RAX, RCX);
    shrRI64(a, RAX, 2);                                       // rax = name index
    movR32BaseDisp(a, RDX, R15, 0x24);                        // AddressOfNameOrdinals RVA
    addRR64(a, RDX, R14);                                     // rdx = ordinals base
    movR32BaseIndex2(a, RAX, RDX, RAX);                       // eax = ordinal
    movR32BaseDisp(a, RDX, R15, 0x1C);                        // AddressOfFunctions RVA
    addRR64(a, RDX, R14);                                     // rdx = functions base
    movR32BaseIndex4(a, RAX, RDX, RAX);                       // eax = function RVA
    testRR32(a, RAX, RAX);
    { int b = jzL(a); a.relLabel.back() = l_nextmod; (void)b; }
    addRR64(a, RAX, R14);                                     // rax = function VA
    { int b = jmpL(a); a.relLabel.back() = l_end; (void)b; }

    a.mark(l_done);
    xorRR32(a, RAX, RAX);

    a.mark(l_end);
    popR64(a, R15); popR64(a, R14); popR64(a, R13); popR64(a, R12);
    popR64(a, RDI); popR64(a, RSI); popR64(a, RBP); popR64(a, RBX);
    ret(a);
}

// mov ecx, hash ; call resolver ; rax = fn or 0
// The returned label must be marked (and emitResolver() emitted) at the end
// of the enclosing function, otherwise the call target resolves to offset 0
// and the block recurses into itself until the stack overflows.
int resolveInto(Asm& a, uint32_t hash) {
    movRI32(a, RCX, hash);
    return callL(a);
}

// ---------------------------------------------------------------------------
// CPUID vendor tags ("VMwareVMware" ...) packed as two little endian qwords
// ---------------------------------------------------------------------------
uint64_t le64(const uint8_t* p) { uint64_t v = 0; for (int i = 0; i < 8; i++) v |= (uint64_t)p[i] << (8 * i); return v; }
struct VmTag { uint64_t lo; uint64_t hi; };
VmTag makeTag(const char* s) {
    uint8_t buf[16];
    std::memset(buf, 0, sizeof(buf));
    size_t n = std::strlen(s);
    if (n > 16) n = 16;
    std::memcpy(buf, s, n);
    VmTag t; t.lo = le64(buf); t.hi = le64(buf + 8);
    return t;
}

} // namespace

// ===========================================================================
// public helpers
// ===========================================================================
uint64_t AntiDebugModule::fnv1a64(const void* data, size_t len) {
    const uint8_t* p = (const uint8_t*)data;
    uint64_t h = fnv_basis;
    for (size_t i = 0; i < len; i++) { h ^= p[i]; h *= fnv_prime; }
    return h;
}

// ===========================================================================
// individual checks
// ===========================================================================

// PEB->BeingDebugged (gs:[0x60] -> BYTE[2])
std::vector<uint8_t> AntiDebugModule::genIsDebuggerPresent() {
    Asm a;
    prologue(a);
    a.u8(0x65); a.u8(0x48); a.u8(0x8B); a.u8(0x04); a.u8(0x25); a.u32(0x60);  // mov rax, gs:[0x60]
    movzxR32ByteBaseDisp(a, RAX, RAX, 2);
    testRR32(a, RAX, RAX);
    int l_clean = jzL(a);
    retVal(a, 1);
    a.mark(l_clean);
    retVal(a, 0);
    a.resolve();
    return a.b;
}

// PEB->NtGlobalFlag (gs:[0x60] + 0xBC): FLG_HEAP_ENABLE_TAIL_CHECK |
// FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS (0x70)
std::vector<uint8_t> AntiDebugModule::genPEBCheck() {
    Asm a;
    prologue(a);
    a.u8(0x65); a.u8(0x48); a.u8(0x8B); a.u8(0x04); a.u8(0x25); a.u32(0x60);
    movR32BaseDisp(a, RAX, RAX, 0xBC);
    andRI32(a, RAX, 0x70);
    cmpRI32(a, RAX, 0x70);
    int l_clean = jnzL(a);
    retVal(a, 1);
    a.mark(l_clean);
    retVal(a, 0);
    a.resolve();
    return a.b;
}

// PEB->ProcessHeap: ForceFlags != 0, or Flags missing HEAP_GROWABLE (0x2)
std::vector<uint8_t> AntiDebugModule::genHeapCheck() {
    Asm a;
    prologue(a);
    a.u8(0x65); a.u8(0x48); a.u8(0x8B); a.u8(0x04); a.u8(0x25); a.u32(0x60);
    movR64BaseDisp(a, RAX, RAX, 0x30);                        // PEB->ProcessHeap
    testRR64(a, RAX, RAX);
    int l_clean = jzL(a);
    movR32BaseDisp(a, RCX, RAX, 0x74);                        // _HEAP.ForceFlags
    testRR32(a, RCX, RCX);
    int l_det = jnzL(a);
    movR32BaseDisp(a, RCX, RAX, 0x70);                        // _HEAP.Flags
    a.u8(0xF7); a.u8(0xC1); a.u32(0x00000002);                // test ecx, HEAP_GROWABLE
    int l_clean2 = jnzL(a);
    a.mark(l_det);
    retVal(a, 1);
    a.mark(l_clean); a.mark(l_clean2);
    retVal(a, 0);
    a.resolve();
    return a.b;
}

// NtQueryInformationProcess: ProcessDebugPort(7) / ProcessDebugFlags(0x1F) /
// ProcessDebugObjectHandle(0x1E). Returns 2 when ntdll cannot be resolved.
std::vector<uint8_t> AntiDebugModule::genNtQueryInfoProcess() {
    Asm a;
    prologue(a);
    int l_res = resolveInto(a, H_NtQueryInformationProcess);
    testRR64(a, RAX, RAX);
    int l_unavail = jzL(a);
    movRR64(a, RBX, RAX);

    // ProcessDebugPort: non zero port means a debugger is attached
    movRspDispImm64(a, SL_A, 0);
    movRspDisp32Imm32(a, SL_B, 0);
    movRI64(a, RCX, (uint64_t)-1);                            // NtCurrentProcess()
    movRI32(a, RDX, 7);
    leaR64RspDisp(a, R8, SL_A);
    movRI32(a, R9, 8);
    leaR64RspDisp(a, RAX, SL_B);
    movRspDispR64(a, SL_ARG5, RAX);
    callR64(a, RBX);
    movR64RspDisp(a, RAX, SL_A);
    testRR64(a, RAX, RAX);
    int l_det = jnzL(a);

    // ProcessDebugFlags: 0 means the process is being debugged
    movRspDispImm64(a, SL_A, 1);
    movRspDisp32Imm32(a, SL_B, 0);
    movRI64(a, RCX, (uint64_t)-1);
    movRI32(a, RDX, 0x1F);
    leaR64RspDisp(a, R8, SL_A);
    movRI32(a, R9, 4);
    leaR64RspDisp(a, RAX, SL_B);
    movRspDispR64(a, SL_ARG5, RAX);
    callR64(a, RBX);
    movR32RspDisp(a, RAX, SL_A);
    testRR32(a, RAX, RAX);
    int l_det2 = jzL(a);

    // ProcessDebugObjectHandle: non zero handle means a debugger is attached
    movRspDispImm64(a, SL_A, 0);
    movRspDisp32Imm32(a, SL_B, 0);
    movRI64(a, RCX, (uint64_t)-1);
    movRI32(a, RDX, 0x1E);
    leaR64RspDisp(a, R8, SL_A);
    movRI32(a, R9, 8);
    leaR64RspDisp(a, RAX, SL_B);
    movRspDispR64(a, SL_ARG5, RAX);
    callR64(a, RBX);
    movR64RspDisp(a, RAX, SL_A);
    testRR64(a, RAX, RAX);
    int l_det3 = jnzL(a);
    retVal(a, 0);

    a.mark(l_det); a.mark(l_det2); a.mark(l_det3);
    retVal(a, 1);
    a.mark(l_unavail);
    retVal(a, 2);
    a.mark(l_res);
    emitResolver(a);
    a.resolve();
    return a.b;
}

// GetThreadContext(GetCurrentThread(), CONTEXT_DEBUG_REGISTERS): Dr0-Dr3
std::vector<uint8_t> AntiDebugModule::genHardwareBreakpointCheck() {
    Asm a;
    prologue(a, FRAME_BIG);
    int l_res = resolveInto(a, H_GetThreadContext);
    testRR64(a, RAX, RAX);
    int l_unavail = jzL(a);
    movRR64(a, RBX, RAX);

    leaR64RspDisp(a, RDI, SL_CTX);
    xorRR32(a, RAX, RAX);
    movRI32(a, RCX, CTX_SIZE / 8);
    repStosq(a);                                              // zero the CONTEXT
    movRspDisp32Imm32(a, SL_CTX + CTX_CONTEXTFLAGS, CONTEXT_DEBUG_REGISTERS);
    movRI64(a, RCX, (uint64_t)-2);                            // GetCurrentThread() pseudo handle
    leaR64RspDisp(a, RDX, SL_CTX);
    callR64(a, RBX);
    testRR32(a, RAX, RAX);
    int l_unavail3 = jzL(a);

    movR64RspDisp(a, RAX, SL_CTX + CTX_DR0);
    movR64RspDisp(a, RCX, SL_CTX + CTX_DR0 + 8);
    orRR64(a, RAX, RCX);
    movR64RspDisp(a, RCX, SL_CTX + CTX_DR0 + 16);
    orRR64(a, RAX, RCX);
    movR64RspDisp(a, RCX, SL_CTX + CTX_DR0 + 24);
    orRR64(a, RAX, RCX);
    testRR64(a, RAX, RAX);
    int l_det = jnzL(a);
    retValBig(a, 0);

    a.mark(l_det);
    retValBig(a, 1);
    a.mark(l_unavail); a.mark(l_unavail3);
    retValBig(a, 2);
    a.mark(l_res);
    emitResolver(a);
    a.resolve();
    return a.b;
}

// RDTSC single step detection: the smallest of eight back to back deltas.
std::vector<uint8_t> AntiDebugModule::genTimingCheck() {
    Asm a;
    prologue(a);
    rdtsc(a);
    shlRI64(a, RDX, 32);
    orRR64(a, RAX, RDX);
    movRR64(a, RSI, RAX);                                     // rsi = best
    movRI32(a, RBP, 7);
    int l_loop = a.newLabel();
    a.mark(l_loop);
    rdtsc(a);
    shlRI64(a, RDX, 32);
    orRR64(a, RAX, RDX);
    movRR64(a, RDI, RAX);                                     // rdi = t0
    rdtsc(a);
    shlRI64(a, RDX, 32);
    orRR64(a, RAX, RDX);
    subRR64(a, RAX, RDI);                                     // rax = delta
    cmpRR64(a, RAX, RSI);
    int l_skip = jaeL(a);
    movRR64(a, RSI, RAX);
    a.mark(l_skip);
    decR32(a, RBP);
    int l_back = jnzL(a);
    a.relLabel.back() = l_loop;                               // loop while the counter lasts
    a.mark(l_back);
    movRI64(a, RAX, 8192);                                    // calibrated threshold
    cmpRR64(a, RSI, RAX);
    int l_clean = jbeL(a);
    retVal(a, 1);
    a.mark(l_clean);
    retVal(a, 0);
    a.resolve();
    return a.b;
}

// CPUID hypervisor: leaf 1 ECX bit 31 plus the leaf 0x40000000 vendor string.
// Microsoft Hyper-V is allowed on purpose (VBS on physical hosts reports it).
std::vector<uint8_t> AntiDebugModule::genCPUIDCheck() {
    Asm a;
    prologue(a);
    movRI32(a, RAX, 1);
    xorRR32(a, RCX, RCX);
    cpuid(a);
    a.u8(0xF7); a.u8(0xC1); a.u32(0x80000000);                // test ecx, 0x80000000
    int l_clean = jzL(a);

    movRI32(a, RAX, 0x40000000);
    xorRR32(a, RCX, RCX);
    cpuid(a);
    testRR32(a, RAX, RAX);
    int l_clean2 = jzL(a);
    movRspDispR32(a, SL_D + 0, RBX);
    movRspDispR32(a, SL_D + 4, RCX);
    movRspDispR32(a, SL_D + 8, RDX);

    const VmTag tags[] = {
        makeTag("VMwareVMware"),
        makeTag("KVMKVMKVM"),
        makeTag("XenVMMXenVMM"),
        makeTag("VBoxVBoxVBox"),
        makeTag("prl hyperv  "),
        makeTag("bhyve bhyve "),
    };
    std::vector<int> hits;
    for (const VmTag& t : tags) {
        movR64RspDisp(a, RAX, SL_D);
        movRI64(a, RCX, t.lo);
        cmpRR64(a, RAX, RCX);
        int l_next = jnzL(a);
        movR64RspDisp(a, RAX, SL_D + 8);
        movRI64(a, RCX, t.hi);
        cmpRR64(a, RAX, RCX);
        int l_next2 = jnzL(a);
        hits.push_back(jmpL(a));
        a.mark(l_next); a.mark(l_next2);
    }
    retVal(a, 0);
    for (int l : hits) a.mark(l);
    retVal(a, 1);
    a.mark(l_clean); a.mark(l_clean2);
    retVal(a, 0);
    a.resolve();
    return a.b;
}

// FNV-1a64 over [image_base + integrity_rva_, +integrity_size_).
// uint32_t fn(void* image_base) -> 0 when the hash matches, 1 when not.
std::vector<uint8_t> AntiDebugModule::genIntegrityCheck() {
    Asm a;
    prologue(a);
    movRR64(a, RBX, RCX);                                     // rbx = image base
    testRR64(a, RBX, RBX);
    int l_clean = jzL(a);
    movRI32(a, RCX, integrity_size_);
    testRR32(a, RCX, RCX);
    int l_clean2 = jzL(a);
    leaR64BaseDisp(a, RDI, RBX, (int32_t)integrity_rva_);
    movRI64(a, RAX, fnv_basis);
    int l_loop = a.newLabel();
    a.mark(l_loop);
    movzxR32ByteBaseDisp(a, RDX, RDI, 0);
    xorRR64(a, RAX, RDX);
    movRI64(a, RDX, fnv_prime);
    imulRR64(a, RAX, RDX);
    incR64(a, RDI);
    decR32(a, RCX);
    int l_back = jnzL(a);
    a.relLabel.back() = l_loop;                               // loop while the counter lasts
    a.mark(l_back);
    movRI64(a, RDX, integrity_expected_);
    cmpRR64(a, RAX, RDX);
    int l_bad = jnzL(a);
    retVal(a, 0);
    a.mark(l_bad);
    retVal(a, 1);
    a.mark(l_clean); a.mark(l_clean2);
    retVal(a, 0);
    a.resolve();
    return a.b;
}

// ===========================================================================
// public entry points
// ===========================================================================

// Placeholder for non x64 requests (the packer only emits x64 today).
static std::vector<uint8_t> stubClean() { return { 0x31, 0xC0, 0xC3 }; }   // xor eax,eax ; ret

std::vector<uint8_t> AntiDebugModule::generateCheckRoutine(bool is64) {
    if (!is64) return stubClean();

    struct Block { uint32_t id; std::vector<uint8_t> code; };
    std::vector<Block> blocks;
    if (config_.level >= 1) {
        blocks.push_back({ 1u,  genIsDebuggerPresent() });        // PEB
        blocks.push_back({ 2u,  genPEBCheck() });                 // NtGlobalFlag
        blocks.push_back({ 3u,  genHeapCheck() });                // heap flags
        blocks.push_back({ 4u,  genNtQueryInfoProcess() });       // NtQueryInformationProcess
    }
    if (config_.level >= 2) {
        blocks.push_back({ 5u,  genHardwareBreakpointCheck() });  // DR registers
    }
    if (config_.level >= 3) {
        blocks.push_back({ 6u,  genTimingCheck() });              // RDTSC
        blocks.push_back({ 7u,  genCPUIDCheck() });               // hypervisor
    }

    Asm a;
    prologue(a);
    std::vector<int> bodyLabels;
    int l_out = a.newLabel();
    for (const Block& blk : blocks) {
        int l_body = a.newLabel();
        a.u8(0xE8); size_t s = a.n(); a.u32(0);
        a.addRel(s, l_body);
        cmpRI8(a, RAX, 1);
        int l_skip = jnzL(a);
        movRI32(a, RAX, blk.id);
        int l_jump = jmpL(a);
        a.relLabel.back() = l_out;      // unconditional jump straight to the epilogue
        a.mark(l_skip);
        bodyLabels.push_back(l_body);
        (void)l_jump;
    }
    a.mark(l_out);
    epilogue(a);
    for (size_t i = 0; i < blocks.size(); i++) {
        a.mark(bodyLabels[i]);
        a.b.insert(a.b.end(), blocks[i].code.begin(), blocks[i].code.end());
    }
    a.resolve();
    return a.b;
}

std::vector<uint8_t> AntiDebugModule::generateAntiVMRoutine(bool is64) {
    if (!is64) return stubClean();
    return genCPUIDCheck();
}

std::vector<uint8_t> AntiDebugModule::generateIntegrityCheck(bool is64, uint32_t target_rva, uint32_t size) {
    if (!is64) return stubClean();
    integrity_rva_ = target_rva;
    integrity_size_ = size;
    return genIntegrityCheck();
}

// void cb(PVOID DllHandle, DWORD Reason, PVOID Reserved)
// Runs the full check chain on DLL_PROCESS_ATTACH and terminates the process
// when something is detected.
std::vector<uint8_t> AntiDebugModule::generateTLSCallback(bool is64) {
    if (!is64) return stubClean();

    std::vector<uint8_t> body = generateCheckRoutine(true);

    Asm a;
    prologue(a);
    cmpRI8(a, RDX, 1);                        // DLL_PROCESS_ATTACH
    int l_done = jnzL(a);
    int l_body = a.newLabel();
    a.u8(0xE8); size_t s = a.n(); a.u32(0);
    a.addRel(s, l_body);
    testRR32(a, RAX, RAX);
    int l_done2 = jzL(a);
    int l_res = resolveInto(a, H_ExitProcess);
    testRR64(a, RAX, RAX);
    int l_done4 = jzL(a);
    xorRR32(a, RCX, RCX);
    callR64(a, RAX);
    a.mark(l_done); a.mark(l_done2); a.mark(l_done4);
    epilogue(a);
    a.mark(l_body);
    a.b.insert(a.b.end(), body.begin(), body.end());
    a.mark(l_res);
    emitResolver(a);
    a.resolve();
    return a.b;
}

} // namespace np
