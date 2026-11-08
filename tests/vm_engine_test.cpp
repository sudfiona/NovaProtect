// vm_engine_test.cpp - semantic-equivalence test for the VM translator.
//
// For each test case we:
//   1. hand-encode a native x86-64 block ending in `ret`
//   2. translate the block body (sans the final ret) with VMTranslator
//   3. run the native block and the wire interpreter on identical reg files
//   4. assert identical rax + register file
//
// The interpreter is a faithful copy of runtime/prot64.c::np_vm_run so the test
// exercises the exact wire format the packer emits.

#include "vm_isa.h"
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <windows.h>
#include <vector>

using namespace np;
typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef long long i64;

extern "C" u64 np_call_native(void* fn, u64* regs);

// ---- interpreter (mirrors runtime/prot64.c::np_vm_run) --------------------
static u64 vm_run(const u8* code, u64 code_len, const u8* reverse, u64* inout_regs) {
    u64 r[16];
    for (int i = 0; i < 16; i++) r[i] = inout_regs[i];
    u64 ip = 0; u32 guard = 0;
    int zf = 0, cf = 0, sf = 0, of = 0;
    while (ip < code_len) {
        if (++guard > 4000000u) break;
        u8 phys = code[ip++];
        u8 op = reverse[phys];
        u32 reg, dst, src, base; u64 imm;
        switch (op) {
        case WIRE_LOADIMM:
            reg = code[ip++]; imm = 0; for (int k = 0; k < 8; k++) imm |= (u64)code[ip++] << (k * 8);
            if (reg < 16) r[reg] = imm; break;
        case WIRE_LOADB:
            reg = code[ip++]; base = code[ip++]; imm = 0; for (int k = 0; k < 4; k++) imm |= (u64)code[ip++] << (k * 8);
            if (reg < 16 && base < 16) r[reg] = (u64)(*(const u8*)(r[base] + imm)); break;
        case WIRE_LOADQ:
            reg = code[ip++]; base = code[ip++]; imm = 0; for (int k = 0; k < 4; k++) imm |= (u64)code[ip++] << (k * 8);
            if (reg < 16 && base < 16) { const u8* p = (const u8*)(r[base] + imm); r[reg] = 0; for (int k = 0; k < 8; k++) r[reg] |= (u64)p[k] << (k * 8); }
            break;
        case WIRE_STOREB:
            base = code[ip++]; imm = 0; for (int k = 0; k < 4; k++) imm |= (u64)code[ip++] << (k * 8); src = code[ip++];
            if (base < 16 && src < 16) { u8* p = (u8*)(r[base] + imm); *p = (u8)r[src]; } break;
        case WIRE_STOREQ:
            base = code[ip++]; imm = 0; for (int k = 0; k < 4; k++) imm |= (u64)code[ip++] << (k * 8); src = code[ip++];
            if (base < 16 && src < 16) { u8* p = (u8*)(r[base] + imm); for (int k = 0; k < 8; k++) p[k] = (u8)(r[src] >> (k * 8)); } break;
        case WIRE_XOREQ: dst = code[ip++]; src = code[ip++]; if (dst < 16 && src < 16) r[dst] ^= r[src]; break;
        case WIRE_MOVE:  dst = code[ip++]; src = code[ip++]; if (dst < 16 && src < 16) r[dst] = r[src]; break;
        case WIRE_ADD: case WIRE_SUB: case WIRE_MUL: case WIRE_AND: case WIRE_OR: case WIRE_XOR:
        case WIRE_SHL: case WIRE_SHR: case WIRE_SAR: {
            dst = code[ip++]; src = code[ip++];
            if (dst < 16 && src < 16) {
                u64 a = r[dst], b = r[src];
                switch (op) {
                case WIRE_ADD: { u64 res = a + b; cf = (res < a); of = (((a ^ res) & (b ^ res)) >> 63) & 1; r[dst] = res; } break;
                case WIRE_SUB: { u64 res = a - b; cf = (a < b); of = (((a ^ b) & (a ^ res)) >> 63) & 1; r[dst] = res; } break;
                case WIRE_MUL: r[dst] = a * b; break;
                case WIRE_AND: r[dst] = a & b; break;
                case WIRE_OR:  r[dst] = a | b; break;
                case WIRE_XOR: r[dst] = a ^ b; break;
                case WIRE_SHL: r[dst] = a << (b & 63u); break;
                case WIRE_SHR: r[dst] = a >> (b & 63u); break;
                case WIRE_SAR: r[dst] = (u64)(((i64)a) >> (b & 63u)); break;
                }
                if (op != WIRE_MUL) { zf = (r[dst] == 0); sf = (int)((r[dst] >> 63) & 1); }
            }
            break;
        }
        case WIRE_NOT: reg = code[ip++]; if (reg < 16) r[reg] = ~r[reg]; break;
        case WIRE_NEG: reg = code[ip++]; if (reg < 16) { u64 a = r[reg]; r[reg] = (u64)(-(i64)a); cf = (a != 0); zf = (r[reg] == 0); sf = (int)((r[reg] >> 63) & 1); } break;
        case WIRE_CMP: { u32 aR = code[ip++], bR = code[ip++]; if (aR < 16 && bR < 16) { u64 a = r[aR], b = r[bR], res = a - b; zf = (res == 0); cf = (a < b); sf = (int)((res >> 63) & 1); of = (int)((((a ^ b) & (a ^ res)) >> 63) & 1); } break; }
        case WIRE_TEST: { u32 aR = code[ip++], bR = code[ip++]; if (aR < 16 && bR < 16) { u64 res = r[aR] & r[bR]; zf = (res == 0); cf = 0; of = 0; sf = (int)((res >> 63) & 1); } break; }
        case WIRE_MULI: case WIRE_ADDI: case WIRE_SUBI: case WIRE_ANDI: case WIRE_RORI:
        case WIRE_XORI: case WIRE_ORI: case WIRE_SHRI: case WIRE_CMPI:
            reg = code[ip++]; imm = 0; for (int k = 0; k < 8; k++) imm |= (u64)code[ip++] << (k * 8);
            if (reg < 16) {
                u64 a = r[reg], res = 0;
                switch (op) {
                case WIRE_MULI: r[reg] *= imm; break;
                case WIRE_ADDI: res = a + imm; cf = (res < a); r[reg] = res; zf = (res == 0); sf = (int)((res >> 63) & 1); break;
                case WIRE_SUBI: res = a - imm; cf = (a < imm); r[reg] = res; zf = (res == 0); sf = (int)((res >> 63) & 1); break;
                case WIRE_ANDI: r[reg] &= imm; zf = (r[reg] == 0); sf = (int)((r[reg] >> 63) & 1); cf = 0; break;
                case WIRE_ORI:  r[reg] |= imm; zf = (r[reg] == 0); sf = (int)((r[reg] >> 63) & 1); cf = 0; break;
                case WIRE_XORI: r[reg] ^= imm; zf = (r[reg] == 0); sf = (int)((r[reg] >> 63) & 1); cf = 0; break;
                case WIRE_SHRI: r[reg] = a >> (imm & 63u); zf = (r[reg] == 0); sf = (int)((r[reg] >> 63) & 1); break;
                case WIRE_RORI: { u32 s = (u32)(imm & 63u); r[reg] = (r[reg] >> s) | (r[reg] << ((64u - s) & 63u)); } break;
                case WIRE_CMPI: res = a - imm; zf = (res == 0); cf = (a < imm); sf = (int)((res >> 63) & 1); of = (int)((((a ^ imm) & (a ^ res)) >> 63) & 1); break;
                }
            }
            break;
        case WIRE_JMP: case WIRE_JE: case WIRE_JNE: case WIRE_JZ: case WIRE_JNZ:
        case WIRE_JAE: case WIRE_JB: case WIRE_JGE: case WIRE_JL: case WIRE_JG: case WIRE_JLE: {
            u32 t = 0; for (int k = 0; k < 4; k++) t |= (u32)code[ip++] << (k * 8);
            int take;
            switch (op) {
            case WIRE_JMP: take = 1; break;
            case WIRE_JE: case WIRE_JZ: take = zf; break;
            case WIRE_JNE: case WIRE_JNZ: take = !zf; break;
            case WIRE_JAE: take = !cf; break;
            case WIRE_JB: take = cf; break;
            case WIRE_JGE: take = (sf == of); break;
            case WIRE_JL: take = (sf != of); break;
            case WIRE_JG: take = (!zf && (sf == of)); break;
            default: take = (zf || (sf != of)); break;
            }
            if (take) ip = t;
            break;
        }
        case WIRE_HALT: ip = code_len; break;
        case WIRE_ENDBR: break;
        // Flag-preserving address arithmetic: exactly LEA's semantics, so the
        // flag variables are deliberately left untouched here. If the runtime
        // version ever starts writing flags, the cmp/lea/jne and
        // cmp/store/jne cases above stop matching native.
        case WIRE_ADDRADD: dst = code[ip++]; src = code[ip++];
            if (dst < 16 && src < 16) r[dst] += r[src]; break;
        case WIRE_ADDRSHLI: dst = code[ip++]; imm = 0;
            for (int k = 0; k < 8; k++) imm |= (u64)code[ip++] << (k * 8);
            if (dst < 16) r[dst] <<= (imm & 63u); break;
        case WIRE_ADDRADDI: dst = code[ip++]; imm = 0;
            for (int k = 0; k < 8; k++) imm |= (u64)code[ip++] << (k * 8);
            if (dst < 16) r[dst] += imm; break;
        default: ip = code_len; break;
        }
    }
    for (int i = 0; i < 16; i++) inout_regs[i] = r[i];
    return r[0];
}

// ---- native execution harness --------------------------------------------
static int g_pass = 0, g_fail = 0;
static std::vector<u8> g_stack(64 * 1024);

// Runs `bytes` (a native block WITHOUT ret) with the given register file,
// appends `ret`, and writes the resulting register file back to regs.
static u64 run_native(const std::vector<u8>& bytes, u64* regs) {
    std::vector<u8> code = bytes;
    code.push_back(0xC3); // ret
    void* mem = VirtualAlloc(0, code.size() + 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem) { printf("VirtualAlloc failed\n"); return 0; }
    memcpy(mem, code.data(), code.size());
    // guest stack top (16-byte aligned, grows down)
    u64 top = ((u64)g_stack.data() + g_stack.size() - 64) & ~(u64)15;
    regs[4] = top; // rsp
    u64 ret = np_call_native(mem, regs);
    VirtualFree(mem, 0, MEM_RELEASE);
    return ret;
}

struct Case { const char* name; std::vector<u8> code; };

static void check(const Case& c, u64* initRegs) {
    // 1. native
    u64 nregs[16]; memcpy(nregs, initRegs, sizeof(nregs));
    u64 nrax = run_native(c.code, nregs);

    // 2. translate + interpret
    VMLoweredBlock blk = VMTranslator::translate(c.code.data(), c.code.size(), 0x1000, 0x140000000ull, 0, 0);
    if (!blk.ok) {
        printf("[FAIL] %-22s translator rejected: %s\n", c.name, blk.skipReason.c_str());
        g_fail++; return;
    }
    u64 vregs[16]; memcpy(vregs, initRegs, sizeof(vregs));
    vregs[4] = initRegs[4]; // guest rsp same (no native stack used by interp)
    u64 vrax = vm_run(blk.bytecode.data(), blk.bytecode.size(), blk.reverse.data(), vregs);

    bool ok = (vrax == nrax);
    // Compare the GPRs the block is allowed to change. rsp is free (the
    // interpreter never uses the native stack), and r14/r15 are the translator's
    // address-build scratch: the packer forces every register the lowered stream
    // writes into the trampoline save mask, so their final value is restored
    // around the region and is not part of the guest-visible contract. Every
    // other register must match exactly, which is what catches a translator that
    // clobbers a live guest value.
    for (int i = 0; i < 16 && ok; i++) {
        if (i == 4 || i == 14 || i == 15) continue;
        if (nregs[i] != vregs[i]) {
            printf("[FAIL] %-22s reg r%d native=%016llx vm=%016llx\n",
                   c.name, i, (unsigned long long)nregs[i], (unsigned long long)vregs[i]);
            ok = false;
        }
    }
    if (ok) { printf("[ ok ] %-22s rax=%016llx (%u insns)\n", c.name,
                     (unsigned long long)nrax, blk.insnsTranslated); g_pass++; }
    else { printf("[FAIL] %-22s rax native=%016llx vm=%016llx\n", c.name,
                  (unsigned long long)nrax, (unsigned long long)vrax); g_fail++; }
}

// ---- x86-64 encoders (minimal, hand-rolled) ------------------------------
static void e(std::vector<u8>& v, std::initializer_list<u8> b) { for (u8 x : b) v.push_back(x); }

// REX.W prefix + opcode reg,rm  (ModRM mod=11)
static void rr(std::vector<u8>& v, u8 op, int dst, int src, bool w = true) {
    u8 rex = 0x40 | (w ? 8 : 0) | ((src >= 8) ? 4 : 0) | ((dst >= 8) ? 1 : 0);
    if (rex != 0x40) v.push_back(rex);
    v.push_back(op);
    v.push_back(0xC0 | ((dst & 7) << 3) | (src & 7));
}
// opcode r/m, imm32 (via 0x81 /digit)
static void ri(std::vector<u8>& v, u8 op, int digit, int dst, int32_t imm, bool w = true) {
    u8 rex = 0x40 | (w ? 8 : 0) | ((dst >= 8) ? 1 : 0);
    if (rex != 0x40) v.push_back(rex);
    v.push_back(op);
    v.push_back(0xC0 | ((digit & 7) << 3) | (dst & 7));
    v.push_back(imm & 0xFF); v.push_back((imm >> 8) & 0xFF);
    v.push_back((imm >> 16) & 0xFF); v.push_back((imm >> 24) & 0xFF);
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("vm_engine semantic tests\n");
    printf("----------------------------------------\n");

    // case 1: mov / add / sub  (reg,reg forms)
    { Case c; c.name = "mov/add/sub";
      rr(c.code, 0x8B, 0, 1);      // mov rax, rcx
      rr(c.code, 0x03, 0, 2);      // add rax, rdx
      rr(c.code, 0x2B, 0, 3);      // sub rax, rbx
      u64 init[16] = {0}; init[1] = 100; init[2] = 55; init[3] = 7;
      check(c, init);
    }

    // case 2: immediates + xor/and/or
    { Case c; c.name = "imm/xor/and/or";
      ri(c.code, 0x81, 0, 0, 0x1234);   // add rax, 0x1234
      rr(c.code, 0x33, 0, 1);           // xor rax, rcx
      ri(c.code, 0x81, 4, 0, 0xFF00);   // and rax, 0xFF00   (81 /4)
      rr(c.code, 0x0B, 0, 2);           // or  rax, rdx
      u64 init[16] = {0}; init[1] = 0xFFFF; init[2] = 0x10000;
      check(c, init);
    }

    // case 3: shifts by CL
    { Case c; c.name = "shl/shr/sar cl";
      rr(c.code, 0xD3, 4, 0);        // shl rax, cl
      rr(c.code, 0xD3, 5, 0);        // shr rax, dl  (src=rdx)
      rr(c.code, 0xD3, 7, 0);        // sar rax, bl  (src=rbx)
      u64 init[16] = {0}; init[1] = 3; init[2] = 2; init[3] = 4;
      check(c, init);
    }

    // case 4: inc/dec/neg/not
    { Case c; c.name = "inc/dec/neg/not";
      rr(c.code, 0xFF, 0, 0);           // inc rax
      rr(c.code, 0xFF, 1, 1);           // dec rcx
      rr(c.code, 0xF7, 3, 2);           // neg rdx
      rr(c.code, 0xF7, 2, 3);           // not rbx
      u64 init[16] = {0}; init[0] = 10; init[1] = 10; init[2] = 5; init[3] = 0x0F;
      check(c, init);
    }

    // case 5: cmp + conditional branch (finite)
    { Case c; c.name = "cmp/jne";
      rr(c.code, 0x03, 0, 2);           // add rax, rdx
      ri(c.code, 0x81, 7, 0, 0);        // cmp rax, 0
      c.code.push_back(0x0F); c.code.push_back(0x85); // jne +6
      c.code.push_back(0x07); c.code.push_back(0); c.code.push_back(0); c.code.push_back(0);
      ri(c.code, 0x81, 0, 1, 0x1111);   // add rcx, 0x1111  (skipped when taken)
      ri(c.code, 0x81, 0, 2, 0x2222);   // add rdx, 0x2222
      u64 init[16] = {0}; init[2] = 5;
      check(c, init);
    }
    // case 5b: same but zero result -> branch not taken
    { Case c; c.name = "cmp/je nottaken";
      rr(c.code, 0x2B, 0, 0);           // sub rax, rax -> 0  (2B: dst=rax src=rax)
      ri(c.code, 0x81, 7, 0, 0);        // cmp rax, 0
      c.code.push_back(0x0F); c.code.push_back(0x85); // jne +6
      c.code.push_back(0x07); c.code.push_back(0); c.code.push_back(0); c.code.push_back(0);
      ri(c.code, 0x81, 0, 1, 0x1111);   // add rcx, 0x1111
      ri(c.code, 0x81, 0, 2, 0x2222);   // add rdx, 0x2222
      u64 init[16] = {0}; init[2] = 5;
      check(c, init);
    }

    // case 6: lea
    { Case c; c.name = "lea";
      e(c.code, {0x48, 0x8D, 0x41, 0x40}); // lea rax, [rcx+0x40]
      rr(c.code, 0x03, 0, 2);              // add rax, rdx
      u64 init[16] = {0}; init[1] = 0x1000; init[2] = 0x20;
      check(c, init);
    }

    // case 6b: flag transparency across a memory operand.
    //
    // `cmp` sets the flags, then a store must not disturb them, then `jne`
    // consumes the cmp. The displacement is what makes this bite: a bare [rdi]
    // only needs a register move, so the address build emits no arithmetic and
    // the bug hides. With [rdi+0x10] the build must emit real arithmetic, and
    // an ordinary ADDI there overwrites zf/sf with the result of the pointer sum
    // and flips the branch. rax stays 0, so a correct build keeps ZF=1 from the
    // cmp, does NOT take the branch, runs `mov rcx, rax`, and rcx ends at 0.
    // The regressed build takes the branch instead and leaves rcx at its entry
    // value - which is why rcx starts non-zero here: with everything zeroed the
    // two outcomes would be indistinguishable and the test would prove nothing.
    { Case c; c.name = "cmp/store/jne flags";
      rr(c.code, 0x2B, 0, 0);                 // sub rax, rax        -> rax = 0, ZF=1
      ri(c.code, 0x81, 7, 0, 0);              // cmp rax, 0          -> ZF=1
      e(c.code, {0x48, 0x89, 0x47, 0x10});    // mov [rdi+0x10], rax
      c.code.push_back(0x0F); c.code.push_back(0x85); // jne +3 (skip the mov)
      c.code.push_back(0x03); c.code.push_back(0); c.code.push_back(0); c.code.push_back(0);
      rr(c.code, 0x8B, 1, 0);                 // mov rcx, rax  (skipped when taken)
      rr(c.code, 0x03, 3, 2);                 // add rbx, rdx  (branch target)
      u64 init[16] = {0}; init[7] = (u64)g_stack.data() + 4096; // rdi -> mapped scratch
      init[1] = 0xCAFE;                        // rcx: must be overwritten with 0
      check(c, init);
    }

    // case 6c: flag transparency for LEA. lea is architecturally forbidden from
    // touching the flags, so `cmp` / `lea` / `jne` must branch on the cmp.
    { Case c; c.name = "cmp/lea/jne flags";
      rr(c.code, 0x2B, 0, 0);                 // sub rax, rax        -> ZF=1
      ri(c.code, 0x81, 7, 0, 0);              // cmp rax, 0
      e(c.code, {0x48, 0x8D, 0x4F, 0x08});    // lea rcx, [rdi+8]
      c.code.push_back(0x0F); c.code.push_back(0x85); // jne +3 (skip the mov)
      c.code.push_back(0x03); c.code.push_back(0); c.code.push_back(0); c.code.push_back(0);
      rr(c.code, 0x8B, 2, 1);                 // mov rdx, rcx  (skipped when taken)
      rr(c.code, 0x03, 3, 0);                 // add rbx, rax  (branch target)
      u64 init[16] = {0}; init[7] = (u64)g_stack.data() + 4096;
      check(c, init);
    }

    // case 6d: scaled index. [rcx + rdx*4 + 0x10] is the form the wire ISA has
    // no direct encoding for; the translator synthesizes index*scale into a
    // scratch. Verifies both the scaling and that the index register is left
    // intact (scaling in place would corrupt a live value).
    { Case c; c.name = "scaled index";
      e(c.code, {0x48, 0x8D, 0x44, 0x91, 0x10}); // lea rax, [rcx+rdx*4+0x10]
      rr(c.code, 0x03, 1, 2);                    // add rcx, rdx
      u64 init[16] = {0}; init[1] = 0x100; init[2] = 0x7;
      check(c, init);
    }

    // case 6e: scaled-index load, 2x and 8x, to cover the other shift amounts.
    { Case c; c.name = "scaled index 2x/8x";
      e(c.code, {0x48, 0x8D, 0x04, 0x51});       // lea rax, [rcx+rdx*2]
      e(c.code, {0x48, 0x8D, 0x1C, 0xC1});       // lea rbx, [rcx+rax*8]
      rr(c.code, 0x2B, 1, 3);                    // sub rcx, rbx
      u64 init[16] = {0}; init[1] = 5; init[2] = 9;
      check(c, init);
    }

    // case 7: long mixed sequence
    { Case c; c.name = "mixed long";
      rr(c.code, 0x8B, 0, 1);      // mov rax, rcx
      ri(c.code, 0x81, 0, 0, 0x1000);  // add rax, 0x1000
      rr(c.code, 0x33, 0, 2);      // xor rax, rdx
      rr(c.code, 0xD3, 4, 0);      // shl rax, cl
      rr(c.code, 0x2B, 0, 3);      // sub rax, rbx
      rr(c.code, 0xFF, 0, 0);      // inc rax
      rr(c.code, 0x0B, 0, 2);      // or  rax, rdx
      u64 init[16] = {0}; init[1] = 0xDEAD; init[2] = 0xBEEF; init[3] = 0x111; init[1+0]=0xDEAD;
      init[1] = 0x12345678; init[2] = 0x9ABCDEF0; init[3] = 0x55; init[0] = 0;
      // note: shl rax, cl uses rcx as shift count
      init[1] = 3;
      check(c, init);
    }

    printf("----------------------------------------\n");
    printf("TESTS: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}