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
#include "wire_table.h"
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <windows.h>
#include <vector>

using namespace np;
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef long long i64;
typedef int i32;
typedef short i16;
typedef signed char i8;

extern "C" u64 np_call_native(void* fn, u64* regs);

// ---- interpreter (mirrors runtime/prot64.c::np_vm_run) --------------------
static int parity_even(u64 res) {
    u8 b = (u8)res;
    b ^= b >> 4; b ^= b >> 2; b ^= b >> 1;
    return (int)((~b) & 1);
}
static u64 vm_run(const u8* code, u64 code_len, const u8* reverse, u64* inout_regs,
                   u64 imgBase) {
    u64 r[52];
    for (int i = 0; i < 52; i++) r[i] = inout_regs[i];
    u8 xm[256];
    for (int i = 0; i < 256; i++) xm[i] = 0;
    u64 ip = 0; u32 guard = 0;
    int zf = 0, cf = 0, sf = 0, of = 0, pf = 0, df = 0;
    while (ip < code_len) {
        if (++guard > 4000000u) break;
        u8 phys = code[ip++];
        u8 op = reverse[phys];
        u32 reg, dst, src, base; u64 imm;
        switch (op) {
        case WIRE_LOADIMM:
            reg = code[ip++]; imm = 0; for (int k = 0; k < 8; k++) imm |= (u64)code[ip++] << (k * 8);
            if (reg < 18) r[reg] = imm; break;
        case WIRE_LOADB:
            reg = code[ip++]; base = code[ip++]; imm = 0; for (int k = 0; k < 4; k++) imm |= (u64)code[ip++] << (k * 8);
            if (reg < 18 && base < 18) r[reg] = (u64)(*(const u8*)(r[base] + imm)); break;
        case WIRE_LOADQ:
            reg = code[ip++]; base = code[ip++]; imm = 0; for (int k = 0; k < 4; k++) imm |= (u64)code[ip++] << (k * 8);
            if (reg < 18 && base < 18) { const u8* p = (const u8*)(r[base] + imm); r[reg] = 0; for (int k = 0; k < 8; k++) r[reg] |= (u64)p[k] << (k * 8); }
            break;
        case WIRE_STOREB:
            base = code[ip++]; imm = 0; for (int k = 0; k < 4; k++) imm |= (u64)code[ip++] << (k * 8); src = code[ip++];
            if (base < 18 && src < 18) { u8* p = (u8*)(r[base] + imm); *p = (u8)r[src]; } break;
        case WIRE_STOREQ:
            base = code[ip++]; imm = 0; for (int k = 0; k < 4; k++) imm |= (u64)code[ip++] << (k * 8); src = code[ip++];
            if (base < 18 && src < 18) { u8* p = (u8*)(r[base] + imm); for (int k = 0; k < 8; k++) p[k] = (u8)(r[src] >> (k * 8)); } break;
        case WIRE_XOREQ: dst = code[ip++]; src = code[ip++]; if (dst < 18 && src < 18) r[dst] ^= r[src]; break;
        case WIRE_MOVE:  dst = code[ip++]; src = code[ip++]; if (dst < 18 && src < 18) r[dst] = r[src]; break;
        case WIRE_ADD: case WIRE_SUB: case WIRE_MUL: case WIRE_AND: case WIRE_OR: case WIRE_XOR:
        case WIRE_SHL: case WIRE_SHR: case WIRE_SAR: {
            dst = code[ip++]; src = code[ip++];
            if (dst < 18 && src < 18) {
                u64 a = r[dst], b = r[src];
                switch (op) {
                case WIRE_ADD: { u64 res = a + b; cf = (res < a); of = (((a ^ res) & (b ^ res)) >> 63) & 1; r[dst] = res; pf = parity_even(res); } break;
                case WIRE_SUB: { u64 res = a - b; cf = (a < b); of = (((a ^ b) & (a ^ res)) >> 63) & 1; r[dst] = res; pf = parity_even(res); } break;
                case WIRE_MUL: r[dst] = a * b; break;
                case WIRE_AND: r[dst] = a & b; break;
                case WIRE_OR:  r[dst] = a | b; break;
                case WIRE_XOR: r[dst] = a ^ b; break;
                case WIRE_SHL: r[dst] = a << (b & 63u); break;
                case WIRE_SHR: r[dst] = a >> (b & 63u); break;
                case WIRE_SAR: r[dst] = (u64)(((i64)a) >> (b & 63u)); break;
                }
                if (op != WIRE_MUL) { zf = (r[dst] == 0); sf = (int)((r[dst] >> 63) & 1); pf = parity_even(r[dst]); }
            }
            break;
        }
        case WIRE_NOT: reg = code[ip++]; if (reg < 18) r[reg] = ~r[reg]; break;
        case WIRE_NEG: reg = code[ip++]; if (reg < 18) { u64 a = r[reg]; r[reg] = (u64)(-(i64)a); cf = (a != 0); zf = (r[reg] == 0); sf = (int)((r[reg] >> 63) & 1); pf = parity_even(r[reg]); } break;
        case WIRE_CMP: { u32 aR = code[ip++], bR = code[ip++]; if (aR < 16 && bR < 16) { u64 a = r[aR], b = r[bR], res = a - b; zf = (res == 0); cf = (a < b); sf = (int)((res >> 63) & 1); of = (int)((((a ^ b) & (a ^ res)) >> 63) & 1); pf = parity_even(res); } break; }
        case WIRE_TEST: { u32 aR = code[ip++], bR = code[ip++]; if (aR < 16 && bR < 16) { u64 res = r[aR] & r[bR]; zf = (res == 0); cf = 0; of = 0; sf = (int)((res >> 63) & 1); pf = parity_even(res); } break; }
        case WIRE_MULI: case WIRE_ADDI: case WIRE_SUBI: case WIRE_ANDI: case WIRE_RORI:
        case WIRE_XORI: case WIRE_ORI: case WIRE_SHRI: case WIRE_CMPI:
            reg = code[ip++]; imm = 0; for (int k = 0; k < 8; k++) imm |= (u64)code[ip++] << (k * 8);
            if (reg < 18) {
                u64 a = r[reg], res = 0;
                switch (op) {
                case WIRE_MULI: r[reg] *= imm; break;
                case WIRE_ADDI: res = a + imm; cf = (res < a); of = (int)((((a ^ res) & (imm ^ res)) >> 63) & 1); r[reg] = res; zf = (res == 0); sf = (int)((res >> 63) & 1); pf = parity_even(res); break;
                case WIRE_SUBI: res = a - imm; cf = (a < imm); of = (int)((((a ^ imm) & (a ^ res)) >> 63) & 1); r[reg] = res; zf = (res == 0); sf = (int)((res >> 63) & 1); pf = parity_even(res); break;
                case WIRE_ANDI: r[reg] &= imm; zf = (r[reg] == 0); sf = (int)((r[reg] >> 63) & 1); cf = 0; pf = parity_even(r[reg]); break;
                case WIRE_ORI:  r[reg] |= imm; zf = (r[reg] == 0); sf = (int)((r[reg] >> 63) & 1); cf = 0; pf = parity_even(r[reg]); break;
                case WIRE_XORI: r[reg] ^= imm; zf = (r[reg] == 0); sf = (int)((r[reg] >> 63) & 1); cf = 0; pf = parity_even(r[reg]); break;
                case WIRE_SHRI: r[reg] = a >> (imm & 63u); zf = (r[reg] == 0); sf = (int)((r[reg] >> 63) & 1); pf = parity_even(r[reg]); break;
                case WIRE_RORI: { u32 s = (u32)(imm & 63u); r[reg] = (r[reg] >> s) | (r[reg] << ((64u - s) & 63u)); } break;
                case WIRE_CMPI: res = a - imm; zf = (res == 0); cf = (a < imm); sf = (int)((res >> 63) & 1); of = (int)((((a ^ imm) & (a ^ res)) >> 63) & 1); pf = parity_even(res); break;
                }
            }
            break;
        case WIRE_JMP: case WIRE_JE: case WIRE_JNE: case WIRE_JZ: case WIRE_JNZ:
        case WIRE_JAE: case WIRE_JB: case WIRE_JGE: case WIRE_JL: case WIRE_JG: case WIRE_JLE:
        case WIRE_JA: case WIRE_JBE: case WIRE_JS: case WIRE_JNS: case WIRE_JO: case WIRE_JNO:
        case WIRE_JP: case WIRE_JNP: {
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
            case WIRE_JLE: take = (zf || (sf != of)); break;
            case WIRE_JA: take = (!cf && !zf); break;
            case WIRE_JBE: take = (cf || zf); break;
            case WIRE_JS: take = sf; break;
            case WIRE_JNS: take = !sf; break;
            case WIRE_JO: take = of; break;
            case WIRE_JNO: take = !of; break;
            case WIRE_JP: take = pf; break;
            case WIRE_JNP: take = !pf; break;
            default: take = 0; break;
            }
            if (take) ip = t;
            break;
        }
        case WIRE_HALT: ip = code_len; break;
        case WIRE_ENDBR: break;
        case WIRE_MOVD: {
            u32 dd = code[ip++], ss = code[ip++];
            if (dd < 18 && ss < 18) r[dd] = (u32)r[ss];
            break;
        }
        // 32-bit operand forms: the result is zero-extended and the flags
        // come from 32-bit arithmetic (mirrors the runtime *D handlers).
        case WIRE_ADDD: case WIRE_SUBD: case WIRE_ANDD: case WIRE_ORD:
        case WIRE_XORD: case WIRE_MULD: {
            u32 dd = code[ip++], ss = code[ip++];
            if (dd < 18 && ss < 18) {
                u32 a = (u32)r[dd], b = (u32)r[ss], res = 0;
                switch (op) {
                case WIRE_ADDD: res = a + b; cf = (res < a); of = (int)((((a ^ b) & (a ^ res)) >> 31) & 1); break;
                case WIRE_SUBD: res = a - b; cf = (a < b); of = (int)((((a ^ b) & (a ^ res)) >> 31) & 1); break;
                case WIRE_ANDD: res = a & b; cf = 0; of = 0; break;
                case WIRE_ORD:  res = a | b; cf = 0; of = 0; break;
                case WIRE_XORD: res = a ^ b; cf = 0; of = 0; break;
                case WIRE_MULD: res = a * b; break;
                }
                r[dd] = res;
                zf = (res == 0); sf = (int)((res >> 31) & 1); pf = parity_even(res);
            }
            break;
        }
        case WIRE_CMPD: case WIRE_TESTD: {
            u32 aR = code[ip++], bR = code[ip++];
            if (aR < 18 && bR < 18) {
                u32 a = (u32)r[aR], b = (u32)r[bR], res = 0;
                if (op == WIRE_CMPD) { res = a - b; cf = (a < b); of = (int)((((a ^ b) & (a ^ res)) >> 31) & 1); }
                else { res = a & b; cf = 0; of = 0; }
                zf = (res == 0); sf = (int)((res >> 31) & 1); pf = parity_even(res);
            }
            break;
        }
        case WIRE_ADDID: case WIRE_SUBID: case WIRE_ANDID: case WIRE_ORID:
        case WIRE_XORID: case WIRE_CMPID: case WIRE_SHLID: case WIRE_SHRID:
        case WIRE_SARID: {
            u32 dd = code[ip++]; u64 immv = 0;
            for (int k = 0; k < 8; k++) immv |= (u64)code[ip++] << (k * 8);
            if (dd < 18) {
                u32 a = (u32)r[dd], b = (u32)immv, res = 0;
                switch (op) {
                case WIRE_ADDID: res = a + b; cf = (res < a); of = (int)((((a ^ b) & (a ^ res)) >> 31) & 1); r[dd] = res; break;
                case WIRE_SUBID: res = a - b; cf = (a < b); of = (int)((((a ^ b) & (a ^ res)) >> 31) & 1); r[dd] = res; break;
                case WIRE_ANDID: res = a & b; cf = 0; of = 0; r[dd] = res; break;
                case WIRE_ORID:  res = a | b; cf = 0; of = 0; r[dd] = res; break;
                case WIRE_XORID: res = a ^ b; cf = 0; of = 0; r[dd] = res; break;
                case WIRE_CMPID: res = a - b; cf = (a < b); of = (int)((((a ^ b) & (a ^ res)) >> 31) & 1); break;
                case WIRE_SHLID: res = a << (b & 31); r[dd] = res; break;
                case WIRE_SHRID: res = a >> (b & 31); r[dd] = res; break;
                case WIRE_SARID: res = (u32)((int)a >> (b & 31)); r[dd] = res; break;
                }
                zf = (res == 0); sf = (int)((res >> 31) & 1); pf = parity_even(res);
            }
            break;
        }
        case WIRE_NEGD: case WIRE_NOTD: {
            u32 dd = code[ip++];
            if (dd < 18) {
                u32 a = (u32)r[dd];
                if (op == WIRE_NEGD) { u32 res = (u32)(0u - a); r[dd] = res; cf = (a != 0); zf = (res == 0); sf = (int)((res >> 31) & 1); of = (a == 0x80000000u); pf = parity_even(res); }
                else { r[dd] = (u32)(~a); }
            }
            break;
        }
        case WIRE_CMPB: case WIRE_CMPW: case WIRE_TESTB: case WIRE_TESTW: {
            u32 aR = code[ip++], bR = code[ip++];
            if (aR < 18 && bR < 18) {
                int bits = (op == WIRE_CMPW || op == WIRE_TESTW) ? 16 : 8;
                u64 mask = (bits == 16) ? 0xFFFF : 0xFF;
                u64 va = r[aR] & mask, vb = r[bR] & mask, res;
                if (op == WIRE_CMPB || op == WIRE_CMPW) {
                    res = (va - vb) & mask;
                    zf = (res == 0); cf = (va < vb);
                    of = (int)((((va ^ vb) & (va ^ res)) >> (bits - 1)) & 1);
                } else {
                    res = va & vb;
                    zf = (res == 0); cf = 0; of = 0;
                }
                sf = (int)((res >> (bits - 1)) & 1);
                pf = parity_even(res);
            }
            break;
        }
        case WIRE_IMGADD: {
            u32 dd = code[ip++]; u32 rva = 0;
            for (int k = 0; k < 4; k++) rva |= (u32)code[ip++] << (k * 8);
            if (dd < 18) r[dd] = imgBase + (u64)rva;
            break;
        }
        case WIRE_INSB: {
            u32 dd = code[ip++], ss = code[ip++];
            if (dd < 18 && ss < 18) r[dd] = (r[dd] & ~0xFFull) | (r[ss] & 0xFFull);
            break;
        }
        case WIRE_INSW: {
            u32 dd = code[ip++], ss = code[ip++];
            if (dd < 18 && ss < 18) r[dd] = (r[dd] & ~0xFFFFull) | (r[ss] & 0xFFFFull);
            break;
        }
        case WIRE_EXITJMP: {
            u32 rva = 0; for (int k = 0; k < 4; k++) rva |= (u32)code[ip++] << (k * 8);
            // Native exit: stop the interpreter. The register file at this
            // point is exactly what the real epilogue would see. (The unit
            // harness compares state here; the packer-level tests execute the
            // real native tail.)
            (void)rva; (void)imgBase;
            ip = code_len;
            break;
        }
        case WIRE_CALL: {
            u32 e = 0; for (int k = 0; k < 4; k++) e |= (u32)code[ip++] << (k * 8);
            u64 target;
            if (e & 0x80000000u) target = r[e & 0x1Fu];
            else target = imgBase + (u64)e;
            if (target) np_call_native((void*)(unsigned long long)target, r);
            break;
        }
        // Flag-preserving address arithmetic: exactly LEA's semantics, so the
        // flag variables are deliberately left untouched here. If the runtime
        // version ever starts writing flags, the cmp/lea/jne and
        // cmp/store/jne cases above stop matching native.
        case WIRE_ADDRADD: dst = code[ip++]; src = code[ip++];
            if (dst < 18 && src < 18) r[dst] += r[src]; break;
        case WIRE_ADDRSHLI: dst = code[ip++]; imm = 0;
            for (int k = 0; k < 8; k++) imm |= (u64)code[ip++] << (k * 8);
            if (dst < 18) r[dst] <<= (imm & 63u); break;
        case WIRE_ADDRADDI: dst = code[ip++]; imm = 0;
            for (int k = 0; k < 8; k++) imm |= (u64)code[ip++] << (k * 8);
            if (dst < 18) r[dst] += imm; break;
        case WIRE_ADDRSHRI: dst = code[ip++]; imm = 0;
            for (int k = 0; k < 8; k++) imm |= (u64)code[ip++] << (k * 8);
            if (dst < 18) {
                u32 n = (u32)(imm & 63u);
                if (n) { u64 sign = (u64)0 - (r[dst] >> 63); r[dst] = (r[dst] >> n) | (sign << (64 - n)); }
            }
            break;
        case WIRE_SETCF: dst = code[ip++];
            if (dst < 18) cf = (int)(r[dst] & 1u); break;
        case WIRE_SAHF: src = code[ip++];
            if (src < 18) {
                u8 ah = (u8)((r[src] >> 8) & 0xFF);
                cf = (ah >> 0) & 1; pf = (ah >> 2) & 1; zf = (ah >> 6) & 1; sf = (ah >> 7) & 1;
            }
            break;
        case WIRE_LAHF: dst = code[ip++];
            if (dst < 18) {
                u64 ah = 0x02u;
                if (cf) ah |= 0x01u; if (pf) ah |= 0x04u; if (zf) ah |= 0x40u; if (sf) ah |= 0x80u;
                r[dst] = (r[dst] & ~0xFF00ull) | (ah << 8);
            }
            break;
        case WIRE_NALU: {
            u32 sel = code[ip++]; dst = code[ip++]; src = code[ip++];
            if (dst >= 18 || src >= 18) break;
            u32 wcode = (sel >> 4) & 3, nop = sel & 15;
            u32 bits = (wcode == 0) ? 8u : (wcode == 1) ? 16u : (wcode == 2) ? 32u : 64u;
            u64 mask = (bits == 64u) ? ~(u64)0 : (((u64)1 << bits) - 1);
            u64 sign = (u64)1 << (bits - 1);
            u64 a = r[dst] & mask, v = r[src] & mask, res = 0;
            int ncf = cf, nof = of;
            switch (nop) {
            case 0: res = (a + v) & mask; ncf = ((a + v) > mask);
                    nof = (int)((((a ^ res) & (v ^ res)) & sign) ? 1 : 0); break;
            case 1: res = (a - v) & mask; ncf = (a < v);
                    nof = (int)((((a ^ v) & (a ^ res)) & sign) ? 1 : 0); break;
            case 2: { u64 t = a + v + (u64)(cf ? 1 : 0); res = t & mask; ncf = (t > mask);
                    nof = (int)((((a ^ res) & (v ^ res)) & sign) ? 1 : 0); break; }
            case 3: { u64 b = v + (u64)(cf ? 1 : 0); res = (a - b) & mask; ncf = (a < b);
                    nof = (int)((((a ^ v) & (a ^ res)) & sign) ? 1 : 0); break; }
            case 4: res = a & v; ncf = 0; nof = 0; break;
            case 5: res = a | v; ncf = 0; nof = 0; break;
            case 6: res = a ^ v; ncf = 0; nof = 0; break;
            case 7: res = (~a) & mask; break;                     /* NOT: no flags */
            case 8: res = (a + 1) & mask;
                    nof = (int)((res & sign) && !(a & sign) ? 1 : 0); break;
            case 9: res = (a - 1) & mask;
                    nof = (int)((a & sign) && !(res & sign) ? 1 : 0); break;
            case 10: res = (0 - a) & mask; ncf = (a != 0); nof = (int)(res == sign); break;
            case 11: case 12: case 13: case 14: case 15: {
                u32 cntMask = (bits == 64u) ? 63u : 31u;
                u32 cnt = (u32)(v & cntMask);
                if (nop >= 14) cnt = (u32)(v & (bits - 1u));
                if (cnt == 0) { res = a; break; }   /* flags untouched */
                if (nop == 11) {
                    if (cnt >= bits) { res = 0; ncf = 0; nof = 0; }
                    else {
                        res = (a << cnt) & mask; ncf = (int)((a >> (bits - cnt)) & 1u);
                        nof = (cnt == 1u) ? (int)((((res & sign) ? 1 : 0) ^ (u32)ncf)) : 0;
                    }
                }
                else if (nop == 12) { res = (a >> cnt) & mask; ncf = (int)((a >> (cnt - 1u)) & 1u);
                                      nof = (cnt == 1u) ? (int)((a & sign) ? 1 : 0) : 0; }
                else if (nop == 13) {
                    u64 x;
                    if (cnt >= bits) x = (a & sign) ? mask : 0;
                    else { x = a >> cnt; if (a & sign) x |= ((mask << (bits - cnt)) & mask); }
                    res = x & mask; ncf = (int)((a >> (cnt - 1u)) & 1u); nof = 0;
                } else {
                    u32 n = cnt & (bits - 1u);
                    if (n == 0) { res = a; break; }
                    if (nop == 14) { res = ((a << n) | (a >> (bits - n))) & mask; ncf = (int)(res & 1u);
                                     nof = (cnt == 1u) ? (int)((((res & sign) ? 1 : 0) ^ (u32)ncf)) : 0; }
                    else { res = ((a >> n) | (a << (bits - n))) & mask; ncf = (int)((res >> (bits - 1)) & 1u);
                           nof = (cnt == 1u) ? (int)(((((res >> (bits - 1)) & 1u) ^ ((res >> (bits - 2)) & 1u)))) : 0; }
                }
                break;
            }
            default: res = a; break;
            }
            if (nop != 7) {
                cf = ncf; of = nof;
                zf = (res == 0); sf = (int)((res >> (bits - 1)) & 1u); pf = parity_even(res);
            }
            if (bits >= 64u) r[dst] = res;
            else if (bits == 32u) r[dst] = res & 0xFFFFFFFFu;
            else r[dst] = (r[dst] & ~mask) | res;
            break;
        }
        case WIRE_MULQ: {
            u32 sel = code[ip++]; dst = code[ip++]; u32 hi = code[ip++]; src = code[ip++];
            if (dst >= 18 || hi >= 18 || src >= 18) break;
            u64 a = r[dst], b = r[src];
            u64 a0 = a & 0xFFFFFFFFull, a1 = a >> 32, b0 = b & 0xFFFFFFFFull, b1 = b >> 32;
            u64 p0 = a0 * b0, p1 = a0 * b1, p2 = a1 * b0, p3 = a1 * b1;
            u64 mid = (p0 >> 32) + (p1 & 0xFFFFFFFFull) + (p2 & 0xFFFFFFFFull);
            u64 lo64 = (p0 & 0xFFFFFFFFull) | ((mid & 0xFFFFFFFFull) << 32);
            u64 hi64 = p3 + (p1 >> 32) + (p2 >> 32) + (mid >> 32);
            if (sel & 1u) { if ((i64)a < 0) hi64 -= b; if ((i64)b < 0) hi64 -= a; }
            r[dst] = lo64; r[hi] = hi64;
            cf = of = (sel & 1u) ? (hi64 != ((lo64 >> 63) ? ~(u64)0 : 0)) : (hi64 != 0);
            zf = (lo64 == 0); sf = (int)((lo64 >> 63) & 1u); pf = parity_even(lo64);
            break;
        }
        case WIRE_DIVQ: case WIRE_IDIVQ: {
            u32 lo = code[ip++], hi = code[ip++], den = code[ip++];
            if (lo >= 18 || hi >= 18 || den >= 18) break;
            u64 nLo = r[lo], nHi = r[hi], d = r[den], uD = d;
            int negQ = 0, negR = 0;
            if (op == WIRE_IDIVQ) {
                if ((i64)nHi < 0) { negQ = 1; negR = 1;
                    u64 tLo = ~nLo + 1; nHi = ~nHi + (tLo == 0 ? 1 : 0); nLo = tLo; }
                if ((i64)d < 0) { negQ = !negQ; uD = (u64)0 - d; }
            }
            if (uD == 0) break;
            u64 qq = 0, rr = 0, overflow = 0;
            for (int i = 127; i >= 0; i--) {
                u64 top = (nHi >> 63) & 1u;
                rr = (rr << 1) | top;
                nHi = (nHi << 1) | ((nLo >> 63) & 1u);
                nLo <<= 1;
                if (rr >= uD) { rr -= uD; if (i >= 64) overflow = 1; else qq |= (u64)1 << i; }
            }
            if (overflow) break;
            if (negQ) qq = (u64)0 - qq;
            if (negR) rr = (u64)0 - rr;
            r[lo] = qq; r[hi] = rr;
            break;
        }
        case WIRE_BITOP: {
            u32 sel = code[ip++]; dst = code[ip++]; src = code[ip++];
            if (dst >= 18 || src >= 18) break;
            u32 bop = sel & 3, isMem = (sel >> 2) & 1, is32 = (sel >> 3) & 1;
            u64 bitIndex = r[src]; u8 byteVal; u32 bit;
            if (isMem) {
                u64 addr = r[dst] + (u64)((i64)bitIndex >> 3);
                byteVal = *(u8*)(unsigned long long)addr;
                bit = (u32)(bitIndex & 7u);
                cf = (byteVal >> bit) & 1;
                if (bop != 0) {
                    u8 nb = (bop == 1) ? (u8)(byteVal | (1u << bit))
                          : (bop == 2) ? (u8)(byteVal & ~(1u << bit))
                          : (u8)(byteVal ^ (1u << bit));
                    *(u8*)(unsigned long long)addr = nb;
                }
            } else {
                u64 m = is32 ? 31u : 63u;
                bitIndex &= m; bit = (u32)bitIndex;
                byteVal = (u8)((r[dst] >> bitIndex) & 1u);
                cf = byteVal & 1;
                if (bop != 0) {
                    u64 v = r[dst];
                    if (bop == 1) v |= ((u64)1 << bitIndex);
                    else if (bop == 2) v &= ~((u64)1 << bitIndex);
                    else v ^= ((u64)1 << bitIndex);
                    if (is32) v &= 0xFFFFFFFFull;
                    r[dst] = v;
                }
            }
            break;
        }
        case WIRE_LOADW: {
            u32 d = code[ip++], b = code[ip++]; u32 o = 0;
            for (int k = 0; k < 4; k++) o |= (u32)code[ip++] << (k * 8);
            if (d < 18 && b < 18) { const u8* p = (const u8*)(unsigned long long)(r[b] + (u64)o);
                r[d] = (u64)p[0] | ((u64)p[1] << 8); }
            break;
        }
        case WIRE_LOADD: {
            u32 d = code[ip++], b = code[ip++]; u32 o = 0;
            for (int k = 0; k < 4; k++) o |= (u32)code[ip++] << (k * 8);
            if (d < 18 && b < 18) { const u8* p = (const u8*)(unsigned long long)(r[b] + (u64)o);
                u64 v = 0; for (int k = 0; k < 4; k++) v |= (u64)p[k] << (k * 8); r[d] = v; }
            break;
        }
        case WIRE_LOADSB: {
            u32 d = code[ip++], b = code[ip++]; u32 o = 0;
            for (int k = 0; k < 4; k++) o |= (u32)code[ip++] << (k * 8);
            if (d < 18 && b < 18) r[d] = (u64)(i64)(i8)*(const u8*)(unsigned long long)(r[b] + (u64)o);
            break;
        }
        case WIRE_LOADSW: {
            u32 d = code[ip++], b = code[ip++]; u32 o = 0;
            for (int k = 0; k < 4; k++) o |= (u32)code[ip++] << (k * 8);
            if (d < 18 && b < 18) { const u8* p = (const u8*)(unsigned long long)(r[b] + (u64)o);
                u16 v = (u16)((u32)p[0] | ((u32)p[1] << 8)); r[d] = (u64)(i64)(i16)v; }
            break;
        }
        case WIRE_LOADSD: {
            u32 d = code[ip++], b = code[ip++]; u32 o = 0;
            for (int k = 0; k < 4; k++) o |= (u32)code[ip++] << (k * 8);
            if (d < 18 && b < 18) { const u8* p = (const u8*)(unsigned long long)(r[b] + (u64)o);
                u32 v = 0; for (int k = 0; k < 4; k++) v |= (u32)p[k] << (k * 8); r[d] = (u64)(i64)(i32)v; }
            break;
        }
        case WIRE_STOREW: {
            u32 b = code[ip++]; u32 o = 0;
            for (int k = 0; k < 4; k++) o |= (u32)code[ip++] << (k * 8);
            u32 s2 = code[ip++];
            if (b < 18 && s2 < 18) { u8* p = (u8*)(unsigned long long)(r[b] + (u64)o);
                p[0] = (u8)r[s2]; p[1] = (u8)(r[s2] >> 8); }
            break;
        }
        case WIRE_STORED: {
            u32 b = code[ip++]; u32 o = 0;
            for (int k = 0; k < 4; k++) o |= (u32)code[ip++] << (k * 8);
            u32 s2 = code[ip++];
            if (b < 18 && s2 < 18) { u8* p = (u8*)(unsigned long long)(r[b] + (u64)o);
                for (int k = 0; k < 4; k++) p[k] = (u8)(r[s2] >> (k * 8)); }
            break;
        }
        case WIRE_ROL: case WIRE_ROR: {
            dst = code[ip++]; src = code[ip++];
            if (dst < 18 && src < 18) {
                u32 s = (u32)(r[src] & 63u);
                if (s) r[dst] = (op == WIRE_ROL) ? ((r[dst] << s) | (r[dst] >> (64u - s)))
                                                 : ((r[dst] >> s) | (r[dst] << (64u - s)));
            }
            break;
        }
        case WIRE_ROLI: {
            reg = code[ip++]; imm = 0;
            for (int k = 0; k < 8; k++) imm |= (u64)code[ip++] << (k * 8);
            u32 s = (u32)(imm & 63u);
            if (reg < 18 && s) r[reg] = (r[reg] << s) | (r[reg] >> ((64u - s) & 63u));
            break;
        }
        case WIRE_SHLI: {
            reg = code[ip++]; imm = 0;
            for (int k = 0; k < 8; k++) imm |= (u64)code[ip++] << (k * 8);
            if (reg < 18) r[reg] <<= (imm & 63u);
            break;
        }
        case WIRE_SARI: {
            reg = code[ip++]; imm = 0;
            for (int k = 0; k < 8; k++) imm |= (u64)code[ip++] << (k * 8);
            if (reg < 18) r[reg] = (u64)(((i64)r[reg]) >> (imm & 63u));
            break;
        }
        case WIRE_MOVSXD: {
            dst = code[ip++]; src = code[ip++];
            if (dst < 18 && src < 18) r[dst] = (u64)(i64)(i32)r[src];
            break;
        }
        case WIRE_MOVZXB: {
            dst = code[ip++]; src = code[ip++];
            if (dst < 18 && src < 18) r[dst] = (u64)(u8)r[src];
            break;
        }
        case WIRE_MOVZXW: {
            dst = code[ip++]; src = code[ip++];
            if (dst < 18 && src < 18) r[dst] = (u64)(u16)r[src];
            break;
        }
        case WIRE_MOVSXB: {
            dst = code[ip++]; src = code[ip++];
            if (dst < 18 && src < 18) r[dst] = (u64)(i64)(i8)r[src];
            break;
        }
        case WIRE_MOVSXW: {
            dst = code[ip++]; src = code[ip++];
            if (dst < 18 && src < 18) r[dst] = (u64)(i64)(i16)r[src];
            break;
        }
        case WIRE_PUSHF: {
            u32 sp = code[ip++];
            if (sp < 18) {
                u64 v = 0x2u;
                if (cf) v |= 0x1u;
                if (pf) v |= 0x4u;
                if (zf) v |= 0x40u;
                if (sf) v |= 0x80u;
                if (df) v |= 0x400u;
                if (of) v |= 0x800u;
                r[sp] -= 8u;
                u8* p = (u8*)(unsigned long long)r[sp];
                for (int k = 0; k < 8; k++) p[k] = (u8)(v >> (k * 8));
            }
            break;
        }
        case WIRE_POPF: {
            u32 sp = code[ip++];
            if (sp < 18) {
                const u8* p = (const u8*)(unsigned long long)r[sp];
                u64 v = 0; for (int k = 0; k < 8; k++) v |= (u64)p[k] << (k * 8);
                r[sp] += 8u;
                cf = (int)(v & 1u);
                pf = (int)((v >> 2) & 1u);
                zf = (int)((v >> 6) & 1u);
                sf = (int)((v >> 7) & 1u);
                df = (int)((v >> 10) & 1u);
                of = (int)((v >> 11) & 1u);
            }
            break;
        }
        case WIRE_MULB: {
            u32 sel = code[ip++]; dst = code[ip++]; src = code[ip++];
            if (dst >= 18 || src >= 18) break;
            u64 av = r[dst], dv = r[src];
            u32 prod;
            if (sel & 1u) {
                i32 a8 = (i32)(i8)(u8)(av & 0xFFu), d8 = (i32)(i8)(u8)(dv & 0xFFu);
                prod = (u32)(u16)(u32)(i32)(a8 * d8);
            } else {
                prod = (u32)(u16)((av & 0xFFu) * (dv & 0xFFu));
            }
            r[dst] = (av & ~0xFFFFull) | (u64)prod;
            cf = of = (sel & 1u) ? ((i32)(i16)(u16)prod != (i32)(i8)(u8)(prod & 0xFFu))
                                 : ((prod >> 8) != 0u);
            zf = ((prod & 0xFFFFu) == 0u);
            sf = (int)((prod >> 15) & 1u);
            pf = parity_even(prod);
            break;
        }
        case WIRE_DIVB: {
            u32 sel = code[ip++]; dst = code[ip++]; src = code[ip++];
            if (dst >= 18 || src >= 18) break;
            u64 av = r[dst], dv = r[src];
            u32 d8 = (u32)(dv & 0xFFu), q, rm;
            if (sel & 1u) {
                i32 num = (i32)(i16)(u16)(av & 0xFFFFu), dd = (i32)(i8)(u8)d8;
                if (dd == 0) break;
                i32 qq = num / dd, rr = num % dd;
                if (qq > 127 || qq < -128) break;
                q = (u32)(u8)(i8)qq; rm = (u32)(u8)(i8)rr;
            } else {
                u32 num = (u32)(av & 0xFFFFu);
                if (d8 == 0) break;
                u32 qq = num / d8, rr = num % d8;
                if (qq > 0xFFu) break;
                q = qq; rm = rr;
            }
            r[dst] = (av & ~0xFFFFull) | (u64)(q & 0xFFu) | ((u64)(rm & 0xFFu) << 8);
            break;
        }
        case WIRE_SBB: case WIRE_ADC: case WIRE_SBBD: case WIRE_ADCD: {
            dst = code[ip++]; src = code[ip++];
            if (dst >= 18 || src >= 18) break;
            int is32 = (op == WIRE_SBBD || op == WIRE_ADCD);
            int isAdd = (op == WIRE_ADC || op == WIRE_ADCD);
            u64 mask = is32 ? 0xFFFFFFFFull : ~(u64)0;
            u32 bits = is32 ? 32u : 64u;
            u64 sign = (u64)1 << (bits - 1);
            u64 a = r[dst] & mask, b = r[src] & mask, res;
            if (isAdd) {
                u64 t = a + b + (u64)(cf ? 1 : 0);
                res = t & mask; cf = (t > mask);
                of = (int)((((a ^ res) & (b ^ res)) & sign) ? 1 : 0);
            } else {
                u64 borrow = (u64)(cf ? 1 : 0), sub = b + borrow;
                res = (a - sub) & mask; cf = (a < sub);
                of = (int)((((a ^ b) & (a ^ res)) & sign) ? 1 : 0);
            }
            r[dst] = is32 ? res : res;
            zf = (res == 0); sf = (int)((res >> (bits - 1)) & 1u); pf = parity_even(res);
            break;
        }
        case WIRE_SBBI: case WIRE_ADCI: {
            reg = code[ip++]; imm = 0;
            for (int k = 0; k < 8; k++) imm |= (u64)code[ip++] << (k * 8);
            if (reg >= 18) break;
            int isAdd = (op == WIRE_ADCI);
            u64 a = r[reg], b = imm, res;
            if (isAdd) {
                u64 t = a + b + (u64)(cf ? 1 : 0);
                res = t; cf = (res < a) || (cf && res == a);
                of = (int)((((a ^ res) & (b ^ res)) >> 63) & 1);
            } else {
                u64 borrow = (u64)(cf ? 1 : 0), sub = b + borrow;
                res = a - sub; cf = (a < sub);
                of = (int)((((a ^ b) & (a ^ res)) >> 63) & 1);
            }
            r[reg] = res; zf = (res == 0); sf = (int)((res >> 63) & 1); pf = parity_even(res);
            break;
        }
        case WIRE_XLOADD: {
            u32 d = code[ip++], g = code[ip++];
            if (d >= 20 && d < 36 && g < 18) {
                u8* p = xm + (u64)(d - 20) * 16;
                for (int k = 0; k < 16; k++) p[k] = 0;
                for (int k = 0; k < 8; k++) p[k] = (u8)(r[g] >> (k * 8));
            }
            break;
        }
        case WIRE_XSTORED: {
            u32 g = code[ip++], sd = code[ip++];
            if (g < 18 && sd >= 20 && sd < 36) {
                const u8* p = xm + (u64)(sd - 20) * 16;
                u64 v = 0;
                for (int k = 0; k < 8; k++) v |= (u64)p[k] << (k * 8);
                r[g] = v;
            }
            break;
        }
        case WIRE_XALU: case WIRE_XALUI: {
            u32 xop = code[ip++]; u32 xfmt = code[ip++];
            dst = code[ip++]; src = code[ip++];
            u32 ximm = 0;
            if (op == WIRE_XALUI) ximm = code[ip++];
            if (dst < 20 || dst >= 36 || src < 20 || src >= 36) break;
            u8* dx = xm + (u64)(dst - 20) * 16;
            const u8* sx = xm + (u64)(src - 20) * 16;
            auto ld32 = [&](const u8* p) { return (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24); };
            auto ld64 = [&](const u8* p) { return (u64)ld32(p) | ((u64)ld32(p + 4) << 32); };
            auto st32 = [&](u8* p, u32 v) { p[0] = (u8)v; p[1] = (u8)(v >> 8); p[2] = (u8)(v >> 16); p[3] = (u8)(v >> 24); };
            auto st64 = [&](u8* p, u64 v) { st32(p, (u32)v); st32(p + 4, (u32)(v >> 32)); };
            auto f32 = [&](const u8* p) { union { u32 b; float f; } u; u.b = ld32(p); return u.f; };
            auto f64 = [&](const u8* p) { union { u64 b; double d; } u; u.b = ld64(p); return u.d; };
            auto sf32 = [&](u8* p, float f) { union { u32 b; float f; } u; u.f = f; st32(p, u.b); };
            auto sf64 = [&](u8* p, double d) { union { u64 b; double d; } u; u.d = d; st64(p, u.b); };
            if (xop >= 16 && xop <= 18) {
                /* conversion */
                int round = (xop == 18);
                switch (xfmt) {
                case 0: sf32(dx, (float)(i32)ld32(sx)); break;
                case 1: sf64(dx, (double)(i32)ld32(sx)); break;
                case 2: sf64(dx, (double)(i64)ld64(sx)); break;
                case 3: sf32(dx, (float)(i64)ld64(sx)); break;
                case 4: case 5: case 6: case 7: {
                    int nan = 0; double f = 0;
                    if (xfmt == 4) { f = (double)f32(sx); nan = (((ld32(sx) & 0x7F800000u) == 0x7F800000u) && (ld32(sx) & 0x007FFFFFu)); }
                    else if (xfmt == 5) { f = f64(sx); nan = (((ld64(sx) & 0x7FF0000000000000ull) == 0x7FF0000000000000ull) && (ld64(sx) & 0x000FFFFFFFFFFFFFull)); }
                    else if (xfmt == 6) { f = f64(sx); nan = (((ld64(sx) & 0x7FF0000000000000ull) == 0x7FF0000000000000ull) && (ld64(sx) & 0x000FFFFFFFFFFFFFull)); }
                    else { f = (double)f32(sx); nan = (((ld32(sx) & 0x7F800000u) == 0x7F800000u) && (ld32(sx) & 0x007FFFFFu)); }
                    if (xfmt == 4 || xfmt == 5) {
                        i32 v = (i32)0x80000000;
                        if (!nan && f >= -2147483648.0 && f <= 2147483649.0) {
                            if (!round) v = (i32)f;
                            else { double neg = (f < 0), t = neg ? -f : f; i64 iv = (i64)t; double fr = t - (double)iv;
                                   if (fr > 0.5 || (fr == 0.5 && (iv & 1))) iv++; v = (i32)(neg ? -iv : iv); }
                        }
                        st64(dx, (u64)(u32)v);
                    } else {
                        i64 v = (i64)0x8000000000000000ull;
                        if (!nan && f >= -9223372036854775808.0 && f < 9223372036854775808.0) {
                            if (!round) v = (i64)f;
                            else { double neg = (f < 0), t = neg ? -f : f; i64 iv = (i64)t; double fr = t - (double)iv;
                                   if (fr > 0.5 || (fr == 0.5 && (iv & 1))) iv++; v = neg ? -iv : iv; }
                        }
                        st64(dx, (u64)v);
                    }
                    break;
                }
                case 8: sf64(dx, (double)f32(sx)); break;
                case 9: sf32(dx, (float)f64(sx)); break;
                case 10: for (u32 k = 0; k < 4; k++) sf32(dx + k * 4, (float)(i32)ld32(sx + k * 4)); break;
                case 11: for (u32 k = 0; k < 4; k++) st32(dx + k * 4, (u32)(i32)f32(sx + k * 4)); break;
                case 12: for (u32 k = 0; k < 2; k++) sf64(dx + k * 8, (double)(i32)ld32(sx + k * 4)); break;
                case 13: for (u32 k = 0; k < 2; k++) st32(dx + k * 4, (u32)(i32)f64(sx + k * 8)); st32(dx + 8, 0); st32(dx + 12, 0); break;
                case 14: { double a = (double)f32(sx), b = (double)f32(sx + 4); sf64(dx, a); sf64(dx + 8, b); break; }
                case 15: { float a = (float)f64(sx), b = (float)f64(sx + 8); sf32(dx, a); sf32(dx + 4, b); break; }
                default: break;
                }
                break;
            }
            if (xop == 27) { u32 n = (xfmt == 2) ? 4 : 8; for (u32 k = 0; k < n; k++) dx[k] = sx[k]; break; }
            if (xop >= 0 && xop <= 5) {
                if (xfmt == 0 || xfmt == 2) {
                    u32 lanes = (xfmt == 0) ? 4 : 1;
                    for (u32 k = 0; k < lanes; k++) {
                        float a = f32(dx + k * 4), b = f32(sx + k * 4), res;
                        switch (xop) {
                        case 0: res = a + b; break; case 1: res = a - b; break;
                        case 2: res = a * b; break; case 3: res = a / b; break;
                        case 4: { union { u32 x; float f; } ua, ub; ua.f = a; ub.f = b;
                                  int na = ((ua.x & 0x7F800000u) == 0x7F800000u) && (ua.x & 0x7FFFFFu);
                                  int nb2 = ((ub.x & 0x7F800000u) == 0x7F800000u) && (ub.x & 0x7FFFFFu);
                                  res = (na || nb2) ? b : ((a == 0.0f && b == 0.0f) ? b : (a < b ? a : b)); break; }
                        default: { union { u32 x; float f; } ua, ub; ua.f = a; ub.f = b;
                                   int na = ((ua.x & 0x7F800000u) == 0x7F800000u) && (ua.x & 0x7FFFFFu);
                                   int nb2 = ((ub.x & 0x7F800000u) == 0x7F800000u) && (ub.x & 0x7FFFFFu);
                                   res = (na || nb2) ? b : ((a == 0.0f && b == 0.0f) ? b : (a > b ? a : b)); break; }
                        }
                        sf32(dx + k * 4, res);
                    }
                } else if (xfmt == 1 || xfmt == 3) {
                    u32 lanes = (xfmt == 1) ? 2 : 1;
                    for (u32 k = 0; k < lanes; k++) {
                        double a = f64(dx + k * 8), b = f64(sx + k * 8), res;
                        switch (xop) {
                        case 0: res = a + b; break; case 1: res = a - b; break;
                        case 2: res = a * b; break; case 3: res = a / b; break;
                        case 4: { union { u64 x; double d; } ua, ub; ua.d = a; ub.d = b;
                                  int na = ((ua.x & 0x7FF0000000000000ull) == 0x7FF0000000000000ull) && (ua.x & 0x000FFFFFFFFFFFFFull);
                                  int nb2 = ((ub.x & 0x7FF0000000000000ull) == 0x7FF0000000000000ull) && (ub.x & 0x000FFFFFFFFFFFFFull);
                                  res = (na || nb2) ? b : ((a == 0.0 && b == 0.0) ? b : (a < b ? a : b)); break; }
                        default: { union { u64 x; double d; } ua, ub; ua.d = a; ub.d = b;
                                   int na = ((ua.x & 0x7FF0000000000000ull) == 0x7FF0000000000000ull) && (ua.x & 0x000FFFFFFFFFFFFFull);
                                   int nb2 = ((ub.x & 0x7FF0000000000000ull) == 0x7FF0000000000000ull) && (ub.x & 0x000FFFFFFFFFFFFFull);
                                   res = (na || nb2) ? b : ((a == 0.0 && b == 0.0) ? b : (a > b ? a : b)); break; }
                        }
                        sf64(dx + k * 8, res);
                    }
                }
                break;
            }
            if (xop == 6) {   /* sqrt */
                if (xfmt == 0 || xfmt == 2) { for (u32 k = 0; k < ((xfmt == 0) ? 4 : 1); k++) sf32(dx + k * 4, (float)__builtin_sqrtf(f32(sx + k * 4))); }
                else { for (u32 k = 0; k < ((xfmt == 1) ? 2 : 1); k++) sf64(dx + k * 8, __builtin_sqrt(f64(sx + k * 8))); }
                break;
            }
            if (xop >= 7 && xop <= 10) {
                for (u32 k = 0; k < 16; k++) {
                    u8 a = dx[k], b = sx[k], res;
                    switch (xop) {
                    case 7: res = (u8)(a & b); break; case 8: res = (u8)(a | b); break;
                    case 9: res = (u8)(a ^ b); break; default: res = (u8)((~a) & b); break;
                    }
                    dx[k] = res;
                }
                break;
            }
            if (xop >= 11 && xop <= 15) {
                /* compare: ximm carries the predicate when present */
                u32 pred = (op == WIRE_XALUI) ? (ximm & 7u)
                         : (xop == 11) ? 0u : (xop == 14) ? 1u : (xop == 13) ? 2u : (xop == 15) ? 7u : 6u;
                u32 lanes = (xfmt == 0) ? 4 : (xfmt == 1) ? 2 : (xfmt == 2 || xfmt == 3) ? 1
                          : (xfmt == 4) ? 16 : (xfmt == 5) ? 8 : (xfmt == 6) ? 4 : 2;
                int scalar = (xfmt == 2 || xfmt == 3);
                int unord0 = 0, lt0 = 0, eq0 = 0;
                for (u32 k = 0; k < lanes; k++) {
                    int lt = 0, eq = 0, ord = 1;
                    if (xfmt == 0 || xfmt == 2) {
                        float a = f32(dx + k * 4), b = f32(sx + k * 4);
                        union { u32 x; float f; } ua, ub; ua.f = a; ub.f = b;
                        if (((ua.x & 0x7F800000u) == 0x7F800000u) && (ua.x & 0x7FFFFFu)) ord = 0;
                        if (((ub.x & 0x7F800000u) == 0x7F800000u) && (ub.x & 0x7FFFFFu)) ord = 0;
                        if (ord) { lt = a < b; eq = a == b; }
                        u32 mv = 0;
                        switch (pred) {
                        case 0: mv = eq ? 0xFFFFFFFFu : 0; break; case 1: mv = lt ? 0xFFFFFFFFu : 0; break;
                        case 2: mv = (lt || eq) ? 0xFFFFFFFFu : 0; break; case 3: mv = ord ? 0 : 0xFFFFFFFFu; break;
                        case 4: mv = eq ? 0 : 0xFFFFFFFFu; break; case 5: mv = lt ? 0 : 0xFFFFFFFFu; break;
                        case 6: mv = (lt || eq) ? 0 : 0xFFFFFFFFu; break; default: mv = ord ? 0xFFFFFFFFu : 0; break;
                        }
                        if (!scalar) st32(dx + k * 4, mv);
                    } else if (xfmt == 1 || xfmt == 3) {
                        double a = f64(dx + k * 8), b = f64(sx + k * 8);
                        union { u64 x; double d; } ua, ub; ua.d = a; ub.d = b;
                        if (((ua.x & 0x7FF0000000000000ull) == 0x7FF0000000000000ull) && (ua.x & 0x000FFFFFFFFFFFFFull)) ord = 0;
                        if (((ub.x & 0x7FF0000000000000ull) == 0x7FF0000000000000ull) && (ub.x & 0x000FFFFFFFFFFFFFull)) ord = 0;
                        if (ord) { lt = a < b; eq = a == b; }
                        u64 mv = 0;
                        switch (pred) {
                        case 0: mv = eq ? ~(u64)0 : 0; break; case 1: mv = lt ? ~(u64)0 : 0; break;
                        case 2: mv = (lt || eq) ? ~(u64)0 : 0; break; case 3: mv = ord ? 0 : ~(u64)0; break;
                        case 4: mv = eq ? 0 : ~(u64)0; break; case 5: mv = lt ? 0 : ~(u64)0; break;
                        case 6: mv = (lt || eq) ? 0 : ~(u64)0; break; default: mv = ord ? ~(u64)0 : 0; break;
                        }
                        if (!scalar) st64(dx + k * 8, mv);
                    }
                    if (!ord) unord0 = 1;
                    if (k == 0) { lt0 = lt; eq0 = eq; }
                }
                if (unord0) { zf = 1; pf = 1; cf = 1; }
                else { zf = eq0; pf = 0; cf = lt0; }
                of = 0; sf = 0;
                break;
            }
            break;
        }
        default: ip = code_len; break;
        }
    }
    for (int i = 0; i < 52; i++) inout_regs[i] = r[i];
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
    u64 nregs[52]; memcpy(nregs, initRegs, 16 * sizeof(u64)); nregs[16] = nregs[17] = nregs[18] = nregs[19] = 0;
    u64 nrax = run_native(c.code, nregs);

    // 2. translate + interpret
    // allowIslands = false: every instruction - pops, leave, ret - is lowered
    // into wire ops so the translated block computes the *complete* register
    // effect of the input. The harness can only compare states where the
    // interpreter stops; a native-epilogue island would leave the tail
    // (leave/pop/ret) unexecuted on the VM side while run_native executes it,
    // and the two states legitimately differ (the packer-level tests are
    // where the island's native tail runs for real).
    VMLoweredBlock blk = VMTranslator::translate(c.code.data(), c.code.size(),
                                                  (u64)c.code.data(), (u64)c.code.data(),
                                                  0, 0, true, 0, false);
    if (!blk.ok) {
        printf("[FAIL] %-22s translator rejected: %s\n", c.name, blk.skipReason.c_str());
        g_fail++; return;
    }
    // Stream integrity: the emitted bytecode has to walk exactly, instruction
    // by instruction, to a final HALT with nothing left over. A stray operand
    // byte (a missing brace around an emit) decodes as an unknown opcode and
    // silently halts the interpreter - the *result* can still look right when
    // the dropped code is a trailing HALT, so this assertion is what actually
    // catches it. It is also mapping-independent, unlike the flaky symptom.
    {
        uint32_t ip = 0;
        int guard = 0;
        bool wellFormed = false;
        while (ip < blk.bytecode.size() && guard++ < 10000) {
            uint8_t phys = blk.bytecode[ip];
            uint8_t logical = blk.reverse[phys];
            uint32_t il = wireInsnLength(logical);
            if (il == 0 || ip + il > blk.bytecode.size()) break;
            if (logical == WIRE_HALT) { wellFormed = (ip + il == blk.bytecode.size()); break; }
            ip += il;
        }
        if (!wellFormed) {
            printf("[FAIL] %-22s malformed bytecode (%zu bytes):", c.name, blk.bytecode.size());
            for (size_t k = 0; k < blk.bytecode.size(); k++) printf(" %02X", blk.bytecode[k]);
            printf("\n");
            g_fail++; return;
        }
    }
    u64 vregs[52]; memcpy(vregs, initRegs, 16 * sizeof(u64)); vregs[16] = vregs[17] = vregs[18] = vregs[19] = 0;
    vregs[4] = initRegs[4]; // guest rsp same (no native stack used by interp)
    u64 vrax = vm_run(blk.bytecode.data(), blk.bytecode.size(), blk.reverse.data(), vregs,
                     (u64)c.code.data());

    bool ok = (vrax == nrax);
    // Compare every guest GPR except rsp (the interpreter never uses the
    // native stack). r14/r15 used to be excluded because they doubled as
    // translator scratch; the scratch slots now live outside the guest file,
    // so a clobbered r14/r15 is a real failure again.
    for (int i = 0; i < 16 && ok; i++) {
        if (i == 4) continue;
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

// Bridge-cut case: the unhandled instruction stops the VM chunk and executes
// natively between two chunks in production. Assert the cut geometry (cutAt /
// resumeOff the packer resumes from) and compare the translated *prefix*
// against the same bytes run natively - the bridged instruction and anything
// after it are outside the block by design.
static void checkBridge(const Case& c, u64* initRegs, uint32_t expectCutAt) {
    VMLoweredBlock blk = VMTranslator::translate(c.code.data(), c.code.size(),
                                                  (u64)c.code.data(), (u64)c.code.data(),
                                                  0, 0, true, 0, false);
    if (!blk.ok || !blk.cut || blk.cutAt != expectCutAt ||
        blk.resumeOff != expectCutAt + 0 /* set below per bytes */ ) {
        // resumeOff must land just past the bridged instruction; the exact
        // length is the distance from cutAt to the next known boundary - for
        // these cases the bridge is the last instruction, so resumeOff is the
        // full size.
        if (!blk.ok || !blk.cut || blk.cutAt != expectCutAt ||
            blk.resumeOff != (uint32_t)c.code.size()) {
            printf("[FAIL] %-22s bridge geometry cut=%u resume=%u (want cut=%u resume=%u)\n",
                   c.name, blk.cutAt, blk.resumeOff, expectCutAt, (uint32_t)c.code.size());
            g_fail++;
            return;
        }
    }
    if (expectCutAt == 0) {
        // empty prefix: nothing to compare semantically
        printf("[ ok ] %-22s bridge at +0 (native, chunk resumes at %u)\n",
               c.name, blk.resumeOff);
        g_pass++;
        return;
    }
    u64 nregs[52]; memcpy(nregs, initRegs, 16 * sizeof(u64)); nregs[16] = nregs[17] = nregs[18] = nregs[19] = 0;
    std::vector<u8> prefix(c.code.begin(), c.code.begin() + expectCutAt);
    u64 nrax = run_native(prefix, nregs);

    u64 vregs[52]; memcpy(vregs, initRegs, 16 * sizeof(u64)); vregs[16] = vregs[17] = vregs[18] = vregs[19] = 0;
    vregs[4] = initRegs[4];
    u64 vrax = vm_run(blk.bytecode.data(), blk.bytecode.size(), blk.reverse.data(), vregs,
                     (u64)c.code.data());
    bool ok = (vrax == nrax);
    for (int i = 0; i < 16 && ok; i++) {
        if (i == 4) continue;
        if (nregs[i] != vregs[i]) {
            printf("[FAIL] %-22s prefix reg r%d native=%016llx vm=%016llx\n",
                   c.name, i, (unsigned long long)nregs[i], (unsigned long long)vregs[i]);
            ok = false;
        }
    }
    if (ok) { printf("[ ok ] %-22s bridge at +%u, prefix rax=%016llx\n",
                     c.name, expectCutAt, (unsigned long long)nrax); g_pass++; }
    else { printf("[FAIL] %-22s prefix rax native=%016llx vm=%016llx\n", c.name,
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

    // case 8: jae (AE/NB). CF=0 => taken. This used to be lowered to JB, which
    // inverts the branch; the native-vs-vm comparison below is what catches it.
    { Case c; c.name = "cmp/jae taken";
      ri(c.code, 0x81, 7, 1, 0);              // cmp rcx, 0  (rcx=5 -> CF=0, ZF=0)
      c.code.push_back(0x0F); c.code.push_back(0x83); // jae +7
      c.code.push_back(0x07); c.code.push_back(0); c.code.push_back(0); c.code.push_back(0);
      ri(c.code, 0x81, 0, 2, 0x1111);         // add rdx, 0x1111  (skipped when taken)
      ri(c.code, 0x81, 0, 3, 0x2222);         // add rbx, 0x2222  (target)
      u64 init[16] = {0}; init[1] = 5;
      check(c, init);
    }

    // case 9: jbe (BE/NA). ZF=1 => taken. This used to be lowered to JAE, which
    // is also an inversion.
    { Case c; c.name = "cmp/jbe taken";
      rr(c.code, 0x2B, 0, 0);                 // sub rax, rax -> ZF=1, CF=0
      ri(c.code, 0x81, 7, 0, 0);              // cmp rax, 0    -> ZF=1, CF=0
      c.code.push_back(0x0F); c.code.push_back(0x86); // jbe +7
      c.code.push_back(0x07); c.code.push_back(0); c.code.push_back(0); c.code.push_back(0);
      ri(c.code, 0x81, 0, 2, 0x1111);         // add rdx, 0x1111  (skipped when taken)
      ri(c.code, 0x81, 0, 3, 0x2222);         // add rbx, 0x2222  (target)
      u64 init[16] = {0};
      check(c, init);
    }

    // case 10: js (S). SF=1 after dec rax -> -1 => taken.
    { Case c; c.name = "js taken";
      rr(c.code, 0x2B, 0, 0);                 // sub rax, rax -> 0
      rr(c.code, 0xFF, 1, 0);                 // dec rax       -> -1, SF=1
      c.code.push_back(0x0F); c.code.push_back(0x88); // js +7
      c.code.push_back(0x07); c.code.push_back(0); c.code.push_back(0); c.code.push_back(0);
      ri(c.code, 0x81, 0, 2, 0x1111);         // add rdx, 0x1111  (skipped when taken)
      ri(c.code, 0x81, 0, 3, 0x2222);         // add rbx, 0x2222  (target)
      u64 init[16] = {0};
      check(c, init);
    }

    // case 11: ADDI must write OF. `add rax, imm` signed-overflows here, so
    // native leaves SF=1/OF=1 and jl (SF!=OF) falls through. A VM ADDI that
    // only writes zf/sf/cf keeps the entry OF=0, takes the branch, and lands
    // on the other mov ecx 鈥攖he register compare is what catches it.
    // Layout: add(7) jl(6) | mov ecx,0x1111(5) jmp(5) | mov ecx,0x2222(5) | nop(1)
    { Case c; c.name = "addi/of/jl";
      e(c.code, {0x48, 0x81, 0xC0, 0x20, 0x00, 0x00, 0x00}); // +0  add rax, 0x20
      e(c.code, {0x0F, 0x8C, 0x0A, 0x00, 0x00, 0x00});       // +7  jl +10 -> +23
      e(c.code, {0xB9, 0x11, 0x11, 0x00, 0x00});             // +13 mov ecx, 0x1111
      e(c.code, {0xE9, 0x05, 0x00, 0x00, 0x00});             // +18 jmp +5 -> +28
      e(c.code, {0xB9, 0x22, 0x22, 0x00, 0x00});             // +23 mov ecx, 0x2222
      e(c.code, {0x90});                                     // +28 nop (shared end)
      u64 init[16] = {0}; init[0] = 0x7FFFFFFFFFFFFFF0ull;
      check(c, init);
    }

    // case 12: SUBI must write OF. a=0x8000000000000010 - 0x20 overflows
    // signed (OF=1, result positive SF=0) so native jl is taken; a stale OF=0
    // would fall through instead.
    { Case c; c.name = "subi/of/jl";
      e(c.code, {0x48, 0x81, 0xE8, 0x20, 0x00, 0x00, 0x00}); // +0  sub rax, 0x20
      e(c.code, {0x0F, 0x8C, 0x0A, 0x00, 0x00, 0x00});       // +7  jl +10 -> +23
      e(c.code, {0xB9, 0x11, 0x11, 0x00, 0x00});             // +13 mov ecx, 0x1111
      e(c.code, {0xE9, 0x05, 0x00, 0x00, 0x00});             // +18 jmp +5 -> +28
      e(c.code, {0xB9, 0x22, 0x22, 0x00, 0x00});             // +23 mov ecx, 0x2222
      e(c.code, {0x90});                                     // +28 nop (shared end)
      u64 init[16] = {0}; init[0] = 0x8000000000000010ull;
      check(c, init);
    }

    // case 13: JP after TEST. rax=3 -> low byte 0x03 has two set bits (even
    // parity) so native PF=1 and jp is taken. A mirror that never writes pf
    // keeps pf=0, falls through, and lands on the other mov ecx.
    { Case c; c.name = "test/jp taken";
      e(c.code, {0xB8, 0x03, 0x00, 0x00, 0x00});             // +0 mov eax, 3 (zero-extends)
      e(c.code, {0x48, 0x85, 0xC0});                         // +5 test rax, rax
      e(c.code, {0x0F, 0x8A, 0x0A, 0x00, 0x00, 0x00});       // +8 jp +10 -> +18
      e(c.code, {0xB9, 0x11, 0x11, 0x00, 0x00});             // +14 mov ecx, 0x1111
      e(c.code, {0xE9, 0x05, 0x00, 0x00, 0x00});             // +19 jmp +5 -> +24
      e(c.code, {0xB9, 0x22, 0x22, 0x00, 0x00});             // +24 mov ecx, 0x2222 (taken)
      e(c.code, {0x90});                                     // +29 nop
      u64 init[16] = {0};
      check(c, init);
    }

    // case 14: JNP after TEST. rax=1 -> low byte 0x01 has one set bit (odd
    // parity) so native PF=0 and jnp is taken.
    { Case c; c.name = "test/jnp taken";
      e(c.code, {0xB8, 0x01, 0x00, 0x00, 0x00});             // +0 mov eax, 1 (zero-extends)
      e(c.code, {0x48, 0x85, 0xC0});                         // +5 test rax, rax
      e(c.code, {0x0F, 0x8B, 0x0A, 0x00, 0x00, 0x00});       // +8 jnp +10 -> +18
      e(c.code, {0xB9, 0x11, 0x11, 0x00, 0x00});             // +14 mov ecx, 0x1111
      e(c.code, {0xE9, 0x05, 0x00, 0x00, 0x00});             // +19 jmp +5 -> +24
      e(c.code, {0xB9, 0x22, 0x22, 0x00, 0x00});             // +24 mov ecx, 0x2222 (taken)
      e(c.code, {0x90});                                     // +29 nop
      u64 init[16] = {0};
      check(c, init);
    }

    printf("----------------------------------------\n");
    // ===== body-virtualization era cases ================================
    // partial-register moves (INSB/INSW splice)
    { Case c; c.name = "mov al,bl splice";
      e(c.code, {0x88, 0xD8});                 // mov al, bl
      u64 init[16] = {0}; init[0] = 0x12345678000000A5ull; init[3] = 0xFF;
      check(c, init);
    }
    { Case c; c.name = "mov ax,bx splice";
      e(c.code, {0x66, 0x89, 0xD8});           // mov ax, bx
      u64 init[16] = {0}; init[0] = 0x123456780000AAAAull; init[3] = 0x1234;
      check(c, init);
    }
    { Case c; c.name = "mov al,imm splice";
      e(c.code, {0xB0, 0x7F});                 // mov al, 0x7F
      u64 init[16] = {0}; init[0] = 0xFFFFFFFFFFFFFF00ull;
      check(c, init);
    }

    // setcc / cmovcc / xchg
    { Case c; c.name = "cmp/sete al";
      e(c.code, {0x48, 0x39, 0xD1});           // cmp rcx, rdx
      e(c.code, {0x0F, 0x94, 0xC0});           // sete al
      u64 init[16] = {0}; init[0] = 0x1234567800000000ull; init[1] = 7; init[2] = 7;
      check(c, init);
    }
    { Case c; c.name = "cmp/setne al";
      e(c.code, {0x48, 0x39, 0xD1});           // cmp rcx, rdx
      e(c.code, {0x0F, 0x95, 0xC0});           // setne al
      u64 init[16] = {0}; init[0] = 0x1234567800000000ull; init[1] = 7; init[2] = 8;
      check(c, init);
    }
    { Case c; c.name = "cmp/cmove rax,rbx";
      e(c.code, {0x48, 0x39, 0xD1});           // cmp rcx, rdx
      e(c.code, {0x48, 0x0F, 0x44, 0xC3});     // cmove rax, rbx
      u64 init[16] = {0}; init[0] = 0xAAAA; init[3] = 0xBBBB; init[1] = 3; init[2] = 3;
      check(c, init);
    }
    { Case c; c.name = "cmp/cmovne rax,rbx";
      e(c.code, {0x48, 0x39, 0xD1});           // cmp rcx, rdx
      e(c.code, {0x48, 0x0F, 0x45, 0xC3});     // cmovne rax, rbx
      u64 init[16] = {0}; init[0] = 0xAAAA; init[3] = 0xBBBB; init[1] = 3; init[2] = 4;
      check(c, init);
    }
    { Case c; c.name = "xchg rax,rcx";
      e(c.code, {0x48, 0x87, 0xC1});           // xchg rax, rcx
      u64 init[16] = {0}; init[0] = 111; init[1] = 222;
      check(c, init);
    }

    // early ret ends the translated block (lowered to a register-indirect
    // exit; the dead code after it is still translated but unreachable).
    // The lowered ret reads the return address from [rsp], so the case needs
    // a readable guest stack like the native run's thunk stack.
    { Case c; c.name = "early ret island";
      e(c.code, {0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00});  // mov rax, 1
      e(c.code, {0xC3});                                     // ret
      e(c.code, {0x48, 0xC7, 0xC0, 0x02, 0x00, 0x00, 0x00});  // mov rax, 2 (dead)
      u64 init[16] = {0};
      init[4] = (u64)(unsigned long long)(g_stack.data() + 4096);
      check(c, init);
    }

    // frame prologue virtualized; body touches [rsp+8] and [rbp-8]; the
    // leave/ret epilogue is lowered too, so rbp comes back restored
    { Case c; c.name = "frame body rsp/rbp";
      e(c.code, {0x55});                                     // push rbp
      e(c.code, {0x48, 0x89, 0xE5});                         // mov rbp, rsp
      e(c.code, {0x48, 0x83, 0xEC, 0x10});                   // sub rsp, 16
      e(c.code, {0x48, 0x89, 0x44, 0x24, 0x08});             // mov [rsp+8], rax
      e(c.code, {0x48, 0x8B, 0x4D, 0xF8});                   // mov rcx, [rbp-8]
      e(c.code, {0x48, 0x83, 0xC1, 0x05});                   // add rcx, 5
      e(c.code, {0x48, 0x8B, 0x54, 0x24, 0x08});             // mov rdx, [rsp+8]
      e(c.code, {0xC9});                                     // leave
      e(c.code, {0xC3});                                     // ret
      u64 init[16] = {0};
      init[0] = 0xDEADBEEFCAFEull;
      init[4] = (u64)(unsigned long long)(g_stack.data() + 4096);
      init[5] = init[4] + 16;
      check(c, init);
    }

    // r14/r15 stay live across memory ops (translator scratch regression:
    // the old scratch slots aliased these guest registers)
    { Case c; c.name = "r14 live across memop";
      static u64 cell = 0x1111;
      e(c.code, {0x48, 0x8B, 0x03});    // mov rax, [rbx]   (rbx = &cell)
      e(c.code, {0x49, 0x03, 0xC6});    // add rax, r14
      e(c.code, {0x49, 0x03, 0xC7});    // add rax, r15
      u64 init[16] = {0};
      init[3] = (u64)(unsigned long long)&cell;
      init[14] = 0x2222; init[15] = 0x3333;
      check(c, init);
    }

    // ===== bridge-cut cases (unhandled forms stop the chunk) =============
    // The translated block covers only the prefix before the bridge; compare
    // that prefix against the same bytes run natively and assert the cut
    // geometry the packer relies on to resume after the bridged instruction.
    {
        Case c; c.name = "bridge cmpxchg8b";
        e(c.code, {0x48, 0xC7, 0xC0, 0x07, 0x00, 0x00, 0x00}); // mov rax, 7
        e(c.code, {0x0F, 0xC7, 0x0C, 0x24});                   // cmpxchg8b [rsp]
        u64 init[16] = {0};
        checkBridge(c, init, 7);
    }
    {
        Case c; c.name = "bridge avx vzeroupper";
        e(c.code, {0xC5, 0xF8, 0x77});                       // vzeroupper (3 bytes)
        u64 init[16] = {0};
        checkBridge(c, init, 0);
    }
    {
        Case c; c.name = "bridge enter nested";
        e(c.code, {0xC8, 0x10, 0x00, 0x01});                   // enter 16, 1
        u64 init[16] = {0};
        checkBridge(c, init, 0);
    }

    // ===== coverage-round lowerings =====================================
    // ret imm16: the trailing pop count must be consumed as part of the
    // instruction - decoding it as a bare ret desynchronises every later
    // boundary and the dead code behind it decodes as garbage.
    { Case c; c.name = "ret imm16 no desync";
      e(c.code, {0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00});  // mov rax, 1
      e(c.code, {0xC2, 0x10, 0x00});                          // ret 16
      e(c.code, {0x48, 0xC7, 0xC0, 0x02, 0x00, 0x00, 0x00});  // mov rax, 2 (dead)
      u64 init[16] = {0};
      init[4] = (u64)(unsigned long long)(g_stack.data() + 4096);
      check(c, init);
    }
    // enter imm16, 0 == push rbp ; mov rbp, rsp ; sub rsp, imm16 (verified
    // against the real CPU: the allocation is the raw imm16, no rounding).
    { Case c; c.name = "enter level 0 frame";
      e(c.code, {0xC8, 0x10, 0x00, 0x00});                     // enter 16, 0
      e(c.code, {0x48, 0x89, 0x44, 0x24, 0x08});               // mov [rsp+8], rax
      e(c.code, {0x48, 0x8B, 0x4D, 0xF8});                     // mov rcx, [rbp-8]
      e(c.code, {0x48, 0x83, 0xC1, 0x05});                     // add rcx, 5
      e(c.code, {0x48, 0x8B, 0x54, 0x24, 0x08});               // mov rdx, [rsp+8]
      e(c.code, {0xC9});                                       // leave
      e(c.code, {0xC3});                                       // ret
      u64 init[16] = {0};
      init[0] = 0xDEADBEEFCAFEull;
      init[4] = (u64)(unsigned long long)(g_stack.data() + 4096);
      init[5] = init[4] + 16;
      check(c, init);
    }
    // pushfq / popfq round-trip the flag file through the guest stack.
    { Case c; c.name = "pushfq/popfq roundtrip";
      e(c.code, {0xF9});                                       // stc
      e(c.code, {0x9C});                                       // pushfq
      e(c.code, {0xF8});                                       // clc
      e(c.code, {0x9D});                                       // popfq
      e(c.code, {0x48, 0xC7, 0xC0, 0x00, 0x00, 0x00, 0x00});  // mov rax, 0
      e(c.code, {0x48, 0x83, 0xD0, 0x00});                     // adc rax, 0
      u64 init[16] = {0};
      init[4] = (u64)(unsigned long long)(g_stack.data() + 4096);
      check(c, init);
    }
    // mul r/m8: AX = AL * bl, CF/OF from AH. 200 * 5 = 1000 -> AH=3, CF=OF=1.
    { Case c; c.name = "mul r/m8 AX pair";
      e(c.code, {0x48, 0xC7, 0xC0, 0x00, 0x00, 0x00, 0x00});  // mov rax, 0
      e(c.code, {0xB0, 0xC8});                                 // mov al, 200
      e(c.code, {0xF6, 0xE3});                                 // mul bl
      e(c.code, {0x48, 0x89, 0xC2});                           // mov rdx, rax
      e(c.code, {0x48, 0xC7, 0xC1, 0x00, 0x00, 0x00, 0x00});  // mov rcx, 0
      e(c.code, {0x48, 0x83, 0xD1, 0x00});                     // adc rcx, 0
      u64 init[16] = {0};
      init[3] = 5;
      check(c, init);
    }
    // div r/m8: AL=quotient, AH=remainder of AX / bl. 1000 / 5 -> AL=200, AH=0.
    { Case c; c.name = "div r/m8 AX pair";
      e(c.code, {0xB8, 0xE8, 0x03, 0x00, 0x00});               // mov eax, 1000
      e(c.code, {0xF6, 0xF3});                                 // div bl
      e(c.code, {0x48, 0x89, 0xC2});                           // mov rdx, rax
      u64 init[16] = {0};
      init[3] = 5;
      check(c, init);
    }

    // ===== zero-bug review locks =========================================
    // 32-bit xchg zero-extends both sides (the old swap kept high bits).
    { Case c; c.name = "xchg eax,ebx 32bit";
      e(c.code, {0x87, 0xD8});                 // xchg eax, ebx
      u64 init[16] = {0};
      init[0] = 0xFFFFFFFFAAAA0001ull; init[3] = 0xFFFFFFFFBBBB0002ull;
      check(c, init);
    }
    // imm8 sign-extends to the operand size in 32-bit mode too:
    // `add eax, -1` (83 C0 FF) must subtract one, not add 255.
    { Case c; c.name = "add eax,imm8 -1";
      e(c.code, {0x83, 0xC0, 0xFF});           // add eax, -1
      u64 init[16] = {0}; init[0] = 10;
      check(c, init);
    }
    { Case c; c.name = "cmp eax,imm8 -1/je";
      e(c.code, {0x83, 0xF8, 0xFF});           // +0  cmp eax, -1
      e(c.code, {0x74, 0x04});                 // +3  je +4 -> +9
      e(c.code, {0x31, 0xC0});                 // +5  xor eax, eax
      e(c.code, {0xEB, 0x05});                 // +7  jmp +5 -> +14 (end)
      e(c.code, {0xB8, 0x07, 0x00, 0x00, 0x00}); // +9  mov eax, 7
      u64 init[16] = {0}; init[0] = 0xFFFFFFFF;
      check(c, init);
    }

    // ===== width-exact ALU (WIRE_NALU) ====================================
    // The byte ALU must produce byte flags: `and al,bl` then `jne` reads zf of
    // the 8-bit result. The old lowering left the *wide* flags behind and the
    // translator refused the branch outright.
    { Case c; c.name = "and al,bl / jne";
      e(c.code, {0x20, 0xD8});                 // and al, bl
      e(c.code, {0x75, 0x04});                 // jne +4 -> +8
      e(c.code, {0x31, 0xC0});                 // +4  xor eax, eax
      e(c.code, {0xEB, 0x05});                 // +6  jmp +5 -> +13
      e(c.code, {0xB8, 0x11, 0x00, 0x00, 0x00}); // +8 mov eax, 17
      u64 init[16] = {0}; init[0] = 0x12345678000000F0ull; init[1] = 0x123456780000000Full;
      check(c, init);
    }
    { Case c; c.name = "add al,bl / jb";
      e(c.code, {0x00, 0xD8});                 // add al, bl
      e(c.code, {0x72, 0x04});                 // jb +4 -> +8
      e(c.code, {0x31, 0xC0});                 // xor eax, eax
      e(c.code, {0xEB, 0x05});                 // jmp +5 -> past the mov
      e(c.code, {0xB8, 0x22, 0x00, 0x00, 0x00}); // mov eax, 34
      u64 init[16] = {0}; init[0] = 0x12345678000000FFull; init[1] = 0x1234567800000002ull;
      check(c, init);
    }
    { Case c; c.name = "add ax,bx / jo";
      e(c.code, {0x66, 0x01, 0xD8});           // add ax, bx
      e(c.code, {0x70, 0x04});                 // jo +4 -> +8
      e(c.code, {0x31, 0xC0});                 // xor eax, eax
      e(c.code, {0xEB, 0x05});                 // jmp +5 -> past the mov
      e(c.code, {0xB8, 0x33, 0x00, 0x00, 0x00}); // mov eax, 51
      u64 init[16] = {0}; init[0] = 0x1234567800007FFFull; init[1] = 0x1234567800000001ull;
      check(c, init);
    }
    { Case c; c.name = "and r8b,bpl / jne";
      e(c.code, {0x45, 0x20, 0xE8});           // and r8b, bpl
      e(c.code, {0x75, 0x04});                 // jne +4 -> +7
      e(c.code, {0x31, 0xC0});                 // xor eax, eax
      e(c.code, {0xEB, 0x05});                 // jmp +5 -> past the mov
      e(c.code, {0xB8, 0x44, 0x00, 0x00, 0x00}); // mov eax, 68
      u64 init[16] = {0}; init[8] = 0x12345678000000AAull; init[5] = 0x123456780000000Full;
      check(c, init);
    }

    // ===== INC/DEC never touch CF (WIRE_NALU) =============================
    // `stc; inc rax; adc rbx, 0` must still see cf=1. The old ADDI lowering
    // wrote cf from the 64-bit increment, silently changing the carry chain.
    { Case c; c.name = "stc/inc/adc cf";
      e(c.code, {0xF9});                       // stc
      e(c.code, {0x48, 0xFF, 0xC0});           // inc rax
      e(c.code, {0x48, 0x83, 0xD3, 0x00});     // adc rbx, 0
      u64 init[16] = {0}; init[0] = 5; init[3] = 100;
      check(c, init);
    }
    { Case c; c.name = "stc/dec/sbb cf";
      e(c.code, {0xF9});                       // stc
      e(c.code, {0x48, 0xFF, 0xC8});           // dec rax
      e(c.code, {0x48, 0x83, 0xDB, 0x00});     // sbb rbx, 0
      u64 init[16] = {0}; init[0] = 5; init[3] = 100;
      check(c, init);
    }
    { Case c; c.name = "inc eax cf 32bit";
      e(c.code, {0xF9});                       // stc
      e(c.code, {0xFF, 0xC0});                 // inc eax
      e(c.code, {0x83, 0xD3, 0x00});           // adc ebx, 0
      u64 init[16] = {0}; init[0] = 5; init[3] = 100;
      check(c, init);
    }

    // ===== narrow shifts move bits in from outside the half ==============
    { Case c; c.name = "shr al,3 / jb";
      e(c.code, {0xC0, 0xE8, 0x03});           // shr al, 3
      e(c.code, {0x72, 0x04});                 // jb +4 -> +8
      e(c.code, {0x31, 0xC0});                 // xor eax, eax
      e(c.code, {0xEB, 0x05});                 // jmp +5 -> past the mov
      e(c.code, {0xB8, 0x55, 0x00, 0x00, 0x00}); // mov eax, 85
      u64 init[16] = {0}; init[0] = 0x1234567800000008ull;
      check(c, init);
    }
    { Case c; c.name = "rol eax,5 32bit";
      e(c.code, {0xC1, 0xC0, 0x05});           // rol eax, 5
      e(c.code, {0xC1, 0xC3, 0x05});           // rol ebx, 5
      u64 init[16] = {0}; init[0] = 0xFFFFFFFF80000001ull; init[3] = 0x0000000000000003ull;
      check(c, init);
    }
    { Case c; c.name = "sar dword [rbp-8],1";
      // memory-destination shift, 32-bit
      e(c.code, {0x8B, 0x45, 0x00});           // mov eax, [rbp+0]  (keep rbp live)
      e(c.code, {0xD1, 0x7D, 0xF8});           // sar dword [rbp-8], 1
      e(c.code, {0x8B, 0x5D, 0xF8});           // mov ebx, [rbp-8]
      u64 init[16] = {0};
      init[5] = (u64)(unsigned long long)g_stack.data() + 0x8000;
      *(unsigned int*)((unsigned char*)g_stack.data() + 0x8000 - 8) = 0xFFFFFFFEu;
      check(c, init);
    }

    // ===== bit test family (WIRE_BITOP) ==================================
    { Case c; c.name = "bt rax,5 / jb";
      e(c.code, {0x48, 0x0F, 0xBA, 0xE0, 0x05}); // bt rax, 5
      e(c.code, {0x72, 0x04});                 // jb +4 -> +9
      e(c.code, {0x31, 0xC0});                 // xor eax, eax
      e(c.code, {0xEB, 0x05});                 // jmp +5 -> past the mov
      e(c.code, {0xB8, 0x66, 0x00, 0x00, 0x00}); // mov eax, 102
      u64 init[16] = {0}; init[0] = 0x20;
      check(c, init);
    }
    { Case c; c.name = "bts rax,5";
      e(c.code, {0x48, 0x0F, 0xBA, 0xE8, 0x05}); // bts rax, 5
      e(c.code, {0x48, 0x0F, 0xBA, 0xE8, 0x09}); // bts rax, 9
      u64 init[16] = {0}; init[0] = 0x20;
      check(c, init);
    }
    { Case c; c.name = "btr/btc rax";
      e(c.code, {0x48, 0x0F, 0xBA, 0xF0, 0x05}); // btr rax, 5
      e(c.code, {0x48, 0x0F, 0xBA, 0xF8, 0x02}); // btc rax, 2
      u64 init[16] = {0}; init[0] = 0x24;
      check(c, init);
    }
    { Case c; c.name = "bt reg,reg index";
      e(c.code, {0x48, 0x0F, 0xA3, 0xC8});     // bt rax, rcx
      e(c.code, {0x72, 0x04});                 // jb +4 -> +8
      e(c.code, {0x31, 0xC0});
      e(c.code, {0xEB, 0x05});
      e(c.code, {0xB8, 0x77, 0x00, 0x00, 0x00});
      u64 init[16] = {0}; init[0] = 0x8000; init[1] = 15;
      check(c, init);
    }

    // ===== carry transfers and sign replication ==========================
    { Case c; c.name = "stc/sahf/lahf roundtrip";
      e(c.code, {0x9E});                       // sahf (flags from AH)
      e(c.code, {0x48, 0x83, 0xD3, 0x00});     // adc rbx, 0   (reads cf)
      e(c.code, {0x9F});                       // lahf (AH <- flags)
      u64 init[16] = {0}; init[0] = 0x1234567800000101ull; init[3] = 10;
      check(c, init);
    }
    { Case c; c.name = "cqo sign replicate";
      e(c.code, {0x48, 0x99});                 // cqo
      u64 init[16] = {0}; init[0] = 0xFFFFFFFFFFFFF000ull;
      check(c, init);
    }
    { Case c; c.name = "cdq sign replicate";
      e(c.code, {0x99});                       // cdq
      u64 init[16] = {0}; init[0] = 0x12345678FFFFF000ull;
      check(c, init);
    }

    // ===== group-1 adc/sbb with an immediate =============================
    { Case c; c.name = "stc/sbb rax,0";
      e(c.code, {0xF9});                       // stc
      e(c.code, {0x48, 0x83, 0xD8, 0x00});     // sbb rax, 0
      u64 init[16] = {0}; init[0] = 100;
      check(c, init);
    }
    { Case c; c.name = "clc/adc rax,5";
      e(c.code, {0xF8});                       // clc
      e(c.code, {0x48, 0x83, 0xD0, 0x05});     // adc rax, 5
      u64 init[16] = {0}; init[0] = 100;
      check(c, init);
    }

    // ===== 1-operand mul / div over RDX:RAX ==============================
    { Case c; c.name = "mul rbx 64x64->128";
      e(c.code, {0x48, 0xF7, 0xE3});           // mul rbx
      u64 init[16] = {0}; init[0] = 0x100000000ull; init[3] = 0x100000000ull;
      check(c, init);
    }
    { Case c; c.name = "div rbx 128/64";
      e(c.code, {0x48, 0xF7, 0xF3});           // div rbx
      u64 init[16] = {0}; init[0] = 100; init[2] = 0; init[3] = 7;
      check(c, init);
    }
    { Case c; c.name = "idiv rbx signed";
      e(c.code, {0x48, 0xF7, 0xFB});           // idiv rbx
      u64 init[16] = {0}; init[0] = 100; init[2] = 0; init[3] = (u64)-7;
      check(c, init);
    }
    { Case c; c.name = "mul eax 32x32->64";
      e(c.code, {0xF7, 0xE3});                 // mul ebx
      u64 init[16] = {0}; init[0] = 0x10000; init[3] = 0x10000;
      check(c, init);
    }

    // ===== two-operand imul with a memory source =========================
    { Case c; c.name = "imul rax,rbx (mem src)";
      e(c.code, {0x48, 0x0F, 0xAF, 0x45, 0x00}); // imul rax, [rbp+0]
      u64 init[16] = {0};
      init[5] = (u64)(unsigned long long)g_stack.data() + 0x8000;
      *(unsigned long long*)((unsigned char*)g_stack.data() + 0x8000) = 3;
      init[0] = 7;
      check(c, init);
    }

    // ===== SSE scalar arithmetic (WIRE_XALU) =============================
    // xmm0 = 2.0, xmm1 = 3.0; addsd -> 5.0 -> movq rax. The float bit pattern
    // is what gets compared, so this pins the whole double pipeline.
    { Case c; c.name = "addsd xmm 2.0+3.0";
      e(c.code, {0x48, 0xB8});                 // movabs rax, 2.0
      for (int k = 0; k < 8; k++) c.code.push_back((u8)(0x4000000000000000ull >> (k * 8) & 0xFF));
      e(c.code, {0x66, 0x48, 0x0F, 0x6E, 0xC0}); // movq xmm0, rax
      e(c.code, {0x48, 0xB9});                 // movabs rcx, 3.0
      for (int k = 0; k < 8; k++) c.code.push_back((u8)(0x4008000000000000ull >> (k * 8) & 0xFF));
      e(c.code, {0x66, 0x48, 0x0F, 0x6E, 0xC9}); // movq xmm1, rcx
      e(c.code, {0xF2, 0x0F, 0x58, 0xC1});     // addsd xmm0, xmm1
      e(c.code, {0x66, 0x48, 0x0F, 0x7E, 0xC0}); // movq rax, xmm0
      u64 init[16] = {0};
      check(c, init);
    }
    { Case c; c.name = "mulsd xmm 2.0*3.0";
      e(c.code, {0x48, 0xB8});
      for (int k = 0; k < 8; k++) c.code.push_back((u8)(0x4000000000000000ull >> (k * 8) & 0xFF));
      e(c.code, {0x66, 0x48, 0x0F, 0x6E, 0xC0});
      e(c.code, {0x48, 0xB9});
      for (int k = 0; k < 8; k++) c.code.push_back((u8)(0x4008000000000000ull >> (k * 8) & 0xFF));
      e(c.code, {0x66, 0x48, 0x0F, 0x6E, 0xC9});
      e(c.code, {0xF2, 0x0F, 0x59, 0xC1});     // mulsd xmm0, xmm1
      e(c.code, {0x66, 0x48, 0x0F, 0x7E, 0xC0});
      u64 init[16] = {0};
      check(c, init);
    }
    { Case c; c.name = "divsd/sqrtsd chain";
      e(c.code, {0x48, 0xB8});
      for (int k = 0; k < 8; k++) c.code.push_back((u8)(0x4008000000000000ull >> (k * 8) & 0xFF)); // 3.0
      e(c.code, {0x66, 0x48, 0x0F, 0x6E, 0xC0});
      e(c.code, {0x48, 0xB9});
      for (int k = 0; k < 8; k++) c.code.push_back((u8)(0x4000000000000000ull >> (k * 8) & 0xFF)); // 2.0
      e(c.code, {0x66, 0x48, 0x0F, 0x6E, 0xC9});
      e(c.code, {0xF2, 0x0F, 0x5E, 0xC1});     // divsd xmm0, xmm1  -> 1.5
      e(c.code, {0xF2, 0x0F, 0x51, 0xC0});     // sqrtsd xmm0, xmm0
      e(c.code, {0x66, 0x48, 0x0F, 0x7E, 0xC0});
      u64 init[16] = {0};
      check(c, init);
    }
    { Case c; c.name = "cvttsd2si rax,xmm0";
      e(c.code, {0x48, 0xB8});
      for (int k = 0; k < 8; k++) c.code.push_back((u8)(0x4008000000000000ull >> (k * 8) & 0xFF)); // 3.0
      e(c.code, {0x66, 0x48, 0x0F, 0x6E, 0xC0});
      e(c.code, {0x48, 0xB9});
      for (int k = 0; k < 8; k++) c.code.push_back((u8)(0x4000000000000000ull >> (k * 8) & 0xFF)); // 2.0
      e(c.code, {0x66, 0x48, 0x0F, 0x6E, 0xC9});
      e(c.code, {0xF2, 0x0F, 0x59, 0xC1});     // mulsd -> 6.0
      e(c.code, {0xF2, 0x48, 0x0F, 0x2C, 0xC0}); // cvttsd2si rax, xmm0 -> 6
      u64 init[16] = {0};
      check(c, init);
    }
    { Case c; c.name = "cvtsi2sd xmm,rax";
      e(c.code, {0x48, 0xB8});
      for (int k = 0; k < 8; k++) c.code.push_back((u8)(0x4000000000000000ull >> (k * 8) & 0xFF)); // 2.0
      e(c.code, {0x66, 0x48, 0x0F, 0x6E, 0xC0});
      e(c.code, {0x48, 0xB9, 0x07, 0, 0, 0, 0, 0, 0, 0}); // movabs rcx, 7
      e(c.code, {0xF2, 0x48, 0x0F, 0x2A, 0xC9}); // cvtsi2sd xmm1, rcx  -> 7.0
      e(c.code, {0xF2, 0x0F, 0x58, 0xC1});     // addsd xmm0, xmm1 -> 9.0
      e(c.code, {0x66, 0x48, 0x0F, 0x7E, 0xC0});
      u64 init[16] = {0};
      check(c, init);
    }
    { Case c; c.name = "ucomisd/jbe branch";
      e(c.code, {0x48, 0xB8});
      for (int k = 0; k < 8; k++) c.code.push_back((u8)(0x4000000000000000ull >> (k * 8) & 0xFF)); // 2.0
      e(c.code, {0x66, 0x48, 0x0F, 0x6E, 0xC0});
      e(c.code, {0x48, 0xB9});
      for (int k = 0; k < 8; k++) c.code.push_back((u8)(0x4008000000000000ull >> (k * 8) & 0xFF)); // 3.0
      e(c.code, {0x66, 0x48, 0x0F, 0x6E, 0xC9});
      e(c.code, {0x66, 0x0F, 0x2E, 0xC1});     // ucomisd xmm0, xmm1
      e(c.code, {0x76, 0x04});                 // jbe +4 -> +27
      e(c.code, {0x31, 0xC0});
      e(c.code, {0xEB, 0x05});
      e(c.code, {0xB8, 0x99, 0x00, 0x00, 0x00});
      u64 init[16] = {0};
      check(c, init);
    }

    // ===== vm_target's instruction sequence (regression bisect) ==========
    // The exact op mix from tests/vm_target.S, which the end-to-end harness
    // protects and runs. Kept here so a lowering change that breaks the
    // protected fixture fails in seconds instead of after a full pack run.
    // encodings used below: accumulator forms carry imm32 with no ModRM,
    // shift groups carry imm8, and 0x83 carries imm8.
    { Case c; c.name = "vm_target seq";
      auto acc32 = [&](u8 op, u32 imm) {
          c.code.push_back(0x48); c.code.push_back(op);
          for (int k = 0; k < 4; k++) c.code.push_back((u8)((imm >> (k * 8)) & 0xFF));
      };
      auto sh8 = [&](u8 digit, u8 imm) {
          e(c.code, {0x48, 0xC1, (u8)(0xC0 | ((digit & 7) << 3) | 0), imm});
      };
      auto grp8 = [&](u8 digit, u8 imm) {
          e(c.code, {0x48, 0x83, (u8)(0xC0 | ((digit & 7) << 3) | 0), imm});
      };
      rr(c.code, 0x01, 0, 1);                  // add rax, rcx
      rr(c.code, 0x31, 0, 1);                  // xor rax, rcx
      acc32(0x05, 0x1234);                     // add rax, 0x1234
      sh8(4, 3);                               // shl rax, 3
      rr(c.code, 0x2B, 0, 1);                  // sub rax, rcx
      rr(c.code, 0x0B, 0, 1);                  // or rax, rcx
      acc32(0x25, 0x00FFFF00);                 // and rax, 0x00FFFF00
      e(c.code, {0x48, 0xFF, 0xC0});           // inc rax
      e(c.code, {0x48, 0xFF, 0xC8});           // dec rax
      e(c.code, {0x48, 0xF7, 0xD0});           // not rax
      e(c.code, {0x48, 0xF7, 0xD8});           // neg rax
      e(c.code, {0x48, 0x8D, 0x40, 0x40});     // lea rax, [rax+0x40]
      rr(c.code, 0x01, 0, 1);                  // add rax, rcx
      rr(c.code, 0x31, 0, 1);                  // xor rax, rcx
      acc32(0x2D, 0x77);                       // sub rax, 0x77
      sh8(4, 5);                               // shl rax, 5
      sh8(5, 2);                               // shr rax, 2
      acc32(0x0D, 0x0101);                     // or rax, 0x0101
      acc32(0x25, 0x7FFFFFFF);                 // and rax, 0x7FFFFFFF
      rr(c.code, 0x01, 0, 1);                  // add rax, rcx
      rr(c.code, 0x33, 0, 1);                  // xor rax, rcx
      e(c.code, {0x48, 0xF7, 0xD0});           // not rax
      e(c.code, {0x48, 0xF7, 0xD8});           // neg rax
      acc32(0x05, 0x1111);                     // add rax, 0x1111
      acc32(0x2D, 0x2222);                     // sub rax, 0x2222
      sh8(4, 1);                               // shl rax, 1
      rr(c.code, 0x09, 0, 1);                  // or rax, rcx
      acc32(0x25, 0x0F0F0F0F);                 // and rax, 0x0F0F0F0F
      e(c.code, {0x48, 0xFF, 0xC0});           // inc rax
      rr(c.code, 0x31, 0, 1);                  // xor rax, rcx
      rr(c.code, 0x01, 0, 1);                  // add rax, rcx
      e(c.code, {0x48, 0x8D, 0x80, 0x00, 0x01, 0x00, 0x00}); // lea rax, [rax+0x100]
      grp8(5, 0x33);                           // sub rax, 0x33
      sh8(5, 4);                               // shr rax, 4
      acc32(0x0D, 0x2020);                     // or rax, 0x2020
      acc32(0x25, 0x00FF00FF);                 // and rax, 0x00FF00FF
      rr(c.code, 0x01, 0, 1);                  // add rax, rcx
      rr(c.code, 0x31, 0, 1);                  // xor rax, rcx
      acc32(0x05, 1);                          // add rax, 1
      acc32(0x2D, 1);                          // sub rax, 1
      e(c.code, {0x48, 0xF7, 0xD0});           // not rax
      e(c.code, {0x48, 0xF7, 0xD8});           // neg rax
      acc32(0x05, 7);                          // add rax, 7
      acc32(0x2D, 9);                          // sub rax, 9
      sh8(4, 2);                               // shl rax, 2
      rr(c.code, 0x09, 0, 1);                  // or rax, rcx
      acc32(0x25, 0x0000FFFF);                 // and rax, 0x0000FFFF
      rr(c.code, 0x01, 0, 1);                  // add rax, rcx
      rr(c.code, 0x31, 0, 1);                  // xor rax, rcx
      acc32(0x05, 0x20);                       // add rax, 0x20
      acc32(0x05, 0x5555);                     // add rax, 0x5555
      acc32(0x2D, 0x111);                      // sub rax, 0x111
      u64 init[16] = {0}; init[0] = 0x123456789ABCDEF0ull; init[1] = 0x0FEDCBA987654321ull;
      check(c, init);
    }

    // Shift count wider than the operand must not underflow the shift amount:
    // `shl al, 20` masks the count to 5 bits (20) which is wider than the byte,
    // and the naive `a >> (bits - cnt)` would shift by a negative amount.
    { Case c; c.name = "shl al,20 wide count";
      e(c.code, {0xC0, 0xE0, 0x14});           // shl al, 20
      e(c.code, {0xC0, 0xE8, 0x14});           // shr al, 20
      e(c.code, {0xC0, 0xF8, 0x14});           // sar al, 20
      u64 init[16] = {0}; init[0] = 0x12345678000000A5ull;
      check(c, init);
    }

    printf("TESTS: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}