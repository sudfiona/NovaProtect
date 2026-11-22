// vmdbg.cpp — VM lowering debug harness
// Replicates the packer's per-region pipeline on a function extracted
// from a PE and compares the outcomes natively-simulated in-process:
//   extract bytes -> mutation pipeline -> VMTranslator -> vmObfuscate
//   -> np_vm_run simulation (original vs mutated, obfuscated or not).
// Usage: vmdbg <exe> <rva-hex> <len-hex> [mutStrength 0-3] [seed] [t]
//   env DIRTY_RAX=1 seeds rax with dirty upper bits (32-bit semantics test)
// Build: g++ -std=c++17 -I include -I src -o vmdbg tools/vmdbg.cpp \
//        src/mutation.cpp src/disasm.cpp src/vm_engine.cpp \
//        src/vm_obfuscate.cpp src/pe_lib.cpp -static
#include "disasm.h"
#include "mutation.h"
#include "vm_isa.h"

#include "pe_lib.h"
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <vector>
#include <string>
#include <random>
#include <cstdlib>

using namespace np;

// ---- C++ port of np_vm_run from runtime/prot64.c ----
static const int NP_VM_REGS_DBG = 16;
struct VmCtx { uint64_t r[16]; };
// logical wire opcodes (from vm_isa.h)
#include "vm_isa.h"

static int parity_even(uint64_t res) {
    uint8_t b = (uint8_t)res;
    b ^= b >> 4; b ^= b >> 2; b ^= b >> 1;
    return (int)((~b) & 1);
}

static uint64_t dbgRun(const uint8_t* code, size_t code_len, const uint8_t* reverse,
                       uint64_t* inout_regs, bool trace) {
    uint64_t r[NP_VM_REGS_DBG];
    for (int i = 0; i < NP_VM_REGS_DBG; i++) r[i] = inout_regs[i];
    uint64_t ip = 0; uint32_t guard = 0;
    int zf = 0, cf = 0, sf = 0, of = 0, pf = 0;
    while (ip < code_len) {
        if (++guard > 4000000u) break;
        uint8_t phys = code[ip++];
        uint8_t op = reverse[phys];
        uint32_t reg, dst, src, base;
        uint64_t imm;
        if (trace) printf("  [%4llu] op=%02x ", (unsigned long long)(ip-1), op);
        switch (op) {
        case WIRE_LOADIMM:
            reg = code[ip++];
            imm = 0; for (uint32_t k = 0; k < 8; k++) imm |= (uint64_t)code[ip++] << (k * 8);
            if (reg < NP_VM_REGS_DBG) r[reg] = imm;
            if (trace) printf("LOADIMM r%u = %llx\n", reg, (unsigned long long)imm);
            break;
        case WIRE_MOVE:
            dst = code[ip++]; src = code[ip++];
            if (dst < NP_VM_REGS_DBG && src < NP_VM_REGS_DBG) r[dst] = r[src];
            if (trace) printf("MOVE r%u <- r%u (=%llx)\n", dst, src, (unsigned long long)r[dst]);
            break;
        case WIRE_ADD: case WIRE_SUB: case WIRE_MUL:
        case WIRE_AND: case WIRE_OR: case WIRE_XOR:
        case WIRE_SHL: case WIRE_SHR: case WIRE_SAR: {
            dst = code[ip++]; src = code[ip++];
            if (dst < NP_VM_REGS_DBG && src < NP_VM_REGS_DBG) {
                uint64_t a = r[dst], b = r[src];
                switch (op) {
                case WIRE_ADD: { uint64_t res = a + b; cf = (res < a); of = (int)(((a ^ res) & (b ^ res)) >> 63) & 1; r[dst] = res; pf = parity_even(res); } break;
                case WIRE_SUB: { uint64_t res = a - b; cf = (a < b); of = (int)(((a ^ b) & (a ^ res)) >> 63) & 1; r[dst] = res; pf = parity_even(res); } break;
                case WIRE_MUL: r[dst] = a * b; break;
                case WIRE_AND: r[dst] = a & b; break;
                case WIRE_OR:  r[dst] = a | b; break;
                case WIRE_XOR: r[dst] = a ^ b; break;
                case WIRE_SHL: r[dst] = a << (b & 63u); break;
                case WIRE_SHR: r[dst] = a >> (b & 63u); break;
                case WIRE_SAR: r[dst] = (uint64_t)(((int64_t)a) >> (b & 63u)); break;
                }
                if (op != WIRE_MUL) { zf = (r[dst] == 0); sf = (int)((r[dst] >> 63) & 1); pf = parity_even(r[dst]); }
            }
            if (trace) printf("ALU op=%02x r%u r%u -> %llx\n", op, dst, src, (unsigned long long)r[dst]);
            break;
        }
        case WIRE_NOT:
            reg = code[ip++];
            if (reg < NP_VM_REGS_DBG) r[reg] = ~r[reg];
            if (trace) printf("NOT r%u\n", reg);
            break;
        case WIRE_NEG: {
            reg = code[ip++];
            if (reg < NP_VM_REGS_DBG) { uint64_t a = r[reg]; r[reg] = (uint64_t)(-(int64_t)a); cf = (a != 0); zf = (r[reg] == 0); sf = (int)((r[reg] >> 63) & 1); pf = parity_even(r[reg]); }
            if (trace) printf("NEG r%u\n", reg);
            break;
        }
        case WIRE_CMP: {
            uint32_t a_reg = code[ip++], b_reg = code[ip++];
            if (a_reg < NP_VM_REGS_DBG && b_reg < NP_VM_REGS_DBG) {
                uint64_t a = r[a_reg], b = r[b_reg], res = a - b;
                zf = (res == 0); cf = (a < b); sf = (int)((res >> 63) & 1);
                of = (int)(((((a ^ b) & (a ^ res)) >> 63)) & 1);
                pf = parity_even(res);
            }
            if (trace) printf("CMP r%u r%u\n", a_reg, b_reg);
            break;
        }
        case WIRE_TEST: {
            uint32_t a_reg = code[ip++], b_reg = code[ip++];
            if (a_reg < NP_VM_REGS_DBG && b_reg < NP_VM_REGS_DBG) {
                uint64_t res = r[a_reg] & r[b_reg];
                zf = (res == 0); cf = 0; of = 0; sf = (int)((res >> 63) & 1);
                pf = parity_even(res);
            }
            if (trace) printf("TEST r%u r%u\n", a_reg, b_reg);
            break;
        }
        case WIRE_MULI: case WIRE_ADDI: case WIRE_SUBI: case WIRE_ANDI:
        case WIRE_RORI: case WIRE_XORI: case WIRE_ORI: case WIRE_SHRI:
        case WIRE_SHLI: case WIRE_SARI: case WIRE_CMPI:
            reg = code[ip++];
            imm = 0; for (uint32_t k = 0; k < 8; k++) imm |= (uint64_t)code[ip++] << (k * 8);
            if (reg < NP_VM_REGS_DBG) {
                uint64_t a = r[reg], res = 0;
                switch (op) {
                case WIRE_MULI: r[reg] *= imm; break;
                case WIRE_ADDI: res = a + imm; cf = (res < a); of = (int)((((a ^ res) & (imm ^ res)) >> 63) & 1); r[reg] = res; zf = (res == 0); sf = (int)((res >> 63) & 1); pf = parity_even(res); break;
                case WIRE_SUBI: res = a - imm; cf = (a < imm); of = (int)((((a ^ imm) & (a ^ res)) >> 63) & 1); r[reg] = res; zf = (res == 0); sf = (int)((res >> 63) & 1); pf = parity_even(res); break;
                case WIRE_ANDI: r[reg] &= imm; zf = (r[reg] == 0); sf = (int)((r[reg] >> 63) & 1); cf = 0; pf = parity_even(r[reg]); break;
                case WIRE_ORI:  r[reg] |= imm; zf = (r[reg] == 0); sf = (int)((r[reg] >> 63) & 1); cf = 0; pf = parity_even(r[reg]); break;
                case WIRE_XORI: r[reg] ^= imm; zf = (r[reg] == 0); sf = (int)((r[reg] >> 63) & 1); cf = 0; pf = parity_even(r[reg]); break;
                case WIRE_SHRI: r[reg] = a >> (imm & 63u); zf = (r[reg] == 0); sf = (int)((r[reg] >> 63) & 1); pf = parity_even(r[reg]); break;
                case WIRE_SHLI: r[reg] = a << (imm & 63u); zf = (r[reg] == 0); sf = (int)((r[reg] >> 63) & 1); pf = parity_even(r[reg]); break;
                case WIRE_SARI: r[reg] = (uint64_t)(((int64_t)a) >> (imm & 63u)); zf = (r[reg] == 0); sf = (int)((r[reg] >> 63) & 1); pf = parity_even(r[reg]); break;
                case WIRE_RORI: { uint32_t s = (uint32_t)(imm & 63u); r[reg] = (r[reg] >> s) | (r[reg] << ((64u - s) & 63u)); break; }
                case WIRE_CMPI: res = a - imm; zf = (res == 0); cf = (a < imm); sf = (int)((res >> 63) & 1);
                    of = (int)(((((a ^ imm) & (a ^ res)) >> 63)) & 1); pf = parity_even(res); break;
                }
            }
            if (trace) printf("ALUI op=%02x r%u imm=%llx -> %llx\n", op, reg, (unsigned long long)imm, (unsigned long long)r[reg]);
            break;
        case WIRE_JMP: case WIRE_JE: case WIRE_JNE: case WIRE_JZ: case WIRE_JNZ:
        case WIRE_JAE: case WIRE_JB: case WIRE_JGE: case WIRE_JL:
        case WIRE_JG: case WIRE_JLE:
        case WIRE_INSB: { u32 dd = code[ip++], ss = code[ip++]; if (dd < 18 && ss < 18) r[dd] = (r[dd] & ~0xFFull) | (r[ss] & 0xFFull); break; }
        case WIRE_INSW: { u32 dd = code[ip++], ss = code[ip++]; if (dd < 18 && ss < 18) r[dd] = (r[dd] & ~0xFFFFull) | (r[ss] & 0xFFFFull); break; }
        case WIRE_EXITJMP: { u32 x = 0; for (int k = 0; k < 4; k++) x |= (u32)code[ip++] << (k * 8); (void)x; ip = code_len; break; }
        case WIRE_CALL: { u32 x = 0; for (int k = 0; k < 4; k++) x |= (u32)code[ip++] << (k * 8); (void)x; break; }  /* CALL: structural skip in the debugger */
        case WIRE_IMGADD: { u32 dd = code[ip++]; u32 rva = 0; for (int k = 0; k < 4; k++) rva |= (u32)code[ip++] << (k * 8); if (dd < 18) r[dd] = (u64)rva; break; }  /* imgBase=0 in the debugger */
        case WIRE_CMPB: case WIRE_CMPW: case WIRE_TESTB: case WIRE_TESTW: {
            u32 aR = code[ip++], bR = code[ip++];
            if (aR < 18 && bR < 18) {
                int bits = (op == WIRE_CMPW || op == WIRE_TESTW) ? 16 : 8;
                u64 mask = (bits == 16) ? 0xFFFFull : 0xFFull;
                u64 va = r[aR] & mask, vb = r[bR] & mask, res;
                if (op == WIRE_CMPB || op == WIRE_CMPW) { res = (va - vb) & mask; zf = (res == 0); cf = (va < vb); of = (int)((((va ^ vb) & (va ^ res)) >> (bits - 1)) & 1); }
                else { res = va & vb; zf = (res == 0); cf = 0; of = 0; }
                sf = (int)((res >> (bits - 1)) & 1);
                pf = parity_even(res);
            }
            break;
        }
        case WIRE_JA: case WIRE_JBE: case WIRE_JS: case WIRE_JNS:
        case WIRE_JO: case WIRE_JNO: case WIRE_JP: case WIRE_JNP: {
            uint32_t t = 0; for (uint32_t k = 0; k < 4; k++) t |= (uint32_t)code[ip++] << (k * 8);
            int take;
            switch (op) {
            case WIRE_JMP: take = 1; break;
            case WIRE_JE: case WIRE_JZ:  take = zf; break;
            case WIRE_JNE: case WIRE_JNZ: take = !zf; break;
            case WIRE_JAE: take = !cf; break;
            case WIRE_JB:  take = cf; break;
            case WIRE_JGE: take = (sf == of); break;
            case WIRE_JL:  take = (sf != of); break;
            case WIRE_JG:  take = (!zf && (sf == of)); break;
            case WIRE_JLE: take = (zf || (sf != of)); break;
            case WIRE_JA:  take = (!cf && !zf); break;
            case WIRE_JBE: take = (cf || zf); break;
            case WIRE_JS:  take = sf; break;
            case WIRE_JNS: take = !sf; break;
            case WIRE_JO:  take = of; break;
            case WIRE_JNO: take = !of; break;
            case WIRE_JP:  take = pf; break;
            case WIRE_JNP: take = !pf; break;
            default:       take = 0; break;
            }
            if (take) ip = t;
            if (trace) printf("JCC op=%02x take=%d -> %u\n", op, take, t);
            break;
        }
        case WIRE_ENDBR:
            if (trace) printf("ENDBR\n");
            break;
        case WIRE_HALT:
            if (trace) printf("HALT\n");
            ip = code_len;
            break;
        default:
            if (trace) printf("UNKNOWN op=%02x -> halt\n", op);
            ip = code_len;
            break;
        }
    }
    for (int i = 0; i < NP_VM_REGS_DBG; i++) inout_regs[i] = r[i];
    return r[0];
}

static void hexdump(const char* tag, const std::vector<uint8_t>& v) {
    printf("%s (%zu bytes):\n", tag, v.size());
    for (size_t i = 0; i < v.size(); i++) {
        if (i % 16 == 0) printf("  %04zx: ", i);
        printf("%02x ", v[i]);
        if (i % 16 == 15) printf("\n");
    }
    if (v.size() % 16) printf("\n");
}

int main(int argc, char** argv) {
    const char* path = argc > 1 ? argv[1] : "sample.exe";
    uint32_t rva = argc > 2 ? (uint32_t)strtoul(argv[2], nullptr, 16) : 0x16D0;
    uint32_t len = argc > 3 ? (uint32_t)strtoul(argv[3], nullptr, 16) : 0x8F;
    uint8_t mutStrength = argc > 4 ? (uint8_t)atoi(argv[4]) : 2;
    uint64_t seed = argc > 5 ? strtoull(argv[5], nullptr, 10) : 12345;
    bool trace = argc > 6 && argv[6][0] == 't';

    PELib pe;
    if (!pe.load(path)) { printf("load failed\n"); return 1; }
    std::vector<uint8_t> data = pe.data();
    // map RVA -> file offset using section table
    uint32_t off = pe.rvaToOffset(rva);
    if (off + len > data.size()) { printf("range out of file\n"); return 1; }
    std::vector<uint8_t> code(data.begin() + off, data.begin() + off + len);
    printf("function @RVA %X len %u (%zu bytes)\n", rva, len, code.size());

    // expected native result for input 42
    uint64_t x = 42;
    // simulate natively via the interpreter of the disasm? No - just run the
    // same ops in a tiny x86 emulator is overkill; instead compile+run is done
    // by the real exe. We compute expected via direct execution:
    // (pure(42) known = 826248)

    // ---- packer mutation pipeline (mirror of packer.cpp) ----
    Disassembler dchk;
    auto supported = [&](const NativeInsn& ni) -> bool {
        if (ni.bytes.empty()) return false;
        DisasmInsn di;
        if (!dchk.disassemble(ni.bytes.data(), ni.bytes.size(), di)) return false;
        using C = InsnCategory;
        switch (di.category) {
        case C::MOV: case C::LEA:
        case C::ADD: case C::SUB: case C::AND: case C::OR: case C::XOR:
        case C::CMP: case C::TEST:
        case C::INC: case C::DEC: case C::NEG: case C::NOT:
        case C::SHL: case C::SHR: case C::SAR:
        case C::NOP:
            return true;
        default:
            return false;
        }
    };

    // disassemble original into stream
    std::vector<NativeInsn> stream;
    {
        Disassembler d;
        uint32_t o = 0;
        while (o < code.size()) {
            DisasmInsn di;
            uint32_t il = d.disassemble(code.data() + o, code.size() - o, di);
            if (!il) break;
            NativeInsn ni;
            ni.bytes.assign(code.begin() + o, code.begin() + o + il);
            ni.length = (uint8_t)il;
            stream.push_back(ni);
            o += il;
        }
    }
    printf("original: %zu instructions\n", stream.size());

    MutationEngine mutEngine(seed);
    mutEngine.setStrength(static_cast<MutationStrength>(std::min<uint8_t>(mutStrength, 3)));
    mutEngine.setInjectGarbage(false);
    mutEngine.setReorder(false);
    std::vector<NativeInsn> mutated_stream;
    int mutation_count = 0;
    for (const auto& insn : stream) {
        auto sub = mutEngine.mutate({insn});
        bool ok = !sub.empty() && !sub[0].bytes.empty() && sub[0].mutated;
        if (ok) {
            for (const auto& mi : sub) {
                if (!supported(mi)) { ok = false; break; }
            }
        }
        if (ok) { mutated_stream.insert(mutated_stream.end(), sub.begin(), sub.end()); mutation_count++; }
        else mutated_stream.push_back(insn);
    }
    printf("mutations accepted: %d -> %zu instructions\n", mutation_count, mutated_stream.size());

    std::vector<uint8_t> mutated_bytes;
    for (const auto& mi : mutated_stream)
        mutated_bytes.insert(mutated_bytes.end(), mi.bytes.begin(), mi.bytes.end());

    // disassemble mutated stream for print
    printf("\n--- mutated stream disassembly ---\n");
    {
        Disassembler d;
        uint32_t o = 0;
        while (o < mutated_bytes.size()) {
            DisasmInsn di;
            uint32_t il = d.disassemble(mutated_bytes.data() + o, mutated_bytes.size() - o, di);
            if (!il) { printf("  decode fail at %u\n", o); break; }
            printf("  +%3u len=%u cat=%d dst=%d src=%d bytes=", o, il, (int)di.category, (int)di.dst.reg, (int)di.src.reg);
            for (uint32_t b = 0; b < il; b++) printf("%02x", mutated_bytes[o + b]);
            printf("\n");
            o += il;
        }
    }

    // ---- translate both ----
    VMLoweredBlock b0 = VMTranslator::translate(code.data(), code.size(), pe.imageBase() + rva, pe.imageBase(), 6, mutStrength);
    VMLoweredBlock b1 = VMTranslator::translate(mutated_bytes.data(), mutated_bytes.size(), pe.imageBase() + rva, pe.imageBase(), 6, mutStrength);
    printf("\noriginal translate: ok=%d insns=%u skipped=%u reason=%s\n", b0.ok, b0.insnsTranslated, b0.insnsSkipped, b0.skipReason.c_str());
    printf("mutated   translate: ok=%d insns=%u skipped=%u reason=%s\n", b1.ok, b1.insnsTranslated, b1.insnsSkipped, b1.skipReason.c_str());

    // mask for original
    uint32_t mask0 = 0;
    {
        Disassembler d; uint32_t o = 0;
        while (o < code.size()) {
            DisasmInsn di; uint32_t il = d.disassemble(code.data() + o, code.size() - o, di);
            if (!il) break;
            Operand ops[3] = { di.dst, di.src, di.extra };
            for (int k = 0; k < 3; k++) {
                uint8_t rg = (uint8_t)ops[k].reg;
                if (rg <= 15) mask0 |= (1u << rg);
                if (ops[k].type == OperandType::Memory) {
                    uint8_t rb = (uint8_t)ops[k].base, ri = (uint8_t)ops[k].index;
                    if (rb <= 15) mask0 |= (1u << rb);
                    if (ri <= 15) mask0 |= (1u << ri);
                }
            }
            o += il;
        }
    }
    uint32_t mask1 = 0;
    {
        Disassembler d; uint32_t o = 0;
        while (o < mutated_bytes.size()) {
            DisasmInsn di; uint32_t il = d.disassemble(mutated_bytes.data() + o, mutated_bytes.size() - o, di);
            if (!il) break;
            Operand ops[3] = { di.dst, di.src, di.extra };
            for (int k = 0; k < 3; k++) {
                uint8_t rg = (uint8_t)ops[k].reg;
                if (rg <= 15) mask1 |= (1u << rg);
                if (ops[k].type == OperandType::Memory) {
                    uint8_t rb = (uint8_t)ops[k].base, ri = (uint8_t)ops[k].index;
                    if (rb <= 15) mask1 |= (1u << rb);
                    if (ri <= 15) mask1 |= (1u << ri);
                }
            }
            o += il;
        }
    }
    printf("mask0=%08x mask1=%08x\n", mask0, mask1);

    // ---- simulate: original (no obfuscation) ----
    auto simulate = [&](const VMLoweredBlock& blk, uint32_t mask, bool doObf, const char* tag) -> uint64_t {
        std::vector<uint8_t> bc = blk.bytecode;
        if (doObf) {
            uint8_t mapping[256] = {0};
            for (int p = 0; p < 256; p++) {
                uint8_t logical = blk.reverse[(size_t)p];
                if (logical < WIRE_COUNT) mapping[logical] = (uint8_t)p;
            }
            bc = vmObfuscate(blk.bytecode, blk.reverse.data(), mapping, mask, 6);
        }
        uint64_t regs[16] = {0};
        regs[1] = x;  // rcx = input (movq %1,%0 with %1 in rcx)
        if (getenv("DIRTY_RAX")) regs[0] = 0xDEADBEEF00000000ull | (x & 0xFFFFFFFF);
        uint64_t res = dbgRun(bc.data(), bc.size(), blk.reverse.data(), regs, trace);
        printf("%s: result=%llu (0x%llx) rax=%llu\n", tag,
               (unsigned long long)res, (unsigned long long)res, (unsigned long long)regs[0]);
        return res;
    };

    printf("\n--- simulate (rcx = input %llu, result read from rax) ---\n\n", (unsigned long long)x);
    simulate(b0, mask0, false, "orig no-obf");
    simulate(b0, mask0, true,  "orig obf   ");
    simulate(b1, mask1, false, "mut  no-obf");
    simulate(b1, mask1, true,  "mut  obf   ");

    if (trace) {
        printf("\n--- trace mutated+obf ---\n");
        uint8_t mapping[256] = {0};
        for (int p = 0; p < 256; p++) {
            uint8_t logical = b1.reverse[(size_t)p];
            if (logical < WIRE_COUNT) mapping[logical] = (uint8_t)p;
        }
        std::vector<uint8_t> bc = vmObfuscate(b1.bytecode, b1.reverse.data(), mapping, mask1, 6);
        uint64_t regs[16] = {0};
        regs[1] = x;
        dbgRun(bc.data(), bc.size(), b1.reverse.data(), regs, true);
    }
    return 0;
}
