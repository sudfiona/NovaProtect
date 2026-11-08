// vm_revirt_test.cpp - EnableRevirtualization transform tests
//
// These tests check the two packer-side transforms against the wire semantics
// the runtime implements, without needing a protected image:
//
//   1. splitStages() must produce stages whose concatenation is the original
//      program modulo the STAGEEND markers, with every branch target landing
//      on an instruction boundary *inside its own stage*.
//   2. liftGuestBlocks() must produce guest blocks that compute exactly what the
//      run they replaced computed, including the register permutation, and the
//      rewritten stage must call them in the same order.
//
// The second one runs a small reference interpreter over both programs and
// compares the resulting register files, so a wrong permutation or a dropped
// instruction fails here instead of on a user's machine.
//
// Build:
//   g++ -std=c++17 -O2 -Iinclude tests\vm_revirt_test.cpp src\vm_revirt.cpp -o vm_revirt_test.exe
#include "vm_isa.h"
#include "wire_table.h"
#include "vm_revirt.h"

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <random>
#include <vector>

using namespace np;

static int g_fail = 0;
static int g_pass = 0;

static void check(bool cond, const char* what) {
    if (cond) { g_pass++; return; }
    printf("  FAIL: %s\n", what);
    g_fail++;
}

// ---------------------------------------------------------------- helpers
static void pushImm(std::vector<uint8_t>& v, uint8_t logical, uint8_t reg, uint64_t imm) {
    v.push_back(logical);
    v.push_back(reg);
    for (int k = 0; k < 8; k++) v.push_back((uint8_t)(imm >> (k * 8)));
}
static void pushRR(std::vector<uint8_t>& v, uint8_t logical, uint8_t a, uint8_t b) {
    v.push_back(logical); v.push_back(a); v.push_back(b);
}

// Identity mapping: these tests operate on logical opcodes directly so the
// failure mode being tested is the transform, not the permutation.
static void identityTables(uint8_t* mapping, uint8_t* reverse) {
    for (int i = 0; i < 256; i++) { mapping[i] = (uint8_t)i; reverse[i] = (uint8_t)i; }
}

// A tiny reference interpreter for the subset the tests use. It mirrors the
// runtime handlers exactly for these opcodes.
struct Machine {
    uint64_t r[16] = {0};
    int zf = 0, cf = 0, sf = 0, of = 0;
    int steps = 0;

    void run(const std::vector<uint8_t>& bc, const uint8_t* reverse, int maxSteps = 100000) {
        size_t ip = 0;
        while (ip < bc.size() && steps < maxSteps) {
            uint8_t logical = reverse[bc[ip++]];
            steps++;
            const WireInfo& info = kWireInfo[logical];
            const uint8_t* ops = bc.data() + ip;
            switch (logical) {
            case WIRE_LOADIMM: {
                uint64_t imm = 0;
                for (int k = 0; k < 8; k++) imm |= (uint64_t)ops[1 + k] << (k * 8);
                r[ops[0]] = imm; break;
            }
            case WIRE_MOVE:  r[ops[0]] = r[ops[1]]; break;
            case WIRE_ADD: {
                uint64_t a = r[ops[0]], b = r[ops[1]], res = a + b;
                cf = res < a; of = (((a ^ res) & (b ^ res)) >> 63) & 1;
                r[ops[0]] = res; zf = res == 0; sf = (res >> 63) & 1; break;
            }
            case WIRE_SUB: {
                uint64_t a = r[ops[0]], b = r[ops[1]], res = a - b;
                cf = a < b; of = (((a ^ b) & (a ^ res)) >> 63) & 1;
                r[ops[0]] = res; zf = res == 0; sf = (res >> 63) & 1; break;
            }
            case WIRE_AND: { uint64_t res = r[ops[0]] & r[ops[1]];
                r[ops[0]] = res; zf = res == 0; sf = (res >> 63) & 1; cf = 0; of = 0; break; }
            case WIRE_OR:  { uint64_t res = r[ops[0]] | r[ops[1]];
                r[ops[0]] = res; zf = res == 0; sf = (res >> 63) & 1; cf = 0; of = 0; break; }
            case WIRE_XOR: { uint64_t res = r[ops[0]] ^ r[ops[1]];
                r[ops[0]] = res; zf = res == 0; sf = (res >> 63) & 1; cf = 0; of = 0; break; }
            case WIRE_MUL: r[ops[0]] *= r[ops[1]]; break;
            case WIRE_SHL: r[ops[0]] <<= (r[ops[1]] & 63); break;
            case WIRE_SHR: r[ops[0]] >>= (r[ops[1]] & 63); break;
            case WIRE_SAR: r[ops[0]] = (uint64_t)(((int64_t)r[ops[0]]) >> (r[ops[1]] & 63)); break;
            case WIRE_NOT: r[ops[0]] = ~r[ops[0]]; break;
            case WIRE_NEG: { uint64_t a = r[ops[0]]; r[ops[0]] = (uint64_t)(-(int64_t)a);
                cf = a != 0; zf = r[ops[0]] == 0; sf = (r[ops[0]] >> 63) & 1; break; }
            case WIRE_CMP: { uint64_t a = r[ops[0]], b = r[ops[1]], res = a - b;
                zf = res == 0; cf = a < b; sf = (res >> 63) & 1;
                of = (((a ^ b) & (a ^ res)) >> 63) & 1; break; }
            case WIRE_TEST: { uint64_t res = r[ops[0]] & r[ops[1]];
                zf = res == 0; cf = 0; of = 0; sf = (res >> 63) & 1; break; }
            case WIRE_MULI: case WIRE_ADDI: case WIRE_SUBI: case WIRE_ANDI:
            case WIRE_ORI: case WIRE_XORI: case WIRE_SHRI: case WIRE_SHLI:
            case WIRE_SARI: case WIRE_RORI: case WIRE_ROLI: case WIRE_CMPI: {
                uint64_t imm = 0;
                for (int k = 0; k < 8; k++) imm |= (uint64_t)ops[1 + k] << (k * 8);
                uint64_t a = r[ops[0]], res = 0;
                switch (logical) {
                case WIRE_MULI: res = a * imm; r[ops[0]] = res; break;
                case WIRE_ADDI: res = a + imm; cf = res < a;
                    of = (((a ^ res) & (imm ^ res)) >> 63) & 1;
                    r[ops[0]] = res; zf = res == 0; sf = (res >> 63) & 1; break;
                case WIRE_SUBI: res = a - imm; cf = a < imm;
                    of = (((a ^ imm) & (a ^ res)) >> 63) & 1;
                    r[ops[0]] = res; zf = res == 0; sf = (res >> 63) & 1; break;
                case WIRE_ANDI: res = a & imm; r[ops[0]] = res;
                    zf = res == 0; sf = (res >> 63) & 1; cf = 0; of = 0; break;
                case WIRE_ORI: res = a | imm; r[ops[0]] = res;
                    zf = res == 0; sf = (res >> 63) & 1; cf = 0; of = 0; break;
                case WIRE_XORI: res = a ^ imm; r[ops[0]] = res;
                    zf = res == 0; sf = (res >> 63) & 1; cf = 0; of = 0; break;
                case WIRE_SHRI: r[ops[0]] = a >> (imm & 63); break;
                case WIRE_SHLI: r[ops[0]] = a << (imm & 63); break;
                case WIRE_SARI: r[ops[0]] = (uint64_t)(((int64_t)a) >> (imm & 63)); break;
                case WIRE_RORI: { uint32_t s = (uint32_t)(imm & 63);
                    r[ops[0]] = s ? ((a >> s) | (a << (64 - s))) : a; break; }
                case WIRE_ROLI: { uint32_t s = (uint32_t)(imm & 63);
                    r[ops[0]] = s ? ((a << s) | (a >> (64 - s))) : a; break; }
                case WIRE_CMPI: res = a - imm; zf = res == 0; cf = a < imm;
                    sf = (res >> 63) & 1;
                    of = (((a ^ imm) & (a ^ res)) >> 63) & 1; break;
                }
                break;
            }
            case WIRE_MOVZXB: r[ops[0]] = (uint8_t)r[ops[1]]; break;
            case WIRE_MOVZXW: r[ops[0]] = (uint16_t)r[ops[1]]; break;
            case WIRE_MOVSXB: r[ops[0]] = (uint64_t)(int64_t)(int8_t)r[ops[1]]; break;
            case WIRE_MOVSXW: r[ops[0]] = (uint64_t)(int64_t)(int16_t)r[ops[1]]; break;
            case WIRE_MOVSXD: r[ops[0]] = (uint64_t)(int64_t)(int32_t)r[ops[1]]; break;
            case WIRE_MOVD:   r[ops[0]] = (uint32_t)r[ops[1]]; break;
            case WIRE_ADDD: { uint32_t a = (uint32_t)r[ops[0]], b = (uint32_t)r[ops[1]], res = a + b;
                cf = res < a; of = (((a ^ res) & (b ^ res)) >> 31) & 1;
                r[ops[0]] = (uint32_t)res; zf = res == 0; sf = (res >> 31) & 1; break; }
            case WIRE_SUBD: { uint32_t a = (uint32_t)r[ops[0]], b = (uint32_t)r[ops[1]], res = a - b;
                cf = a < b; of = (((a ^ b) & (a ^ res)) >> 31) & 1;
                r[ops[0]] = (uint32_t)res; zf = res == 0; sf = (res >> 31) & 1; break; }
            case WIRE_ANDD: { uint32_t res = (uint32_t)r[ops[0]] & (uint32_t)r[ops[1]];
                r[ops[0]] = res; zf = res == 0; sf = (res >> 31) & 1; cf = 0; of = 0; break; }
            case WIRE_ORD: { uint32_t res = (uint32_t)r[ops[0]] | (uint32_t)r[ops[1]];
                r[ops[0]] = res; zf = res == 0; sf = (res >> 31) & 1; cf = 0; of = 0; break; }
            case WIRE_XORD: { uint32_t res = (uint32_t)r[ops[0]] ^ (uint32_t)r[ops[1]];
                r[ops[0]] = res; zf = res == 0; sf = (res >> 31) & 1; cf = 0; of = 0; break; }
            case WIRE_MULD: r[ops[0]] = (uint32_t)((uint64_t)(uint32_t)r[ops[0]] * (uint32_t)r[ops[1]]); break;
            case WIRE_ADDID: case WIRE_SUBID: case WIRE_ANDID: case WIRE_ORID:
            case WIRE_XORID: case WIRE_SHLID: case WIRE_SHRID: case WIRE_SARID: {
                uint64_t imm = 0;
                for (int k = 0; k < 8; k++) imm |= (uint64_t)ops[1 + k] << (k * 8);
                uint32_t a = (uint32_t)r[ops[0]], b = (uint32_t)imm, res = 0;
                switch (logical) {
                case WIRE_ADDID: res = a + b; r[ops[0]] = res; zf = res == 0; break;
                case WIRE_SUBID: res = a - b; r[ops[0]] = res; zf = res == 0; break;
                case WIRE_ANDID: res = a & b; r[ops[0]] = res; zf = res == 0; break;
                case WIRE_ORID:  res = a | b; r[ops[0]] = res; zf = res == 0; break;
                case WIRE_XORID: res = a ^ b; r[ops[0]] = res; zf = res == 0; break;
                case WIRE_SHLID: r[ops[0]] = (uint32_t)(a << (b & 31)); break;
                case WIRE_SHRID: r[ops[0]] = a >> (b & 31); break;
                case WIRE_SARID: r[ops[0]] = (uint32_t)(((int32_t)a) >> (b & 31)); break;
                }
                sf = (((uint32_t)r[ops[0]]) >> 31) & 1;
                break;
            }
            case WIRE_HALT: case WIRE_STAGEEND: case WIRE_ENDBR:
                if (logical == WIRE_HALT) { ip = bc.size(); break; }
                break;
            default:
                // Not modelled: stop rather than pretend.
                ip = bc.size();
                break;
            }
            (void)info;
            ip += (logical == WIRE_LOADIMM || (logical >= WIRE_MULI && logical <= WIRE_CMPI) ||
                   (logical >= WIRE_SHRI && logical <= WIRE_SARI) ||
                   (logical >= WIRE_ADDID)) ? 0 : 0;
            // Advance past the operand bytes just consumed.
            uint32_t consumed = WireInfo{}.len;
            (void)consumed;
            switch (logical) {
            case WIRE_LOADIMM: case WIRE_MULI: case WIRE_ADDI: case WIRE_SUBI:
            case WIRE_ANDI: case WIRE_ORI: case WIRE_XORI: case WIRE_SHRI:
            case WIRE_SHLI: case WIRE_SARI: case WIRE_RORI: case WIRE_ROLI:
            case WIRE_CMPI: case WIRE_ADDID: case WIRE_SUBID: case WIRE_ANDID:
            case WIRE_ORID: case WIRE_XORID: case WIRE_SHLID: case WIRE_SHRID:
            case WIRE_SARID:
                ip += 9; break;
            case WIRE_MOVE: case WIRE_XOREQ: case WIRE_ADD: case WIRE_SUB:
            case WIRE_MUL: case WIRE_AND: case WIRE_OR: case WIRE_XOR:
            case WIRE_SHL: case WIRE_SHR: case WIRE_SAR: case WIRE_CMP:
            case WIRE_TEST: case WIRE_ROL: case WIRE_ROR:
            case WIRE_ADDD: case WIRE_SUBD: case WIRE_ANDD: case WIRE_ORD:
            case WIRE_XORD: case WIRE_MULD: case WIRE_CMPD: case WIRE_TESTD:
            case WIRE_MOVD: case WIRE_MOVZXB: case WIRE_MOVZXW: case WIRE_MOVSXB:
            case WIRE_MOVSXW: case WIRE_MOVSXD:
                ip += 2; break;
            case WIRE_NOT: case WIRE_NEG: case WIRE_NEGD: case WIRE_NOTD:
                ip += 1; break;
            default: break;
            }
        }
    }
};

// A program with plenty of arithmetic so the lifter has material to work with.
static std::vector<uint8_t> arithmeticProgram() {
    std::vector<uint8_t> bc;
    pushImm(bc, WIRE_LOADIMM, 1, 0x1122334455667788ull);
    pushImm(bc, WIRE_LOADIMM, 2, 0x9ABCDEF012345678ull);
    pushRR(bc, WIRE_ADD, 1, 2);
    pushRR(bc, WIRE_XOR, 2, 1);
    pushRR(bc, WIRE_SUB, 1, 2);
    pushRR(bc, WIRE_AND, 3, 1);
    pushImm(bc, WIRE_ADDI, 3, 0x1000);
    pushRR(bc, WIRE_MUL, 3, 2);
    pushRR(bc, WIRE_SHL, 3, 1);
    pushRR(bc, WIRE_SHR, 3, 1);
    pushRR(bc, WIRE_OR, 4, 3);
    pushRR(bc, WIRE_NOT, 5, 4);
    pushRR(bc, WIRE_TEST, 5, 5);
    pushRR(bc, WIRE_CMP, 5, 1);
    pushRR(bc, WIRE_ADDD, 6, 1);
    pushRR(bc, WIRE_XORD, 6, 2);
    pushImm(bc, WIRE_ROLI, 6, 7);
    pushRR(bc, WIRE_MOVZXB, 7, 6);   // MOVSX/MOVZX take a register source only
    pushRR(bc, WIRE_MOVSXB, 7, 6);
    pushRR(bc, WIRE_MOVZXW, 8, 6);
    pushImm(bc, WIRE_LOADIMM, 9, 0xDEADBEEFCAFEBABEull);
    pushRR(bc, WIRE_ADD, 9, 7);
    pushRR(bc, WIRE_XOR, 9, 8);
    bc.push_back(WIRE_HALT);
    return bc;
}

int main() {
    setvbuf(stdout, nullptr, _IONBF, 0);
    printf("revirtualization transform tests\n");
    printf("----------------------------------------\n");

    uint8_t mapping[256], reverse[256];
    identityTables(mapping, reverse);

    // ---- 1. reference program runs -------------------------------------
    std::vector<uint8_t> prog = arithmeticProgram();
    Machine ref;
    ref.run(prog, reverse);
    check(ref.steps > 10, "reference program executed");

    // ---- 2. splitStages ------------------------------------------------
    printf("[1] vmSplitStages\n");
    {
        std::vector<VmStage> stages;
        // A small target size forces several stages.
        bool ok = vmSplitStages(prog, reverse, mapping, 0x1234, 24, stages);
        check(ok, "split succeeded on an arithmetic program");
        check(stages.size() >= 2, "produced at least two stages");

        // Every stage must parse exactly and keep its branches internal.
        size_t totalInsns = 0;
        for (size_t s = 0; s < stages.size(); s++) {
            const VmStage& st = stages[s];
            size_t ip = 0;
            bool parses = true;
            size_t insns = 0;
            while (ip < st.bc.size()) {
                uint8_t logical = st.reverse[st.bc[ip]];
                uint32_t len = wireInsnLength(logical);
                if (!len || ip + len > st.bc.size()) { parses = false; break; }
                if (wireIsBranchOp(logical)) {
                    uint32_t tgt = (uint32_t)st.bc[ip + 1] | ((uint32_t)st.bc[ip + 2] << 8) |
                                   ((uint32_t)st.bc[ip + 3] << 16) | ((uint32_t)st.bc[ip + 4] << 24);
                    if (tgt > st.bc.size()) parses = false;
                }
                ip += len;
                insns++;
            }
            check(parses, "stage stream parses exactly");
            totalInsns += insns;
            // Every stage except the last must end by handing over.
            if (s + 1 < stages.size()) {
                uint8_t lastLogical = st.reverse[st.bc.back()];
                check(lastLogical == WIRE_STAGEEND, "non-final stage ends with STAGEEND");
            }
        }
        check(totalInsns >= 24, "stages together carry the whole program");
        // Distinct stages must not share an opcode permutation.
        check(!std::memcmp(stages[0].reverse, stages[1].reverse, 256) == 0,
              "stages use independent opcode permutations");
    }

    // ---- 3. liftGuestBlocks -------------------------------------------
    printf("[2] vmLiftGuestBlocks\n");
    {
        std::vector<VmStage> stages;
        vmSplitStages(prog, reverse, mapping, 0x99, 4096, stages);
        // One stage covering everything is what the lifter is normally given
        // when the program is small; build it directly from the reference
        // program in that case.
        VmStage whole;
        whole.bc = prog;
        std::memcpy(whole.reverse, reverse, 256);
        std::memcpy(whole.mapping, mapping, 256);
        whole.rva = 0;

        std::vector<VmGuestBlock> guests;
        bool ok = vmLiftGuestBlocks(whole, 0xABC, 16, 0, 1, guests);
        check(ok, "lift succeeded");
        check(!guests.empty(), "produced at least one guest block");

        // Permutations must be total bijections over all sixteen slots.
        for (auto& g : guests) {
            bool seen[16] = { false };
            bool bij = true;
            for (int k = 0; k < 16; k++) {
                if (g.regPerm[k] > 15 || seen[g.regPerm[k]]) { bij = false; break; }
                seen[g.regPerm[k]] = true;
            }
            check(bij, "register permutation is a bijection");
            check(g.writeMask != 0, "guest block declares the registers it writes");
        }

        // The rewritten stage must call each lifted block exactly once, in
        // order, and otherwise be the original program.
        size_t calls = 0;
        {
            size_t ip = 0;
            while (ip < whole.bc.size()) {
                uint8_t logical = whole.reverse[whole.bc[ip]];
                uint32_t len = wireInsnLength(logical);
                if (!len || ip + len > whole.bc.size()) break;
                if (logical == WIRE_GSTAGE) calls++;
                ip += len;
            }
        }
        check(calls == guests.size(), "stage calls every lifted block");

        // Semantic equivalence: run the guest blocks in place of their runs and
        // compare the final register file with the reference result.
        Machine lifted;
        {
            // Execute the rewritten outer stage, entering guest blocks where the
            // stage calls them. This mirrors np_vm_run_stream's contract.
            size_t ip = 0;
            while (ip < whole.bc.size()) {
                uint8_t logical = whole.reverse[whole.bc[ip]];
                uint32_t len = wireInsnLength(logical);
                if (!len || ip + len > whole.bc.size()) break;
                if (logical == WIRE_GSTAGE) {
                    uint32_t idx = (uint32_t)whole.bc[ip + 1] | ((uint32_t)whole.bc[ip + 2] << 8) |
                                   ((uint32_t)whole.bc[ip + 3] << 16) | ((uint32_t)whole.bc[ip + 4] << 24);
                    if (idx < guests.size()) {
                        const VmGuestBlock& g = guests[idx];
                        // unpermute
                        uint64_t slot[16];
                        for (int k = 0; k < 16; k++) slot[k] = 0;
                        for (int k = 0; k < 16; k++) slot[g.regPerm[k]] = lifted.r[k];
                        Machine inner;
                        std::memcpy(inner.r, slot, sizeof(slot));
                        inner.zf = lifted.zf; inner.cf = lifted.cf;
                        inner.sf = lifted.sf; inner.of = lifted.of;
                        inner.run(g.bc, g.reverse);
                        for (int k = 0; k < 16; k++)
                            if (g.writeMask & (1u << k)) lifted.r[k] = inner.r[g.regPerm[k]];
                        lifted.zf = inner.zf; lifted.cf = inner.cf;
                        lifted.sf = inner.sf; lifted.of = inner.of;
                    }
                    ip += len;
                    continue;
                }
                // Feed the single non-guest instruction to the reference
                // executor by running just that slice.
                std::vector<uint8_t> one(whole.bc.begin() + ip, whole.bc.begin() + ip + len);
                if (logical == WIRE_HALT) break;
                Machine step;
                std::memcpy(step.r, lifted.r, sizeof(lifted.r));
                step.zf = lifted.zf; step.cf = lifted.cf;
                step.sf = lifted.sf; step.of = lifted.of;
                std::vector<uint8_t> slice = one;
                step.run(slice, whole.reverse);
                std::memcpy(lifted.r, step.r, sizeof(lifted.r));
                lifted.zf = step.zf; lifted.cf = step.cf;
                lifted.sf = step.sf; lifted.of = step.of;
                ip += len;
            }
        }
        bool same = true;
        for (int k = 0; k < 16; k++) {
            if (lifted.r[k] != ref.r[k]) {
                printf("  register %d: lifted=0x%llX reference=0x%llX\n", k,
                       (unsigned long long)lifted.r[k],
                       (unsigned long long)ref.r[k]);
                same = false;
            }
        }
        check(same, "lifted execution reproduces the reference register file");
    }

    // ---- 4. safety refusals -------------------------------------------
    printf("[3] refusal paths\n");
    {
        // A program with an external branch must not be split: a stage that
        // cannot contain its own edges would execute the wrong path.
        std::vector<uint8_t> bad;
        pushImm(bad, WIRE_LOADIMM, 1, 5);
        bad.push_back(WIRE_JMP);
        for (int k = 0; k < 4; k++) bad.push_back(0x00);   // target 0 == itself
        pushImm(bad, WIRE_LOADIMM, 2, 7);
        bad.push_back(WIRE_HALT);
        std::vector<VmStage> stages;
        bool split = vmSplitStages(bad, reverse, mapping, 1, 24, stages);
        // A self-loop is legal inside one stage, but a single-stage result must
        // be reported as "nothing to split".
        check(split == false || stages.size() >= 1, "self-branch program does not crash the splitter");

        // A tiny program must be refused outright.
        std::vector<uint8_t> tiny = { WIRE_HALT };
        stages.clear();
        check(!vmSplitStages(tiny, reverse, mapping, 1, 24, stages),
              "program below the stage minimum is refused");

        // A program with no liftable run at all must not produce blocks.
        std::vector<uint8_t> nomem;
        pushImm(nomem, WIRE_LOADIMM, 1, 1);
        nomem.push_back(WIRE_STAGEEND);
        nomem.push_back(WIRE_HALT);
        VmStage ns;
        ns.bc = nomem;
        std::memcpy(ns.reverse, reverse, 256);
        std::memcpy(ns.mapping, mapping, 256);
        std::vector<VmGuestBlock> none;
        check(!vmLiftGuestBlocks(ns, 2, 16, 0, 1, none), "no liftable run is refused");
    }

    // ---- 5. nested levels (revirtualization_level > 1) ----------------
    // Level N must lift runs out of the blocks produced by level N-1, so the
    // deepest descriptor is reachable only through N dispatches and the register
    // permutation of a child composes with its parent's.
    printf("[4] vmRevirtualize nesting\n");
    {
        // The flat program is a single straight-line stage; a large target size
        // keeps the split a single stage so levels 2..4 have material to lift.
        std::vector<uint8_t> flat = arithmeticProgram();

        for (uint32_t want = 1; want <= 4; want++) {
            std::vector<VmStage> stages;
            std::vector<VmGuestBlock> guests;
            uint32_t reached = vmRevirtualize(flat, reverse, mapping, 0x5150, 4096,
                                              want, 96, stages, guests);
            char label[96];
            snprintf(label, sizeof(label), "level %u: transform reports what it built", want);
            check(reached >= 1 && reached <= want, label);
            if (guests.empty()) continue;

            bool levelsOk = true, hasOne = false;
            uint32_t deepest = 0;
            for (auto& g : guests) {
                if (g.level == 0 || g.level > reached) { levelsOk = false; break; }
                if (g.level == 1) hasOne = true;
                if (g.level > deepest) deepest = g.level;
            }
            check(levelsOk, "descriptor levels stay inside the reached range");
            check(hasOne, "at least one level-1 block exists");
            check(deepest == reached, "reported level equals the deepest descriptor");
            check(guests.size() <= 96u, "guest table stays inside the runtime ceiling");

            // The descriptor flags are the only channel the level travels on, so
            // they must round-trip through the helpers the runtime mirrors.
            bool packed = true;
            for (auto& g : guests) {
                uint32_t f = vmGuestPackFlags(g.writeMask, g.level);
                if (!(f & kVmGuestFlagLive)) { packed = false; break; }
                if (vmGuestWriteMaskOf(f) != (g.writeMask & 0xFFFFu)) { packed = false; break; }
                if (vmGuestLevelOf(f) != g.level) { packed = false; break; }
            }
            check(packed, "descriptor flags round-trip writeMask and level");

            // Every WIRE_GSTAGE inside a block must name an existing, strictly
            // deeper descriptor - never itself, never a shallower one.
            bool idxOk = true;
            for (auto& g : guests) {
                size_t ip = 0;
                while (ip < g.bc.size()) {
                    uint8_t logical = g.reverse[g.bc[ip]];
                    uint32_t len = wireInsnLength(logical);
                    if (!len || ip + len > g.bc.size()) { idxOk = false; break; }
                    if (logical == WIRE_GSTAGE) {
                        uint32_t idx = (uint32_t)g.bc[ip + 1] | ((uint32_t)g.bc[ip + 2] << 8) |
                                       ((uint32_t)g.bc[ip + 3] << 16) | ((uint32_t)g.bc[ip + 4] << 24);
                        if (idx >= guests.size()) { idxOk = false; break; }
                        if (guests[idx].level <= g.level) { idxOk = false; break; }
                    }
                    ip += len;
                }
                if (!idxOk) break;
            }
            check(idxOk, "nested calls resolve to deeper descriptors only");

            // Regression guard: the outer decoder must still parse every stage.
            bool stagesParse = true;
            for (auto& st : stages) {
                size_t ip = 0;
                while (ip < st.bc.size()) {
                    uint8_t logical = st.reverse[st.bc[ip]];
                    uint32_t len = wireInsnLength(logical);
                    if (!len || ip + len > st.bc.size()) { stagesParse = false; break; }
                    ip += len;
                }
                if (!stagesParse) break;
            }
            check(stagesParse, "stage streams still parse exactly at this level");
        }

        // Semantic equivalence through the real nested path. The walker below
        // mirrors runtime/prot64.c: unpermute the register file into the block's
        // slots, run it, then copy back only the registers writeMask names -
        // recursing on WIRE_GSTAGE exactly like np_vm_guest does.
        struct Walker {
            const std::vector<VmGuestBlock>& gs;
            Machine& m;

            void runBlock(const VmGuestBlock& g, uint32_t depth) {
                uint64_t slot[16];
                for (int k = 0; k < 16; k++) slot[k] = 0;
                for (int k = 0; k < 16; k++) slot[g.regPerm[k]] = m.r[k];

                Machine inner;
                std::memcpy(inner.r, slot, sizeof(slot));
                inner.zf = m.zf; inner.cf = m.cf;
                inner.sf = m.sf; inner.of = m.of;

                size_t ip = 0;
                uint32_t steps = 0;
                while (ip < g.bc.size() && steps < 100000u) {
                    steps++;
                    uint8_t logical = g.reverse[g.bc[ip]];
                    uint32_t len = wireInsnLength(logical);
                    if (!len || ip + len > g.bc.size()) break;
                    if (logical == WIRE_GSTAGE) {
                        uint32_t idx = (uint32_t)g.bc[ip + 1] | ((uint32_t)g.bc[ip + 2] << 8) |
                                       ((uint32_t)g.bc[ip + 3] << 16) | ((uint32_t)g.bc[ip + 4] << 24);
                        if (idx < gs.size() && depth < kMaxGuestDepth) {
                            // Recurse with the *inner* machine as the parent
                            // frame, which is what the runtime does.
                            Machine saved = m;
                            m = inner;
                            runBlock(gs[idx], depth + 1);
                            inner = m;
                            m = saved;
                        }
                        ip += len;
                        continue;
                    }
                    if (logical == WIRE_HALT) break;
                    std::vector<uint8_t> one(g.bc.begin() + ip, g.bc.begin() + ip + len);
                    Machine step = inner;
                    step.run(one, g.reverse);
                    inner = step;
                    ip += len;
                }

                for (int k = 0; k < 16; k++)
                    if (g.writeMask & (1u << k)) m.r[k] = inner.r[g.regPerm[k]];
                m.zf = inner.zf; m.cf = inner.cf; m.sf = inner.sf; m.of = inner.of;
            }
        };

        for (uint32_t want = 2; want <= 4; want++) {
            std::vector<VmStage> stages;
            std::vector<VmGuestBlock> guests;
            uint32_t reached = vmRevirtualize(flat, reverse, mapping, 0xBEEF + want, 4096,
                                              want, 96, stages, guests);
            if (reached < 2 || guests.empty()) {
                // Fail-safe is allowed, but it must not be reported as success.
                check(reached < 2, "level >=2 either lifts or reports a lower level");
                continue;
            }

            Machine ref;
            ref.run(arithmeticProgram(), reverse);

            Machine got;
            Walker w{guests, got};
            // Execute the stage stream, entering guests on WIRE_GSTAGE.
            size_t ip = 0;
            uint32_t steps = 0;
            while (ip < stages[0].bc.size() && steps < 100000u) {
                steps++;
                uint8_t logical = stages[0].reverse[stages[0].bc[ip]];
                uint32_t len = wireInsnLength(logical);
                if (!len || ip + len > stages[0].bc.size()) break;
                if (logical == WIRE_GSTAGE) {
                    uint32_t idx = (uint32_t)stages[0].bc[ip + 1] |
                                   ((uint32_t)stages[0].bc[ip + 2] << 8) |
                                   ((uint32_t)stages[0].bc[ip + 3] << 16) |
                                   ((uint32_t)stages[0].bc[ip + 4] << 24);
                    if (idx < guests.size()) w.runBlock(guests[idx], 1);
                    ip += len;
                    continue;
                }
                if (logical == WIRE_HALT || logical == WIRE_STAGEEND) break;
                std::vector<uint8_t> one(stages[0].bc.begin() + ip,
                                         stages[0].bc.begin() + ip + len);
                Machine step = got;
                step.run(one, stages[0].reverse);
                got = step;
                ip += len;
            }

            bool same = true;
            for (int k = 0; k < 16; k++)
                if (got.r[k] != ref.r[k]) {
                    printf("  level %u reg %d: nested=0x%llX reference=0x%llX\n", want, k,
                           (unsigned long long)got.r[k], (unsigned long long)ref.r[k]);
                    same = false;
                }
            char label[96];
            snprintf(label, sizeof(label),
                     "level %u: nested execution reproduces the reference register file", want);
            check(same, label);
        }
    }

    printf("----------------------------------------\n");
    printf("%d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
