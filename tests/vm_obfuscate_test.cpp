// vm_obfuscate_test.cpp — focused tests for the wire-bytecode obfuscator.
//
// The obfuscator inserts instructions (junk and opaque-predicate fake jumps),
// which shifts every byte offset a branch operand refers to. These tests pin
// two properties that a structural change can silently break:
//
//   1. Every branch target in the output lands on an instruction boundary.
//   2. A program with forward and backward branches still computes the same
//      result after obfuscation, at every complexity level.
//
// They run the output through a minimal reference interpreter for the subset of
// the wire ISA the fixtures use. Build:
//   g++ -std=c++17 -Iinclude -o vm_obfuscate_test tests/vm_obfuscate_test.cpp \
//       src/vm_obfuscate.cpp
#include "vm_isa.h"
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

using namespace np;

namespace {

int failures = 0;

void check(bool ok, const char* what) {
    if (!ok) { std::printf("[FAIL] %s\n", what); ++failures; }
    else std::printf("[ OK ] %s\n", what);
}

// ---- tiny assembler over logical opcodes --------------------------------
struct Asm {
    std::vector<uint8_t> code;
    void op(uint8_t o) { code.push_back(o); }
    void imm8(uint8_t v) { code.push_back(v); }
    void imm64(uint64_t v) { for (int k = 0; k < 8; k++) code.push_back((uint8_t)(v >> (k * 8))); }
    void regImm(uint8_t o, uint8_t r, uint64_t v) { op(o); imm8(r); imm64(v); }
    void regReg(uint8_t o, uint8_t a, uint8_t b) { op(o); imm8(a); imm8(b); }
    void branch(uint8_t o) { op(o); code.insert(code.end(), 4, 0); }
    size_t here() const { return code.size(); }
    void patch(size_t at, size_t target) {
        for (int k = 0; k < 4; k++) code[at + 1 + k] = (uint8_t)((uint32_t)target >> (k * 8));
    }
};

struct Machine {
    uint64_t r[16] = {};
    int zf = 0;
    bool halted = false;
};

// Reference semantics for the subset used by the fixtures.
bool run(const std::vector<uint8_t>& code, const uint8_t* reverse, Machine& m) {
    size_t ip = 0;
    int steps = 0;
    while (ip < code.size()) {
        if (++steps > 100000) return false;
        uint8_t op = reverse[code[ip++]];
        switch (op) {
        case WIRE_LOADIMM: {
            uint8_t d = code[ip++];
            uint64_t v = 0;
            for (int k = 0; k < 8; k++) v |= (uint64_t)code[ip++] << (k * 8);
            m.r[d] = v;
            break;
        }
        case WIRE_ADDI: case WIRE_SUBI: case WIRE_ANDI: case WIRE_MULI:
        case WIRE_SHRI: case WIRE_SHLI: case WIRE_CMPI: {
            uint8_t d = code[ip++];
            uint64_t v = 0;
            for (int k = 0; k < 8; k++) v |= (uint64_t)code[ip++] << (k * 8);
            switch (op) {
            case WIRE_ADDI: m.r[d] += v; break;
            case WIRE_SUBI: m.r[d] -= v; break;
            case WIRE_ANDI: m.r[d] &= v; break;
            case WIRE_MULI: m.r[d] *= v; break;
            case WIRE_SHRI: m.r[d] >>= (v & 63u); break;
            case WIRE_SHLI: m.r[d] <<= (v & 63u); break;
            default:        m.zf = (m.r[d] == v); break;
            }
            break;
        }
        case WIRE_MOVE: { uint8_t d = code[ip++], s = code[ip++]; m.r[d] = m.r[s]; break; }
        case WIRE_NOT:  { uint8_t d = code[ip++]; m.r[d] = ~m.r[d]; break; }
        case WIRE_JMP: case WIRE_JZ: case WIRE_JNZ: case WIRE_JE: case WIRE_JNE: {
            uint32_t t = 0;
            for (int k = 0; k < 4; k++) t |= (uint32_t)code[ip++] << (k * 8);
            bool take;
            switch (op) {
            case WIRE_JMP: take = true; break;
            case WIRE_JZ: case WIRE_JE: take = (m.zf != 0); break;
            default: take = (m.zf == 0); break;
            }
            if (take) ip = t;
            break;
        }
        case WIRE_HALT: case WIRE_ENDBR: m.halted = true; return true;
        default: return false; // unknown opcode: the stream is corrupt
        }
    }
    return true;
}

// Every branch must land exactly on an instruction start. Two passes: a forward
// target is not in `starts` yet while the linear scan is still before it.
bool branchesAligned(const std::vector<uint8_t>& code, const uint8_t* reverse) {
    std::vector<size_t> starts;
    std::vector<uint32_t> targets;
    size_t ip = 0;
    while (ip < code.size()) {
        starts.push_back(ip);
        uint8_t op = reverse[code[ip]];
        size_t len = 1;
        switch (op) {
        case WIRE_LOADIMM: case WIRE_MULI: case WIRE_ADDI: case WIRE_SUBI:
        case WIRE_ANDI: case WIRE_RORI: case WIRE_CMPI: case WIRE_XORI:
        case WIRE_SHRI: case WIRE_ORI: case WIRE_SHLI: case WIRE_SARI: len = 10; break;
        case WIRE_LOADB: case WIRE_LOADQ: case WIRE_STOREB: case WIRE_STOREQ: len = 7; break;
        case WIRE_JE: case WIRE_JNE: case WIRE_JMP: case WIRE_JNZ:
        case WIRE_JZ: case WIRE_JAE: case WIRE_JB: case WIRE_JGE:
        case WIRE_JL: case WIRE_JG: case WIRE_JLE: len = 5; break;
        case WIRE_MOVE: case WIRE_XOREQ: case WIRE_ADD: case WIRE_SUB:
        case WIRE_MUL: case WIRE_AND: case WIRE_OR: case WIRE_XOR:
        case WIRE_SHL: case WIRE_SHR: case WIRE_SAR: case WIRE_CMP:
        case WIRE_TEST: len = 3; break;
        case WIRE_NOT: case WIRE_NEG: len = 2; break;
        default: len = 1; break;
        }
        if (ip + len > code.size()) return false;
        if (len == 5) {
            uint32_t t = 0;
            for (int k = 0; k < 4; k++) t |= (uint32_t)code[ip + 1 + k] << (k * 8);
            targets.push_back(t);
        }
        ip += len;
    }
    for (uint32_t t : targets) {
        if (t == code.size()) continue;          // branch to the end is fine
        bool found = false;
        for (size_t s : starts) if (s == t) { found = true; break; }
        if (!found) return false;
    }
    return true;
}

} // namespace

int main() {
    uint8_t reverse[256], mapping[256];
    for (int i = 0; i < 256; i++) { reverse[i] = (uint8_t)i; mapping[i] = (uint8_t)i; }

    // Fixture A: counted loop (backward branch).
    {
        Asm a;
        a.regImm(WIRE_LOADIMM, 0, 0);
        a.regImm(WIRE_LOADIMM, 1, 5);
        size_t loop = a.here();
        a.regImm(WIRE_ADDI, 0, 1);
        a.regImm(WIRE_SUBI, 1, 1);
        a.regImm(WIRE_CMPI, 1, 0);
        size_t jnz = a.here();
        a.branch(WIRE_JNZ);
        a.patch(jnz, loop);
        a.op(WIRE_HALT);

        for (int complexity : {0, 1, 2, 5, 9}) {
            Machine m;
            std::vector<uint8_t> out = vmObfuscate(a.code, reverse, mapping, 0x0003u, (uint8_t)complexity);
            bool ok = run(out, reverse, m) && m.r[0] == 5;
            char label[96];
            std::snprintf(label, sizeof(label), "loop fixture: r0==5 at complexity %d (%zu -> %zu bytes)",
                          complexity, a.code.size(), out.size());
            check(ok, label);
            std::snprintf(label, sizeof(label), "loop fixture: branch targets aligned at complexity %d", complexity);
            check(branchesAligned(out, reverse), label);
        }
    }

    // Fixture B: forward branch that is taken.
    {
        Asm a;
        a.regImm(WIRE_LOADIMM, 0, 7);
        a.regImm(WIRE_CMPI, 0, 7);
        size_t jz = a.here();
        a.branch(WIRE_JZ);
        a.regImm(WIRE_ADDI, 0, 100);
        a.patch(jz, a.here());
        a.op(WIRE_HALT);

        for (int complexity : {0, 1, 2, 5, 9}) {
            Machine m;
            std::vector<uint8_t> out = vmObfuscate(a.code, reverse, mapping, 0x0003u, (uint8_t)complexity);
            bool ok = run(out, reverse, m) && m.r[0] == 7;
            char label[96];
            std::snprintf(label, sizeof(label), "forward-branch fixture: r0==7 at complexity %d (%zu -> %zu bytes)",
                          complexity, a.code.size(), out.size());
            check(ok, label);
        }
    }

    // Fixture C: flags must survive junk insertion. The branch reads flags set
    // two instructions earlier, which is exactly where a careless insertion
    // point would clobber them.
    {
        Asm a;
        a.regImm(WIRE_LOADIMM, 0, 0);
        a.regImm(WIRE_LOADIMM, 1, 3);
        a.regImm(WIRE_CMPI, 1, 3);       // sets zf
        a.regImm(WIRE_LOADIMM, 2, 9);    // does not touch flags
        a.regImm(WIRE_MULI, 2, 2);       // does not touch flags
        size_t jz = a.here();
        a.branch(WIRE_JZ);
        a.regImm(WIRE_ADDI, 0, 100);     // must be skipped
        a.patch(jz, a.here());
        a.op(WIRE_HALT);

        for (int complexity : {0, 1, 2, 5, 9}) {
            Machine m;
            std::vector<uint8_t> out = vmObfuscate(a.code, reverse, mapping, 0x0007u, (uint8_t)complexity);
            bool ok = run(out, reverse, m) && m.r[0] == 0;
            char label[96];
            std::snprintf(label, sizeof(label), "live-flags fixture: r0==0 at complexity %d", complexity);
            check(ok, label);
        }
    }

    if (failures) { std::printf("VM-OBFUSCATE-FAILED (%d)\n", failures); return 1; }
    std::printf("VM-OBFUSCATE-OK\n");
    return 0;
}
