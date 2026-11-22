#include <cstdio>
#include <cstdint>
#include "pe_lib.h"
#include "disasm.h"
using namespace np;
int main(int argc, char** argv) {
    if (argc < 2) return 1;
    PELib pe;
    if (!pe.load(argv[1])) { printf("load fail\n"); return 1; }
    const auto* exc = pe.dataDirectory(3);
    if (!exc || !exc->VirtualAddress) { printf("no pdata\n"); return 1; }
    const uint8_t* p = pe.rvaToPtr(exc->VirtualAddress);
    uint32_t count = exc->Size / 12;
    Disassembler dis;
    int shown = 0;
    int cap = argc > 2 ? atoi(argv[2]) : 6;
    for (uint32_t i = 0; i < count && shown < cap; i++) {
        uint32_t b, e, u;
        memcpy(&b, p + i*12, 4); memcpy(&e, p + i*12 + 4, 4);
        uint32_t len = e - b;
        if (len < 8 || len > 4000) continue;
        const uint8_t* code = pe.rvaToPtr(b);
        if (!code) continue;
        // quick rsp/rbp scan
        bool rsp = false, rbp = false;
        uint32_t off = 0;
        while (off < len) {
            DisasmInsn in;
            uint32_t il = dis.disassemble(code + off, len - off, in);
            if (!il) break;
            Operand ops[3] = {in.dst, in.src, in.extra};
            for (int k = 0; k < 3; k++) {
                if ((uint8_t)ops[k].reg == 4) rsp = true;
                if ((uint8_t)ops[k].reg == 5) rbp = true;
                if (ops[k].type == OperandType::Memory) {
                    if ((uint8_t)ops[k].base == 4 || (uint8_t)ops[k].index == 4) rsp = true;
                    if ((uint8_t)ops[k].base == 5 || (uint8_t)ops[k].index == 5) rbp = true;
                }
            }
            off += il;
        }
        if (!rsp && !rbp) continue;
        printf("=== rva 0x%X len=%u rsp=%d rbp=%d ===\n", b, len, rsp, rbp);
        off = 0;
        int insns = 0;
        while (off < len && insns < 14) {
            DisasmInsn in;
            uint32_t il = dis.disassemble(code + off, len - off, in);
            if (!il) { printf("  +0x%X: <decode fail>\n", off); break; }
            printf("  +0x%03X: %-52s cat=%d\n", off, in.toString().c_str(), (int)in.category);
            off += il; insns++;
        }
        if (off < len) printf("  ... (%u bytes left)\n", len - off);
        shown++;
    }
    return 0;
}
