// vmwhy.cpp - why did translation stop? Dump the decoded instruction stream of
// a single function up to (and past) the first rejection, mirroring the
// translator's flag-safety state machine so the exact rejection rule is visible.
//
// Build:
//   g++ -std=c++17 -O2 -Iinclude tools/vmwhy.cpp src/pe_lib.cpp src/disasm.cpp \
//       src/vm_engine.cpp -o tools/vmwhy.exe -static -static-libgcc -static-libstdc++
// Usage:
//   vmwhy <target.exe> <function-rva> [dump-count]
#include "pe_lib.h"
#include "disasm.h"
#include "vm_isa.h"

#include <cstdio>
#include <cstring>
#include <string>

using namespace np;

namespace {

const uint8_t* locate(const PELib& pe, uint32_t rva, uint32_t len, size_t& secOut) {
    secOut = (size_t)-1;
    for (size_t si = 0; si < pe.sectionCount(); si++) {
        const auto& s = pe.section(si);
        if (rva < s.VirtualAddress) continue;
        if ((uint64_t)rva + len > (uint64_t)s.VirtualAddress + s.VirtualSize) continue;
        size_t off = rva - s.VirtualAddress;
        const auto& d = const_cast<PELib&>(pe).sectionData(si);
        if (off + len > d.size()) continue;
        secOut = si;
        return d.data() + off;
    }
    return nullptr;
}

std::string hexOf(const uint8_t* p, uint32_t n) {
    std::string s;
    char b[8];
    for (uint32_t i = 0; i < n; i++) { std::snprintf(b, sizeof(b), "%02X ", p[i]); s += b; }
    return s;
}

bool isIslandInsn(const DisasmInsn& in) {
    switch (in.category) {
    case InsnCategory::RET: case InsnCategory::LEAVE:
        return true;
    case InsnCategory::POP: case InsnCategory::ADD:
        return true;
    default: return false;
    }
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 3) {
        std::printf("usage: vmwhy <exe> <function-rva-hex> [dump-count]\n");
        return 2;
    }
    const uint32_t rva = (uint32_t)std::strtoul(argv[2], nullptr, 16);
    int dumpCount = argc > 3 ? std::atoi(argv[3]) : 40;

    PELib pe;
    if (!pe.load(argv[1])) { std::printf("load failed: %s\n", pe.lastError().c_str()); return 1; }

    // find the .pdata entry covering rva
    const DataDirectory* exc = pe.dataDirectory(3);
    if (!exc || !exc->VirtualAddress) { std::printf("no .pdata\n"); return 1; }
    uint32_t begin = 0, end = 0;
    const uint32_t n = exc->Size / 12;
    for (uint32_t i = 0; i < n; i++) {
        const uint8_t* e = pe.rvaToPtr(exc->VirtualAddress + i * 12);
        if (!e) continue;
        uint32_t b = (uint32_t)e[0] | ((uint32_t)e[1] << 8) | ((uint32_t)e[2] << 16) | ((uint32_t)e[3] << 24);
        uint32_t t = (uint32_t)e[4] | ((uint32_t)e[5] << 8) | ((uint32_t)e[6] << 16) | ((uint32_t)e[7] << 24);
        if (rva >= b && rva < t) { begin = b; end = t; break; }
    }
    if (!begin) { std::printf("no .pdata entry covers 0x%X\n", rva); return 1; }
    uint32_t len = end - begin;
    std::printf("function 0x%X..0x%X (len=%u, %u bytes)\n", begin, end, len, len);

    size_t sec = 0;
    const uint8_t* code = locate(pe, begin, len, sec);
    if (!code) { std::printf("outside section\n"); return 1; }

    // Run the real translator to get its verdict.
    VMLoweredBlock blk = VMTranslator::translate(code, len, pe.imageBase() + begin,
                                                 pe.imageBase(), 6, 0, true, 0);
    std::printf("translate: ok=%d translated=%u skip=%u bodyOff=%u\n",
                (int)blk.ok, blk.insnsTranslated, blk.insnsSkipped, blk.bodyOff);
    std::printf("  reason: %s\n", blk.skipReason.c_str());
    std::printf("  stop at input offset +0x%X (cat %u op %u/%u)\n\n",
                blk.skipOffset, (unsigned)blk.skipCat, (unsigned)blk.skipOp, (unsigned)blk.skipOp2);

    // Walk the instruction stream, mirroring the translator's pending-flag state.
    Disassembler dis;
    size_t off = 0;
    int idx = 0;
    bool mulFlagsPending = false, byteFlagsPending = false;
    uint32_t mulFlagsOff = 0, byteFlagsOff = 0;
    while (off < len && idx < dumpCount + 30) {
        DisasmInsn in;
        uint32_t l = dis.disassemble(code + off, len - off, in);
        if (!l) { std::printf("+0x%04X  <decode failed>\n", (unsigned)off); break; }
        const bool atStop = ((uint32_t)off == blk.skipOffset);
        std::string flag;
        if (mulFlagsPending) flag += " MULFLAGS(from+" + std::to_string(mulFlagsOff) + ")";
        if (byteFlagsPending) flag += " BYTEFLAGS(from+" + std::to_string(byteFlagsOff) + ")";
        std::printf("%s+0x%04X  %-18s %-28s cc=%u%s\n",
                    atStop ? ">>" : "  ",
                    (unsigned)off,
                    Disassembler::categoryToString(in.category),
                    hexOf(code + off, l).c_str(),
                    (unsigned)in.condition, flag.c_str());
        if (atStop) std::printf("   ^^^^ translator stopped here\n");

        // Mirror the translator's flag bookkeeping (see vm_engine.cpp).
        const uint8_t rexW = (in.prefixes & PREFIX_REX_W) ? 1 : 0;
        const uint8_t width = rexW ? 8u
                            : ((in.prefixes & PREFIX_66) ? 2u
                            : ((in.category == InsnCategory::MOVZX ||
                                in.category == InsnCategory::MOVSX) ? 0u
                            : (in.dst.size ? in.dst.size : 4u)));
        const bool partial = (width == 2 || width == 1) &&
                             in.category != InsnCategory::MOVZX &&
                             in.category != InsnCategory::MOVSX;
        switch (in.category) {
        case InsnCategory::IMUL:
            mulFlagsPending = true; mulFlagsOff = (uint32_t)off;
            byteFlagsPending = false; break;
        case InsnCategory::CMP: case InsnCategory::TEST:
            mulFlagsPending = false; byteFlagsPending = false; break;
        case InsnCategory::ADD: case InsnCategory::SUB: case InsnCategory::AND:
        case InsnCategory::OR: case InsnCategory::XOR:
        case InsnCategory::INC: case InsnCategory::DEC:
        case InsnCategory::NEG: case InsnCategory::SHL: case InsnCategory::SHR:
        case InsnCategory::SAR: case InsnCategory::ROL: case InsnCategory::ROR:
            mulFlagsPending = false;
            byteFlagsPending = partial;
            if (partial) byteFlagsOff = (uint32_t)off;
            break;
        default: break;
        }
        off += l; idx++;
    }
    return 0;
}
