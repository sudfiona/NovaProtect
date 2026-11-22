// vmcoverage.cpp - measure virtualization coverage by running the REAL
// translator over every .pdata function of a target image.
//
// This is the measurement tool behind docs/exceed-vmprotect-roadmap.md: the
// classification is whatever Packer::vmLowerRegion + VMTranslator would do,
// because it calls VMTranslator::translate directly and buckets by the
// reported skip reason (or "virtualizable"). Region RVA coverage additionally
// reports how many bytes end up inside virtualized bodies.
//
// Build:
//   g++ -std=c++17 -O2 -Iinclude tools/vmcoverage.cpp src/pe_lib.cpp ^
//       src/disasm.cpp src/vm_engine.cpp -o vmcoverage.exe
// Usage:
//   vmcoverage <target.exe> [max-examples-per-bucket]
//
// x64 only (the .pdata walker is the x64 function source).
#include "pe_lib.h"
#include "disasm.h"
#include "vm_isa.h"
#include "wire_table.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <map>
#include <string>
#include <vector>

using namespace np;

namespace {

struct Bucket {
    uint32_t count = 0;
    uint32_t bytes = 0;
    std::vector<uint32_t> examples;  // function RVAs
    std::vector<std::string> insnExamples;  // raw bytes of the failing instruction
};

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

} // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::printf("usage: vmcoverage <target.exe> [max-examples]\n");
        return 2;
    }
    int maxExamples = argc > 2 ? std::atoi(argv[2]) : 6;

    PELib pe;
    if (!pe.load(argv[1])) {
        std::printf("cannot load %s: %s\n", argv[1], pe.lastError().c_str());
        return 1;
    }
    if (!pe.is64()) {
        std::printf("%s is x86; .pdata enumeration is x64-only\n", argv[1]);
        return 1;
    }
    const DataDirectory* exc = pe.dataDirectory(3);
    if (!exc || exc->VirtualAddress == 0 || exc->Size < 12) {
        std::printf("no exception directory (.pdata) in %s\n", argv[1]);
        return 1;
    }
    const uint32_t entryCount = exc->Size / 12;
    std::printf("image: %s\nfunctions in .pdata: %u\n\n", argv[1], entryCount);

    std::map<std::string, Bucket> buckets;
    uint32_t virtBytes = 0, totalBytes = 0;

    uint32_t seen = 0, skippedRange = 0;
    for (uint32_t i = 0; i < entryCount; i++) {
        const uint8_t* ent = pe.rvaToPtr(exc->VirtualAddress + i * 12);
        if (!ent) { skippedRange++; continue; }
        uint32_t begin = (uint32_t)ent[0] | ((uint32_t)ent[1] << 8) |
                         ((uint32_t)ent[2] << 16) | ((uint32_t)ent[3] << 24);
        uint32_t end   = (uint32_t)ent[4] | ((uint32_t)ent[5] << 8) |
                         ((uint32_t)ent[6] << 16) | ((uint32_t)ent[7] << 24);
        if (end <= begin || end - begin > 0x10000) { skippedRange++; continue; }
        uint32_t len = end - begin;
        totalBytes += len;

        size_t secA = (size_t)-1;
        const uint8_t* code = locate(pe, begin, len, secA);
        if (!code || secA == (size_t)-1) {
            buckets["outside_section"].count++;
            continue;
        }
        seen++;

        // Exactly what the packer does: walk the function in chunks the same
        // way vmLowerRegion's caller does - a native-bridge cut ends a chunk
        // and the walk resumes after the bridge - and bucket each chunk by
        // its verdict.
        uint32_t chunkStart = 0;
        bool fnFail = false;
        std::string fnWhy;
        for (;;) {
            if (chunkStart >= len) break;
            VMLoweredBlock blk = VMTranslator::translate(code + chunkStart, len - chunkStart,
                                                          pe.imageBase() + begin + chunkStart,
                                                          pe.imageBase(),
                                                          6, 0, true, 0);
        // Stream integrity: the bytecode must walk exactly, instruction by
        // instruction, to a final HALT with nothing left over. A stray
        // operand byte (a missing brace around an emit) shows up here as an
        // early stop or a trailing remainder - it would otherwise decode as
        // an unknown opcode and silently halt the interpreter mid-region.
        if (blk.ok && !blk.bytecode.empty()) {
            const std::vector<uint8_t>& bc = blk.bytecode;
            uint32_t ip = 0;
            int guard = 0;
            bool wellFormed = false;
            while (ip < bc.size() && guard++ < 200000) {
                uint8_t phys = bc[ip];
                uint8_t logical = blk.reverse[phys];
                uint32_t il = wireInsnLength(logical);
                if (il == 0 || ip + il > bc.size()) break;
                if (logical == WIRE_HALT) { wellFormed = (ip + il == bc.size()); break; }
                ip += il;
            }
            if (!wellFormed) {
                Bucket& b = buckets["MALFORMED-BYTECODE"];
                b.count++;
                b.bytes += len;
                if ((int)b.examples.size() < maxExamples) b.examples.push_back(begin);
                continue;
            }
        }
        uint32_t chunkLen = (blk.cut ? blk.cutAt : (len - chunkStart));
        if (blk.ok && !blk.bytecode.empty()) {
            // Mirror the packer's stub rule: the five-byte jump lands at
            // bodyOff and may spill past the chunk only into alignment
            // padding that is not the next function's entry.
            uint32_t stubOff = chunkStart + blk.bodyOff;
            if (chunkLen - blk.bodyOff < 5) {
                bool spillOk = false;
                uint32_t nextBegin = 0xFFFFFFFFu;
                if (i + 1 < entryCount) {
                    const uint8_t* ent2 = pe.rvaToPtr(exc->VirtualAddress + (i + 1) * 12);
                    if (ent2) {
                        nextBegin = (uint32_t)ent2[0] | ((uint32_t)ent2[1] << 8) |
                                    ((uint32_t)ent2[2] << 16) | ((uint32_t)ent2[3] << 24);
                    }
                }
                if (nextBegin >= begin + stubOff + 5) {
                    const uint8_t* spillAt = code + chunkStart + chunkLen;
                    uint32_t spillNeed = 5u - (chunkLen - blk.bodyOff);
                    bool allPad = true;
                    for (uint32_t k = 0; k < spillNeed; k++) {
                        uint8_t bb = spillAt[k];
                        if (bb != 0x00 && bb != 0x90 && bb != 0xCC) { allPad = false; break; }
                    }
                    spillOk = allPad;
                    if (!allPad) {
                        Disassembler dn;
                        uint32_t o = 0;
                        bool ok = true;
                        while (o < spillNeed) {
                            DisasmInsn di;
                            uint32_t il = dn.disassemble(spillAt + o, spillNeed - o, di);
                            if (!il || di.category != InsnCategory::NOP) { ok = false; break; }
                            o += il;
                        }
                        spillOk = ok && (o == spillNeed);
                    }
                }
                if (!spillOk) {
                    Bucket& b = buckets["too small for stub"];
                    b.count++;
                    b.bytes += chunkLen;
                    if ((int)b.examples.size() < maxExamples)
                        b.examples.push_back(begin + chunkStart);
                    if (blk.cut && blk.resumeOff > 0) {
                        chunkStart += blk.resumeOff;
                        continue;
                    }
                    break;
                }
            }
            std::string why = "virtualizable";
            if (blk.bodyOff > 0) why = "virtualizable (prologue trimmed)";
            Bucket& b = buckets[why];
            b.count++;
            b.bytes += chunkLen;
            if ((int)b.examples.size() < maxExamples) b.examples.push_back(begin + chunkStart);
            virtBytes += (chunkLen > blk.bodyOff) ? (chunkLen - blk.bodyOff) : 0;
        } else {
            std::string why = blk.skipReason.empty() ? "unknown" : blk.skipReason;
            Bucket& b = buckets[why];
            b.count++;
            b.bytes += chunkLen;
            if ((int)b.examples.size() < maxExamples) b.examples.push_back(begin + chunkStart);
            if ((int)b.insnExamples.size() < maxExamples && blk.skipOffset < chunkLen) {
                Disassembler d2;
                DisasmInsn in2;
                uint32_t l2 = d2.disassemble(code + chunkStart + blk.skipOffset,
                                             chunkLen - blk.skipOffset, in2);
                std::string hx;
                char buf[8];
                for (uint32_t k = 0; k < (l2 ? l2 : 8) && k < 16; k++) {
                    std::snprintf(buf, sizeof(buf), "%02X ", code[chunkStart + blk.skipOffset + k]);
                    hx += buf;
                }
                b.insnExamples.push_back("+" + std::to_string(blk.skipOffset) + " [" + hx + "] cat" +
                    std::to_string((int)blk.skipCat) + " op" + std::to_string((int)blk.skipOp) +
                    "/" + std::to_string((int)blk.skipOp2) + " " + in2.toString());
            }
            fnFail = true;
            fnWhy = why;
        }
        if (blk.cut && blk.resumeOff > 0) {
            // The bridge instruction itself stays native - its bytes are not
            // part of any chunk and never count as virtualized.
            totalBytes += 0;  // already counted once for the function
            chunkStart += blk.resumeOff;
            continue;
        }
        break;
    }
    if (fnFail && fnWhy.rfind("virtualizable", 0) != 0) {
        // keep per-chunk buckets as recorded above
    }
    }

    std::printf("analysed: %u   unparsable range entries: %u\n\n", seen, skippedRange);
    uint32_t total = 0;
    for (const auto& kv : buckets) total += kv.second.count;
    if (total == 0) { std::printf("no functions analysed\n"); return 0; }

    std::vector<std::pair<std::string, Bucket>> rows(buckets.begin(), buckets.end());
    std::sort(rows.begin(), rows.end(),
              [](const auto& a, const auto& b) { return a.second.bytes > b.second.bytes; });

    std::printf("%-46s %8s %10s %8s\n", "bucket", "count", "bytes", "byte-share");
    std::printf("---------------------------------------------- ---------- ---------- --------\n");
    for (const auto& kv : rows) {
        std::printf("%-46s %8u %10u %7.1f%%\n", kv.first.c_str(), kv.second.count, kv.second.bytes,
                    totalBytes ? 100.0 * kv.second.bytes / totalBytes : 0.0);
    }
    std::printf("---------------------------------------------- ---------- ---------- --------\n");
    std::printf("%-46s %8u %7.1f%%\n", "TOTAL", total, 100.0);
    std::printf("\nvirtualized bytes: %u / %u (%.1f%%)\n", virtBytes, totalBytes,
                totalBytes ? 100.0 * virtBytes / totalBytes : 0.0);
    for (const auto& kv : rows) {
        if (kv.first.rfind("virtualizable", 0) == 0) continue;
        if (kv.second.examples.empty()) continue;
        std::printf("\n%s examples (RVA):", kv.first.c_str());
        for (uint32_t rva : kv.second.examples) std::printf(" 0x%X", rva);
        for (const auto& s : kv.second.insnExamples) std::printf("\n    %s", s.c_str());
    }
    std::printf("\n");
    return 0;
}
