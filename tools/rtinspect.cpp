// rtinspect.cpp - development diagnostic for the revirtualization payload.
//
// Dumps the VM region table, the stage table and the guest table of a packed
// image straight out of its NPP1 payload, then walks every stage stream and
// every guest block through the wire instruction table. This is how a stage
// split or a lifted run is checked without a debugger: a stream that does not
// parse exactly, a branch target outside its stage, or a guest block whose
// register operands fall outside the permutation all show up as text here.
//
// Build:
//   g++ -std=c++17 -O2 -Iinclude tools\rtinspect.cpp -o rtinspect.exe
#include "wire_table.h"
#include "vm_isa.h"
#include "vm_revirt.h"
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <string>
#include <vector>

using namespace np;

static uint32_t rd32(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static uint64_t rd64(const uint8_t* p) {
    uint64_t v = 0;
    for (int k = 0; k < 8; k++) v |= (uint64_t)p[k] << (k * 8);
    return v;
}
static int32_t rd32s(const uint8_t* p) { return (int32_t)rd32(p); }

// ---- keystream -----------------------------------------------------------
// Bytecode and reverse tables are stored XOR-ed with a counter-mode keystream
// (see vmBytecodeCrypt in src/crypto_layers.cpp and np_vm_window in
// runtime/prot64.c). A dump is unreadable without undoing it first, so the
// inspector reproduces the generator exactly; any divergence between this copy
// and the two originals would show up as an unparsable stream, which is itself
// the diagnostic.
static uint64_t vmMix(uint64_t x) {
    x ^= x >> 30; x *= 0xBF58476D1CE4E5B9ull;
    x ^= x >> 27; x *= 0x94D049BB133111EBull;
    x ^= x >> 31;
    return x;
}
static uint64_t keystreamWord(uint64_t key, uint32_t rva, uint64_t block) {
    uint64_t salted = key ^ ((uint64_t)rva * 0x9E3779B97F4A7C15ull);
    return vmMix(salted + block * 0x9E3779B97F4A7C15ull);
}
static std::vector<uint8_t> decrypt(const uint8_t* p, size_t len, uint64_t key, uint32_t rva) {
    std::vector<uint8_t> out(p, p + len);
    uint64_t current = ~0ull, word = 0;
    for (size_t i = 0; i < len; i++) {
        uint64_t block = (uint64_t)i >> 3;
        if (block != current) { current = block; word = keystreamWord(key, rva, block); }
        out[i] ^= (uint8_t)(word >> ((i & 7u) * 8u));
    }
    return out;
}

static std::vector<uint8_t> readFile(const char* path) {
    std::vector<uint8_t> b;
    FILE* f = nullptr;
    if (fopen_s(&f, path, "rb") || !f) return b;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (n > 0) { b.resize((size_t)n); fread(b.data(), 1, (size_t)n, f); }
    fclose(f);
    return b;
}

// Locate the NPP1 blob. The payload is encrypted at rest in the packed file, so
// a raw byte scan is not reliable: instead walk the section table for the
// protection payload and start from the header the loader uses. For a
// development diagnostic it is enough to find the magic in either the raw image
// or the section whose name is .np_prot.
static const uint8_t* findNpp1(const std::vector<uint8_t>& img, size_t& off) {
    for (size_t i = 0; i + 128 < img.size(); i++) {
        if (img[i] == 'N' && img[i + 1] == 'P' && img[i + 2] == 'P' && img[i + 3] == '1') {
            // Validate before accepting: the region table must sit inside the
            // file and the count must be plausible. A false positive here would
            // otherwise send the walker into unrelated bytes.
            uint32_t tableOff = rd32(img.data() + i + 20);
            uint32_t count = rd32(img.data() + i + 88);
            if (count >= 1 && count <= 64 && tableOff >= 128 &&
                i + tableOff + (size_t)count * 32 <= img.size()) {
                off = i;
                return img.data() + i;
            }
        }
    }
    return nullptr;
}

static const char* opName(uint8_t logical) {
    static const char* names[NP_WIRE_OPCODE_SLOTS] = {
        "unused", "LOADIMM", "LOADB", "XOREQ", "MULI", "ADDI", "SUBI", "ANDI",
        "RORI", "CMPI", "JE", "JNE", "JMP", "MOVE", "XORI", "HALT",
        "LOADQ", "STOREB", "STOREQ", "ADD", "SUB", "MUL", "AND", "OR",
        "XOR", "SHL", "SHR", "SAR", "SHRI", "ORI", "NOT", "NEG",
        "CMP", "TEST", "JNZ", "JZ", "JAE", "JB", "JGE", "JL",
        "JG", "JLE", "ENDBR", "SHLI", "SARI", "LOADW", "LOADD", "LOADSB",
        "LOADSW", "LOADSD", "STOREW", "STORED", "ROL", "ROR", "ROLI", "ADDD",
        "SUBD", "ANDD", "ORD", "XORD", "MULD", "CMPD", "TESTD", "ADDID",
        "SUBID", "ANDID", "ORID", "XORID", "CMPID", "SHLID", "SHRID", "SARID",
        "NEGD", "NOTD", "MOVD", "MOVZXB", "MOVZXW", "MOVSXB", "MOVSXW", "MOVSXD",
        "GSTAGE", "STAGEEND",
    };
    return logical < NP_WIRE_OPCODE_SLOTS ? names[logical] : "?";
}

// Walk one encoded stream and report parse problems plus branch sanity.
static int walk(const char* label, const uint8_t* bc, uint32_t len,
                const uint8_t* reverse, int maxPrint) {
    printf("  %s: %u bytes\n", label, len);
    // First pass: record every instruction boundary. A branch target that lands
    // in the middle of an instruction decodes as garbage at run time, which is
    // the usual way a rewritten stream misbehaves silently, so targets are
    // checked against this map rather than only against the stream length.
    std::vector<char> boundary(len + 1, 0);
    for (uint32_t o = 0; o <= len;) {
        boundary[o] = 1;
        if (o == len) break;
        uint32_t il = wireInsnLength(reverse[bc[o]]);
        if (il == 0 || o + il > len) break;
        o += il;
    }

    uint32_t off = 0, n = 0;
    int bad = 0;
    while (off < len) {
        uint8_t logical = reverse[bc[off]];
        uint32_t ilen = wireInsnLength(logical);
        if (ilen == 0) {
            printf("    !! offset %u: undefined opcode phys=0x%02X\n", off, bc[off]);
            return bad + 1;
        }
        if (off + ilen > len) {
            printf("    !! offset %u: %s truncated (%u > %u)\n", off, opName(logical), off + ilen, len);
            return bad + 1;
        }
        if (wireIsBranchOp(logical)) {
            uint32_t tgt = rd32(bc + off + 1);
            if (tgt > len) {
                printf("    !! offset %u: %s target %u outside stream (%u)\n",
                       off, opName(logical), tgt, len);
                bad++;
            } else if (!boundary[tgt]) {
                printf("    !! offset %u: %s target %u is not an instruction boundary\n",
                       off, opName(logical), tgt);
                bad++;
            }
        }
        if (logical == WIRE_GSTAGE) {
            uint32_t idx = rd32(bc + off + 1);
            if (idx > 4096) {
                printf("    !! offset %u: GSTAGE index %u implausible\n", off, idx);
                bad++;
            }
        }
        if ((int)n < maxPrint) {
            printf("    [%3u] @%-4u %-10s", n, off, opName(logical));
            const WireInfo& info = kWireInfo[logical];
            uint32_t o = off + 1;
            for (uint8_t k = 0; k < info.nops; k++) {
                if (info.op[k] == WireOperandKind::Reg) {
                    printf(" r%u", bc[o]); o += 1;
                } else if (info.op[k] == WireOperandKind::Imm64) {
                    printf(" 0x%llX", (unsigned long long)rd64(bc + o)); o += 8;
                } else {
                    if (info.op[k] == WireOperandKind::Target32)
                        printf(" ->%u", rd32(bc + o));
                    else
                        printf(" %d", rd32s(bc + o));
                    o += 4;
                }
            }
            printf("\n");
        }
        off += ilen;
        n++;
    }
    if (off != len) {
        printf("    !! stream ended at %u, expected %u\n", off, len);
        bad++;
    }
    printf("    %u instructions, %d problem(s)\n", n, bad);
    return bad;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        printf("usage: rtinspect <packed.exe> [max-print]\n");
        return 2;
    }
    int maxPrint = argc > 2 ? atoi(argv[2]) : 12;
    std::vector<uint8_t> img = readFile(argv[1]);
    if (img.empty()) { printf("cannot read %s\n", argv[1]); return 1; }

    size_t npp = 0;
    const uint8_t* b = findNpp1(img, npp);
    if (!b) { printf("no NPP1 payload found\n"); return 1; }
    const size_t payloadRemain = img.size() - npp;
    printf("NPP1 at file offset 0x%zX, flags=0x%X, %zu bytes to end of file\n",
           npp, rd32(b + 8), payloadRemain);

    // Every offset below is payload-relative; refuse to follow one that leaves
    // the image so a misidentified blob reports a diagnostic instead of
    // walking off the end of the buffer.
    auto inBounds = [&](uint64_t payloadOff, uint64_t len) {
        return payloadOff + len <= payloadRemain;
    };

    uint32_t tableOff = rd32(b + 20);
    uint32_t count = rd32(b + 88);
    printf("VM regions: %u (table at payload+%u)\n", count, tableOff);
    if (!count || !tableOff || count > 64 ||
        !inBounds(tableOff, (uint64_t)count * 32)) {
        printf("no usable VM regions\n");
        return 0;
    }

    const uint8_t* rec = b + tableOff;
    int problems = 0;
    for (uint32_t i = 0; i < count; i++) {
        const uint8_t* r = rec + (size_t)i * 32;
        uint32_t rva = rd32(r + 0), size = rd32(r + 4);
        uint32_t bc = rd32(r + 8), bclen = rd32(r + 12);
        uint32_t rev = rd32(r + 16), mask = rd32(r + 20);
        uint32_t reserved = rd32(r + 24);
        uint32_t stages = reserved & 0xFFFFu;
        uint32_t guestBase = reserved >> 16;
        printf("\nregion %u: rva=0x%X size=%u bc=+%u len=%u rev=+%u mask=0x%04X"
               " stages=%u guestBase=%u\n",
               i, rva, size, bc, bclen, rev, mask, stages, guestBase);

        const uint8_t* rv = b + rev;
        printf("  trailer: key=0x%llX rva=0x%X flags=0x%X stageDelta=%d guestDelta=%d guestCount=%u\n",
               (unsigned long long)rd64(rv + 256), rd32(rv + 264), rd32(rv + 268),
               rd32s(rv + 272), rd32s(rv + 276), rd32(rv + 280));

        if (stages) {
            const uint8_t* st = rv + rd32s(rv + 272);
            printf("  stage table at payload+%d\n", (int)((rv - b) + rd32s(rv + 272)));
            for (uint32_t s = 0; s < stages; s++) {
                const uint8_t* e = st + (size_t)s * kVmStageEntrySize;
                uint32_t sbc = rd32(e + 0), slen = rd32(e + 4), srev = rd32(e + 8);
                uint64_t skey = rd64(e + 12);
                uint32_t srva = rd32(e + 20);
                printf("  stage %u: bc=+%u len=%u rev=+%u key=0x%llX rva=0x%X\n",
                       s, sbc, slen, srev, (unsigned long long)skey, srva);
                std::vector<uint8_t> body = decrypt(rv + (int32_t)sbc, slen, skey, srva);
                const uint8_t* srev_p = rv + (int32_t)srev;
                char lbl[48];
                snprintf(lbl, sizeof(lbl), "stage %u stream", s);
                problems += walk(lbl, body.data(), (uint32_t)body.size(), srev_p, maxPrint);
            }
        } else {
            uint64_t rkey = rd64(rv + 256);
            uint32_t rrva = rd32(rv + 264);
            printf("  legacy single stage\n");
            std::vector<uint8_t> body = decrypt(b + bc, bclen, rkey, rrva);
            std::vector<uint8_t> rev(rv, rv + 256);  // reverse tables stay plaintext
            problems += walk("region stream", body.data(), (uint32_t)body.size(), rev.data(), maxPrint);
        }

        uint32_t gc = rd32(rv + 280);
        if (gc && rd32s(rv + 276)) {
            const uint8_t* gt = rv + rd32s(rv + 276);
            printf("  guest table at payload+%d, %u block(s)\n",
                   (int)((rv - b) + rd32s(rv + 276)), gc);
            for (uint32_t g = 0; g < gc; g++) {
                const uint8_t* d = gt + (size_t)g * kVmGuestStageSize;
                int32_t gbc = rd32s(d + 0), grev = rd32s(d + 8);
                uint32_t glen = rd32(d + 4); const uint8_t* gperm_p = rv + rd32s(d + 12);
                uint32_t gflags = rd32(d + 28);
                printf("  guest %u: bc=+%u len=%u rev=+%u perm=+%u key=0x%llX"
                       " rva=0x%X flags=0x%X writeMask=0x%04X\n",
                       g, (unsigned)gbc, glen, (unsigned)grev,
                       (unsigned)(gperm_p - rv),
                       (unsigned long long)rd64(d + 16), rd32(d + 24), gflags,
                       gflags >> 8);
                const uint8_t* perm = gperm_p;
                printf("    perm:");
                for (int k = 0; k < 16; k++) printf(" %u", perm[k]);
                printf("\n");
                uint64_t gkey = rd64(d + 16);
                uint32_t grva = rd32(d + 24);
                std::vector<uint8_t> body = decrypt(rv + gbc, glen, gkey, grva);
                const uint8_t* grev_p = rv + grev;
                char lbl[48];
                snprintf(lbl, sizeof(lbl), "guest %u stream", g);
                problems += walk(lbl, body.data(), (uint32_t)body.size(), grev_p, maxPrint);
            }
        }
    }
    printf("\nTOTAL PROBLEMS: %d\n", problems);
    return problems ? 1 : 0;
}
