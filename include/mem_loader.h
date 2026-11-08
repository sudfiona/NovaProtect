#pragma once
// NovaProtect memory loader / memory obfuscation.
//
// Two jobs, both file-side so they can be tested without executing anything:
//
//   1. turn a parsed PE into a LoaderPlan: per-region ciphertext plus the
//      protection each region must map with, so the runtime never needs one
//      big RWX allocation (the single strongest behavioural signal a memory
//      scanner has);
//   2. serialise that plan and emit the freestanding C driver that decrypts a
//      window at a time and flips RW -> RX as regions become live.
//
// The keystream is XOR-only and therefore its own inverse: the same function
// encrypts and decrypts, which means the round trip is provable in a unit test
// rather than asserted in a document.

#include "evasion.h"
#include "pe_lib.h"

#include <cstdint>
#include <string>
#include <vector>

namespace np {

struct MemRegionSpec {
    uint32_t rva = 0;
    uint32_t size = 0;
    uint32_t characteristics = 0;
    uint32_t protect = 0;             // PAGE_* constant the runtime maps with
    uint64_t key = 0;
    uint8_t rounds = 0;
    std::vector<uint8_t> cipher;
};

struct LoaderPlan {
    bool is64 = true;
    uint64_t image_base = 0;
    uint32_t entry_rva = 0;
    uint32_t image_size = 0;
    uint32_t window = 4096;
    std::vector<MemRegionSpec> regions;
    std::vector<std::string> import_dlls;
    std::vector<std::pair<uint32_t, std::vector<uint8_t>>> zero_runs;  // .bss-style spans

    uint32_t totalCipherBytes() const;
    std::vector<uint8_t> encode() const;
    static bool decode(const std::vector<uint8_t>& blob, LoaderPlan& out, std::string& error);
};

class MemLoader {
public:
    // Build an encrypted region plan. `pe` must already be in its final
    // on-disk shape; the plan mirrors its section layout one region at a time.
    static bool build(PELib& pe, const EvasionConfig& cfg, LoaderPlan& plan, std::string& error);

    // Self-inverse keystream. `rva` seeds the per-region stream so two regions
    // never share bytes even when their plaintext does.
    static void crypt(uint8_t* data, size_t len, uint64_t key, uint32_t rva,
                      uint8_t rounds, uint32_t window);

    static uint64_t deriveRegionKey(uint64_t seed, uint32_t rva);

    static std::string emitRuntimeSource(const LoaderPlan& plan, const std::string& symbol);
};

} // namespace np
