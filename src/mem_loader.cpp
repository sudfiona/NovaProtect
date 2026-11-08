// NovaProtect memory loader - region plan, keystream and runtime driver source.
#include "mem_loader.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <sstream>

namespace np {
namespace {

constexpr uint32_t kMagic = 0x504D504Eu;   // 'NPMP'
constexpr uint16_t kVersion = 1;

// PAGE_* values the runtime maps with. Duplicated rather than included so this
// file stays buildable in the engine's freestanding-ish translation units.
constexpr uint32_t kPageExecuteRead = 0x20;
constexpr uint32_t kPageReadWrite = 0x04;
constexpr uint32_t kPageReadOnly = 0x02;

uint64_t memMix64(uint64_t x) {
    x += 0x9E3779B97F4A7C15ull;
    x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ull;
    x = (x ^ (x >> 27)) * 0x94D049BB133111EBull;
    return x ^ (x >> 31);
}

void put16(std::vector<uint8_t>& out, uint16_t v) {
    out.push_back(static_cast<uint8_t>(v & 0xFF));
    out.push_back(static_cast<uint8_t>(v >> 8));
}

void put32(std::vector<uint8_t>& out, uint32_t v) {
    for (int i = 0; i < 4; i++) out.push_back(static_cast<uint8_t>((v >> (i * 8)) & 0xFF));
}

void put64(std::vector<uint8_t>& out, uint64_t v) {
    for (int i = 0; i < 8; i++) out.push_back(static_cast<uint8_t>((v >> (i * 8)) & 0xFF));
}

uint16_t get16(const std::vector<uint8_t>& in, size_t pos) {
    return static_cast<uint16_t>(in[pos] | (in[pos + 1] << 8));
}

uint32_t get32(const std::vector<uint8_t>& in, size_t pos) {
    return static_cast<uint32_t>(in[pos]) | (static_cast<uint32_t>(in[pos + 1]) << 8) |
           (static_cast<uint32_t>(in[pos + 2]) << 16) | (static_cast<uint32_t>(in[pos + 3]) << 24);
}

uint64_t get64(const std::vector<uint8_t>& in, size_t pos) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v |= static_cast<uint64_t>(in[pos + i]) << (i * 8);
    return v;
}

} // namespace

uint32_t LoaderPlan::totalCipherBytes() const {
    uint32_t total = 0;
    for (const auto& region : regions) total += static_cast<uint32_t>(region.cipher.size());
    return total;
}

uint64_t MemLoader::deriveRegionKey(uint64_t seed, uint32_t rva) {
    return memMix64(seed ^ (static_cast<uint64_t>(rva) * 0x9E3779B97F4A7C15ull) ^ 0x4D454D4F5259ull);
}

void MemLoader::crypt(uint8_t* data, size_t len, uint64_t key, uint32_t rva,
                      uint8_t rounds, uint32_t window) {
    if (!data || !len || !rounds) return;
    if (window < 64) window = 64;
    for (uint8_t round = 0; round < rounds; round++) {
        for (size_t base = 0; base < len; base += window) {
            const size_t span = std::min<size_t>(window, len - base);
            const uint64_t window_key =
                memMix64(key ^ static_cast<uint64_t>(rva + base) ^ (static_cast<uint64_t>(round) << 40));
            for (size_t i = 0; i < span; i++) {
                const uint64_t ks = memMix64(window_key + i);
                data[base + i] ^= static_cast<uint8_t>(ks & 0xFF);
            }
        }
    }
}

bool MemLoader::build(PELib& pe, const EvasionConfig& cfg, LoaderPlan& plan, std::string& error) {
    if (pe.sectionCount() == 0) { error = "no sections to plan"; return false; }
    plan = LoaderPlan{};
    plan.is64 = pe.is64();
    plan.image_base = pe.imageBase();
    plan.entry_rva = pe.entryPoint();
    plan.image_size = pe.imageSize();
    plan.window = cfg.mem_window ? cfg.mem_window : 4096;
    const uint8_t rounds = cfg.mem_stream_rounds;

    for (size_t i = 0; i < pe.sectionCount(); i++) {
        const auto& section = pe.section(i);
        if (section.SizeOfRawData == 0) continue;
        const auto& bytes = pe.sectionData(i);
        if (bytes.empty()) continue;

        MemRegionSpec region;
        region.rva = section.VirtualAddress;
        region.size = section.SizeOfRawData;
        region.characteristics = section.Characteristics;
        const bool exec = (section.Characteristics & (SEC_MEM_EXECUTE | SEC_CODE)) != 0;
        const bool write = (section.Characteristics & SEC_MEM_WRITE) != 0;
        // The runtime maps everything RW first, decrypts, then transitions.
        // Storing the *final* protection keeps that transition out of the
        // plan's data path and makes the intent auditable.
        region.protect = exec ? kPageExecuteRead : (write ? kPageReadWrite : kPageReadOnly);
        region.key = deriveRegionKey(cfg.seed ? cfg.seed : 0x4D454D4F52ull, region.rva);
        region.rounds = rounds;
        region.cipher.assign(bytes.begin(), bytes.end());
        if (rounds) crypt(region.cipher.data(), region.cipher.size(), region.key, region.rva, rounds, plan.window);

        // .bss-style tail: mapped zero, never part of the ciphertext.
        if (section.VirtualSize > section.SizeOfRawData) {
            plan.zero_runs.emplace_back(section.VirtualAddress + section.SizeOfRawData,
                                        section.VirtualSize - section.SizeOfRawData);
        }
        plan.regions.push_back(std::move(region));
    }

    for (const auto& imp : pe.getImports()) plan.import_dlls.push_back(imp.dll_name);

    if (plan.regions.empty()) { error = "every section was empty"; return false; }
    return true;
}

std::vector<uint8_t> LoaderPlan::encode() const {
    std::vector<uint8_t> out;
    put32(out, kMagic);
    put16(out, kVersion);
    out.push_back(is64 ? 1 : 0);
    out.push_back(0);
    put64(out, image_base);
    put32(out, entry_rva);
    put32(out, image_size);
    put32(out, window);
    put32(out, static_cast<uint32_t>(regions.size()));
    put32(out, static_cast<uint32_t>(zero_runs.size()));
    put32(out, static_cast<uint32_t>(import_dlls.size()));
    for (const auto& region : regions) {
        put32(out, region.rva);
        put32(out, region.size);
        put32(out, region.characteristics);
        put32(out, region.protect);
        put64(out, region.key);
        out.push_back(region.rounds);
        out.push_back(0);
        put16(out, 0);
        put32(out, static_cast<uint32_t>(region.cipher.size()));
        out.insert(out.end(), region.cipher.begin(), region.cipher.end());
    }
    for (const auto& run : zero_runs) {
        put32(out, run.first);
        put32(out, static_cast<uint32_t>(run.second.size()));
    }
    for (const auto& dll : import_dlls) {
        put16(out, static_cast<uint16_t>(dll.size()));
        out.insert(out.end(), dll.begin(), dll.end());
    }
    return out;
}

bool LoaderPlan::decode(const std::vector<uint8_t>& blob, LoaderPlan& out, std::string& error) {
    if (blob.size() < 32) { error = "loader plan truncated"; return false; }
    if (get32(blob, 0) != kMagic) { error = "bad loader plan magic"; return false; }
    if (get16(blob, 4) != kVersion) { error = "unsupported loader plan version"; return false; }
    // magic (4) + version (2) = 6, then is64, reserved, image_base.
    size_t pos = 6;
    out = LoaderPlan{};
    out.is64 = blob[pos++] != 0;
    pos++;  // reserved
    out.image_base = get64(blob, pos); pos += 8;
    out.entry_rva = get32(blob, pos); pos += 4;
    out.image_size = get32(blob, pos); pos += 4;
    out.window = get32(blob, pos); pos += 4;
    const uint32_t region_count = get32(blob, pos); pos += 4;
    const uint32_t zero_count = get32(blob, pos); pos += 4;
    const uint32_t dll_count = get32(blob, pos); pos += 4;

    out.regions.reserve(region_count);
    for (uint32_t i = 0; i < region_count; i++) {
        if (pos + 32 > blob.size()) { error = "loader plan truncated (region header)"; return false; }
        MemRegionSpec region;
        region.rva = get32(blob, pos); pos += 4;
        region.size = get32(blob, pos); pos += 4;
        region.characteristics = get32(blob, pos); pos += 4;
        region.protect = get32(blob, pos); pos += 4;
        region.key = get64(blob, pos); pos += 8;
        region.rounds = blob[pos];
        pos += 4;  // rounds + reserved
        const uint32_t cipher_len = get32(blob, pos); pos += 4;
        if (pos + cipher_len > blob.size()) { error = "loader plan truncated (cipher)"; return false; }
        region.cipher.assign(blob.begin() + pos, blob.begin() + pos + cipher_len);
        pos += cipher_len;
        out.regions.push_back(std::move(region));
    }
    out.zero_runs.reserve(zero_count);
    for (uint32_t i = 0; i < zero_count; i++) {
        if (pos + 8 > blob.size()) { error = "loader plan truncated (zero run)"; return false; }
        const uint32_t rva = get32(blob, pos); pos += 4;
        const uint32_t size = get32(blob, pos); pos += 4;
        out.zero_runs.emplace_back(rva, std::vector<uint8_t>(size, 0));
    }
    out.import_dlls.reserve(dll_count);
    for (uint32_t i = 0; i < dll_count; i++) {
        if (pos + 2 > blob.size()) { error = "loader plan truncated (dll)"; return false; }
        const uint16_t len = get16(blob, pos); pos += 2;
        if (pos + len > blob.size()) { error = "loader plan truncated (dll name)"; return false; }
        out.import_dlls.emplace_back(blob.begin() + pos, blob.begin() + pos + len);
        pos += len;
    }
    return true;
}

std::string MemLoader::emitRuntimeSource(const LoaderPlan& plan, const std::string& symbol) {
    std::ostringstream os;
    os << "// Generated by NovaProtect: memory loader plan (" << plan.regions.size()
       << " regions, " << plan.totalCipherBytes() << " ciphertext bytes).\n";
    os << "// ABI: uint32_t " << symbol << "(void);  0 = image live, 1 = failed.\n";
    os << "//\n";
    os << "// Driver outline (no CRT, no import table):\n";
    os << "//   1. NtAllocateVirtualMemory per region at image_base + rva, PAGE_READWRITE.\n";
    os << "//   2. Copy the ciphertext, then run the keystream in place window by window.\n";
    os << "//   3. memset the zero runs (VirtualSize > SizeOfRawData tails).\n";
    os << "//   4. NtProtectVirtualMemory to each region's stored protect value: RW -> RX.\n";
    os << "//   5. Resolve imports by name from the recorded DLL list, apply relocations,\n";
    os << "//      then call the entry point through the TEB's activation context.\n";
    os << "//\n";
    os << "// Keystream: memMix64(key ^ (rva + window_base) ^ (round << 40) + i) per byte;\n";
    os << "// XOR only, so encryption and decryption are the same call.\n\n";
    const std::vector<uint8_t> blob = plan.encode();
    os << "static const unsigned char k" << symbol << "Blob[] = {\n";
    for (size_t i = 0; i < blob.size(); i++) {
        if (i % 16 == 0) os << "    ";
        char buf[8];
        std::snprintf(buf, sizeof(buf), "0x%02x,", blob[i]);
        os << buf;
        if (i % 16 == 15) os << "\n";
        else os << " ";
    }
    if (blob.size() % 16) os << "\n";
    os << "};\n";
    return os.str();
}

} // namespace np
