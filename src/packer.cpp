// NovaProtect Packer Implementation
#include "packer.h"
#include "disasm.h"
#include "crypto_layers.h"
#include "evasion_static.h"
#include "stub_blob.h"
#include "prot_blob.h"
#include "mutkern_blob.h"
#include <cstring>
#include <algorithm>
#include <random>
#include <chrono>
#include <cstdio>
#include <cstdlib>

namespace np {

uint64_t Packer::buildSeed() const {
    const uint64_t planned = config_.evasion.build.seed ? config_.evasion.build.seed
                                                       : config_.evasion.seed;
    if (planned) return planned;
    return static_cast<uint64_t>(
        std::chrono::high_resolution_clock::now().time_since_epoch().count());
}

// ============================================================
// SimpleCompressor - LZ-based compression
// ============================================================
class SimpleCompressor {
public:
    // LZ77-style compression with fixed window
    static constexpr int WINDOW_SIZE = 4096;
    static constexpr int MIN_MATCH = 4;
    static constexpr int MAX_MATCH = 255 + MIN_MATCH;
    
    static std::vector<uint8_t> compress(const uint8_t* data, size_t size) {
        std::vector<uint8_t> output;
        output.reserve(size + size / 8);
        
        // Header: original size
        output.push_back(size & 0xFF);
        output.push_back((size >> 8) & 0xFF);
        output.push_back((size >> 16) & 0xFF);
        output.push_back((size >> 24) & 0xFF);
        
        size_t i = 0;
        while (i < size) {
            // Find longest match
            size_t best_len = 0;
            size_t best_dist = 0;
            
            size_t window_start = (i > WINDOW_SIZE) ? i - WINDOW_SIZE : 0;
            for (size_t j = window_start; j < i; j++) {
                size_t match_len = 0;
                while (i + match_len < size && 
                       data[j + match_len] == data[i + match_len] && 
                       match_len < MAX_MATCH) {
                    match_len++;
                }
                if (match_len > best_len && match_len >= MIN_MATCH) {
                    best_len = match_len;
                    best_dist = i - j;
                }
            }
            
            if (best_len >= MIN_MATCH) {
                // Emit match token
                // Format: [flag_byte=1][dist_lo][dist_hi][len]
                output.push_back(1);
                output.push_back(best_dist & 0xFF);
                output.push_back((best_dist >> 8) & 0xFF);
                output.push_back((uint8_t)(best_len - MIN_MATCH));
                i += best_len;
            } else {
                // Emit literal
                // Format: [flag_byte=0][byte]
                output.push_back(0);
                output.push_back(data[i]);
                i++;
            }
        }
        return output;
    }
    
    static std::vector<uint8_t> decompress(const uint8_t* data, size_t size, size_t expected) {
        std::vector<uint8_t> output;
        output.reserve(expected);
        
        // Skip header (4 bytes original size)
        size_t i = 4;
        while (i < size) {
            uint8_t flag = data[i++];
            if (flag == 0) {
                // Literal
                output.push_back(data[i++]);
            } else {
                // Match
                uint16_t dist = data[i] | (data[i+1] << 8);
                uint8_t len = data[i+2] + MIN_MATCH;
                i += 3;
                size_t pos = output.size() - dist;
                for (int j = 0; j < len; j++) {
                    output.push_back(output[pos + j]);
                }
            }
        }
        return output;
    }
};

// ============================================================
// Packer implementation
// ============================================================

PackResult Packer::pack(const std::string& input_path, const std::string& output_path) {
    PackResult result;
    result_ = &result;
    narrow_input_path_ = input_path;
    narrow_output_path_ = output_path;

    progress(0, "Loading input file...");
    PELib pe;
    if (!pe.load(input_path)) {
        result.error_message = "Failed to load PE: " + pe.lastError();
        return result;
    }
    
    result.original_size = pe.size();
    original_ep_ = pe.entryPoint();
    config_.is_64bit = pe.is64();
    
    progress(10, "Analyzing PE structure...");
    if (!phase_analyze(pe)) {
        result.error_message = "Analysis failed";
        return result;
    }
    
    // Generate encryption key
    auto seed = buildSeed();
    std::mt19937_64 rng(seed);
    encryption_key_.resize(32);
    for (auto& k : encryption_key_) k = rng() & 0xFF;
    
    // Pack sections
    progress(30, "Encrypting sections...");
    std::vector<uint8_t> packed_data;
    if (config_.pack_sections) {
        if (!phase_encryptSections(pe, packed_data)) {
            result.error_message = "Section packing failed";
            return result;
        }
    }
    
    // Assemble the protection metadata container (watermark, license, virtual
    // files, import descriptor table, build fingerprint).
    progress(50, "Building protection metadata...");
    buildMetadataBlob(pe, meta_blob_);

    // Strip debug information before the loader images are rebuilt so the
    // PDB/CodeView references never reach the output file.
    if (config_.strip_debug_info) {
        stripDebugInfo(pe, result);
    }
    if (result.debug_entries_stripped) {
        progress(55, "Stripped debug directory entries");
    }

    // Import protection: drop the loader-visible import directory. The unpacker
    // stub rebuilds the IAT at runtime from the descriptor table captured in
    // the metadata container.
    if (config_.import_protection) {
        stripImportDirectory(pe);
        // An image that imports nothing is a named static detection, so put back
        // a small table of real exports that the loader resolves normally. The
        // stub's own slots live in the original sections and never touch these.
        if (config_.decoy_imports) {
            if (writeDecoyImports(pe)) progress(59, "Decoy import table installed");
        }
        progress(58, "Import directory stripped (resolved at runtime)");
    }
    if (config_.strip_relocations) {
        stripRelocations(pe);
        progress(58, "Relocation directory stripped (ASLR disabled)");
    }
    if (config_.strip_export) {
        stripExports(pe);
        progress(58, "Export directory stripped");
    }

    // Assemble the protection runtime section (needs the metadata RVA, so it
    // runs after the metadata blob and section stripping are settled but
    // before the payload header is committed by phase_buildOutput).
    progress(59, "Building protection runtime...");
    if (!phase_buildProtection(pe, packed_data)) {
        result.error_message = "Protection runtime build failed";
        return result;
    }

    // Build output and generate the unpacker against the final data RVA.
    progress(60, "Building protected image...");
    if (!phase_buildOutput(pe, packed_data)) {
        result.error_message = "Output build failed";
        return result;
    }

    // Static evasion runs on the finished image: it rewrites headers and the
    // file-side layout only, so it must come after every section exists and
    // before the file is written. The checksum is recomputed inside apply(),
    // last, over the exact bytes that reach the disk.
    if (config_.evasion.enabled() && !result.skipped_no_packable_code) {
        progress(92, "Applying static evasion...");
        StaticEvader evader(config_.evasion);
        StaticEvasionReport evasion_report;
        if (evader.apply(pe, evasion_report)) {
            result.evasion_changes = static_cast<uint32_t>(evasion_report.changes.size());
            // The tag is what the caller records in the build log: same seed ->
            // same tag -> byte-identical image, which is how a repro build is
            // verified instead of assumed.
            result.evasion_build_tag = evader.buildSignature().build_tag;
            result.evasion_seed = evader.buildSignature().seed;
            progress(93, evasion_report.summary());
            progress(93, "signature build " + result.evasion_build_tag);
        } else {
            progress(93, "Static evasion skipped (image not mutable in place)");
        }
    }
    // Save.  When nothing could be packed the output has already been written
    // as an untouched copy of the input, so do not overwrite it here.
    if (!result.skipped_no_packable_code) {
        progress(95, "Writing output...");
        if (!pe.save(output_path)) {
            // A failed write must not be reported as a successful build: the
            // file on disk would be a half-written image.
            result.error_message = "Writing the output failed: " + pe.lastError();
            return result;
        }
        result.packed_size = pe.size();
    }

    result.success = true;
    result.output_path = output_path;

    progress(100, "Done!");
    return result;
}

bool Packer::phase_analyze(PELib& pe) {
    // Verify it's a valid executable we can pack
    if (pe.sectionCount() == 0) return false;
    
    // Check for TLS callbacks
    auto* tls_dir = pe.dataDirectory(DIR_ENTRY_TLS);
    if (tls_dir && tls_dir->VirtualAddress != 0) {
        // We need to preserve TLS callbacks
        progress(15, "TLS callbacks detected, preserving...");
    }
    
    // Analyze imports
    auto imports = pe.getImports();
    if (imports.empty()) {
        progress(18, "Warning: no imports found");
    }
    
    return true;
}

static void clearDirectoryPayload(PELib& pe, int directoryIndex) {
    auto* dd = pe.dataDirectory(directoryIndex);
    if (!dd || !dd->VirtualAddress || !dd->Size) return;
    for (size_t i = 0; i < pe.sectionCount(); ++i) {
        const auto& section = pe.section(i);
        const uint32_t span = std::max(section.VirtualSize, section.SizeOfRawData);
        if (dd->VirtualAddress < section.VirtualAddress ||
            dd->VirtualAddress >= section.VirtualAddress + span) continue;
        const size_t offset = dd->VirtualAddress - section.VirtualAddress;
        auto& data = pe.sectionData(i);
        if (offset < data.size()) {
            const size_t count = std::min<size_t>(dd->Size, data.size() - offset);
            std::fill(data.begin() + offset, data.begin() + offset + count, 0);
        }
        break;
    }
    dd->VirtualAddress = 0;
    dd->Size = 0;
}

void Packer::stripRelocations(PELib& pe) {
    clearDirectoryPayload(pe, DIR_ENTRY_BASERELOC);
    auto* opt = pe.optionalHeader();
    if (!opt) return;
    if (pe.is64()) {
        auto* header = reinterpret_cast<OptionalHeader64*>(opt);
        header->DllCharacteristics &= static_cast<uint16_t>(~0x0040u);
    } else {
        auto* header = reinterpret_cast<OptionalHeader32*>(opt);
        header->DllCharacteristics &= static_cast<uint16_t>(~0x0040u);
    }
}

void Packer::stripExports(PELib& pe) {
    clearDirectoryPayload(pe, DIR_ENTRY_EXPORT);
}

// ------------------------------------------------------------
// RLE compression used by the bootstrap stub. Format:
//   0xxxxxxx [1..128 literal bytes]
//   1xxxxxxx [one byte repeated 1..128 times]
// ------------------------------------------------------------
static std::vector<uint8_t> rleCompress(const uint8_t* data, size_t size) {
    std::vector<uint8_t> out;
    out.reserve(size);
    size_t i = 0;
    while (i < size) {
        size_t run = 1;
        while (i + run < size && data[i + run] == data[i] && run < 128) run++;

        if (run >= 3) {
            out.push_back((uint8_t)(0x80 | (run - 1)));
            out.push_back(data[i]);
            i += run;
            continue;
        }

        size_t lit = 0;
        while (i + lit < size && lit < 128) {
            // Stop a literal run immediately before the next useful run.
            if (i + lit + 2 < size &&
                data[i + lit] == data[i + lit + 1] &&
                data[i + lit] == data[i + lit + 2]) {
                break;
            }
            lit++;
        }
        if (lit == 0) lit = 1;
        out.push_back((uint8_t)(lit - 1));
        out.insert(out.end(), data + i, data + i + lit);
        i += lit;
    }
    return out;
}

static uint32_t fnv1a32(const uint8_t* data, size_t size) {
    uint32_t h = 0x811C9DC5u;
    for (size_t i = 0; i < size; ++i) {
        h ^= data[i];
        h *= 0x01000193u;
    }
    return h;
}

static uint64_t fnv1a64(const uint8_t* data, size_t size) {
    uint64_t h = 0xCBF29CE484222325ULL;
    for (size_t i = 0; i < size; ++i) {
        h ^= data[i];
        h *= 0x100000001B3ULL;
    }
    return h;
}

// Some PE32 images place loader-critical metadata (Load Config, SEH tables,
// GuardCF tables, security cookies) inside the first bytes of an executable
// section. Windows parses that metadata before it transfers control to the
// entry point, so the loader must leave a small prefix of each executable
// section readable. Encrypt everything after that prefix.
static constexpr uint32_t kLoaderHeaderReserve = 0x1000;

static uint32_t loaderReserveForSection(const np::SectionHeader& sec) {
    const uint32_t maxreserve = (sec.VirtualSize < kLoaderHeaderReserve)
                                    ? sec.VirtualSize
                                    : kLoaderHeaderReserve;
    return maxreserve;
}

bool Packer::phase_encryptSections(PELib& pe, std::vector<uint8_t>& packed_data) {
    const bool is64 = pe.is64();

    struct Region {
        uint32_t rva = 0;
        uint32_t original_size = 0;
        uint32_t stored_size = 0;
        uint32_t flags = 0;
        uint64_t integrity = 0;
        std::vector<uint8_t> payload;
    };

    std::vector<Region> regions;
    regions.reserve(pe.sectionCount());

    for (size_t i = 0; i < pe.sectionCount(); i++) {
        const auto& sec = pe.section(i);
        const bool is_exec = (sec.Characteristics & SEC_MEM_EXECUTE) != 0;
        // Resource protection pulls the resource directory into the encrypted
        // payload as well. Resources are not needed by the loader, so they can
        // be encrypted from byte zero.
        const bool is_rsrc = config_.resource_protection &&
                             strncmp(sec.Name, ".rsrc", 5) == 0;
        if (!is_exec && !is_rsrc) continue;
        if (sec.VirtualSize == 0 || sec.SizeOfRawData == 0) continue;
        if (strncmp(sec.Name, ".np_", 4) == 0) continue;

        auto& raw = pe.sectionData(i);
        if (raw.empty()) continue;

        // Restore only mapped bytes. Raw size can include file-alignment.
        const size_t mapped_size = std::min<size_t>(raw.size(), sec.VirtualSize);
        if (mapped_size == 0) continue;

        // Loader-critical metadata (Load Config, SEH, GuardCF) can live in the
        // first bytes of an executable section and must remain readable before
        // the entry point runs. Encrypt everything after that prefix.
        const uint32_t reserve = is_exec ? loaderReserveForSection(sec) : 0;
        if (reserve >= mapped_size) continue;
        const uint8_t* code = raw.data() + reserve;
        const size_t code_size = mapped_size - reserve;
        if (code_size == 0) continue;

        Region region;
        region.rva = sec.VirtualAddress + reserve;
        region.original_size = (uint32_t)code_size;

        auto rle = rleCompress(code, code_size);
        if (!rle.empty() && rle.size() < code_size) {
            region.payload = std::move(rle);
            region.flags |= 1;
        } else {
            region.payload.assign(code, code + code_size);
        }

        if (config_.memory_protection) {
            region.flags |= 2;
            region.integrity = is64
                ? fnv1a64(code, code_size)
                : (uint64_t)fnv1a32(code, code_size);
        }

        if (config_.encrypt_sections) {
            region.flags |= 4;
            util::xor_crypt(region.payload.data(), region.payload.size(),
                            encryption_key_.data(), encryption_key_.size());
        }
        region.stored_size = (uint32_t)region.payload.size();
        regions.push_back(std::move(region));
    }

    if (regions.empty()) {
        progress(32, "No executable sections available for packing");
        packed_data.clear();
        return true;
    }

    constexpr uint32_t tls_capacity = 64;
    const uint32_t header_size = 128;
    std::vector<uint8_t> header(header_size, 0);
    auto put32 = [](std::vector<uint8_t>& v, size_t off, uint32_t x) {
        memcpy(v.data() + off, &x, sizeof(x));
    };
    auto put64 = [](std::vector<uint8_t>& v, size_t off, uint64_t x) {
        memcpy(v.data() + off, &x, sizeof(x));
    };

    put32(header, 0, 0x41564F4E);
    put32(header, 4, 3);
    put32(header, 8, (uint32_t)regions.size());
    put32(header, 12, original_ep_);
    memcpy(header.data() + 16, encryption_key_.data(), encryption_key_.size());

    const auto* reloc = pe.dataDirectory(DIR_ENTRY_BASERELOC);
    put32(header, 48, config_.strip_relocations ? 0 : (reloc ? reloc->VirtualAddress : 0));
    put32(header, 52, config_.strip_relocations ? 0 : (reloc ? reloc->Size : 0));

    // MinGW/MSVC TLS callbacks run before the entry point. Redirect them to a
    // temporary harmless callback, then let the loader replay the originals.
    uint32_t tls_orig_rva = 0;
    uint32_t tls_count = 0;
    const auto* tls_dir = pe.dataDirectory(DIR_ENTRY_TLS);
    tls_array_offset_ = SIZE_MAX;
    if (tls_dir && tls_dir->VirtualAddress && tls_dir->Size >= 40) {
        const uint8_t* tls = pe.rvaToPtr(tls_dir->VirtualAddress);
        if (tls) {
            uint64_t callbacks_va = 0;
            memcpy(&callbacks_va, tls + 24, sizeof(callbacks_va));
            const uint64_t preferred_base = pe.imageBase();
            if (callbacks_va > preferred_base) {
                tls_orig_rva = (uint32_t)(callbacks_va - preferred_base);
                const uint8_t* arr = pe.rvaToPtr(tls_orig_rva);
                if (arr) {
                    while (tls_count + 1 < tls_capacity) {
                        uint64_t fn = 0;
                        memcpy(&fn, arr + tls_count * 8, sizeof(fn));
                        if (!fn) break;
                        ++tls_count;
                    }
                }
            }
        }
    }

    put64(header, 80, pe.imageBase());
    // Runtime flag word. bit0 anti-debug on, bit1 anti-VM on, bit2 memory
    // integrity on, bits4-5 anti-debug level (0-3), bits6-7 anti-VM level (0-2).
    put32(header, 88,
        (config_.anti_debug_level > 0 ? 1u : 0u) |
        (config_.anti_vm_level > 0 ? 2u : 0u) |
        (config_.memory_protection ? 4u : 0u) |
        (config_.resource_protection ? 8u : 0u) |
        (((uint32_t)config_.anti_debug_level & 3u) << 4) |
        (((uint32_t)config_.anti_vm_level & 3u) << 6));
    packed_data.insert(packed_data.begin(), header.begin(), header.end());

    for (const auto& r : regions) {
        uint8_t rec[32] = {};
        memcpy(rec + 0, &r.rva, 4);
        memcpy(rec + 4, &r.original_size, 4);
        memcpy(rec + 8, &r.stored_size, 4);
        memcpy(rec + 12, &r.flags, 4);
        memcpy(rec + 16, &r.integrity, 8);
        packed_data.insert(packed_data.end(), rec, rec + 32);
    }
    for (const auto& r : regions) {
        packed_data.insert(packed_data.end(), r.payload.begin(), r.payload.end());
        while (packed_data.size() & 7) packed_data.push_back(0);
    }

    if (tls_count) {
        put32(header, 56, tls_orig_rva);
        put32(header, 64, tls_capacity);
        put32(header, 68, tls_count);
        memcpy(packed_data.data(), header.data(), header_size);

        while (packed_data.size() & 7) packed_data.push_back(0);
        tls_array_offset_ = packed_data.size();
        packed_data.insert(packed_data.end(),
                           (tls_capacity + 1) * sizeof(uint32_t), 0);
    }

    return true;
}

static bool patchTlsDirectory(PELib& pe, uint32_t new_array_rva) {
    const auto* dd = pe.dataDirectory(DIR_ENTRY_TLS);
    if (!dd || !dd->VirtualAddress || dd->Size < 40) return true;
    if (!pe.is64()) return false;

    for (size_t i = 0; i < pe.sectionCount(); i++) {
        const auto& sec = pe.section(i);
        uint32_t span = std::max(sec.VirtualSize, sec.SizeOfRawData);
        if (dd->VirtualAddress < sec.VirtualAddress ||
            dd->VirtualAddress >= sec.VirtualAddress + span) continue;

        size_t off = (size_t)(dd->VirtualAddress - sec.VirtualAddress) + 24;
        auto& data = pe.sectionData(i);
        if (off + sizeof(uint64_t) > data.size()) return false;
        uint64_t va = pe.imageBase() + new_array_rva;
        memcpy(data.data() + off, &va, sizeof(va));
        return true;
    }
    return false;
}

bool Packer::phase_generateStub(PELib& pe, std::vector<uint8_t>& stub_data, uint32_t data_rva) {
    const bool is64 = pe.is64();
    if (is64) {
        stub_data.assign(kUnpackerStub, kUnpackerStub + kUnpackerStubSize);
    } else {
        stub_data.assign(kUnpackerStub32, kUnpackerStub32 + kUnpackerStub32Size);
    }

    // The data RVA is patched via a literal marker in the stub. The x64 stub uses
    // "mov edi, 0xDEADBEEF" (BF EF BE AD DE) and the x86 stub uses the same
    // opcode sequence so the marker scan works for both architectures.
    const uint8_t pattern[5] = { 0xBF, 0xEF, 0xBE, 0xAD, 0xDE };
    size_t patch = std::string::npos;
    for (size_t i = 0; i + sizeof(pattern) <= stub_data.size(); i++) {
        if (memcmp(stub_data.data() + i, pattern, sizeof(pattern)) == 0) {
            patch = i;
            break;
        }
    }
    if (patch == std::string::npos) return false;
    memcpy(stub_data.data() + patch + 1, &data_rva, sizeof(data_rva));

    // Strength-dependent postamble keeps builds variable without changing the
    // fixed loader/data contract.
    if (config_.anti_debug_level >= 2) {
        stub_data.insert(stub_data.end(),
                         { 0x0F, 0x31, 0x48, 0xC1, 0xEA, 0x20, 0x31, 0xC0, 0xC3 });
    }
    return true;
}

// ============================================================
// Icon preservation
// ============================================================
// Resource protection encrypts the whole .rsrc section, which would strip
// the target's Explorer icon and replace it with the default Windows icon.
// The icon is application identity rather than protection surface, so the
// packer rebuilds a minimal resource directory that carries only the
// RT_ICON / RT_GROUP_ICON entries. Every other resource stays encrypted in
// the payload and is restored by the loader at runtime.

#pragma pack(push, 1)
struct IconResourceDir {
    uint32_t Characteristics;
    uint32_t TimeDateStamp;
    uint16_t MajorVersion;
    uint16_t MinorVersion;
    uint16_t NumberOfNamedEntries;
    uint16_t NumberOfIdEntries;
};
struct IconResourceEntry {
    uint32_t Name;
    uint32_t OffsetToData;
};
struct IconResourceData {
    uint32_t OffsetToData;
    uint32_t Size;
    uint32_t CodePage;
    uint32_t Reserved;
};
#pragma pack(pop)

struct IconLeaf {
    bool named = false;
    uint32_t id = 0;
    std::wstring name;
    uint32_t language = 0x0409;
    uint32_t data_rva = 0;
    uint32_t data_size = 0;
};

// Collect the leaf data entries below one type-level directory. Offsets are
// relative to the resource section base; anything malformed is skipped.
// Standard images use Type -> Name -> Language -> Data, but a two-level
// Type -> Data layout is also legal and is accepted here.
static void collectIconLeaves(const uint8_t* base, size_t limit, uint32_t dir_offset,
                              std::vector<IconLeaf>& out) {
    if ((size_t)dir_offset + sizeof(IconResourceDir) > limit) return;
    const auto* dir = reinterpret_cast<const IconResourceDir*>(base + dir_offset);
    const uint16_t total = (uint16_t)(dir->NumberOfNamedEntries + dir->NumberOfIdEntries);
    const size_t entries_at = (size_t)dir_offset + sizeof(IconResourceDir);
    if (entries_at + (size_t)total * sizeof(IconResourceEntry) > limit) return;
    const auto* entries = reinterpret_cast<const IconResourceEntry*>(base + entries_at);
    for (uint16_t i = 0; i < total; i++) {
        const IconResourceEntry& name_entry = entries[i];
        IconLeaf leaf;
        if (name_entry.Name & 0x80000000u) {
            const uint32_t str_offset = name_entry.Name & 0x7FFFFFFFu;
            if ((size_t)str_offset + 2 > limit) continue;
            const uint16_t length = *reinterpret_cast<const uint16_t*>(base + str_offset);
            if ((size_t)str_offset + 2 + (size_t)length * 2 > limit) continue;
            leaf.named = true;
            leaf.name.assign(reinterpret_cast<const wchar_t*>(base + str_offset + 2), length);
        } else {
            leaf.id = name_entry.Name;
        }

        if (name_entry.OffsetToData & 0x80000000u) {
            // Standard three-level layout: name -> language -> data entry.
            const uint32_t name_offset = name_entry.OffsetToData & 0x7FFFFFFFu;
            if ((size_t)name_offset + sizeof(IconResourceDir) > limit) continue;
            const auto* name_dir = reinterpret_cast<const IconResourceDir*>(base + name_offset);
            const uint16_t name_total = (uint16_t)(name_dir->NumberOfNamedEntries + name_dir->NumberOfIdEntries);
            const size_t name_entries_at = (size_t)name_offset + sizeof(IconResourceDir);
            if (name_entries_at + (size_t)name_total * sizeof(IconResourceEntry) > limit) continue;
            const auto* name_entries = reinterpret_cast<const IconResourceEntry*>(base + name_entries_at);
            for (uint16_t j = 0; j < name_total; j++) {
                const IconResourceEntry& lang_entry = name_entries[j];
                if (lang_entry.OffsetToData & 0x80000000u) continue;  // leaf must be a data entry
                if ((size_t)lang_entry.OffsetToData + sizeof(IconResourceData) > limit) continue;
                IconLeaf language_leaf = leaf;
                if (!(lang_entry.Name & 0x80000000u)) language_leaf.language = lang_entry.Name;
                const auto* data = reinterpret_cast<const IconResourceData*>(base + lang_entry.OffsetToData);
                language_leaf.data_rva = data->OffsetToData;
                language_leaf.data_size = data->Size;
                if (language_leaf.data_size == 0 || language_leaf.data_size > 16u * 1024u * 1024u) continue;
                out.push_back(std::move(language_leaf));
            }
        } else {
            // Non-standard two-level layout: the name entry IS the data entry.
            if ((size_t)name_entry.OffsetToData + sizeof(IconResourceData) > limit) continue;
            const auto* data = reinterpret_cast<const IconResourceData*>(base + name_entry.OffsetToData);
            leaf.data_rva = data->OffsetToData;
            leaf.data_size = data->Size;
            if (leaf.data_size == 0 || leaf.data_size > 16u * 1024u * 1024u) continue;
            out.push_back(std::move(leaf));
        }
    }
}

// Rebuild a resource directory that contains only the icon subtree. All
// offsets inside the blob are relative to its start; the caller writes the
// blob at the beginning of the .rsrc section. Returns an empty vector when
// the target carries no icon resources.
static std::vector<uint8_t> buildIconResourceBlob(PELib& pe, size_t rsrc_index) {
    const auto* rsrc = pe.dataDirectory(DIR_ENTRY_RESOURCE);
    if (!rsrc || !rsrc->VirtualAddress) return {};
    const uint8_t* base = pe.rvaToPtr(rsrc->VirtualAddress);
    if (!base) return {};
    const size_t limit = std::min<size_t>(pe.section(rsrc_index).SizeOfRawData,
                                          pe.size() - (size_t)(base - pe.data().data()));

    std::vector<IconLeaf> icons;
    std::vector<IconLeaf> groups;
    std::vector<IconLeaf> manifests;
    if (sizeof(IconResourceDir) <= limit) {
        const auto* root = reinterpret_cast<const IconResourceDir*>(base);
        const uint16_t total = (uint16_t)(root->NumberOfNamedEntries + root->NumberOfIdEntries);
        const size_t entries_at = sizeof(IconResourceDir);
        if (entries_at + (size_t)total * sizeof(IconResourceEntry) <= limit) {
            const auto* entries = reinterpret_cast<const IconResourceEntry*>(base + entries_at);
            for (uint16_t i = 0; i < total; i++) {
                if (entries[i].Name & 0x80000000u) continue;      // named type: never an icon type
                if (!(entries[i].OffsetToData & 0x80000000u)) continue;
                const uint32_t type = entries[i].Name;
                if (type == 3)       // RT_ICON
                    collectIconLeaves(base, limit, entries[i].OffsetToData & 0x7FFFFFFFu, icons);
                else if (type == 14) // RT_GROUP_ICON
                    collectIconLeaves(base, limit, entries[i].OffsetToData & 0x7FFFFFFFu, groups);
                else if (type == 24) // RT_MANIFEST
                    // The manifest drives the activation context (UAC, SxS
                    // binding, DPI awareness).  Encrypting it would leave the
                    // loader without it, so it stays in the clear like the
                    // icons do.
                    collectIconLeaves(base, limit, entries[i].OffsetToData & 0x7FFFFFFFu, manifests);
            }
        }
    }
    if (icons.empty() && groups.empty() && manifests.empty()) return {};

    auto order = [](const IconLeaf& a, const IconLeaf& b) {
        if (a.named != b.named) return a.named;                   // named entries sort first
        if (a.named) return a.name < b.name;
        return a.id < b.id;
    };
    std::sort(icons.begin(), icons.end(), order);
    std::sort(groups.begin(), groups.end(), order);

    const size_t dir_size = sizeof(IconResourceDir);
    const size_t entry_size = sizeof(IconResourceEntry);
    const size_t data_size = sizeof(IconResourceData);
    const size_t lang_size = dir_size + entry_size;               // one language per leaf
    const size_t leaf_count = icons.size() + groups.size() + manifests.size();
    auto leaf_at = [&](size_t i) -> const IconLeaf& {
        if (i < icons.size()) return icons[i];
        if (i < icons.size() + groups.size()) return groups[i - icons.size()];
        return manifests[i - icons.size() - groups.size()];
    };

    // Layout: root, type directories, language directories, data entries,
    // name strings, then the icon payloads (4-byte aligned).
    size_t offset = dir_size + 3 * entry_size;                    // root with three ID entries
    const size_t icons_dir = offset;
    offset += dir_size + icons.size() * entry_size;
    const size_t groups_dir = offset;
    offset += dir_size + groups.size() * entry_size;
    const size_t manifests_dir = offset;
    offset += dir_size + manifests.size() * entry_size;
    std::vector<size_t> lang_offsets(leaf_count);
    for (size_t i = 0; i < leaf_count; i++) { lang_offsets[i] = offset; offset += lang_size; }
    std::vector<size_t> data_offsets(leaf_count);
    for (size_t i = 0; i < leaf_count; i++) { data_offsets[i] = offset; offset += data_size; }
    std::vector<size_t> string_offsets(leaf_count, 0);
    for (size_t i = 0; i < leaf_count; i++) {
        if (!leaf_at(i).named) continue;
        string_offsets[i] = offset;
        offset += 2 + leaf_at(i).name.size() * 2;
    }
    std::vector<size_t> payload_offsets(leaf_count, 0);
    for (size_t i = 0; i < leaf_count; i++) {
        offset = (offset + 3) & ~size_t(3);
        payload_offsets[i] = offset;
        offset += leaf_at(i).data_size;
    }

    std::vector<uint8_t> blob(offset, 0);
    auto write_dir = [&](size_t at, uint16_t named, uint16_t ids) {
        IconResourceDir dir{};
        dir.NumberOfNamedEntries = named;
        dir.NumberOfIdEntries = ids;
        memcpy(blob.data() + at, &dir, dir_size);
    };
    auto write_entry = [&](size_t at, uint32_t name, uint32_t target) {
        IconResourceEntry entry{name, target};
        memcpy(blob.data() + at, &entry, entry_size);
    };

    // A resource directory header splits its entries into named entries
    // (Name field has the high bit set and points at a length-prefixed string)
    // and ID entries (plain numeric Name). Windows rejects a directory whose
    // counts do not match the entry encoding, so count them per leaf kind;
    // the sort above already placed named entries before ID entries.
    uint16_t icons_named = 0;
    for (const auto& leaf : icons) { if (leaf.named) icons_named++; }
    uint16_t groups_named = 0;
    for (const auto& leaf : groups) { if (leaf.named) groups_named++; }
    uint16_t manifests_named = 0;
    for (const auto& leaf : manifests) { if (leaf.named) manifests_named++; }

    write_dir(0, 0, 3);
    write_entry(dir_size, 3, 0x80000000u | (uint32_t)icons_dir);
    write_entry(dir_size + entry_size, 14, 0x80000000u | (uint32_t)groups_dir);
    write_entry(dir_size + 2 * entry_size, 24, 0x80000000u | (uint32_t)manifests_dir);

    write_dir(icons_dir, icons_named, (uint16_t)(icons.size() - icons_named));
    for (size_t i = 0; i < icons.size(); i++) {
        const uint32_t name = icons[i].named ? (0x80000000u | (uint32_t)string_offsets[i]) : icons[i].id;
        write_entry(icons_dir + dir_size + i * entry_size, name, 0x80000000u | (uint32_t)lang_offsets[i]);
    }
    write_dir(groups_dir, groups_named, (uint16_t)(groups.size() - groups_named));
    for (size_t i = 0; i < groups.size(); i++) {
        const size_t index = icons.size() + i;
        const uint32_t name = groups[i].named ? (0x80000000u | (uint32_t)string_offsets[index]) : groups[i].id;
        write_entry(groups_dir + dir_size + i * entry_size, name, 0x80000000u | (uint32_t)lang_offsets[index]);
    }
    write_dir(manifests_dir, manifests_named, (uint16_t)(manifests.size() - manifests_named));
    for (size_t i = 0; i < manifests.size(); i++) {
        const size_t index = icons.size() + groups.size() + i;
        const uint32_t name = manifests[i].named ? (0x80000000u | (uint32_t)string_offsets[index]) : manifests[i].id;
        write_entry(manifests_dir + dir_size + i * entry_size, name, 0x80000000u | (uint32_t)lang_offsets[index]);
    }

    const uint32_t rsrc_rva = pe.section(rsrc_index).VirtualAddress;
    for (size_t i = 0; i < leaf_count; i++) {
        const IconLeaf& leaf = leaf_at(i);
        write_dir(lang_offsets[i], 0, 1);
        write_entry(lang_offsets[i] + dir_size, leaf.language, (uint32_t)data_offsets[i]);
        IconResourceData data{};
        data.OffsetToData = rsrc_rva + (uint32_t)payload_offsets[i];
        data.Size = leaf.data_size;
        memcpy(blob.data() + data_offsets[i], &data, data_size);
        if (leaf.named) {
            const uint16_t length = (uint16_t)leaf.name.size();
            memcpy(blob.data() + string_offsets[i], &length, 2);
            if (length) memcpy(blob.data() + string_offsets[i] + 2, leaf.name.data(), length * 2);
        }
        const uint8_t* src = pe.rvaToPtr(leaf.data_rva);
        if (src) memcpy(blob.data() + payload_offsets[i], src, leaf.data_size);
    }
    return blob;
}

bool Packer::phase_buildOutput(PELib& pe, std::vector<uint8_t>& packed_data) {
    const bool is64 = pe.is64();

    // Nothing could be packed (for example every executable section is smaller
    // than the loader header reserve, or the target has no executable section
    // at all).  Installing the loader stub in that state would move the entry
    // point into an empty payload section and produce an image Windows refuses
    // to load, so write out an untouched copy of the input instead.
    if (packed_data.empty()) {
        progress(60, "No packable code found - writing an unprotected copy");
        if (result_) result_->skipped_no_packable_code = true;
        // Earlier steps may already have stripped the import directory,
        // relocations or exports; without the loader stub nothing would put
        // them back, so restore the original image before saving it.
        PELib original;
        bool loaded = false;
        if (!wide_input_path_.empty()) {
            loaded = original.load(wide_input_path_);
            if (loaded) original.save(wide_output_path_);
        } else {
            loaded = original.load(narrow_input_path_);
            if (loaded) original.save(narrow_output_path_);
        }
        if (loaded) {
            if (result_) result_->packed_size = original.size();
        } else {
            pe.setEntryPoint(original_ep_);
            pe.updateHeaders();
        }
        return true;
    }

    int data_idx = pe.addSection(".np_data",
                                  (uint32_t)packed_data.size(),
                                  SEC_MEM_READ | SEC_MEM_WRITE | SEC_INITIALIZED_DATA);
    data_section_idx_ = data_idx;
    uint32_t data_rva = pe.section(data_idx).VirtualAddress;

    // The loader needs the TLS callback array RVA before it patches the image
    // headers, so publish it through the payload header (offset 96) as well as
    // the legacy offset 60 field.
    tls_new_rva_ = 0;
    if (tls_array_offset_ != SIZE_MAX && tls_array_offset_ + 8 <= packed_data.size()) {
        tls_new_rva_ = data_rva + (uint32_t)tls_array_offset_;
        uint32_t tmp = tls_new_rva_;
        memcpy(packed_data.data() + 60, &tmp, sizeof(tmp));
        memcpy(packed_data.data() + 96, &tmp, sizeof(tmp));
    }

    std::vector<uint8_t> stub_data;
    if (!phase_generateStub(pe, stub_data, data_rva)) return false;

    if (config_.pack_sections) {
        progress(82, "Stripping executable sections...");
        for (size_t i = 0; i < pe.sectionCount(); i++) {
            if (i == (size_t)data_idx) continue;
            const bool is_exec = (pe.section(i).Characteristics & SEC_MEM_EXECUTE) != 0;
            const bool is_rsrc = config_.resource_protection &&
                                 strncmp(pe.section(i).Name, ".rsrc", 5) == 0;
            if (!is_exec && !is_rsrc) continue;
            if (strncmp(pe.section(i).Name, ".np_", 4) == 0) continue;
            auto& sect = pe.section(i);

            // A PE32 executable section with VirtualSize > 0 but SizeOfRawData
            // = 0 makes the loader reject the image (0xC000007B). Keep a legal
            // raw mapping, keep the loader-visible metadata prefix, and wipe
            // only the encrypted code range.
            const uint32_t reserve = is_exec ? loaderReserveForSection(sect) : 0;
            // The loader stub writes the restored code back into this section,
            // so the loaded page must be writable.
            sect.Characteristics |= SEC_MEM_WRITE;
            auto& data = pe.sectionData(i);
            if (is_rsrc) {
                // Keep the target's Explorer icon: rebuild a minimal icon-only
                // resource directory in place of the encrypted resource tree.
                // Everything else stays encrypted in the payload.
                auto icon_blob = buildIconResourceBlob(pe, i);
                if (!icon_blob.empty() && icon_blob.size() <= data.size()) {
                    std::fill(data.begin(), data.end(), 0);
                    std::copy(icon_blob.begin(), icon_blob.end(), data.begin());
                    continue;
                }
            }
            if (data.size() > reserve) {
                std::fill(data.begin() + reserve, data.end(), 0);
            }
        }
    }

    // GuardCF metadata in the Load Config directory points at the original
    // section layout; the stripped image no longer matches it, so clear the
    // GUARD_CF image flag and the GuardFlags field to avoid 0xC0000409.
    {
        const auto* lc = pe.dataDirectory(10 /* DIR_ENTRY_LOAD_CONFIG */);
        if (lc && lc->VirtualAddress && lc->Size >= 0x5C) {
            uint8_t* cfg = pe.rvaToPtr(lc->VirtualAddress);
            if (cfg) {
                uint32_t guardFlags = 0;
                memcpy(&guardFlags, cfg + 0x58, sizeof(guardFlags));
                guardFlags &= ~0x00000100u; // IMAGE_GUARD_CF_INSTRUMENTED etc.
                memcpy(cfg + 0x58, &guardFlags, sizeof(guardFlags));
            }
        }

        const auto* opt = pe.optionalHeader();
        if (opt) {
            uint16_t dllchar = 0;
            if (is64) dllchar = ((const OptionalHeader64*)opt)->DllCharacteristics;
            else dllchar = ((const OptionalHeader32*)opt)->DllCharacteristics;
            dllchar &= ~0x4000u; // IMAGE_DLLCHARACTERISTICS_GUARD_CF
            if (is64) ((OptionalHeader64*)opt)->DllCharacteristics = dllchar;
            else ((OptionalHeader32*)opt)->DllCharacteristics = dllchar;
        }
    }

    // The stub is writable because it decrypts its own name table in place
    // before it resolves the imports: the names must not be readable in the
    // output file.
    int stub_idx = pe.addSection(".np_stub",
                                  (uint32_t)stub_data.size(),
                                  SEC_MEM_READ | SEC_MEM_WRITE | SEC_MEM_EXECUTE | SEC_CODE);
    pe.setSectionData(stub_idx, stub_data);
    stub_section_idx_ = stub_idx;

    if (tls_array_offset_ != SIZE_MAX && is64) {
        if (!patchTlsDirectory(pe, tls_new_rva_)) return false;
    }

    // Metadata lives in its own section so it survives independently of the
    // encrypted payload and can be audited after the fact. The section must
    // be created BEFORE the payload is committed so the header field at
    // offset 72 can be patched with the real metadata RVA.
    //
    // The section is writable because the loader decrypts the import block
    // in place before it walks the descriptors: keeping the names encrypted
    // in the output file is what stops "strings" from handing out the whole
    // import table.  Only the loader touches this section.
    if (!meta_blob_.empty()) {
        int meta_idx = pe.addSection(".np_meta",
                                     (uint32_t)meta_blob_.size(),
                                     SEC_MEM_READ | SEC_MEM_WRITE | SEC_INITIALIZED_DATA);
        pe.setSectionData(meta_idx, meta_blob_);
        meta_rva_ = pe.section(meta_idx).VirtualAddress;

        // Publish the metadata RVA/size in the payload header (offsets 72/76)
        // so the stub can locate the import descriptor table before the image
        // headers are valid.
        if (packed_data.size() >= 80) {
            uint32_t msz = (uint32_t)meta_blob_.size();
            memcpy(packed_data.data() + 72, &meta_rva_, 4);
            memcpy(packed_data.data() + 76, &msz, 4);
        }
    }

    // Commit the payload last so all header fixups above are preserved.
    pe.setSectionData(data_idx, packed_data);

    // Publish the protection statistics for the CLI/GUI report.
    if (result_) {
        result_->stub_size = (uint32_t)stub_data.size();
        result_->virtual_files_embedded = 0;
        for (size_t i = 0; i < pe.sectionCount(); i++) {
            if (strncmp(pe.section(i).Name, ".np_meta", 8) == 0) {
                // Count vfile records inside the metadata container.
                const auto& d = pe.sectionData(i);
                for (size_t o = 0; o + 4 <= d.size(); ) {
                    if (d[o] == 'N' && d[o+1] == 'P' && d[o+2] == 'M' && d[o+3] == '1') {
                        uint32_t cnt = 0; memcpy(&cnt, d.data() + o + 8, 4);
                        for (uint32_t e = 0; e < cnt; e++) {
                            size_t eb = o + 16 + (size_t)e * 16;
                            if (eb + 16 > d.size()) break;
                            uint32_t ty = 0; memcpy(&ty, d.data() + eb, 4);
                            if (ty == 4) result_->virtual_files_embedded++;
                        }
                        break;
                    }
                    break;
                }
            }
        }
    }

    pe.setEntryPoint(pe.section(stub_idx).VirtualAddress);
    pe.updateHeaders();
    return true;
}
// ------------------------------------------------------------
// Protection runtime assembly (NPP1 data blob + mutation kernel).
//
// The .np_prot section is split into three consecutive sub-regions that the
// loader stub reaches through the payload header:
//   [ code ][ data ][ kernel ]
//   code   : freestanding x64 protection runtime (runtime/prot64.c)
//   data   : NPP1 descriptor consumed by np_prot_start
//   kernel : per-build mutation kernel verified by np_chk_mutation
//
// Header fields published here:
//   +100 code RVA  +104 data RVA  +108 kernel RVA  +112 code size
// ------------------------------------------------------------
static void npPatch64(std::vector<uint8_t>& v, size_t off, uint64_t x) {
    if (off + 8 <= v.size()) memcpy(v.data() + off, &x, 8);
}
static void npPatch32(std::vector<uint8_t>& v, size_t off, uint32_t x) {
    if (off + 4 <= v.size()) memcpy(v.data() + off, &x, 4);
}
// Append helper. npPatch32() cannot be used to append: it requires the four
// bytes to already exist, so calling it with off == size() silently writes
// nothing. Every "append a dword" site uses this instead.
static void npPush32(std::vector<uint8_t>& v, uint32_t x) {
    uint8_t b[4];
    memcpy(b, &x, 4);
    v.insert(v.end(), b, b + 4);
}

// VM opcodes understood by runtime/prot64.c (np_vm_run).
enum : uint8_t {
    PV_LOADIMM = 0x01, PV_LOADB = 0x02, PV_XOREQ = 0x03, PV_MULI = 0x04,
    PV_ADDI = 0x05, PV_SUBI = 0x06, PV_ANDI = 0x07, PV_RORI = 0x08,
    PV_CMPI = 0x09, PV_JE = 0x0A, PV_JNE = 0x0B, PV_JMP = 0x0C,
    PV_MOVE = 0x0D, PV_XORI = 0x0E, PV_HALT = 0x0F, PV_LOADQ = 0x10
};

// Compile the licence verification program. The interpreter decrypts the
// embedded key blob with a rolling XOR and folds the plaintext into FNV-1a;
// the packer mirrors the identical arithmetic to obtain the expected value.
static std::vector<uint8_t> npBuildLicenseProgram(size_t blob_len,
                                                  uint64_t fnv_basis, uint64_t fnv_prime,
                                                  uint8_t roll_start, uint8_t roll_step,
                                                  std::vector<uint8_t>& mapping_out) {
    std::vector<uint8_t> bc;
    std::mt19937 rng(0xC0FFEEu ^ (uint32_t)blob_len);
    std::vector<uint8_t> perm(256);
    for (int i = 0; i < 256; i++) perm[i] = (uint8_t)i;
    std::shuffle(perm.begin(), perm.end(), rng);
    mapping_out = perm;   // physical = perm[logical]

    auto emit = [&](uint8_t logical) { bc.push_back(mapping_out[logical]); };
    auto u8  = [&](uint8_t v)  { bc.push_back(v); };
    auto u32 = [&](uint32_t v) { for (int k = 0; k < 4; k++) bc.push_back((uint8_t)(v >> (k * 8))); };
    auto u64 = [&](uint64_t v) { for (int k = 0; k < 8; k++) bc.push_back((uint8_t)(v >> (k * 8))); };

    // r0 = hash, r1 = blob ptr, r3 = remaining, r4 = rolling key
    emit(PV_LOADIMM); u8(0); u64(fnv_basis);
    emit(PV_LOADIMM); u8(3); u64((uint64_t)blob_len);
    emit(PV_LOADIMM); u8(4); u64(roll_start);

    uint32_t loop_top = (uint32_t)bc.size();
    emit(PV_CMPI); u8(3); u64(0);
    uint32_t je_off = (uint32_t)bc.size();
    emit(PV_JE); u32(0);                      // patched to end

    emit(PV_LOADB); u8(5); u8(1); u32(0);     // r5 = *r1
    emit(PV_XOREQ); u8(5); u8(4);             // r5 ^= key
    emit(PV_XOREQ); u8(0); u8(5);             // r0 ^= r5
    emit(PV_MULI); u8(0); u64(fnv_prime);     // r0 *= prime
    emit(PV_ADDI); u8(4); u64(roll_step);     // key += step
    emit(PV_ADDI); u8(1); u64(1);             // ptr++
    emit(PV_SUBI); u8(3); u64(1);             // remaining--
    emit(PV_JMP); u32(loop_top);

    uint32_t end = (uint32_t)bc.size();
    emit(PV_HALT);
    memcpy(bc.data() + je_off + 1, &end, 4);
    return bc;
}

// Runtime np_vm_install clamps its table to 64 entries; keep the packer in
// step so a "protect every function" run does not silently drop regions.
// The VM region table used to be capped at 64, which silently dropped every
// function after the first 64 in RVA order - a selection of a few thousand
// scanned functions was mostly unprotected without saying so. The cap is now
// only a sanity bound against a pathological selection; every function that
// the translator can actually express gets a region.
static constexpr size_t kMaxVmRegions = 8192;

// One trampoline slot in the arena reserved for np_vm_install. Must match
// NP_VM_TRAMP_STRIDE in runtime/prot64.c: 51 fixed bytes + 20 per saved
// register, rounded up to 16.
static constexpr uint32_t kTrampStride = 384;

// Lower one code range [start, end) to VM bytecode. Shared by the SDK marker
// path and the scanned-function path. See include/packer.h for the contract.
bool Packer::vmLowerRegion(PELib& pe, std::vector<uint8_t>& data, std::vector<VmRegion>& vm_regions,
                           std::mt19937_64& rng, uint32_t start, uint32_t end,
                           const FunctionProtect* selected, const char* origin,
                           uint32_t& revirt_levels_applied) {
    (void)origin;
    revirt_levels_applied = 0;
    if (end <= start) return false;
    uint32_t len = end - start;
    if (vm_regions.size() >= kMaxVmRegions) {
        vmSkip("region table full - limit is " + std::to_string(kMaxVmRegions) +
               " regions per image");
        return false;
    }

    const bool mut = config_.enable_mutation && config_.mutation_strength > 0;
    // A region runs through the virtualizer when it is explicitly marked for
    // virtualization, when it is marked ultra, or when it carries no level at
    // all and therefore inherits the global setting.
    const bool region_vm = !selected || selected->level == ProtectLevel::None ||
                           selected->level == ProtectLevel::Virtualization ||
                           selected->level == ProtectLevel::Ultra;
    if (!region_vm) return false;   // caller filters this earlier; defensive
    // Mutation is applied for the explicit mutation level, for ultra, and for
    // regions that inherit the global setting.
    const bool region_mut = mut &&
        (!selected || selected->level == ProtectLevel::None ||
         selected->level == ProtectLevel::Mutation ||
         selected->level == ProtectLevel::Ultra);
    const uint8_t region_complexity = selected && selected->vm_complexity > 0
        ? selected->vm_complexity : config_.vm_default_complexity;
    const uint8_t region_mutation = selected ? selected->vm_mutation : config_.mutation_strength;

    // Locate the bytes in the original section data.
    const uint8_t* code = nullptr;
    for (size_t si = 0; si < pe.sectionCount() && !code; si++) {
        const auto& s = pe.section(si);
        if (start < s.VirtualAddress) continue;
        if ((uint64_t)start + len > (uint64_t)s.VirtualAddress + s.VirtualSize) continue;
        auto& d = pe.sectionData(si);
        size_t off = start - s.VirtualAddress;
        if (off + len <= d.size()) code = d.data() + off;
    }
    if (!code) {
        vmSkip("outside section bounds");
        return false;
    }

    // A scanned function body ends with RET. The wire VM has no return
    // instruction and the trampoline jumps to the byte after the region, so
    // lower only up to the first RET and leave the terminator native: the
    // tail jump lands exactly on it and the original return executes. SDK
    // markers never contain a RET (their END marker is NOPs), so this only
    // applies to the function-scanner path.
    if (selected && selected->source == FunctionSource::ScanFunction) {
        Disassembler rdis;
        uint32_t off = 0;
        uint32_t first_ret = 0;
        while (off < len) {
            DisasmInsn insn;
            uint32_t ilen = rdis.disassemble(code + off, len - off, insn);
            if (!ilen) break;
            if (insn.category == InsnCategory::RET) { first_ret = off; break; }
            off += ilen;
        }
        if (first_ret == 0) {
            // Either the first instruction is the RET (nothing to lower) or
            // no RET decodes before the end of the range.
            vmSkip("no function body before RET");
            return false;
        }
        len = first_ret;
    }

    // Validate that the whole region decodes cleanly and collect
    // the guest registers the block touches. The trampoline only
    // has to preserve those. RSP/RBP own its frame and R15 is the
    // interpreter stack pointer, so those must not appear.
    uint32_t mask = 0;
    bool bad = false;
    {
        Disassembler dis;
        uint32_t off2 = 0;
        while (off2 < len) {
            DisasmInsn insn;
            uint32_t ilen = dis.disassemble(code + off2, len - off2, insn);
            if (!ilen) { bad = true; break; }
            Operand ops[3] = { insn.dst, insn.src, insn.extra };
            for (int k = 0; k < 3; k++) {
                uint8_t rg = (uint8_t)ops[k].reg;
                if (rg <= 15) mask |= (1u << rg);
                if (ops[k].type == OperandType::Memory) {
                    uint8_t rb = (uint8_t)ops[k].base, ri = (uint8_t)ops[k].index;
                    if (rb <= 15) mask |= (1u << rb);
                    if (ri <= 15) mask |= (1u << ri);
                }
            }
            off2 += ilen;
        }
        if (off2 != len) bad = true;
    }
    if (bad || mask == 0) {
        vmSkip("undecodable or empty");
        return false;
    }
    if (mask & ((1u << 4) | (1u << 5))) {   // RSP / RBP
        vmSkip("uses RSP/RBP");
        return false;
    }

    // ---- pre-translation code mutation -------------------------
    // Feed the region through the mutation engine first. The
    // mutated stream is then lowered to wire bytecode exactly like
    // the original, so the interpreter sees a semantically
    // equivalent but structurally different program. If any step
    // fails we fall back to the unmutated translation.
    const uint8_t* translate_src = code;
    uint32_t translate_len = len;
    std::vector<uint8_t> mutated_bytes;
    uint32_t used_mask = mask;
    uint32_t mutation_count = 0;
    if (region_mut && len >= 16) {
        std::vector<NativeInsn> stream;
        {
            Disassembler dis;
            uint32_t off3 = 0;
            while (off3 < len) {
                DisasmInsn insn;
                uint32_t ilen = dis.disassemble(code + off3, len - off3, insn);
                if (!ilen) break;
                NativeInsn ni;
                ni.bytes = insn.bytes;
                ni.rva = start + off3;
                ni.length = insn.length;
                ni.opcode = insn.opcode;
                ni.modrm = insn.modrm;
                ni.sib = insn.sib;
                ni.is_jcc = insn.category == InsnCategory::JCC;
                ni.is_call = insn.category == InsnCategory::CALL;
                ni.is_ret = insn.category == InsnCategory::RET;
                ni.is_push = insn.category == InsnCategory::PUSH;
                ni.is_pop = insn.category == InsnCategory::POP;
                ni.is_mov = insn.category == InsnCategory::MOV;
                ni.is_arith = insn.category == InsnCategory::ADD ||
                              insn.category == InsnCategory::SUB ||
                              insn.category == InsnCategory::MUL ||
                              insn.category == InsnCategory::IMUL;
                ni.is_logic = insn.category == InsnCategory::AND ||
                              insn.category == InsnCategory::OR ||
                              insn.category == InsnCategory::XOR ||
                              insn.category == InsnCategory::NOT;
                ni.is_shift = insn.category == InsnCategory::SHL ||
                              insn.category == InsnCategory::SHR ||
                              insn.category == InsnCategory::SAR;
                ni.is_test = insn.category == InsnCategory::TEST ||
                             insn.category == InsnCategory::CMP;
                stream.push_back(std::move(ni));
                off3 += ilen;
            }
        }
        // The VM only understands a small register-only subset, so
        // the VM mutation pass keeps substitutions only: garbage
        // injection and opaque predicates expand the stream with
        // encodings the translator cannot lower, which would make
        // every region fall back to the unmutated program.
        MutationEngine mutEngine(buildSeed() ^ 0x2545F4914F6CDD1Dull);
        mutEngine.setStrength(static_cast<MutationStrength>(std::min<uint8_t>(region_mutation, 3)));
        mutEngine.setInjectGarbage(false);
        mutEngine.setReorder(false);
        std::vector<NativeInsn> mutated_stream;
        {
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
            for (const auto& insn : stream) {
                auto sub = mutEngine.mutate({insn});
                bool ok = !sub.empty() && !sub[0].bytes.empty() && sub[0].mutated;
                if (ok) {
                    for (const auto& mi : sub) {
                        if (!supported(mi)) { ok = false; break; }
                    }
                }
                if (ok) {
                    mutated_stream.insert(mutated_stream.end(), sub.begin(), sub.end());
                    mutation_count++;
                } else {
                    mutated_stream.push_back(insn);
                }
            }
        }
        progress(57, std::string("Mutation: ") + std::to_string(mutation_count) +
                " substitutions accepted");

        if (mutation_count > 0) {
            for (const auto& mi : mutated_stream)
                mutated_bytes.insert(mutated_bytes.end(),
                                     mi.bytes.begin(), mi.bytes.end());
            // Recompute the register mask on the mutated stream:
            // the substitutions may touch registers the original
            // never mentioned, and the trampoline must preserve
            // every one of them.
            uint32_t new_mask = 0;
            bool new_bad = false;
            Disassembler dis2;
            uint32_t off4 = 0;
            while (off4 < mutated_bytes.size()) {
                DisasmInsn insn;
                uint32_t ilen = dis2.disassemble(mutated_bytes.data() + off4,
                                                 mutated_bytes.size() - off4, insn);
                if (!ilen) { new_bad = true; break; }
                Operand ops[3] = { insn.dst, insn.src, insn.extra };
                for (int k = 0; k < 3; k++) {
                    uint8_t rg = (uint8_t)ops[k].reg;
                    if (rg <= 15) new_mask |= (1u << rg);
                    if (ops[k].type == OperandType::Memory) {
                        uint8_t rb = (uint8_t)ops[k].base, ri = (uint8_t)ops[k].index;
                        if (rb <= 15) new_mask |= (1u << rb);
                        if (ri <= 15) new_mask |= (1u << ri);
                    }
                }
                off4 += ilen;
            }
            if (!new_bad && off4 == mutated_bytes.size() &&
                !(new_mask & ((1u << 4) | (1u << 5))) && new_mask) {
                translate_src = mutated_bytes.data();
                translate_len = (uint32_t)mutated_bytes.size();
                used_mask = new_mask;
            } else {
                mutated_bytes.clear();
                mutation_count = 0;
            }
        }
    }

    VMLoweredBlock blk = VMTranslator::translate(translate_src, translate_len,
                                                  pe.imageBase() + start,
                                                  pe.imageBase(),
                                                  region_complexity,
                                                  region_mutation,
                                                  pe.is64(), buildSeed());
    if (!blk.ok || blk.bytecode.empty()) {
        if (mutation_count > 0) {
            // The mutated stream did not lower cleanly; retry the
            // original code so the region keeps its protection.
            mutated_bytes.clear();
            used_mask = mask;
            blk = VMTranslator::translate(code, len,
                                           pe.imageBase() + start,
                                           pe.imageBase(),
                                           region_complexity,
                                           region_mutation,
                                           pe.is64(), buildSeed());
            mutation_count = 0;
        }
        if (!blk.ok || blk.bytecode.empty()) {
            vmSkip(blk.skipReason);
            return false;
        }
    }
    mask = used_mask;

    // ---- trampoline clobber set ---------------------------------
    // The runtime trampoline loads the interpreter arguments into
    // rcx (bytecode), edx (length), r8 (reverse table) and r9
    // (register file) before calling np_vm_run, and np_vm_run itself
    // is compiled C that returns through rax and uses r10/r11 as
    // scratch.  The save/restore loop in np_vm_install only covers
    // registers present in this mask, so every register the call
    // sequence can destroy must be forced in here even when the guest
    // block never mentions it: compilers legally keep live values in
    // caller-saved registers across a call to a function whose body
    // they can see (interprocedural register allocation), and the
    // virtualized region must honour exactly the same contract the
    // original code did.  rbx/rbp/r12-r15/rdi/rsi are preserved by
    // np_vm_run itself (verified against its disassembly), and rbp is
    // additionally anchored by the trampoline frame, so they need no
    // special handling.
    mask |= (1u << 0) | (1u << 1) | (1u << 2) | (1u << 8) |
            (1u << 9) | (1u << 10) | (1u << 11);

    // ---- post-translation obfuscation --------------------------
    // Dead-register junk emission + control-flow flattening.
    // Derive the logical->physical opcode table from the reverse
    // table so we can re-encode the obfuscated stream.
    if (region_complexity > 0) {
        uint8_t mapping[256] = {0};
        for (int p = 0; p < 256; p++) {
            uint8_t logical = blk.reverse[(size_t)p];
            if (logical < WIRE_COUNT) mapping[logical] = (uint8_t)p;
        }
        blk.bytecode = vmObfuscate(blk.bytecode, blk.reverse.data(),
                                    mapping, mask,
                                    region_complexity);
    }

    // The trampoline no longer has to fit inside the region: np_vm_install
    // generates it into a dedicated arena and leaves a five-byte jump here.
    // Only the jump has to fit, which is what finally makes small functions
    // virtualizable.
    if (len < 5) {
        vmSkip("too small for trampoline");
        return false;
    }

    // ---- revirtualization (EnableRevirtualization) --------------
    // Two independent transforms, both optional and both fail-safe: if either
    // cannot be applied the region simply stays the single-level program that
    // was just built.
    //
    // Layout contract (mirrored by np_vm_run_stream in runtime/prot64.c):
    // every offset stored in the stage and guest tables is measured from the
    // region's own reverse-table base, which is what the trailer hands the
    // runtime. The tables therefore have to be written *after* rev_off is
    // known, and the trailer deltas are back-patched once they are placed.
    uint32_t stage_count = 0;
    uint32_t stage_table_off = 0;
    uint32_t guest_table_off = 0;
    uint32_t guest_count = 0;
    std::vector<np::VmStageEntry> stage_entries;
    std::vector<uint32_t> guest_fields;   // 7 dwords + key per block, rev-relative later

    struct GuestPending {
        std::vector<uint8_t> bc;
        uint8_t reverse[256];
        uint8_t regPerm[16];
        uint64_t key;
        uint32_t rva, flags;
    };
    std::vector<GuestPending> guest_pending;
    struct StagePending {
        std::vector<uint8_t> bc;
        uint8_t reverse[256];
        uint64_t key;
        uint32_t rva;
    };
    std::vector<StagePending> stage_pending;

    if (config_.enable_revirtualization && pe.is64() &&
        blk.bytecode.size() >= np::kMinStageBytes * 2) {
        // (1) Split the program into stages with independent opcode
        //     permutations and keystream keys, then (2) lift the arithmetic
        //     runs of each stage into guest blocks and repeat that lift on the
        //     blocks themselves once per additional nesting level.
        uint8_t mapping[256] = {0};
        for (int p = 0; p < 256; p++) {
            uint8_t logical = blk.reverse[(size_t)p];
            if (logical < NP_WIRE_OPCODE_SLOTS) mapping[logical] = (uint8_t)p;
        }
        std::vector<VmStage> stages;
        std::vector<VmGuestBlock> lifted;
        uint64_t split_seed = ((uint64_t)rng() << 32) ^ (uint64_t)(uint32_t)rng();
        // Target ~48 wire bytes per stage: small enough that a dump of one
        // stage window says nothing about the rest, large enough that the
        // per-stage reverse table is amortised.
        uint32_t levels = config_.revirtualization_level;
        if (levels == 0) levels = 1;              // enabled with level 0 == one layer
        uint32_t reached = vmRevirtualize(blk.bytecode, blk.reverse.data(), mapping,
                                          split_seed, 48, levels,
                                          np::kMaxGuestStages, stages, lifted);
        if (reached > 0 && (!lifted.empty() || stages.size() >= 2)) {
            for (auto& g : lifted) {
                GuestPending gp;
                gp.bc = g.bc;
                std::memcpy(gp.reverse, g.reverse, 256);
                std::memcpy(gp.regPerm, g.regPerm, 16);
                gp.key = g.key;
                gp.rva = g.rva;
                // bit0 = live, bits 8..23 = the outer registers the block
                // assigns (only those are copied back), bits 24..27 = nesting
                // level, which is what lets a level-N block reach its children.
                gp.flags = np::vmGuestPackFlags(g.writeMask, g.level);
                guest_pending.push_back(std::move(gp));
            }
            for (auto& st : stages) {
                StagePending sp;
                std::memcpy(sp.reverse, st.reverse, 256);
                sp.bc = st.bc;
                sp.key = st.key;
                sp.rva = st.rva;
                stage_pending.push_back(std::move(sp));
            }
            revirt_levels_applied = reached;
        }
    }

    // Emit the revirtualized payload pieces. Their absolute offsets are
    // recorded now and rebased against rev_off once it is known.
    std::vector<uint32_t> guest_bc_off, guest_rev_off, guest_perm_off;
    std::vector<uint32_t> stage_bc_off, stage_rev_off;
    for (auto& gp : guest_pending) {
        vmBytecodeCrypt(gp.bc.data(), gp.bc.size(), gp.key, gp.rva);
        guest_bc_off.push_back((uint32_t)data.size());
        data.insert(data.end(), gp.bc.begin(), gp.bc.end());
        while (data.size() & 3) data.push_back(0);
        guest_rev_off.push_back((uint32_t)data.size());
        data.insert(data.end(), gp.reverse, gp.reverse + 256);
        guest_perm_off.push_back((uint32_t)data.size());
        data.insert(data.end(), gp.regPerm, gp.regPerm + 16);
        while (data.size() & 7) data.push_back(0);
    }
    for (auto& sp : stage_pending) {
        vmBytecodeCrypt(sp.bc.data(), sp.bc.size(), sp.key, sp.rva);
        stage_bc_off.push_back((uint32_t)data.size());
        data.insert(data.end(), sp.bc.begin(), sp.bc.end());
        while (data.size() & 3) data.push_back(0);
        stage_rev_off.push_back((uint32_t)data.size());
        data.insert(data.end(), sp.reverse, sp.reverse + 256);
        while (data.size() & 7) data.push_back(0);
    }

    // Exec-time decoding: the bytecode is stored as a counter-mode keystream
    // ciphertext and the runtime decodes one 256-byte window at a time, so the
    // plaintext program never exists in memory as a whole. The key is per
    // region and folded with the RVA inside vmBytecodeCrypt().
    uint64_t vm_key = ((uint64_t)rng() << 32) | (uint64_t)(uint32_t)rng();

    // When stages are in use this region's own program is never executed: the
    // runtime enters through the stage table. Store decoy bytes rather than the
    // real program so nothing legible sits at the address a dumper would try
    // first, and leave them unencrypted since nothing consumes them.
    const bool staged = !stage_pending.empty();
    if (staged) {
        blk.bytecode.assign((size_t)64, 0);
        for (auto& b : blk.bytecode) b = (uint8_t)rng();
        std::memset(blk.reverse.data(), 0, 256);
    } else {
        vmBytecodeCrypt(blk.bytecode.data(), blk.bytecode.size(), vm_key, start);
    }

    uint32_t bc_off = (uint32_t)data.size();
    data.insert(data.end(), blk.bytecode.begin(), blk.bytecode.end());
    while (data.size() & 7) data.push_back(0);
    uint32_t rev_off = (uint32_t)data.size();
    data.insert(data.end(), blk.reverse.begin(), blk.reverse.end());
    // Key (8 bytes) + region RVA (4 bytes) ride behind the reverse table; the
    // runtime reads them at reverse+256 / reverse+264 so np_vm_run keeps its
    // four-argument signature and the trampoline needs no extra stack slots.
    for (int k = 0; k < 8; k++) data.push_back((uint8_t)(vm_key >> (k * 8)));
    for (int k = 0; k < 4; k++) data.push_back((uint8_t)(start >> (k * 8)));
    // +268 stage flags (bit0 = stage table present, bits 8.. = stage count),
    // +272/276 reverse-relative deltas to the stage and guest tables,
    // +280 guest block count. A legacy region leaves all of them zero.
    size_t trailerFlags = data.size();
    npPush32(data, staged ? (1u | ((uint32_t)stage_pending.size() << 8)) : 0u);
    size_t trailerStageDelta = data.size();
    npPush32(data, 0);                       // back-patched below
    size_t trailerGuestDelta = data.size();
    npPush32(data, 0);                       // back-patched below
    npPush32(data, (uint32_t)guest_pending.size());
    while (data.size() & 7) data.push_back(0);

    if (staged) {
        // Stage table. bc_len is a plain count; the three addresses are
        // reverse-relative offsets.
        stage_table_off = (uint32_t)data.size();
        for (size_t s = 0; s < stage_pending.size(); s++) {
            npPush32(data, (uint32_t)((int64_t)stage_bc_off[s] - (int64_t)rev_off));
            npPush32(data, (uint32_t)stage_pending[s].bc.size());
            npPush32(data, (uint32_t)((int64_t)stage_rev_off[s] - (int64_t)rev_off));
            for (int k = 0; k < 8; k++)
                data.push_back((uint8_t)(stage_pending[s].key >> (k * 8)));
            npPush32(data, stage_pending[s].rva);
        }
        stage_count = (uint32_t)stage_pending.size();

        if (!guest_pending.empty()) {
            guest_table_off = (uint32_t)data.size();
            for (size_t g = 0; g < guest_pending.size(); g++) {
                npPush32(data, (uint32_t)((int64_t)guest_bc_off[g] - (int64_t)rev_off));
                npPush32(data, (uint32_t)guest_pending[g].bc.size());
                npPush32(data, (uint32_t)((int64_t)guest_rev_off[g] - (int64_t)rev_off));
                npPush32(data, (uint32_t)((int64_t)guest_perm_off[g] - (int64_t)rev_off));
                for (int k = 0; k < 8; k++)
                    data.push_back((uint8_t)(guest_pending[g].key >> (k * 8)));
                npPush32(data, guest_pending[g].rva);
                npPush32(data, guest_pending[g].flags);
            }
            guest_count = (uint32_t)guest_pending.size();
        }

        // Deltas only now exist: patch them into the trailer reserved above.
        npPatch32(data, trailerStageDelta,
                  (uint32_t)((int64_t)stage_table_off - (int64_t)rev_off));
        npPatch32(data, trailerGuestDelta,
                  guest_count ? (uint32_t)((int64_t)guest_table_off - (int64_t)rev_off) : 0u);
        npPatch32(data, trailerFlags, 1u | (stage_count << 8));
        while (data.size() & 7) data.push_back(0);
    }

    VmRegion reg{start, len, bc_off,
                 (uint32_t)blk.bytecode.size(), rev_off, mask, 0};
    if (stage_count) reg.setRevirt(stage_count, guest_count);
    vm_regions.push_back(reg);
    if (result_) result_->vm_instructions += blk.insnsTranslated;
    if (result_ && mutation_count > 0) result_->mutation_applied += mutation_count;
    progress(58, std::string("VM translated ") + std::to_string(blk.insnsTranslated) +
            (mutation_count > 0 ? " instructions (mutated x" + std::to_string(mutation_count) + ")" : " instructions"));
    if (revirt_levels_applied)
        progress(58, "Revirtualization: " + std::to_string(stage_count) + " stage(s), " +
                     std::to_string(guest_count) + " guest block(s), level " +
                     std::to_string(revirt_levels_applied));
    return true;
}

bool Packer::phase_buildProtection(PELib& pe, std::vector<uint8_t>& packed_data) {
    if (!pe.is64()) return true;              // x64 runtime only
    if (!config_.enable_protection_runtime) return true;

    std::mt19937_64 rng(buildSeed() ^ 0x5DEECE66Dull);
    auto rnd64 = [&]() { return (uint64_t)rng(); };

    const bool ad  = config_.anti_debug_level > 0;
    const bool avm = config_.anti_vm_level > 0;
    const bool tim = config_.anti_debug_level >= 3;
    const bool dr  = config_.anti_debug_level >= 2;
    const bool lic = config_.enable_licensing;
    const bool vm  = config_.enable_vm;
    const bool itg = config_.memory_protection;
    const bool mut = config_.enable_mutation && config_.mutation_strength > 0;
    const bool act = config_.enable_activation && !config_.activation_key.empty();
    const bool sandbox = config_.enable_sandbox_guard;
    const bool antidump = config_.enable_anti_dump;
    const bool envchk = config_.enable_env_check;
    const bool isob   = config_.enable_self_isolation;

    uint32_t flags = 0;
    if (ad)  flags |= 0x01;
    if (avm) flags |= 0x02;
    if (tim) flags |= 0x04;
    if (dr)  flags |= 0x08;
    if (lic) flags |= 0x10;
    if (vm)  flags |= 0x20;
    if (itg) flags |= 0x40;
    if (mut) flags |= 0x80;
    if (act) flags |= 0x100;
    if (sandbox) flags |= 0x200;
    if (antidump) flags |= 0x400;
    if (envchk) flags |= 0x800;
    if (isob)   flags |= 0x1000;
    if (config_.enable_audit_recheck) flags |= 0x2000;
    // Hypervisor-level and driver-level layers ride on the sandbox guard: they
    // feed the same score, and a guard that is off has nothing to feed.
    const bool hv_exit = sandbox && config_.evasion.enabled() &&
                         (config_.evasion.hypervisor_exit_cost || config_.evasion.hypervisor_vendor_probe);
    const bool kernprobe = sandbox && config_.evasion.enabled() && config_.evasion.kernel_level >= 1;
    if (hv_exit)   flags |= 0x4000;
    if (kernprobe) flags |= 0x8000;
    if (!flags) return true;

    // ---- mutation kernel --------------------------------------------------
    std::vector<uint8_t> kernel;
    uint64_t expected_mut_hash = 0;
    if (mut) {
        kernel.assign(kMutationKernel64, kMutationKernel64 + kMutationKernel64Size);
        const uint64_t basis  = rnd64() | 1ull;
        const uint64_t prime  = rnd64() | 1ull;
        const uint64_t seed   = rnd64();
        const uint64_t prime2 = rnd64() | 1ull;
        npPatch64(kernel, kMutKernBasisOff,  basis);
        npPatch64(kernel, kMutKernPrimeOff,  prime);
        npPatch64(kernel, kMutKernSeedOff,   seed);
        npPatch64(kernel, kMutKernPrime2Off, prime2);

        uint8_t probe[32];
        for (uint32_t i = 0; i < 32; i++)
            probe[i] = (uint8_t)(0xA5u ^ (i * 0x3Du) ^ (uint8_t)(i << 3));
        uint64_t h = basis;
        for (uint32_t i = 0; i < 32; i++) { h ^= (uint64_t)probe[i]; h *= prime; }
        h ^= seed;
        h = (h << 17) | (h >> 47);
        h *= prime2;
        expected_mut_hash = h;
    }

    // ---- NPP1 descriptor (v2) ---------------------------------------------
    std::vector<uint8_t> data(128, 0);
    npPatch32(data, 0, 0x3150504E);        // 'NPP1'
    npPatch32(data, 4, 2);                 // version 2 (sandbox/dump/env fields)
    npPatch32(data, 8, flags);
    npPatch32(data, 12, config_.anti_debug_level);
    npPatch32(data, 16, config_.anti_vm_level);
    npPatch64(data, 24, tim ? 8000ull : 0ull);
    npPatch64(data, 32, expected_mut_hash);
    if (act) npPatch64(data, 80, std::strtoull(config_.activation_key.c_str(), nullptr, 16));
    /* Honour an explicit 0: the runtime gate skips scoring at 0, which is
     * the documented "guard on, never block" mode. The PackerConfig default
     * (40) still applies when the option is never set. */
    if (sandbox) npPatch32(data, 96, config_.sandbox_score_threshold);
    if (envchk) {
        npPatch32(data, 100, config_.min_cpu_count);
        npPatch32(data, 104, config_.min_ram_mb);
        npPatch32(data, 108, config_.min_uptime_ms);
        npPatch32(data, 112, config_.min_screen_width);
        npPatch32(data, 116, config_.min_screen_height);
        npPatch32(data, 120, config_.min_monitor_count);
        npPatch32(data, 124, config_.env_score_threshold);   /* runtime falls back to 7 at 0 */
    }

    // ---- license program --------------------------------------------------
    std::vector<uint8_t> reverse(256, 0);
    if (lic && !config_.license_key.empty()) {
        const uint8_t roll_start = (uint8_t)(rnd64() & 0xFF);
        const uint8_t roll_step  = (uint8_t)((rnd64() & 0x7F) | 1);

        std::vector<uint8_t> blob(config_.license_key.begin(), config_.license_key.end());
        uint8_t roll = roll_start;
        for (size_t i = 0; i < blob.size(); i++) {
            blob[i] ^= roll;
            roll = (uint8_t)(roll + roll_step);
        }

        const uint64_t basis = 0xCBF29CE484222325ull;
        const uint64_t prime = 0x100000001B3ull;
        std::vector<uint8_t> mapping;
        std::vector<uint8_t> bc = npBuildLicenseProgram(blob.size(), basis, prime,
                                                        roll_start, roll_step, mapping);
        for (int logical = 0; logical < 256; logical++)
            reverse[mapping[logical]] = (uint8_t)logical;

        uint64_t expect = basis;
        uint64_t rk = roll_start;
        for (size_t i = 0; i < blob.size(); i++) {
            uint64_t plain = (uint64_t)blob[i] ^ rk;
            expect ^= (uint64_t)plain;
            expect *= prime;
            rk += roll_step;
        }

        uint32_t blob_off = (uint32_t)data.size();
        data.insert(data.end(), blob.begin(), blob.end());
        while (data.size() & 7) data.push_back(0);
        uint32_t bc_off = (uint32_t)data.size();
        // The licence program is ciphertext too: the runtime decodes it a
        // window at a time like every other VM region. The key is derived from
        // header fields the runtime already has (expected hash + blob length),
        // so no extra header slot is needed.
        uint64_t lic_key = expect ^ ((uint64_t)blob.size() * 0x9E3779B97F4A7C15ull);
        vmBytecodeCrypt(bc.data(), bc.size(), lic_key, bc_off);
        data.insert(data.end(), bc.begin(), bc.end());
        while (data.size() & 7) data.push_back(0);
        uint32_t rev_off = (uint32_t)data.size();
        data.insert(data.end(), reverse.begin(), reverse.end());
        // Same trailer contract as a VM region: key then RVA.
        for (int k = 0; k < 8; k++) data.push_back((uint8_t)(lic_key >> (k * 8)));
        for (int k = 0; k < 4; k++) data.push_back((uint8_t)(bc_off >> (k * 8)));
        for (int k = 0; k < 4; k++) data.push_back(0x00);
        while (data.size() & 7) data.push_back(0);

        npPatch64(data, 40, expect);
        npPatch32(data, 48, blob_off);
        npPatch32(data, 52, (uint32_t)blob.size());
        npPatch32(data, 60, bc_off);
        npPatch32(data, 64, (uint32_t)bc.size());
        npPatch32(data, 68, rev_off);
    }

    // ---- VM virtualisation ------------------------------------------------
    // Two sources feed the VM translator:
    //   1. NOVAPROTECT_BEGIN/END (or legacy NOVAPACK_BEGIN/END) marker pairs,
    //      optionally filtered by the SDK object editor (-region).
    //   2. Functions picked in the client's function scanner (-func), whose
    //      RVA range is the whole function body and needs no marker.
    // Either way the runtime replaces the region with a register-preserving
    // trampoline that runs the interpreter, so the code never executes
    // natively. Regions the translator cannot express stay native.
    std::vector<VmRegion> vm_regions;
    // Deepest nesting level any region actually reached. Regions that refuse
    // the transform (or lift fewer levels than requested) simply do not raise
    // this, so the reported number is measured, not echoed from the config.
    uint32_t revirt_deepest = 0;
    if (vm && pe.is64()) {
        auto markers = pe.findMarkers();
        if (markers.empty() && config_.function_regions.empty()) {
            progress(57, "VM enabled but no SDK markers or scanned functions found");
        }
        if (!markers.empty()) {
            progress(57, std::string("Found ") + std::to_string(markers.size()) + " SDK markers");
            for (size_t i = 0; i < markers.size(); i++) {
                if (markers[i].type != 0) continue;
                size_t j = i + 1;
                while (j < markers.size() && markers[j].type != 1) j++;
                if (j >= markers.size()) break;

                const uint32_t begin_len = 27;          // x64 marker prologue
                uint32_t start = markers[i].rva + begin_len;
                uint32_t end_rva = markers[j].rva;
                i = j;
                if (end_rva <= start) continue;

                const FunctionProtect* selected = nullptr;
                for (const auto& rule : config_.function_regions) {
                    if (rule.source != FunctionSource::SdkMarker) continue;
                    if (rule.rva_start == start && rule.rva_end == end_rva) {
                        selected = &rule;
                        break;
                    }
                }
                if (!config_.function_regions.empty() && !selected) {
                    // Only skip when the editor actually governs markers: a
                    // function-scanner-only run must not silence markers.
                    bool marker_governed = false;
                    for (const auto& rule : config_.function_regions)
                        if (rule.source == FunctionSource::SdkMarker) { marker_governed = true; break; }
                    if (marker_governed) {
                        vmSkip("not selected in SDK object editor");
                        continue;
                    }
                }
                if (selected && selected->name == "skip") {
                    vmSkip("disabled by SDK object editor");
                    continue;
                }
                uint32_t applied = 0;
                vmLowerRegion(pe, data, vm_regions, rng, start, end_rva, selected, "marker", applied);
                if (applied > revirt_deepest) revirt_deepest = applied;
            }
        }

        // ---- scanned functions (-func) -------------------------------------
        // Each rule is a whole function body. Rules are applied in ascending
        // RVA order so the payload layout is deterministic.
        std::vector<const FunctionProtect*> scanned;
        for (const auto& rule : config_.function_regions)
            if (rule.source == FunctionSource::ScanFunction) scanned.push_back(&rule);
        std::sort(scanned.begin(), scanned.end(),
                  [](const FunctionProtect* a, const FunctionProtect* b) {
                      return a->rva_start < b->rva_start;
                  });
        if (!scanned.empty()) {
            progress(57, std::string("Function scanner: ") + std::to_string(scanned.size()) +
                    " selected function(s)");
            for (const auto* rule : scanned) {
                if (rule->name == "skip") continue;
                uint32_t applied = 0;
                vmLowerRegion(pe, data, vm_regions, rng,
                              rule->rva_start, rule->rva_end, rule, "func", applied);
                if (applied > revirt_deepest) revirt_deepest = applied;
            }
        }
    }
    if (vm_regions.empty()) progress(57, "VM enabled but no region could be lowered");
    if (vm && pe.is64()) {
        uint32_t skipped = 0;
        for (const auto& entry : vm_skip_counts_) skipped += entry.second;
        progress(57, "VM: " + std::to_string(vm_regions.size()) + " region(s) virtualized, " +
                     std::to_string(skipped) + " skipped");
        for (const auto& entry : vm_skip_counts_)
            progress(57, "  " + std::to_string(entry.second) + "x " + entry.first);
    }

            if (!vm_regions.empty()) {
                uint32_t desc_off = (uint32_t)data.size();
                for (const auto& vr : vm_regions) {
                    uint8_t rec[32] = {};
                    memcpy(rec + 0, &vr.rva, 4);
                    memcpy(rec + 4, &vr.size, 4);
                    memcpy(rec + 8, &vr.bc_off, 4);
                    memcpy(rec + 12, &vr.bc_len, 4);
                    memcpy(rec + 16, &vr.rev_off, 4);
                    memcpy(rec + 20, &vr.reg_mask, 4);
                    memcpy(rec + 24, &vr.reserved, 4);
                    data.insert(data.end(), rec, rec + 32);
                }
                npPatch32(data, 20, desc_off);          // was: reserved
                npPatch32(data, 88, (uint32_t)vm_regions.size());
                // Trampoline arena: one fixed-stride slot per region, inside the
                // executable .np_prot section. np_vm_install generates the
                // trampolines here and leaves a five-byte jump in each region,
                // so a region no longer has to hold the trampoline itself.
                while (data.size() & 15) data.push_back(0x00);
                uint32_t arena_off = (uint32_t)data.size();
                data.resize(data.size() + (size_t)vm_regions.size() * kTrampStride, 0x00);
                npPatch32(data, 92, arena_off);
            }
    if (result_) result_->revirtualization_level = revirt_deepest;
    if (revirt_deepest && revirt_deepest < (uint32_t)config_.revirtualization_level)
        progress(58, "Revirtualization: requested level " +
                     std::to_string((int)config_.revirtualization_level) +
                     ", engine established " + std::to_string(revirt_deepest));
    // ---- assemble section -------------------------------------------------
    std::vector<uint8_t> prot_section;
    uint32_t code_size = kProtBlob64Size;
    while (code_size & 15) code_size++;
    prot_section.insert(prot_section.end(), kProtBlob64, kProtBlob64 + kProtBlob64Size);
    while (prot_section.size() < code_size) prot_section.push_back(0x90);

    /* The runtime's writable statics (np_snap_buf, the registry probe
     * buffer) are linked as .np_bss (NOLOAD) directly behind the blob
     * image, so every PC-relative reference from the code points just
     * past code_size. Deploy a zeroed window of the link-time size here
     * and keep the section writable - without it those references read
     * and write the blob's own code bytes. */
    uint32_t bss_off = (uint32_t)prot_section.size();
    for (uint32_t i = 0; i < kProtBlob64BssSize; i++) prot_section.push_back(0);
    while (prot_section.size() & 7) prot_section.push_back(0);

    uint32_t data_off = (uint32_t)prot_section.size();
    prot_section.insert(prot_section.end(), data.begin(), data.end());
    while (prot_section.size() & 7) prot_section.push_back(0);

    uint32_t kernel_off = (uint32_t)prot_section.size();
    if (!kernel.empty()) prot_section.insert(prot_section.end(), kernel.begin(), kernel.end());

    int idx = pe.addSection(".np_prot",
                            (uint32_t)prot_section.size(),
                            SEC_MEM_READ | SEC_MEM_WRITE | SEC_MEM_EXECUTE | SEC_CODE);
    pe.setSectionData(idx, prot_section);
    uint32_t base = pe.section(idx).VirtualAddress;
    prot_code_rva_   = base;
    prot_code_size_  = code_size;
    prot_bss_rva_    = base + bss_off;
    prot_data_rva_   = base + data_off;
    prot_kernel_rva_ = kernel.empty() ? 0 : base + kernel_off;

    if (packed_data.size() >= 116) {
        memcpy(packed_data.data() + 100, &prot_code_rva_, 4);
        memcpy(packed_data.data() + 104, &prot_data_rva_, 4);
        memcpy(packed_data.data() + 108, &prot_kernel_rva_, 4);
        memcpy(packed_data.data() + 112, &prot_code_size_, 4);
    }
    if (result_) result_->functions_protected++;
    return true;
}
std::vector<uint8_t> Packer::encryptData(const uint8_t* data, size_t size, const uint8_t* key, size_t key_size) {
    std::vector<uint8_t> result(data, data + size);
    util::xor_crypt(result.data(), result.size(), key, key_size);
    return result;
}

std::vector<uint8_t> Packer::compressData(const uint8_t* data, size_t size) {
    return SimpleCompressor::compress(data, size);
}

std::vector<uint8_t> Packer::generateUnpackerStub(bool is64, uint32_t data_rva, uint32_t data_size) {
    std::vector<uint8_t> stub;
    // Full stub generation would be implemented here
    return stub;
}

PackResult Packer::pack(const std::wstring& input_path, const std::wstring& output_path) {
    PackResult result;
    result_ = &result;
    wide_input_path_ = input_path;
    wide_output_path_ = output_path;

    progress(0, "Loading input file...");
    PELib pe;
    if (!pe.load(input_path)) {
        result.error_message = "Failed to load PE: " + pe.lastError();
        return result;
    }

    result.original_size = pe.size();
    original_ep_ = pe.entryPoint();
    config_.is_64bit = pe.is64();

    progress(10, "Analyzing PE structure...");
    if (!phase_analyze(pe)) {
        result.error_message = "Analysis failed";
        return result;
    }

    auto seed = buildSeed();
    std::mt19937_64 rng(seed);
    encryption_key_.resize(32);
    for (auto& k : encryption_key_) k = rng() & 0xFF;

    progress(30, "Encrypting sections...");
    std::vector<uint8_t> packed_data;
    if (config_.pack_sections && !phase_encryptSections(pe, packed_data)) {
        result.error_message = "Section packing failed";
        return result;
    }

    progress(50, "Building protection metadata...");
    buildMetadataBlob(pe, meta_blob_);

    if (config_.strip_debug_info) {
        stripDebugInfo(pe, result);
    }
    if (result.debug_entries_stripped) progress(55, "Stripped debug directory entries");
    if (config_.import_protection) {
        stripImportDirectory(pe);
        if (config_.decoy_imports) {
            if (writeDecoyImports(pe)) progress(59, "Decoy import table installed");
        }
        progress(58, "Import directory stripped (resolved at runtime)");
    }
    if (config_.strip_relocations) {
        stripRelocations(pe);
        progress(58, "Relocation directory stripped (ASLR disabled)");
    }
    if (config_.strip_export) {
        stripExports(pe);
        progress(58, "Export directory stripped");
    }
    progress(59, "Building protection runtime...");
    if (!phase_buildProtection(pe, packed_data)) {
        result.error_message = "Protection runtime build failed";
        return result;
    }
    progress(60, "Building protected image...");
    if (!phase_buildOutput(pe, packed_data)) {
        result.error_message = "Output build failed";
        return result;
    }
    // Static evasion, second call site. The engine has two packing pipelines
    // (the region/VM path and this one); the CLI drives this one, so leaving the
    // pass only in the other meant "evasion: aggressive" produced an image with
    // an untouched Rich header, original section names and a stale checksum.
    if (config_.evasion.enabled() && !result.skipped_no_packable_code) {
        progress(92, "Applying static evasion...");
        StaticEvader evader(config_.evasion);
        StaticEvasionReport evasion_report;
        if (evader.apply(pe, evasion_report)) {
            result.evasion_changes = static_cast<uint32_t>(evasion_report.changes.size());
            result.evasion_build_tag = evader.buildSignature().build_tag;
            result.evasion_seed = evader.buildSignature().seed;
            progress(93, evasion_report.summary());
            progress(93, "signature build " + result.evasion_build_tag);
        } else {
            progress(93, "Static evasion skipped (image not mutable in place)");
        }
    }
    // Nothing could be packed: the output already holds an untouched copy of
    // the input, so saving the modified image again would break it.
    if (!result.skipped_no_packable_code) {
        progress(95, "Writing output...");
        if (!pe.save(output_path)) {
            result.error_message = "Failed to save output: " + pe.lastError();
            return result;
        }
        result.packed_size = pe.size();
    }
    result.success = true;
    result.output_path.clear();
    progress(100, "Done!");
    return result;
}
} // namespace np



