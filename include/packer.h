#pragma once
// NovaProtect Packer Core - Orchestrates all protection modules
#include "pe_types.h"
#include "pe_lib.h"
#include "vm_isa.h"
#include "vm_revirt.h"
#include "mutation.h"
#include "anti_debug.h"
#include <memory>
#include <functional>
#include <random>
#include <cstdint>

namespace np {

// Packer result
struct PackResult {
    bool success = false;
    std::string output_path;
    std::string error_message;
    // Statistics
    size_t original_size = 0;
    size_t packed_size = 0;
    uint32_t functions_protected = 0;
    uint32_t mutation_applied = 0;
    uint32_t vm_instructions = 0;
    uint32_t stub_size = 0;
    double compression_ratio = 0.0;
    // New protection statistics
    uint32_t imports_protected = 0;
    uint32_t resources_protected = 0;
    uint32_t virtual_files_embedded = 0;
    uint32_t debug_entries_stripped = 0;
    // Set when the target had no code the packer could take (for example every
    // executable section is smaller than the loader header reserve).  The
    // output is then a working copy of the input instead of a protected image.
    bool skipped_no_packable_code = false;
    // Deepest revirtualization nesting level the engine actually established
    // (0 when the transform was off or could not be applied to any region).
    // Reported so the CLI/UI can tell "requested 3, built 2" apart from
    // "requested 3, built 3" instead of echoing the request back.
    uint32_t revirtualization_level = 0;
    // Number of static-evasion edits actually written into the output image
    // (Rich header, timestamp, section names, PDB, padding, checksum).
    uint32_t evasion_changes = 0;
    // Per-build signature tag; two builds with different tags share no derived
    // byte pattern. Empty when evasion was off.
    std::string evasion_build_tag;
    // Seed that produced the tag: handing it back reproduces the build.
    uint64_t evasion_seed = 0;
};

// Packer class
class Packer {
public:
    Packer() = default;

    // Configure the packer
    void setConfig(const PackerConfig& config) { config_ = config; }
    PackerConfig& config() { return config_; }

    // Pack a PE file
    PackResult pack(const std::string& input_path, const std::string& output_path);
    PackResult pack(const std::wstring& input_path, const std::wstring& output_path);

    // Progress callback (for UI integration)
    void setProgressCallback(std::function<void(int percent, const std::string& msg)> cb) {
        progress_ = cb;
    }

    // Read the watermark back out of a protected image (CLI -showwatermark)
    static bool readWatermark(const std::string& packed_path, std::string& out, std::string& err);
    // List embedded virtual files (CLI -listvf)
    static bool listVirtualFiles(const std::string& packed_path, std::vector<std::string>& names, std::string& err);
    // Extract one embedded virtual file (CLI -extractvf name)
    static bool extractVirtualFile(const std::string& packed_path, const std::string& name,
                                   std::vector<uint8_t>& out, std::string& err);

private:
    // One number drives every random choice in a build: with it pinned the
    // whole artefact reproduces, without it each build is distinct. Priority is
    // the caller's pinned signature seed, then plain system entropy.
    uint64_t buildSeed() const;
    // Individual packing phases
    bool phase_analyze(PELib& pe);
    bool phase_encryptSections(PELib& pe, std::vector<uint8_t>& packed_data);
    bool phase_generateStub(PELib& pe, std::vector<uint8_t>& stub_data, uint32_t data_rva);
    bool phase_buildOutput(PELib& pe, std::vector<uint8_t>& packed_data);
    bool phase_buildProtection(PELib& pe, std::vector<uint8_t>& packed_data);

    // New protection phases
    void buildMetadataBlob(PELib& pe, std::vector<uint8_t>& blob);
    bool buildImportBlob(PELib& pe, std::vector<uint8_t>& blob, uint32_t& key);
    void stripImportDirectory(PELib& pe);
    // Writes a small set of real, loader-resolved imports after the real table
    // has been stripped. An image with zero imports is a named static detection
    // ("empty_import", impfuzzy "3::"), so the output keeps a plausible table
    // that nothing in the stub depends on.
    bool writeDecoyImports(PELib& pe);
    void stripDebugInfo(PELib& pe, PackResult& result);
    void stripRelocations(PELib& pe);
    void stripExports(PELib& pe);

    // Encrypt/compress section data
    std::vector<uint8_t> encryptData(const uint8_t* data, size_t size, const uint8_t* key, size_t key_size);
    std::vector<uint8_t> compressData(const uint8_t* data, size_t size);

    // Generate unpacker stub code
    std::vector<uint8_t> generateUnpackerStub(bool is64, uint32_t data_rva, uint32_t data_size);

    // One VM region descriptor emitted into the NPP1 payload (runtime
    // np_vm_install reads the table at offset 20 / count at 88).
    // Layout: rva, size, bc_off, bc_len, rev_off, reg_mask, reserved.
    // The bytecode key is NOT here: it is emitted directly behind the reverse
    // table so the generated trampoline keeps its four-argument ABI.
    //
    // With revirtualization on, `reserved` is split: the low 16 bits hold the
    // region's outer stage count and the high 16 bits the index of the region's
    // first guest block in the global guest table. Both stay 0 for a legacy
    // single-stage region, which is what keeps the format backward compatible.
    struct VmRegion {
        uint32_t rva, size, bc_off, bc_len, rev_off, reg_mask, reserved;

        uint16_t stageCount() const { return (uint16_t)(reserved & 0xFFFFu); }
        uint16_t guestBase() const { return (uint16_t)(reserved >> 16); }
        void setRevirt(uint32_t stages, uint32_t guest_base) {
            reserved = (stages & 0xFFFFu) | ((guest_base & 0xFFFFu) << 16);
        }
    };

    // Lower one code range [start, end) to VM bytecode. Shared by the SDK
    // marker path and the scanned-function path (-func). Returns false when
    // the range cannot be virtualized (undecodable, uses RSP/RBP, too small
    // for the trampoline, or the region table is full); the reason is
    // reported through the progress channel. `selected` may be null, in
    // which case the global defaults apply.
    bool vmLowerRegion(PELib& pe, std::vector<uint8_t>& data, std::vector<VmRegion>& vm_regions,
                       std::mt19937_64& rng, uint32_t start, uint32_t end,
                       const FunctionProtect* selected, const char* origin,
                       uint32_t& revirt_levels_applied);

    void progress(int pct, const std::string& msg) {
        if (progress_) progress_(pct, msg);
    }

    // Skip reasons are counted instead of printed one per region. A function
    // selection of a few thousand entries used to emit one log line per
    // rejected region, which flooded the UI and made the window freeze while
    // the engine itself finished in about a second.
    void vmSkip(const std::string& reason) {
        for (auto& entry : vm_skip_counts_)
            if (entry.first == reason) { entry.second++; return; }
        vm_skip_counts_.emplace_back(reason, 1u);
    }

    PackerConfig config_;
    std::function<void(int, const std::string&)> progress_;
    std::vector<std::pair<std::string, uint32_t>> vm_skip_counts_;

    // Internal state
    uint32_t stub_section_idx_ = 0;
    uint32_t data_section_idx_ = 0;
    uint32_t original_ep_ = 0;
    uint32_t new_ep_ = 0;
    std::vector<uint8_t> encryption_key_;
    size_t tls_array_offset_ = SIZE_MAX;
    uint32_t tls_new_rva_ = 0;

    // Metadata / import protection offsets inside the payload
    size_t meta_offset_ = 0;
    size_t meta_size_ = 0;
    size_t import_offset_ = 0;
    size_t import_size_ = 0;
    uint32_t import_key_ = 0;
    std::vector<uint8_t> import_blob_;
    std::vector<uint8_t> meta_blob_;
    uint32_t meta_rva_ = 0;

    // Protection runtime (.np_prot) section RVAs published through the payload
    // header at offsets 100/104/108/112.
    uint32_t prot_code_rva_ = 0;
    uint32_t prot_bss_rva_ = 0;
    uint32_t prot_data_rva_ = 0;
    uint32_t prot_kernel_rva_ = 0;
    uint32_t prot_code_size_ = 0;

    PackResult* result_ = nullptr;   // current run statistics sink
    // Path of the image currently being packed, kept so a build that has
    // nothing to pack can fall back to writing an untouched copy.
    std::string narrow_input_path_;
    std::string narrow_output_path_;
    std::wstring wide_input_path_;
    std::wstring wide_output_path_;
};

// NovaProtect SDK header. Marker bytes stay backward compatible with NovaPack 1.x.
constexpr const char* NOVAPROTECT_SDK_VERSION = "2.6.0";
constexpr const char* NOVAPACK_SDK_VERSION = NOVAPROTECT_SDK_VERSION;

#if defined(_MSC_VER) && !defined(__clang__)
#define NOVAPACK_INLINE __forceinline
#elif defined(__GNUC__)
#define NOVAPACK_INLINE __attribute__((always_inline))
#else
#define NOVAPACK_INLINE inline
#endif

// NovaProtect SDK marker names. The legacy NOVAPACK_* names remain
// source-compatible because the on-disk byte pattern is intentionally stable.
#define NOVAPROTECT_BEGIN(name) NOVAPACK_BEGIN(name)
#define NOVAPROTECT_END() NOVAPACK_END()

#if defined(_WIN64)
#define NOVAPACK_BEGIN(name) \
    __asm__ volatile(".byte 0x48,0x8D,0x0D,0x00,0x00,0x00,0x00"); \
    __asm__ volatile("nop; nop; nop; nop; nop; nop; nop; nop; nop; nop"); \
    __asm__ volatile("nop; nop; nop; nop; nop; nop; nop; nop; nop; nop")

#define NOVAPACK_END() \
    __asm__ volatile("nop; nop; nop; nop; nop; nop; nop; nop; nop; nop"); \
    __asm__ volatile("nop; nop; nop; nop; nop; nop; nop; nop; nop; nop")
#elif defined(_WIN32)
#define NOVAPACK_BEGIN(name) \
    __asm__ volatile(".byte 0x8D,0x0D,0x00,0x00,0x00,0x00"); \
    __asm__ volatile("nop; nop; nop; nop; nop; nop; nop; nop; nop; nop"); \
    __asm__ volatile("nop; nop; nop; nop; nop; nop; nop; nop; nop; nop")

#define NOVAPACK_END() \
    __asm__ volatile("nop; nop; nop; nop; nop; nop; nop; nop; nop; nop"); \
    __asm__ volatile("nop; nop; nop; nop; nop; nop; nop; nop; nop; nop")
#else
#error "Unsupported target architecture"
#endif

} // namespace np

