#pragma once
// NovaProtect PE Types - Windows PE format structures
// Minimal definitions, no dependency on winnt.h for portability

#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>
#include <optional>

#include "evasion.h"

namespace np {

#pragma pack(push, 1)

struct DOSHeader {
    uint16_t e_magic;       // 'MZ'
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    int32_t  e_lfanew;      // offset to PE header
};

struct PEHeader {
    uint32_t Signature;          // 'PE\0\0'
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
};

struct DataDirectory {
    uint32_t VirtualAddress;
    uint32_t Size;
};

struct OptionalHeader64 {
    uint16_t Magic;              // 0x20B for PE32+
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSize;
    DataDirectory DataDirectory[16];
};

struct OptionalHeader32 {
    uint16_t Magic;              // 0x10B for PE32
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint32_t BaseOfData;
    uint32_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint32_t SizeOfStackReserve;
    uint32_t SizeOfStackCommit;
    uint32_t SizeOfHeapReserve;
    uint32_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSize;
    DataDirectory DataDirectory[16];
};

struct SectionHeader {
    char     Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
};

struct ImportDescriptor {
    uint32_t OriginalFirstThunk;  // RVA to IAT (INT)
    uint32_t TimeDateStamp;
    uint32_t ForwarderChain;
    uint32_t Name;               // RVA to DLL name string
    uint32_t FirstThunk;         // RVA to IAT
};

struct ExportDirectory {
    uint32_t Characteristics;
    uint32_t TimeDateStamp;
    uint16_t MajorVersion;
    uint16_t MinorVersion;
    uint32_t Name;
    uint32_t Base;
    uint32_t NumberOfFunctions;
    uint32_t NumberOfNames;
    uint32_t AddressOfFunctions;
    uint32_t AddressOfNames;
    uint32_t AddressOfNameOrdinals;
};

#pragma pack(pop)

// Constants
constexpr uint16_t DOS_MAGIC       = 0x5A4D; // 'MZ'
constexpr uint32_t PE_MAGIC        = 0x00004550; // 'PE\0\0'
constexpr uint16_t OPT_MAGIC_32    = 0x10B;
constexpr uint16_t OPT_MAGIC_64    = 0x20B;
constexpr uint16_t MACHINE_X86     = 0x014C;
constexpr uint16_t MACHINE_X64     = 0x8664;
constexpr uint16_t MACHINE_ARM64   = 0xAA64;

constexpr uint32_t SEC_CODE            = 0x00000020;
constexpr uint32_t SEC_INITIALIZED_DATA= 0x00000040;
constexpr uint32_t SEC_UNINITIALIZED   = 0x00000080;
constexpr uint32_t SEC_MEM_DISCARDABLE = 0x02000000;
constexpr uint32_t SEC_MEM_EXECUTE     = 0x20000000;
constexpr uint32_t SEC_MEM_READ        = 0x40000000;
constexpr uint32_t SEC_MEM_WRITE       = 0x80000000;

constexpr int DIR_ENTRY_EXPORT     = 0;
constexpr int DIR_ENTRY_IMPORT     = 1;
constexpr int DIR_ENTRY_RESOURCE   = 2;
constexpr int DIR_ENTRY_EXCEPTION  = 3;
constexpr int DIR_ENTRY_SECURITY   = 4;
constexpr int DIR_ENTRY_BASERELOC  = 5;
constexpr int DIR_ENTRY_DEBUG      = 6;
constexpr int DIR_ENTRY_TLS        = 9;
constexpr int DIR_ENTRY_IAT        = 12;

constexpr uint32_t RELOC_BASE = 0x00010000; // IMAGE_REL_BASED

// Section flags string for debugging
inline std::string section_flags_str(uint32_t flags) {
    std::string s;
    if (flags & SEC_CODE) s += "C";
    if (flags & SEC_MEM_EXECUTE) s += "X";
    if (flags & SEC_MEM_READ) s += "R";
    if (flags & SEC_MEM_WRITE) s += "W";
    return s;
}

// Protection level for functions
enum class ProtectLevel : uint8_t {
    None        = 0,
    Mutation    = 1,
    Virtualization = 2,
    Ultra       = 3  // Virtualization + Mutation
};

// Origin of a function protection descriptor.
enum class FunctionSource : uint8_t {
    SdkMarker = 0,   // NOVAPROTECT_BEGIN/END pair detected in the target
    ScanFunction = 1 // function selected in the client's function scanner
};

// Function protection descriptor (from SDK markers or the function scanner)
struct FunctionProtect {
    uint32_t rva_start = 0;       // first byte after begin marker
    uint32_t rva_end = 0;         // end marker address (exclusive)
    ProtectLevel level = ProtectLevel::None;
    std::string name;         // optional debug name
    // VM parameters
    uint8_t vm_complexity = 5;    // 1-10, affects dispatch complexity
    uint8_t vm_mutation = 1;      // 0-3, mutation strength
    bool vm_lock_to_key = false;  // activation-bound region
    FunctionSource source = FunctionSource::SdkMarker;
};

// Packer configuration
struct PackerConfig {
    // VM settings
    bool enable_vm            = true;
    uint8_t vm_default_complexity = 5;
    uint8_t vm_default_mutation   = 1;
    std::vector<FunctionProtect> function_regions;

    // Themida-style second-level virtualization. When on, each virtualized
    // region is split into stages with independent opcode permutations and
    // keystream keys, and its straight-line arithmetic runs are lifted into
    // second-level ("guest") blocks executed by a separate dispatcher with a
    // permuted register file. Purely additive: a region that cannot be split
    // stays in its original single-stage form.
    bool enable_revirtualization = true;
    // Number of nested levels the packer should aim for. Level 1 is what the
    // runtime currently implements (outer stage stream + one guest layer);
    // higher values are accepted and reported so a UI can express intent
    // without the engine silently pretending to honour it.
    uint8_t revirtualization_level = 1;
    
    // Mutation settings
    bool enable_mutation      = true;
    uint8_t mutation_strength = 1;  // 0=off, 1=light, 2=medium, 3=heavy
    
    // Anti-debug
    bool enable_anti_debug    = true;
    uint8_t anti_debug_level  = 2;  // 0=off, 1=basic, 2=advanced, 3=paranoid
    
    // Packing
    bool enable_pack          = true;
    bool pack_sections        = true;
    bool encrypt_sections     = true;
    bool strip_relocations    = false;
    bool strip_debug_info     = true;
    bool strip_export         = false;
    bool virtualize_imports   = false;
    
    // Licensing
    bool enable_licensing     = false;
    
    // Protection options
    bool memory_protection    = false;
    bool enable_protection_runtime = true;  // deploy the x64 protection runtime blob
    bool import_protection    = false;
    // After the real import table is stripped, install a small table of real
    // loader-resolved exports. Zero imports is itself a static detection
    // ("empty_import" tag, degenerate impfuzzy), so the default is on.
    bool decoy_imports        = true;
    bool resource_protection  = false;
    uint8_t anti_vm_level     = 0;
    bool enable_sandbox_guard = false;   // NPP1 bit9: cumulative sandbox scoring
    uint32_t sandbox_score_threshold = 40; // default tuned for online-analysis hosts
    bool enable_anti_dump     = false;   // NPP1 bit10: live-memory dump self-check
    bool enable_env_check     = false;   // NPP1 bit11: interactive desktop minimums
    uint32_t env_score_threshold = 7;    // NPP1 +124: headless env score block point
    bool enable_self_isolation = false;  // NPP1 bit12: process self-isolation / anti-read
    bool enable_audit_recheck = false;   // NPP1 bit14: delayed re-audit worker
    // Tracks whether the user said anything about the re-audit worker. When
    // they did not, enabling the sandbox guard arms it automatically: a guard
    // that only samples at startup is blind to a monitor that attaches later,
    // so the two halves are useless apart and must not be left to the caller.
    // Explicit -audit-recheck=0 still wins, so the old behaviour stays reachable.
    bool audit_recheck_explicit = false;
    uint32_t min_cpu_count    = 2;
    uint32_t min_ram_mb       = 4096;
    uint32_t min_uptime_ms    = 3000;
    uint32_t min_screen_width = 1024;
    uint32_t min_screen_height = 768;
    uint32_t min_monitor_count = 1;

    // Evasion subsystem (static image scrubbing, junk code, dynamic gates,
    // encrypted region loader, API unhooking, signed-host launch plans).
    // Profile Off means "touch nothing"; every sub-switch stays individually
    // settable so the UI can express "paranoid, except keep the timestamp".
    EvasionConfig evasion;

    // Additional features
    bool enable_watermark     = false;    std::string watermark;
    bool enable_script        = false;
    std::string script_path;
    std::string license_key;
    bool enable_activation    = false;
    std::string activation_key;
    bool enable_virtual_files = false;
    std::vector<std::string> virtual_files;

    // Misc

    // Target
    bool is_64bit             = true;
};

} // namespace np




