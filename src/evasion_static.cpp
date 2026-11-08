// NovaProtect static image evasion - implementation.
#include "evasion_static.h"
#include "junk_emitter.h"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <sstream>
#include <unordered_set>

namespace np {
namespace {

constexpr uint8_t kRichMagic[4] = {'R', 'i', 'c', 'h'};

uint64_t splitmix64(uint64_t& state) {
    uint64_t z = (state += 0x9E3779B97F4A7C15ull);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    return z ^ (z >> 31);
}

// Standard PE checksum over an arbitrary buffer (the loader's algorithm).
uint32_t checksumOf(const std::vector<uint8_t>& image, size_t checksum_field) {
    uint64_t sum = 0;
    const size_t words = image.size() / 2;
    size_t skip_begin = checksum_field;
    size_t skip_end = checksum_field + 4;
    for (size_t i = 0; i < words; i++) {
        const size_t off = i * 2;
        if (off + 2 > skip_begin && off < skip_end) continue;
        uint16_t w = static_cast<uint16_t>(image[off] | (image[off + 1] << 8));
        sum += w;
        sum = (sum & 0xFFFFu) + (sum >> 16);
    }
    if (image.size() & 1) sum += image.back();
    sum = (sum & 0xFFFFu) + (sum >> 16);
    return static_cast<uint32_t>(sum + image.size());
}

// Names a linker would plausibly emit for the given characteristics, ordered
// so that the candidate list is exhausted before repeating a name.
const char* plausibleName(uint32_t characteristics, size_t choice) {
    static const char* const kCode[] = {".text", "CODE", ".text$mn"};
    static const char* const kRdata[] = {".rdata", ".rodata", "CONST"};
    static const char* const kData[] = {".data", "DATA", ".data$d"};
    static const char* const kBss[] = {".bss", "BSS", ".data$z"};
    const bool exec = (characteristics & (SEC_MEM_EXECUTE | SEC_CODE)) != 0;
    const bool write = (characteristics & SEC_MEM_WRITE) != 0;
    const bool init = (characteristics & SEC_INITIALIZED_DATA) != 0;
    if (exec) return kCode[choice % 3];
    if (write && !init) return kBss[choice % 3];
    if (write) return kData[choice % 3];
    return kRdata[choice % 3];
}

void setSectionName(SectionHeader& section, const char* name) {
    std::memset(section.Name, 0, sizeof(section.Name));
    const size_t len = std::min<size_t>(std::strlen(name), sizeof(section.Name));
    std::memcpy(section.Name, name, len);
}

} // namespace

std::string StaticEvasionReport::summary() const {
    std::ostringstream os;
    os << "static evasion:";
    if (rich_scrubbed) os << " rich(-" << rich_bytes_cleared << "B)";
    if (timestamp_randomized) os << " ts(" << new_timestamp << ")";
    if (sections_renamed) os << " names(" << sections_renamed << ")";
    if (pdb_entries_stripped) os << " pdb(" << pdb_entries_stripped << ")";
    if (padding_bytes_filled) os << " pad(" << padding_bytes_filled << "B)";
    if (signature_dropped) os << " sig(-)";
    if (checksum_updated) os << " sum(" << new_checksum << ")";
    if (changes.empty()) os << " noop";
    return os.str();
}

StaticEvader::StaticEvader(const EvasionConfig& cfg, uint64_t seed)
    : cfg_(cfg),
      seed_(seed ? seed : (cfg.seed ? cfg.seed : systemEntropy())) {
    // The signature is planned from the effective seed. A caller that already
    // planned one on the config keeps it, so the manifest stays stable across
    // the packer, the audit and the CLI.
    if (cfg_.build.seed == seed_ && !cfg_.build.build_tag.empty()) {
        signature_ = cfg_.build;
    } else {
        signature_ = SignatureRandomizer(seed_).signature();
    }
}

const BuildSignature& StaticEvader::buildSignature() const { return signature_; }

double StaticEvader::shannonEntropy(const uint8_t* data, size_t len) {
    if (!data || len == 0) return 0.0;
    uint64_t counts[256] = {0};
    for (size_t i = 0; i < len; i++) counts[data[i]]++;
    double entropy = 0.0;
    const double total = static_cast<double>(len);
    for (uint64_t c : counts) {
        if (!c) continue;
        const double p = static_cast<double>(c) / total;
        entropy -= p * std::log2(p);
    }
    return entropy;
}

StaticAudit StaticEvader::audit(PELib& pe) {
    StaticAudit audit;
    for (size_t i = 0; i < pe.sectionCount(); i++) {
        const auto& section = pe.section(i);
        StaticAudit::SectionEntropy info;
        char name[9] = {};
        std::memcpy(name, section.Name, 8);
        info.name = name;
        info.raw_size = section.SizeOfRawData;
        info.virtual_size = section.VirtualSize;
        const auto& bytes = pe.sectionData(i);
        info.entropy = shannonEntropy(bytes.data(), bytes.size());
        audit.sections.push_back(info);

        if (section.SizeOfRawData > section.VirtualSize) {
            const size_t slack = std::min<size_t>(section.SizeOfRawData - section.VirtualSize,
                                                 bytes.size() > section.VirtualSize
                                                     ? bytes.size() - section.VirtualSize : 0);
            for (size_t j = 0; j < slack; j++) {
                if (bytes[section.VirtualSize + j] == 0) audit.zero_padding_bytes++;
                else break;
            }
        }
    }

    // Import names that are, by themselves, enough to put a sample on a
    // triage queue. Reported so the caller can decide, not rewritten.
    static const char* const kFlagged[] = {
        "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "SetWindowsHookEx",
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "GetTickCount", "QueryPerformanceCounter",
        "LoadLibraryA", "LoadLibraryW", "GetProcAddress", "VirtualProtect", "VirtualProtectEx",
        "NtQueryInformationProcess", "CreateToolhelp32Snapshot", "OpenProcess",
        "AdjustTokenPrivileges", "WinExec", "ShellExecuteA", "ShellExecuteW", "URLDownloadToFileA",
        "NtUnmapViewOfSection", "QueueUserAPC", "SetThreadContext", "GetThreadContext",
    };
    std::unordered_set<std::string> seen;
    for (const auto& imp : pe.getImports()) {
        for (const auto& fn : imp.functions) {
            for (const char* flag : kFlagged) {
                if (fn != flag) continue;
                if (seen.insert(fn).second) audit.flagged_imports.push_back(fn);
            }
        }
    }

    if (const auto* sec = pe.dataDirectory(DIR_ENTRY_SECURITY))
        audit.has_signature = sec->VirtualAddress != 0 && sec->Size != 0;

    // CodeView path (a PDB file name leaks the build machine and the source
    // layout: the single most informative string in a leaked binary).
    if (const auto* dbg = pe.dataDirectory(DIR_ENTRY_DEBUG)) {
        if (dbg->VirtualAddress && dbg->Size) {
            const uint8_t* entries = pe.rvaToPtr(dbg->VirtualAddress);
            const uint32_t count = dbg->Size / 28;
            for (uint32_t i = 0; entries && i < count; i++) {
                const uint32_t type = *reinterpret_cast<const uint32_t*>(entries + i * 28 + 12);
                if (type == 2) { audit.has_pdb_path = true; break; }
            }
        }
    }

    const int e_lfanew = pe.dosHeader()->e_lfanew;
    for (int off = 0x40; off + 4 <= e_lfanew; off++) {
        if (std::memcmp(pe.data().data() + off, kRichMagic, 4) == 0) {
            audit.has_rich_header = true;
            audit.dos_stub_size = static_cast<uint32_t>(off - 0x40);
            break;
        }
    }
    return audit;
}

bool StaticEvader::scrubRichHeader(PELib& pe, StaticEvasionReport& report) {
    auto& image = pe.data();
    const int e_lfanew = pe.dosHeader()->e_lfanew;
    if (e_lfanew <= 0x40 || static_cast<size_t>(e_lfanew) >= image.size()) return false;

    int rich_off = -1;
    for (int off = 0x40; off + 4 <= e_lfanew; off++) {
        if (std::memcmp(image.data() + off, kRichMagic, 4) == 0) rich_off = off;
    }
    // The block is "Rich" followed by a 4-byte XOR key, so the erase has to run
    // eight bytes past the marker. Stopping at the marker left the literal
    // "Rich" in place and every scanner still saw the header.
    int erase_end = e_lfanew;
    if (rich_off > 0x40) erase_end = std::min(rich_off + 8, e_lfanew);
    if (erase_end <= 0x40) return false;

    // Scratch the Rich block and the "This program cannot be run in DOS mode"
    // stub, then stamp this build's 16-byte nonce there. Zeroing alone leaves
    // the same 64 zero bytes in every image the product has ever shipped,
    // which is itself a signature; a per-build nonce makes that region differ
    // on every build while staying inert (never mapped, never executed).
    std::fill(image.begin() + 0x40, image.begin() + erase_end, 0);
    const size_t nonce_bytes = static_cast<size_t>(erase_end - 0x40);
    const uint8_t* nonce = reinterpret_cast<const uint8_t*>(signature_.nonce);
    for (size_t i = 0; i < nonce_bytes; i++)
        image[0x40 + i] = nonce[i % 16] ^ static_cast<uint8_t>((i * 0x9D) & 0xFF);

    report.rich_scrubbed = true;
    report.rich_bytes_cleared = static_cast<uint32_t>(erase_end - 0x40);
    report.changes.push_back("rich header and DOS stub replaced by build nonce (" +
                             std::to_string(report.rich_bytes_cleared) + " bytes, tag " +
                             signature_.build_tag + ")");
    return true;
}

bool StaticEvader::randomizeTimestamp(PELib& pe, StaticEvasionReport& report) {
    pe.peHeader()->TimeDateStamp = 0;   // placeholder so a failed step is visible
    // The timestamp comes from the signature plan, so it moves with the build
    // instead of being re-drawn here (one plan, one manifest, one rebuild).
    const uint32_t stamp = signature_.timestamp;
    pe.peHeader()->TimeDateStamp = stamp;
    report.timestamp_randomized = true;
    report.new_timestamp = stamp;
    report.changes.push_back("TimeDateStamp -> " + std::to_string(stamp));
    return true;
}

bool StaticEvader::renameSections(PELib& pe, StaticEvasionReport& report) {
    uint32_t renamed = 0;
    std::unordered_set<std::string> used;
    Rng rng(mix64(seed_ ^ 0x534543544E414D45ull));
    for (size_t i = 0; i < pe.sectionCount(); i++) {
        auto& section = pe.section(i);
        char current[9] = {};
        std::memcpy(current, section.Name, 8);
        // Sections the packer deployed are part of the loader contract; the
        // runtime locates them by RVA, but leaving their names alone keeps the
        // output recognisable in a debugger and avoids churn between builds.
        if (current[0] == '.' && current[1] == 'n' && current[2] == 'p') continue;
        if (std::strcmp(current, ".text") == 0 || std::strcmp(current, ".rdata") == 0 ||
            std::strcmp(current, ".data") == 0) {
            continue;  // already plausible
        }
        // A real MSVC name carries a "$" group suffix (.text$mn, .data$d).
        // Randomising that suffix gives every build its own name without
        // producing anything a linker would not emit.
        std::string name;
        for (size_t attempt = 0; attempt < 12; attempt++) {
            const char* base = plausibleName(section.Characteristics,
                                             rng.below(3) + attempt);
            std::string candidate = base;
            if (candidate.size() < 6) {
                candidate += "$";
                candidate += signature_.section_suffix.substr(0, 1);
                candidate += static_cast<char>('a' + rng.below(26));
            }
            if (candidate.size() > 8) candidate.resize(8);
            if (used.insert(candidate).second) { name = candidate; break; }
        }
        if (name.empty()) continue;
        setSectionName(section, name.c_str());
        renamed++;
        report.changes.push_back(std::string("section ") + current + " -> " + name);
    }
    report.sections_renamed = renamed;
    return renamed > 0;
}

bool StaticEvader::stripPdbEntries(PELib& pe, StaticEvasionReport& report) {
    auto* dbg = pe.dataDirectory(DIR_ENTRY_DEBUG);
    if (!dbg || !dbg->VirtualAddress || !dbg->Size) return false;
    auto& image = pe.data();
    const uint8_t* entries = pe.rvaToPtr(dbg->VirtualAddress);
    if (!entries) return false;
    const uint32_t count = dbg->Size / 28;
    uint32_t stripped = 0;
    for (uint32_t i = 0; i < count; i++) {
        const size_t entry_off = static_cast<size_t>(entries - image.data()) + i * 28;
        if (entry_off + 28 > image.size()) break;
        const uint32_t type = *reinterpret_cast<const uint32_t*>(image.data() + entry_off + 12);
        if (type != 2) continue;  // IMAGE_DEBUG_TYPE_CODEVIEW
        const uint32_t size = *reinterpret_cast<const uint32_t*>(image.data() + entry_off + 16);
        const uint32_t ptr = *reinterpret_cast<const uint32_t*>(image.data() + entry_off + 24);
        if (ptr && size && static_cast<size_t>(ptr) + size <= image.size())
            std::fill(image.begin() + ptr, image.begin() + ptr + size, 0);
        std::fill(image.begin() + entry_off, image.begin() + entry_off + 28, 0);
        stripped++;
    }
    if (stripped) {
        dbg->VirtualAddress = 0;
        dbg->Size = 0;
        report.pdb_entries_stripped = stripped;
        report.changes.push_back("CodeView/PDB entries stripped: " + std::to_string(stripped));
    }
    return stripped > 0;
}

bool StaticEvader::fillSectionPadding(PELib& pe, StaticEvasionReport& report) {
    JunkEmitter junk(mix64(seed_ ^ 0x50414444494E47ull));
    uint32_t filled = 0;
    for (size_t i = 0; i < pe.sectionCount(); i++) {
        auto& section = pe.section(i);
        auto& bytes = pe.sectionData(i);
        if (section.SizeOfRawData <= section.VirtualSize) continue;
        const size_t begin = std::min<size_t>(section.VirtualSize, bytes.size());
        const size_t end = std::min<size_t>(section.SizeOfRawData, bytes.size());
        if (end <= begin) continue;
        // Zero slack is a stable, well-known fingerprint: packers and stubs
        // leave zeros, real linkers leave their own filler. Whole junk blocks
        // come first, then this build's filler byte for the remainder.
        std::vector<uint8_t> filler = junk.pad(end - begin);
        const uint8_t tail = signature_.filler_byte;
        for (size_t j = 0; j < filler.size(); j++)
            if (filler[j] == 0x90) filler[j] = tail;
        std::memcpy(bytes.data() + begin, filler.data(), filler.size());
        filled += static_cast<uint32_t>(end - begin);
    }
    report.padding_bytes_filled = filled;
    if (filled) report.changes.push_back("section padding filled: " + std::to_string(filled) + " bytes");
    return filled > 0;
}

bool StaticEvader::dropSignature(PELib& pe, StaticEvasionReport& report) {
    auto* sec = pe.dataDirectory(DIR_ENTRY_SECURITY);
    if (!sec || !sec->VirtualAddress || !sec->Size) return false;
    // Any byte we rewrote invalidates the Authenticode digest, and a present
    // but broken signature is a stronger signal than no signature at all.
    sec->VirtualAddress = 0;
    sec->Size = 0;
    report.signature_dropped = true;
    report.changes.push_back("Authenticode directory cleared (digest no longer valid)");
    return true;
}

bool StaticEvader::updateChecksum(PELib& pe, StaticEvasionReport& report) {
    // Build the prospective image exactly as PELib::save() will write it:
    // headers plus the overlay of every section buffer, truncated or padded to
    // the end of the last section. Anything else (an Authenticode overlay, a
    // stale section body) makes the stored checksum disagree with the file, and
    // the OS is the one that notices.
    uint32_t max_offset = 0;
    for (size_t i = 0; i < pe.sectionCount(); i++) {
        const auto& section = pe.section(i);
        const uint64_t end = static_cast<uint64_t>(section.PointerToRawData) + section.SizeOfRawData;
        if (end > max_offset) max_offset = static_cast<uint32_t>(end);
    }
    std::vector<uint8_t> image = pe.data();
    if (max_offset > image.size()) image.resize(max_offset, 0);
    for (size_t i = 0; i < pe.sectionCount(); i++) {
        const auto& section = pe.section(i);
        const auto& bytes = pe.sectionData(i);
        if (bytes.empty()) continue;
        const size_t limit = std::min<size_t>(bytes.size(), section.SizeOfRawData);
        if (static_cast<size_t>(section.PointerToRawData) + limit > image.size()) continue;
        std::memcpy(image.data() + section.PointerToRawData, bytes.data(), limit);
    }
    // save() drops everything past the last section, so the digest has to stop
    // there too.
    if (image.size() > max_offset) image.resize(max_offset);

    // Header offsets are computed arithmetically. Pointer arithmetic across two
    // different buffers (pe_hdr lives in data_, image is a copy) is undefined
    // behaviour and the optimiser is allowed to fold it into nonsense.
    const size_t pe_off = static_cast<size_t>(pe.dosHeader()->e_lfanew);
    const size_t checksum_field = pe_off + sizeof(PEHeader) + 64;
    if (checksum_field + 4 > image.size()) return false;

    // save() rewrites the section header table from the in-memory section list,
    // so the renamed section names only exist there, not in data(). Summing
    // data() alone therefore produced a checksum for an image that is not the
    // one on disk. Mirror the write here.
    const auto* header = pe.peHeader();
    const size_t header_table = pe_off + sizeof(PEHeader) + header->SizeOfOptionalHeader;
    const size_t header_needed =
        header_table + pe.sectionCount() * sizeof(SectionHeader);
    if (header_needed <= image.size()) {
        image[pe_off + 6] = static_cast<uint8_t>(pe.sectionCount() & 0xFF);
        image[pe_off + 7] = static_cast<uint8_t>((pe.sectionCount() >> 8) & 0xFF);
        for (size_t i = 0; i < pe.sectionCount(); i++)
            std::memcpy(image.data() + header_table + i * sizeof(SectionHeader), &pe.section(i),
                        sizeof(SectionHeader));
    }

    const uint32_t sum = checksumOf(image, checksum_field);

    uint8_t* opt = reinterpret_cast<uint8_t*>(pe.peHeader()) + sizeof(PEHeader);
    if (pe.is64()) reinterpret_cast<OptionalHeader64*>(opt)->CheckSum = sum;
    else reinterpret_cast<OptionalHeader32*>(opt)->CheckSum = sum;

    report.checksum_updated = true;
    report.new_checksum = sum;
    report.changes.push_back("CheckSum -> 0x" + std::to_string(sum));
    return true;
}

bool StaticEvader::apply(PELib& pe, StaticEvasionReport& report) {
    if (pe.sectionCount() == 0) return false;
    if (cfg_.static_rich_scrub) scrubRichHeader(pe, report);
    if (cfg_.static_timestamp) randomizeTimestamp(pe, report);
    if (cfg_.static_strip_pdb) stripPdbEntries(pe, report);
    if (cfg_.static_section_rename) renameSections(pe, report);
    if (cfg_.static_pad_fill) fillSectionPadding(pe, report);
    if (cfg_.static_drop_signature) dropSignature(pe, report);
    // Last: every earlier step invalidates a previously computed checksum.
    if (cfg_.static_checksum) updateChecksum(pe, report);
    return true;
}

} // namespace np
