// NovaProtect PE Library Implementation
#include "pe_lib.h"
#include <cstring>
#include <algorithm>
#include <cstdio>
#include <windows.h>
#include <fstream>
#include <filesystem>

namespace np {

// ============================================================
// Utility functions
// ============================================================
namespace util {

uint32_t alignUp(uint32_t value, uint32_t alignment) {
    return (value + alignment - 1) & ~(alignment - 1);
}

uint32_t alignDown(uint32_t value, uint32_t alignment) {
    return value & ~(alignment - 1);
}

uint32_t fnv1a_hash(const uint8_t* data, size_t len, uint32_t seed) {
    uint32_t hash = seed;
    for (size_t i = 0; i < len; i++) {
        hash ^= data[i];
        hash *= 0x01000193;
    }
    return hash;
}

uint64_t fnv1a_hash64(const uint8_t* data, size_t len, uint64_t seed) {
    uint64_t hash = seed;
    for (size_t i = 0; i < len; i++) {
        hash ^= (uint64_t)data[i];
        hash *= 0x100000001B3ULL;
    }
    return hash;
}

void xor_crypt(uint8_t* data, size_t len, const uint8_t* key, size_t key_len) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= key[i % key_len];
    }
}

} // namespace util

// ============================================================
// PELib implementation
// ============================================================

bool PELib::load(const std::string& filepath) {
    // The narrow overload receives UTF-8 (all CLI paths do). Constructing
    // std::filesystem::path straight from a char string would let the ANSI CRT
    // decode it with the active code page and break non-ASCII paths.
    std::ifstream f(std::filesystem::u8path(filepath), std::ios::binary);
    if (!f.is_open()) {
        lastError_ = "Cannot open file: " + filepath;
        return false;
    }
    f.seekg(0, std::ios::end);
    size_t size = f.tellg();
    f.seekg(0, std::ios::beg);
    data_.resize(size);
    f.read(reinterpret_cast<char*>(data_.data()), size);
    f.close();
    return load(data_.data(), size);
}

bool PELib::load(const std::wstring& filepath) {
    std::ifstream f(std::filesystem::path(filepath), std::ios::binary);
    if (!f.is_open()) {
        lastError_ = "Cannot open file";
        return false;
    }
    f.seekg(0, std::ios::end);
    const auto end = f.tellg();
    if (end < 0) {
        lastError_ = "Cannot determine file size";
        return false;
    }
    const size_t size = static_cast<size_t>(end);
    f.seekg(0, std::ios::beg);
    data_.resize(size);
    if (size != 0) f.read(reinterpret_cast<char*>(data_.data()), static_cast<std::streamsize>(size));
    f.close();
    return load(data_.data(), size);
}
bool PELib::load(const uint8_t* data, size_t size) {
    data_.assign(data, data + size);
    if (!validatePE()) return false;
    parseHeaders();
    loadSections();
    return true;
}

bool PELib::save(const std::wstring& filepath) {
    uint32_t maxOffset = 0;
    for (auto& s : sections_) {
        if (s.PointerToRawData + s.SizeOfRawData > maxOffset)
            maxOffset = s.PointerToRawData + s.SizeOfRawData;
    }
    if (maxOffset > data_.size()) data_.resize(maxOffset, 0);

    for (size_t i = 0; i < sections_.size(); i++) {
        auto& sect = sections_[i];
        if (sect.PointerToRawData + sect.SizeOfRawData <= data_.size()) {
            auto& sdata = sectionData_[i];
            if (!sdata.empty()) {
                memcpy(data_.data() + sect.PointerToRawData, sdata.data(),
                       std::min(sdata.size(), (size_t)sect.SizeOfRawData));
            }
        }
    }

    auto* peHdr = peHeader();
    auto* optPtr = reinterpret_cast<uint8_t*>(peHdr) + sizeof(PEHeader);
    auto* sectOut = reinterpret_cast<SectionHeader*>(optPtr + peHdr->SizeOfOptionalHeader);
    for (size_t i = 0; i < sections_.size(); i++) sectOut[i] = sections_[i];
    peHdr->NumberOfSections = (uint16_t)sections_.size();

    // Only the sections are written out.  Anything the original file carried
    // past the last section (an overlay) is dropped: it is not part of the
    // image, and keeping it would leak the original import names and other
    // strings straight through the protector.
    const size_t imageEnd = (maxOffset < data_.size()) ? (size_t)maxOffset : data_.size();

    // Write to a temporary file and rename it into place, so a failure
    // never leaves a half-written image that looks like a successful build.
    const std::filesystem::path target(filepath);
    // Append in wide form: path::string() narrows with the active code page, so
    // a non-ASCII path would be round-tripped through ANSI (lossy on characters
    // outside GBK) before being widened again.
    std::filesystem::path tmp = target;
    tmp += L".np.tmp";
    {
        std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
        if (!f.is_open()) {
            lastError_ = "Cannot create output file: " + tmp.string();
            return false;
        }
        f.write(reinterpret_cast<const char*>(data_.data()),
                static_cast<std::streamsize>(imageEnd));
        f.flush();
        if (!f) {
            f.close();
            std::error_code ec;
            std::filesystem::remove(tmp, ec);
            lastError_ = "Failed to write output";
            return false;
        }
    }
    std::error_code ec;
    std::filesystem::remove(target, ec);
    std::filesystem::rename(tmp, target, ec);
    if (ec) {
        std::filesystem::remove(tmp, ec);
        lastError_ = "Cannot replace output file: " + ec.message();
        return false;
    }
    return true;
}
bool PELib::save(const std::string& filepath) {
    // Ensure file is large enough for all sections
    uint32_t maxOffset = 0;
    for (auto& s : sections_) {
        if (s.PointerToRawData + s.SizeOfRawData > maxOffset)
            maxOffset = s.PointerToRawData + s.SizeOfRawData;
    }
    if (maxOffset > data_.size()) data_.resize(maxOffset, 0);
    
    // Write back section data
    for (size_t i = 0; i < sections_.size(); i++) {
        auto& sect = sections_[i];
        if (sect.PointerToRawData + sect.SizeOfRawData <= data_.size()) {
            auto& sdata = sectionData_[i];
            if (sdata.size() > 0) {
                memcpy(data_.data() + sect.PointerToRawData, sdata.data(),
                       std::min(sdata.size(), (size_t)sect.SizeOfRawData));
            }
        }
    }
    
    // Write section headers back
    auto* peHdr = peHeader();
    auto* optPtr = reinterpret_cast<uint8_t*>(peHdr) + sizeof(PEHeader);
    auto* sectOut = reinterpret_cast<SectionHeader*>(optPtr + peHdr->SizeOfOptionalHeader);
    for (size_t i = 0; i < sections_.size(); i++) {
        sectOut[i] = sections_[i];
    }
    
    // Update PE header section count
    peHdr->NumberOfSections = (uint16_t)sections_.size();
    
    // Same as the wide overload: drop the overlay and write atomically.
    const size_t imageEnd = (maxOffset < data_.size()) ? (size_t)maxOffset : data_.size();
    const std::filesystem::path target(filepath);
    // Append in wide form: path::string() narrows with the active code page, so
    // a non-ASCII path would be round-tripped through ANSI (lossy on characters
    // outside GBK) before being widened again.
    std::filesystem::path tmp = target;
    tmp += L".np.tmp";
    {
        std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
        if (!f.is_open()) {
            lastError_ = "Cannot write file: " + tmp.string();
            return false;
        }
        f.write(reinterpret_cast<const char*>(data_.data()),
                static_cast<std::streamsize>(imageEnd));
        f.flush();
        if (!f) {
            f.close();
            std::error_code ec;
            std::filesystem::remove(tmp, ec);
            lastError_ = "Failed to write output";
            return false;
        }
    }
    std::error_code ec;
    std::filesystem::remove(target, ec);
    std::filesystem::rename(tmp, target, ec);
    if (ec) {
        std::filesystem::remove(tmp, ec);
        lastError_ = "Cannot replace output file: " + ec.message();
        return false;
    }
    return true;
}

bool PELib::validatePE() {
    if (data_.size() < sizeof(DOSHeader)) {
        lastError_ = "File too small";
        return false;
    }
    auto* dos = reinterpret_cast<const DOSHeader*>(data_.data());
    if (dos->e_magic != DOS_MAGIC) {
        lastError_ = "Not a valid PE (missing MZ)";
        return false;
    }
    if (dos->e_lfanew < 0 || (size_t)dos->e_lfanew >= data_.size()) {
        lastError_ = "Invalid e_lfanew";
        return false;
    }
    auto* pe = reinterpret_cast<const PEHeader*>(data_.data() + dos->e_lfanew);
    if (pe->Signature != PE_MAGIC) {
        lastError_ = "Invalid PE signature";
        return false;
    }
    auto* opt = reinterpret_cast<const uint8_t*>(pe) + sizeof(PEHeader);
    uint16_t magic = *reinterpret_cast<const uint16_t*>(opt);
    if (magic != OPT_MAGIC_32 && magic != OPT_MAGIC_64) {
        lastError_ = "Invalid optional header magic";
        return false;
    }
    return true;
}

void PELib::parseHeaders() {
    auto* pe = peHeader();
    auto* opt = reinterpret_cast<uint8_t*>(pe) + sizeof(PEHeader);
    
    // Check magic
    uint16_t magic = *reinterpret_cast<uint16_t*>(opt);
    is64_ = (magic == OPT_MAGIC_64);
    
    ep_ = is64_
        ? reinterpret_cast<OptionalHeader64*>(opt)->AddressOfEntryPoint
        : reinterpret_cast<OptionalHeader32*>(opt)->AddressOfEntryPoint;
    
    imageBase_ = is64_
        ? reinterpret_cast<OptionalHeader64*>(opt)->ImageBase
        : reinterpret_cast<OptionalHeader32*>(opt)->ImageBase;
    
    sectAlign_ = is64_
        ? reinterpret_cast<OptionalHeader64*>(opt)->SectionAlignment
        : reinterpret_cast<OptionalHeader32*>(opt)->SectionAlignment;
    
    fileAlign_ = is64_
        ? reinterpret_cast<OptionalHeader64*>(opt)->FileAlignment
        : reinterpret_cast<OptionalHeader32*>(opt)->FileAlignment;
    
    // Parse section headers
    sections_.clear();
    auto* sect = reinterpret_cast<SectionHeader*>(reinterpret_cast<uint8_t*>(opt) + pe->SizeOfOptionalHeader);
    for (uint16_t i = 0; i < pe->NumberOfSections; i++) {
        sections_.push_back(sect[i]);
    }
}

void PELib::loadSections() {
    sectionData_.resize(sections_.size());
    for (size_t i = 0; i < sections_.size(); i++) {
        auto& s = sections_[i];
        if (s.SizeOfRawData > 0 && s.PointerToRawData + s.SizeOfRawData <= data_.size()) {
            sectionData_[i].assign(
                data_.begin() + s.PointerToRawData,
                data_.begin() + s.PointerToRawData + s.SizeOfRawData
            );
        }
    }
}

uint32_t PELib::rvaToOffset(uint32_t rva) const {
    for (const auto& s : sections_) {
        uint32_t vaStart = s.VirtualAddress;
        uint32_t vaEnd = vaStart + std::max(s.VirtualSize, s.SizeOfRawData);
        if (rva >= vaStart && rva < vaEnd) {
            return s.PointerToRawData + (rva - vaStart);
        }
    }
    return 0;
}

uint32_t PELib::offsetToRva(uint32_t offset) const {
    for (const auto& s : sections_) {
        if (offset >= s.PointerToRawData && 
            offset < s.PointerToRawData + s.SizeOfRawData) {
            return s.VirtualAddress + (offset - s.PointerToRawData);
        }
    }
    return 0;
}

uint8_t* PELib::rvaToPtr(uint32_t rva) {
    uint32_t off = rvaToOffset(rva);
    if (off == 0 || off >= data_.size()) return nullptr;
    return data_.data() + off;
}

const uint8_t* PELib::rvaToPtr(uint32_t rva) const {
    uint32_t off = rvaToOffset(rva);
    if (off == 0 || off >= data_.size()) return nullptr;
    return data_.data() + off;
}

DataDirectory* PELib::dataDirectory(int index) {
    auto* opt = reinterpret_cast<uint8_t*>(peHeader()) + sizeof(PEHeader);
    if (is64_) {
        auto* oh = reinterpret_cast<OptionalHeader64*>(opt);
        if (oh->NumberOfRvaAndSize <= (uint32_t)index) return nullptr;
        return &oh->DataDirectory[index];
    } else {
        auto* oh = reinterpret_cast<OptionalHeader32*>(opt);
        if (oh->NumberOfRvaAndSize <= (uint32_t)index) return nullptr;
        return &oh->DataDirectory[index];
    }
}

const DataDirectory* PELib::dataDirectory(int index) const {
    auto* opt = reinterpret_cast<const uint8_t*>(peHeader()) + sizeof(PEHeader);
    if (is64_) {
        auto* oh = reinterpret_cast<const OptionalHeader64*>(opt);
        if (oh->NumberOfRvaAndSize <= (uint32_t)index) return nullptr;
        return &oh->DataDirectory[index];
    } else {
        auto* oh = reinterpret_cast<const OptionalHeader32*>(opt);
        if (oh->NumberOfRvaAndSize <= (uint32_t)index) return nullptr;
        return &oh->DataDirectory[index];
    }
}

uint64_t PELib::imageBase() const { return imageBase_; }
uint32_t PELib::imageSize() const {
    auto* opt = reinterpret_cast<const uint8_t*>(peHeader()) + sizeof(PEHeader);
    return is64_
        ? reinterpret_cast<const OptionalHeader64*>(opt)->SizeOfImage
        : reinterpret_cast<const OptionalHeader32*>(opt)->SizeOfImage;
}

int PELib::addSection(const char* name, uint32_t virtualSize, uint32_t characteristics) {
    auto* pe = peHeader();
    SectionHeader newSect = {};
    strncpy(newSect.Name, name, 8);
    newSect.VirtualSize = virtualSize;
    newSect.VirtualAddress = nextSectionRVA();
    newSect.SizeOfRawData = util::alignUp(virtualSize, fileAlign_);
    newSect.PointerToRawData = nextSectionFileOffset();
    newSect.Characteristics = characteristics;
    
    sections_.push_back(newSect);
    sectionData_.emplace_back();
    sectionData_.back().resize(util::alignUp(virtualSize, fileAlign_), 0);
    
    // Update PE header section count
    pe->NumberOfSections = (uint16_t)sections_.size();
    
    // Update SizeOfImage
    auto* opt = reinterpret_cast<uint8_t*>(pe) + sizeof(PEHeader);
    if (is64_) {
        auto* oh = reinterpret_cast<OptionalHeader64*>(opt);
        oh->SizeOfImage = util::alignUp(newSect.VirtualAddress + newSect.VirtualSize, sectAlign_);
    } else {
        auto* oh = reinterpret_cast<OptionalHeader32*>(opt);
        oh->SizeOfImage = util::alignUp(newSect.VirtualAddress + newSect.VirtualSize, sectAlign_);
    }
    
    return (int)sections_.size() - 1;
}

void PELib::setSectionData(size_t idx, const std::vector<uint8_t>& data) {
    if (idx >= sectionData_.size()) return;
    sectionData_[idx] = data;
    // Update header
    if (idx < sections_.size()) {
        sections_[idx].SizeOfRawData = util::alignUp((uint32_t)data.size(), fileAlign_);
        sectionData_[idx].resize(sections_[idx].SizeOfRawData, 0);
    }
}

uint32_t PELib::nextSectionRVA() const {
    if (sections_.empty()) return util::alignUp((uint32_t)(dosHeader()->e_lfanew + sizeof(PEHeader) + peHeader()->SizeOfOptionalHeader), sectAlign_);
    auto& last = sections_.back();
    return util::alignUp(last.VirtualAddress + std::max(last.VirtualSize, last.SizeOfRawData), sectAlign_);
}

uint32_t PELib::nextSectionFileOffset() const {
    uint32_t offset = util::alignUp(
        (uint32_t)(dosHeader()->e_lfanew + sizeof(PEHeader) + peHeader()->SizeOfOptionalHeader),
        fileAlign_);
    for (const auto& s : sections_) {
        offset = std::max(offset, util::alignUp(s.PointerToRawData + s.SizeOfRawData, fileAlign_));
    }
    return offset;
}

std::vector<uint8_t> PELib::getSectionFileData(size_t idx) const {
    if (idx >= sections_.size()) return {};
    return sectionData_[idx];
}

std::vector<PELib::ImportInfo> PELib::getImports() const {
    std::vector<ImportInfo> result;
    auto* dd = dataDirectory(DIR_ENTRY_IMPORT);
    if (!dd || dd->VirtualAddress == 0) return result;
    
    auto* impDesc = reinterpret_cast<const ImportDescriptor*>(rvaToPtr(dd->VirtualAddress));
    if (!impDesc) return result;
    
    for (int i = 0; impDesc[i].Name != 0; i++) {
        ImportInfo info;
        auto* name = reinterpret_cast<const char*>(rvaToPtr(impDesc[i].Name));
        if (name) info.dll_name = name;
        info.iat_rva = impDesc[i].FirstThunk;
        info.orig_rva = impDesc[i].OriginalFirstThunk;
        
        // Parse the thunk array using the target architecture pointer width.
        uint32_t thunkRVA = impDesc[i].OriginalFirstThunk ? impDesc[i].OriginalFirstThunk : impDesc[i].FirstThunk;
        const uint8_t* thunk = rvaToPtr(thunkRVA);
        if (!thunk) continue;

        if (is64_) {
            for (int j = 0;; j++) {
                uint64_t value = 0;
                memcpy(&value, thunk + (size_t)j * sizeof(uint64_t), sizeof(value));
                if (!value) break;
                if (value & 0x8000000000000000ULL) {
                    info.functions.push_back("ord_" + std::to_string(value & 0xFFFF));
                } else {
                    uint32_t nameRVA = (uint32_t)(value & 0xFFFFFFFF);
                    auto* fname = reinterpret_cast<const char*>(rvaToPtr(nameRVA + 2));
                    if (fname) info.functions.push_back(fname);
                }
            }
        } else {
            for (int j = 0;; j++) {
                uint32_t value = 0;
                memcpy(&value, thunk + (size_t)j * sizeof(uint32_t), sizeof(value));
                if (!value) break;
                if (value & 0x80000000u) {
                    info.functions.push_back("ord_" + std::to_string(value & 0xFFFFu));
                } else {
                    auto* fname = reinterpret_cast<const char*>(rvaToPtr(value + 2));
                    if (fname) info.functions.push_back(fname);
                }
            }
        }
        info.count = info.functions.size();
        result.push_back(info);
    }
    return result;
}

std::vector<PELib::ExportInfo> PELib::getExports() const {
    std::vector<ExportInfo> result;
    auto* dd = dataDirectory(DIR_ENTRY_EXPORT);
    if (!dd || dd->VirtualAddress == 0) return result;
    
    auto* expDir = reinterpret_cast<const ExportDirectory*>(rvaToPtr(dd->VirtualAddress));
    if (!expDir) return result;
    
    auto* names = reinterpret_cast<const uint32_t*>(rvaToPtr(expDir->AddressOfNames));
    auto* ordinals = reinterpret_cast<const uint16_t*>(rvaToPtr(expDir->AddressOfNameOrdinals));
    auto* functions = reinterpret_cast<const uint32_t*>(rvaToPtr(expDir->AddressOfFunctions));
    if (!names || !ordinals || !functions) return result;
    
    for (uint32_t i = 0; i < expDir->NumberOfNames; i++) {
        ExportInfo info;
        auto* name = reinterpret_cast<const char*>(rvaToPtr(names[i]));
        if (name) info.name = name;
        info.ordinal = expDir->Base + ordinals[i];
        info.rva = functions[ordinals[i]];
        result.push_back(info);
    }
    return result;
}

std::vector<PELib::RelocEntry> PELib::getRelocations() const {
    std::vector<RelocEntry> result;
    auto* dd = dataDirectory(DIR_ENTRY_BASERELOC);
    if (!dd || dd->VirtualAddress == 0) return result;
    
    auto* ptr = rvaToPtr(dd->VirtualAddress);
    uint32_t remaining = dd->Size;
    
    while (remaining >= 8) {
        auto* block = reinterpret_cast<const uint32_t*>(ptr);
        uint32_t pageRVA = block[0];
        uint32_t blockSize = block[1];
        if (blockSize == 0 || blockSize > remaining) break;
        
        uint16_t numEntries = (blockSize - 8) / 2;
        auto* entries = reinterpret_cast<const uint16_t*>(ptr + 8);
        for (uint16_t i = 0; i < numEntries; i++) {
            uint16_t type = entries[i] >> 12;
            uint16_t offset = entries[i] & 0xFFF;
            if (type == 0) continue; // padding
            result.push_back({pageRVA + offset, type});
        }
        ptr += blockSize;
        remaining -= blockSize;
    }
    return result;
}

std::vector<uint32_t> PELib::searchPattern(const uint8_t* pattern, size_t pattern_len, const uint8_t* mask) {
    std::vector<uint32_t> results;
    for (size_t i = 0; i < sections_.size(); i++) {
        if (!(sections_[i].Characteristics & SEC_MEM_EXECUTE)) continue;
        auto& data = sectionData_[i];
        uint32_t sectRVA = sections_[i].VirtualAddress;
        
        for (size_t j = 0; j + pattern_len <= data.size(); j++) {
            bool found = true;
            for (size_t k = 0; k < pattern_len; k++) {
                if (mask) {
                    if (mask[k] != '?' && data[j+k] != pattern[k]) { found = false; break; }
                } else {
                    if (data[j+k] != pattern[k]) { found = false; break; }
                }
            }
            if (found) {
                results.push_back(sectRVA + (uint32_t)j);
            }
        }
    }
    return results;
}

std::vector<PELib::SDKMarker> PELib::findMarkers() {
    std::vector<SDKMarker> result;
    
    // Scan for NovaProtect SDK marker patterns; legacy NOVAPACK bytes remain compatible:
    // x64 BEGIN: 48 8D 0D 00 00 00 00 + 20×90 (27 bytes)
    // x86 BEGIN: 8D 0D 00 00 00 00 + 20×90 (26 bytes)
    // END: 20×90 (20 bytes)
    
    if (is64_) {
        // x64 BEGIN pattern: lea rcx,[rip+0] + 20 nops
        uint8_t beginPat[27];
        beginPat[0]=0x48; beginPat[1]=0x8D; beginPat[2]=0x0D;
        beginPat[3]=0x00; beginPat[4]=0x00; beginPat[5]=0x00; beginPat[6]=0x00;
        for (int i=7; i<27; i++) beginPat[i] = 0x90;
        
        auto beginRvas = searchPattern(beginPat, 27);
        for (uint32_t rva : beginRvas) {
            result.push_back({rva, "novaprotect_begin", 0});
        }
    } else {
        // x86 BEGIN pattern: lea ecx,[0] + 20 nops
        uint8_t beginPat[26];
        beginPat[0]=0x8D; beginPat[1]=0x0D;
        beginPat[2]=0x00; beginPat[3]=0x00; beginPat[4]=0x00; beginPat[5]=0x00;
        for (int i=6; i<26; i++) beginPat[i] = 0x90;
        
        auto beginRvas = searchPattern(beginPat, 26);
        for (uint32_t rva : beginRvas) {
            result.push_back({rva, "novaprotect_begin", 0});
        }
    }
    
    // END pattern: 20×90
    uint8_t endPat[20];
    for (int i=0; i<20; i++) endPat[i] = 0x90;
    auto endRvas = searchPattern(endPat, 20);
    
    // Filter: only keep END markers that come after a BEGIN
    for (uint32_t endRva : endRvas) {
        bool afterBegin = false;
        for (auto& mk : result) {
            if (mk.type == 0 && endRva > mk.rva + (is64_ ? 27u : 26u)) {
                afterBegin = true;
                break;
            }
        }
        if (afterBegin) {
            result.push_back({endRva, "novaprotect_end", 1});
        }
    }
    
    // Sort by RVA
    std::sort(result.begin(), result.end(), [](const SDKMarker& a, const SDKMarker& b) { return a.rva < b.rva; });
    return result;
}

uint32_t PELib::computeChecksum() const {
    // Standard PE checksum (the same algorithm the Windows loader uses):
    // sum every 16-bit word with carry folding, skip the CheckSum field
    // itself, and add the file length.  The previous version folded the
    // CheckSum field into the sum, which makes the result depend on the
    // value it is supposed to produce.
    uint64_t sum = 0;
    const size_t count = data_.size() / 2;
    const auto* words = reinterpret_cast<const uint16_t*>(data_.data());

    // Locate the CheckSum field so it can be excluded.
    size_t skip_off = 0, skip_end = 0;
    {
        auto* pe = peHeader();
        auto* opt = reinterpret_cast<const uint8_t*>(pe) + sizeof(PEHeader);
        if (pe->SizeOfOptionalHeader >= 68) {
            size_t field = (size_t)(opt - data_.data()) + 64;
            skip_off = field;
            skip_end = field + 4;
        }
    }

    for (size_t i = 0; i < count; i++) {
        const size_t off = i * 2;
        if (off + 2 > skip_off && off < skip_end) continue;
        sum += words[i];
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    if (data_.size() % 2) {
        const size_t off = data_.size() - 1;
        if (!(off >= skip_off && off < skip_end)) sum += data_[off];
    }
    // Fold the carry twice, as the loader does.
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint32_t)(sum + data_.size());
}

void PELib::updateHeaders() {
    auto* pe = peHeader();
    pe->NumberOfSections = (uint16_t)sections_.size();
    
    auto* opt = reinterpret_cast<uint8_t*>(pe) + sizeof(PEHeader);
    uint32_t maxImageSize = 0;
    
    // Rebuild section headers in file
    auto* sectOut = reinterpret_cast<SectionHeader*>(opt + pe->SizeOfOptionalHeader);
    for (size_t i = 0; i < sections_.size(); i++) {
        sectOut[i] = sections_[i];
        uint32_t endVA = sections_[i].VirtualAddress + sections_[i].VirtualSize;
        maxImageSize = std::max(maxImageSize, util::alignUp(endVA, sectAlign_));
    }
    
    if (is64_) {
        auto* oh = reinterpret_cast<OptionalHeader64*>(opt);
        oh->AddressOfEntryPoint = ep_;
        oh->SizeOfImage = maxImageSize;
        oh->CheckSum = computeChecksum();
    } else {
        auto* oh = reinterpret_cast<OptionalHeader32*>(opt);
        oh->AddressOfEntryPoint = ep_;
        oh->SizeOfImage = maxImageSize;
        oh->CheckSum = computeChecksum();
    }
}

} // namespace np



