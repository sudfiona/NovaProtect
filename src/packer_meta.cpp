// NovaProtect - metadata container, watermark, virtual files, debug stripping,
// import descriptor blob. Kept in a separate translation unit so the core
// loader contract in packer.cpp stays untouched.
#include "packer.h"
#include "crypto_stream.h"
#include <cstring>
#include <cstdio>
#include <fstream>
#include <filesystem>
#include <algorithm>
#include <chrono>
#include <windows.h>

namespace np {

// ---------------------------------------------------------------
// hashing helpers (kept local, no dependency on pe_lib internals)
// ---------------------------------------------------------------
static uint32_t metaFnv1a32(const uint8_t* d, size_t n, uint32_t h = 0x811C9DC5u) {
    for (size_t i = 0; i < n; ++i) { h ^= d[i]; h *= 0x01000193u; }
    return h;
}
static uint64_t metaFnv1a64(const uint8_t* d, size_t n, uint64_t h = 0xCBF29CE484222325ULL) {
    for (size_t i = 0; i < n; ++i) { h ^= d[i]; h *= 0x100000001B3ULL; }
    return h;
}
static uint32_t metaFnv1a32Str(const std::string& s) {
    uint32_t h = 0x811C9DC5u;
    for (unsigned char c : s) {
        if (c >= 'A' && c <= 'Z') c = (unsigned char)(c - 'A' + 'a');
        h ^= c; h *= 0x01000193u;
    }
    return h;
}

static std::vector<uint8_t>* sectionDataForRva(PELib& pe, uint32_t rva, size_t& off) {
    for (size_t i = 0; i < pe.sectionCount(); i++) {
        auto& s = pe.section(i);
        uint32_t span = std::max(s.VirtualSize, s.SizeOfRawData);
        if (rva >= s.VirtualAddress && rva < s.VirtualAddress + span) {
            off = (size_t)(rva - s.VirtualAddress);
            return &pe.sectionData(i);
        }
    }
    return nullptr;
}

static std::wstring utf8ToWidePath(const std::string& value) {
    if (value.empty()) return {};
    const int count = MultiByteToWideChar(
        CP_UTF8, MB_ERR_INVALID_CHARS,
        value.data(), static_cast<int>(value.size()),
        nullptr, 0);
    if (count <= 0) return {};
    std::wstring result(static_cast<size_t>(count), L'\0');
    if (MultiByteToWideChar(
            CP_UTF8, MB_ERR_INVALID_CHARS,
            value.data(), static_cast<int>(value.size()),
            result.data(), count) != count) {
        return {};
    }
    return result;
}

static bool readWholeFile(const std::string& path, std::vector<uint8_t>& out) {
    const auto widePath = utf8ToWidePath(path);
    if (widePath.empty() && !path.empty()) return false;
    std::ifstream f(std::filesystem::path(widePath), std::ios::binary);
    if (!f.is_open()) return false;
    f.seekg(0, std::ios::end);
    std::streamoff n = f.tellg();
    f.seekg(0, std::ios::beg);
    if (n < 0) return false;
    out.resize((size_t)n);
    if (n > 0) f.read(reinterpret_cast<char*>(out.data()), n);
    return true;
}

static void putU32(std::vector<uint8_t>& v, uint32_t x) {
    uint8_t b[4]; memcpy(b, &x, 4); v.insert(v.end(), b, b + 4);
}
static void putU64(std::vector<uint8_t>& v, uint64_t x) {
    uint8_t b[8]; memcpy(b, &x, 8); v.insert(v.end(), b, b + 8);
}

// ---------------------------------------------------------------
// metadata container
//   header : "NPM1" | version u32 | entry_count u32 | flags u32
//   entry  : type u32 | hash u32 | offset u32 | size u32   (16 bytes)
//   payload: concatenated, 4-byte aligned
// ---------------------------------------------------------------
enum MetaType : uint32_t {
    META_WATERMARK  = 1,
    META_LICENSE    = 2,
    META_ACTIVATION = 3,
    META_VFILE      = 4,
    META_BUILD      = 5,
    META_IMPORTS    = 6,
};

struct MetaEntry { uint32_t type, hash, off, size; };

static void metaAppend(std::vector<uint8_t>& payload, std::vector<MetaEntry>& entries,
                       uint32_t type, uint32_t hash, const std::vector<uint8_t>& data) {
    MetaEntry e;
    e.type = type;
    e.hash = hash;
    e.off = (uint32_t)payload.size();
    e.size = (uint32_t)data.size();
    payload.insert(payload.end(), data.begin(), data.end());
    while (payload.size() & 3) payload.push_back(0);
    entries.push_back(e);
}

// ---------------------------------------------------------------
// import descriptor blob
//   u32 dll_count
//   per dll : u32 name_len | name bytes (NUL terminated)
//             u32 fn_count
//             per fn : u8 kind(0=name,1=ordinal) | u16 ordinal
//                      u32 iat_rva (absolute RVA of the IAT slot)
//                      u32 name_len | name bytes
// ---------------------------------------------------------------
bool Packer::buildImportBlob(PELib& pe, std::vector<uint8_t>& blob, uint32_t& key) {
    blob.clear();
    // Derived from the build seed so a repro build produces the same IAT key.
    key = metaFnv1a32((const uint8_t*)"NovaPackIAT", 11) ^
          (uint32_t)(buildSeed() >> 17);

    auto imports = pe.getImports();
    if (imports.empty()) return false;

    std::vector<uint8_t> dlls;
    uint32_t dll_count = 0;

    for (const auto& im : imports) {
        if (im.dll_name.empty()) continue;
        std::vector<uint8_t> one;
        std::string name = im.dll_name;
        name.push_back('\0');
        putU32(one, (uint32_t)name.size());
        one.insert(one.end(), name.begin(), name.end());

        struct Slot { bool ordinal; uint16_t ord; std::string name; uint32_t rva; };
        std::vector<Slot> slots;
        const bool is64 = pe.is64();
        uint32_t int_rva = im.orig_rva ? im.orig_rva : im.iat_rva;
        const uint32_t step = is64 ? 8 : 4;
        for (size_t idx = 0; idx < im.count; idx++) {
            const uint8_t* thunk = pe.rvaToPtr(int_rva + (uint32_t)(idx * step));
            if (!thunk) break;
            uint64_t value = 0;
            memcpy(&value, thunk, step);
            if (value == 0) break;
            Slot s;
            s.rva = im.iat_rva + (uint32_t)(idx * step);
            uint64_t ordinal_flag = is64 ? 0x8000000000000000ULL : 0x80000000ULL;
            if (value & ordinal_flag) {
                s.ordinal = true;
                s.ord = (uint16_t)(value & 0xFFFF);
                s.name.clear();
            } else {
                s.ordinal = false;
                s.ord = 0;
                const uint8_t* hint = pe.rvaToPtr((uint32_t)(value & 0x7FFFFFFF));
                if (hint) s.name = std::string(reinterpret_cast<const char*>(hint + 2));
                else break;
            }
            slots.push_back(s);
        }
        if (slots.empty()) continue;

        putU32(one, (uint32_t)slots.size());
        for (const auto& s : slots) {
            one.push_back(s.ordinal ? 1 : 0);
            uint8_t ob[2]; memcpy(ob, &s.ord, 2); one.insert(one.end(), ob, ob + 2);
            putU32(one, s.rva);
            if (s.ordinal) {
                putU32(one, 0);
            } else {
                std::string fn = s.name; fn.push_back('\0');
                putU32(one, (uint32_t)fn.size());
                one.insert(one.end(), fn.begin(), fn.end());
            }
        }
        dlls.insert(dlls.end(), one.begin(), one.end());
        dll_count++;
    }

    if (dll_count == 0) return false;

    // The blob is stored encrypted: without this, "strings" on the output
    // file hands the complete import table to anyone who looks.  The loader
    // decrypts the block before it walks the descriptors, so the plaintext
    // never has to exist in the image.
    //
    // Layout:  u32 seed | u32 plain_len | cipher bytes (plain_len long)
    std::vector<uint8_t> plain;
    putU32(plain, dll_count);
    plain.insert(plain.end(), dlls.begin(), dlls.end());

    blob.clear();
    putU32(blob, key);
    putU32(blob, (uint32_t)plain.size());
    blob.insert(blob.end(), plain.begin(), plain.end());
    streamCrypt(blob.data() + 8, blob.size() - 8, key);
    return true;
}

// Wipe the import directory so the Windows loader resolves nothing and the
// in-stub resolver becomes the only source of imports.
void Packer::stripImportDirectory(PELib& pe) {
    auto* dd = pe.dataDirectory(DIR_ENTRY_IMPORT);
    if (!dd || !dd->VirtualAddress) return;

    size_t off = 0;
    std::vector<uint8_t>* sec = sectionDataForRva(pe, dd->VirtualAddress, off);
    if (sec && off + dd->Size <= sec->size()) {
        std::fill(sec->begin() + off, sec->begin() + off + dd->Size, 0);
    }

    auto imports = pe.getImports();
    for (const auto& im : imports) {
        if (im.dll_name.empty()) continue;
        std::vector<uint8_t> needle(im.dll_name.begin(), im.dll_name.end());
        needle.push_back(0);
        for (size_t i = 0; i < pe.sectionCount(); i++) {
            auto& d = pe.sectionData(i);
            if (needle.size() > d.size()) continue;
            for (size_t p = 0; p + needle.size() <= d.size(); p++) {
                if (memcmp(d.data() + p, needle.data(), needle.size()) == 0) {
                    std::fill(d.begin() + p, d.begin() + p + needle.size() - 1, 0);
                }
            }
        }
    }

    // The stub writes the resolved function pointers straight back into the
    // original IAT slots, so every section that hosts an IAT must be writable
    // in the loaded image. Otherwise the first store faults on a read-only page.
    for (const auto& im : imports) {
        if (im.iat_rva == 0) continue;
        for (size_t i = 0; i < pe.sectionCount(); i++) {
            auto& s = pe.section(i);
            uint32_t span = std::max(s.VirtualSize, s.SizeOfRawData);
            if (im.iat_rva >= s.VirtualAddress && im.iat_rva < s.VirtualAddress + span) {
                s.Characteristics |= SEC_MEM_WRITE;
                break;
            }
        }
    }

    dd->VirtualAddress = 0;
    dd->Size = 0;

    auto* iat = pe.dataDirectory(DIR_ENTRY_IAT);
    if (iat) { iat->VirtualAddress = 0; iat->Size = 0; }
}

// An empty import table is itself a signature. "This executable imports no
// functions" is a named detection on every static-analysis platform, it forces
// impfuzzy down to the degenerate "3::" value, and it tags the file as
// empty_import -- all three were present in the ThreatBook report for this
// sample, and none of them say anything about the payload: they only say the
// packer wiped the directory.
//
// This writes back a small, plausible table instead. The functions are real
// kernel32/user32 exports that the Windows loader resolves normally; nothing in
// the stub touches these slots, so they cost nothing beyond a few bytes and they
// make the file look like the ordinary GUI application it claims to be.
//
// The decoy slots deliberately do NOT point at anything the packer's own
// resolver uses: our IAT lives in the original sections and is filled by the
// stub, so loader-filled decoy entries cannot collide with it.
bool Packer::writeDecoyImports(PELib& pe) {
    struct DecoyFn { const char* name; };
    struct DecoyDll { const char* dll; const std::vector<DecoyFn>& fns; };

    static const std::vector<DecoyFn> kKernel32 = {
        {"GetModuleHandleA"}, {"GetProcAddress"}, {"GetSystemTimeAsFileTime"},
        {"QueryPerformanceCounter"}, {"GetCurrentProcessId"}, {"Sleep"},
    };
    static const std::vector<DecoyFn> kUser32 = {
        {"MessageBoxA"}, {"GetSystemMetrics"},
    };
    static const std::vector<DecoyDll> kDecoys = {
        {"kernel32.dll", kKernel32},
        {"user32.dll", kUser32},
    };

    const uint32_t thunk = pe.is64() ? 8u : 4u;
    const uint32_t kDescSize = 20;

    // Layout inside the new section: descriptors, then the hint/name blob, then
    // the INT and IAT arrays (pointer aligned), which is the order the loader
    // expects to be able to walk.
    size_t total_fns = 0;
    for (const auto& d : kDecoys) total_fns += d.fns.size();

    std::vector<uint8_t> names;              // hint/name entries, dll by dll
    std::vector<uint32_t> name_off;          // per dll: offset of its dll name
    std::vector<std::vector<uint32_t>> fn_off;
    fn_off.resize(kDecoys.size());

    for (size_t di = 0; di < kDecoys.size(); ++di) {
        name_off.push_back((uint32_t)names.size());
        std::string dll = kDecoys[di].dll; dll.push_back('\0');
        names.insert(names.end(), dll.begin(), dll.end());
        for (const auto& fn : kDecoys[di].fns) {
            fn_off[di].push_back((uint32_t)names.size());
            names.push_back(0); names.push_back(0);           // Hint
            names.insert(names.end(), fn.name, fn.name + strlen(fn.name));
            names.push_back('\0');
            if (names.size() % 2) names.push_back(0);          // keep word aligned
        }
    }

    const uint32_t desc_bytes = (uint32_t)((kDecoys.size() + 1) * kDescSize);
    uint32_t cur = desc_bytes + (uint32_t)names.size();
    const uint32_t align = thunk;
    while (cur % align) { names.push_back(0); ++cur; }
    const uint32_t int_off = cur;
    const uint32_t iat_off = int_off + (uint32_t)(total_fns * thunk);
    const uint32_t total = iat_off + (uint32_t)(total_fns * thunk);

    // The loader writes resolved addresses into FirstThunk, so this section has
    // to be writable or the process faults during load. RW-and-not-executable is
    // the ordinary shape for an import section and is not a packer signature;
    // what would be a signature is RWX, which this deliberately is not.
    int idx = pe.addSection(".idata", total, SEC_MEM_READ | SEC_MEM_WRITE | SEC_INITIALIZED_DATA);
    if (idx < 0) return false;
    const uint32_t base = pe.section((size_t)idx).VirtualAddress;

    std::vector<uint8_t> blob(total, 0);
    auto put32 = [&](uint32_t at, uint32_t v) { memcpy(blob.data() + at, &v, 4); };
    auto put64 = [&](uint32_t at, uint64_t v) { memcpy(blob.data() + at, &v, 8); };

    uint32_t fn_index = 0;
    for (size_t di = 0; di < kDecoys.size(); ++di) {
        const uint32_t d = (uint32_t)(di * kDescSize);
        const uint32_t my_int = int_off + fn_index * thunk;
        const uint32_t my_iat = iat_off + fn_index * thunk;

        put32(d + 0,  base + my_int);                       // OriginalFirstThunk
        put32(d + 12, base + name_off[di]);                 // Name
        put32(d + 16, base + my_iat);                       // FirstThunk

        for (size_t fi = 0; fi < kDecoys[di].fns.size(); ++fi) {
            const uint32_t slot = (uint32_t)fi * thunk;
            const uint32_t hn = base + fn_off[di][fi];
            if (pe.is64()) {
                put64(my_int + slot, hn);
                put64(my_iat + slot, hn);
            } else {
                put32(my_int + slot, hn);
                put32(my_iat + slot, hn);
            }
        }
        fn_index += (uint32_t)kDecoys[di].fns.size();
    }
    // Terminating descriptor already zeroed by the initial fill.

    memcpy(blob.data() + desc_bytes, names.data(), names.size());

    auto* dd = pe.dataDirectory(DIR_ENTRY_IMPORT);
    if (!dd) return false;
    dd->VirtualAddress = base;
    dd->Size = desc_bytes;

    auto* iatdd = pe.dataDirectory(DIR_ENTRY_IAT);
    if (iatdd) {
        iatdd->VirtualAddress = base + iat_off;
        iatdd->Size = (uint32_t)(total_fns * thunk);
    }

    pe.setSectionData((size_t)idx, blob);
    return true;
}

// ---------------------------------------------------------------
// debug info stripping
// ---------------------------------------------------------------
void Packer::stripDebugInfo(PELib& pe, PackResult& result) {
    auto* dd = pe.dataDirectory(DIR_ENTRY_DEBUG);
    if (!dd) return;
    if (dd->VirtualAddress && dd->Size) {
        const uint32_t kDebugDirEntry = 28;
        result.debug_entries_stripped = dd->Size / kDebugDirEntry;
        if (result.debug_entries_stripped == 0) result.debug_entries_stripped = 1;

        size_t off = 0;
        std::vector<uint8_t>* sec = sectionDataForRva(pe, dd->VirtualAddress, off);
        if (sec && off + dd->Size <= sec->size()) {
            // Walk each IMAGE_DEBUG_DIRECTORY entry and erase the referenced
            // CodeView/PDB record body before clearing the directory itself.
            // Without this the RSDS blob survives as dead .rdata.
            for (uint32_t e = 0; e + kDebugDirEntry <= dd->Size; e += kDebugDirEntry) {
                size_t eb = off + e;
                uint32_t dataRva = 0, dataSize = 0, rawPtr = 0;
                memcpy(&dataSize, sec->data() + eb + 16, 4);
                memcpy(&dataRva,  sec->data() + eb + 20, 4);
                memcpy(&rawPtr,   sec->data() + eb + 24, 4);
                (void)rawPtr;
                if (!dataRva || !dataSize) continue;
                size_t doff = 0;
                std::vector<uint8_t>* dsec = sectionDataForRva(pe, dataRva, doff);
                if (dsec && doff + dataSize <= dsec->size()) {
                    std::fill(dsec->begin() + doff, dsec->begin() + doff + dataSize, 0);
                }
            }
            std::fill(sec->begin() + off, sec->begin() + off + dd->Size, 0);
        }
    }
    dd->VirtualAddress = 0;
    dd->Size = 0;
}

// ---------------------------------------------------------------
// metadata assembly
// ---------------------------------------------------------------
void Packer::buildMetadataBlob(PELib& pe, std::vector<uint8_t>& blob) {
    std::vector<MetaEntry> entries;
    std::vector<uint8_t> payload;
    uint32_t flags = 0;

    if (config_.enable_watermark && !config_.watermark.empty()) {
        std::vector<uint8_t> d(config_.watermark.begin(), config_.watermark.end());
        metaAppend(payload, entries, META_WATERMARK, metaFnv1a32(d.data(), d.size()), d);
        flags |= 1u << 0;
    }
    if (config_.enable_licensing && !config_.license_key.empty()) {
        uint64_t h = metaFnv1a64((const uint8_t*)config_.license_key.data(), config_.license_key.size());
        std::vector<uint8_t> d; putU64(d, h);
        metaAppend(payload, entries, META_LICENSE, metaFnv1a32(d.data(), d.size()), d);
        flags |= 1u << 1;
    }
    if (config_.enable_activation && !config_.activation_key.empty()) {
        std::string dom = std::string("activation:") + config_.activation_key;
        uint64_t h = metaFnv1a64((const uint8_t*)dom.data(), dom.size());
        std::vector<uint8_t> d; putU64(d, h);
        metaAppend(payload, entries, META_ACTIVATION, metaFnv1a32(d.data(), d.size()), d);
        flags |= 1u << 2;
    }

    if (config_.enable_virtual_files) {
        for (const auto& path : config_.virtual_files) {
            std::vector<uint8_t> data;
            if (!readWholeFile(path, data)) continue;
            size_t slash = path.find_last_of("\\/");
            std::string base = (slash == std::string::npos) ? path : path.substr(slash + 1);
            std::vector<uint8_t> entryBlob;
            putU32(entryBlob, (uint32_t)base.size());
            entryBlob.insert(entryBlob.end(), base.begin(), base.end());
            while (entryBlob.size() & 3) entryBlob.push_back(0);
            putU32(entryBlob, (uint32_t)data.size());
            entryBlob.insert(entryBlob.end(), data.begin(), data.end());
            metaAppend(payload, entries, META_VFILE, metaFnv1a32Str(base), entryBlob);
            flags |= 1u << 3;
        }
    }

    if (config_.import_protection) {
        std::vector<uint8_t> imp;
        if (buildImportBlob(pe, imp, import_key_)) {
            import_blob_ = imp;
            metaAppend(payload, entries, META_IMPORTS, import_key_, imp);
            flags |= 1u << 4;
        }
    }

    {
        std::vector<uint8_t> d;
        uint64_t id = buildSeed() ^ 0xB17E1D2C3ull;
        uint32_t ts = (uint32_t)(buildSeed() >> 24);
        putU64(d, id);
        putU32(d, ts);
        putU32(d, flags);
        metaAppend(payload, entries, META_BUILD, metaFnv1a32(d.data(), d.size()), d);
    }

    blob.clear();
    blob.push_back('N'); blob.push_back('P'); blob.push_back('M'); blob.push_back('1');
    putU32(blob, 1);
    putU32(blob, (uint32_t)entries.size());
    putU32(blob, flags);
    for (const auto& e : entries) {
        putU32(blob, e.type);
        putU32(blob, e.hash);
        putU32(blob, e.off);
        putU32(blob, e.size);
    }
    blob.insert(blob.end(), payload.begin(), payload.end());

    meta_offset_ = 0;
    meta_size_ = blob.size();
}

// ---------------------------------------------------------------
// read-back helpers (static, operate on a packed image)
// ---------------------------------------------------------------
static bool loadMetaSection(const std::string& packed_path, std::vector<uint8_t>& out, std::string& err) {
    PELib pe;
    if (!pe.load(packed_path)) { err = pe.lastError(); return false; }
    for (size_t i = 0; i < pe.sectionCount(); i++) {
        if (strncmp(pe.section(i).Name, ".np_meta", 8) == 0) {
            out = pe.sectionData(i);
            return true;
        }
    }
    err = "no .np_meta section (image was not packed by NovaProtect, or packing was disabled)";
    return false;
}

struct ParsedMeta {
    std::vector<MetaEntry> entries;
    std::vector<uint8_t> payload;
    uint32_t flags = 0;
};

static bool parseMeta(const std::vector<uint8_t>& blob, ParsedMeta& pm, std::string& err) {
    if (blob.size() < 16 || blob[0] != 'N' || blob[1] != 'P' || blob[2] != 'M' || blob[3] != '1') {
        err = "bad metadata magic";
        return false;
    }
    auto rd32 = [&](size_t o) -> uint32_t { uint32_t v = 0; memcpy(&v, blob.data() + o, 4); return v; };
    uint32_t count = rd32(8);
    pm.flags = rd32(12);
    if (16 + (size_t)count * 16 > blob.size()) { err = "metadata truncated"; return false; }
    for (uint32_t i = 0; i < count; i++) {
        MetaEntry e;
        e.type = rd32(16 + i * 16 + 0);
        e.hash = rd32(16 + i * 16 + 4);
        e.off  = rd32(16 + i * 16 + 8);
        e.size = rd32(16 + i * 16 + 12);
        pm.entries.push_back(e);
    }
    size_t payloadStart = 16 + (size_t)count * 16;
    pm.payload.assign(blob.begin() + payloadStart, blob.end());
    return true;
}

bool Packer::readWatermark(const std::string& packed_path, std::string& out, std::string& err) {
    std::vector<uint8_t> blob;
    if (!loadMetaSection(packed_path, blob, err)) return false;
    ParsedMeta pm;
    if (!parseMeta(blob, pm, err)) return false;
    for (const auto& e : pm.entries) {
        if (e.type == META_WATERMARK && e.off + e.size <= pm.payload.size()) {
            out.assign(reinterpret_cast<const char*>(pm.payload.data() + e.off), e.size);
            return true;
        }
    }
    err = "no watermark embedded in this image";
    return false;
}

bool Packer::listVirtualFiles(const std::string& packed_path, std::vector<std::string>& names, std::string& err) {
    std::vector<uint8_t> blob;
    if (!loadMetaSection(packed_path, blob, err)) return false;
    ParsedMeta pm;
    if (!parseMeta(blob, pm, err)) return false;
    names.clear();
    for (const auto& e : pm.entries) {
        if (e.type != META_VFILE) continue;
        if (e.off + 4 > pm.payload.size()) continue;
        uint32_t nlen = 0; memcpy(&nlen, pm.payload.data() + e.off, 4);
        if (e.off + 4 + nlen > pm.payload.size()) continue;
        names.emplace_back(reinterpret_cast<const char*>(pm.payload.data() + e.off + 4), nlen);
    }
    return true;
}

bool Packer::extractVirtualFile(const std::string& packed_path, const std::string& name,
                                std::vector<uint8_t>& out, std::string& err) {
    std::vector<uint8_t> blob;
    if (!loadMetaSection(packed_path, blob, err)) return false;
    ParsedMeta pm;
    if (!parseMeta(blob, pm, err)) return false;
    uint32_t want = metaFnv1a32Str(name);
    for (const auto& e : pm.entries) {
        if (e.type != META_VFILE || e.hash != want) continue;
        if (e.off + 8 > pm.payload.size()) continue;
        uint32_t nlen = 0; memcpy(&nlen, pm.payload.data() + e.off, 4);
        size_t dataLenOff = e.off + 4 + nlen;
        while (dataLenOff & 3) dataLenOff++;
        if (dataLenOff + 4 > pm.payload.size()) continue;
        uint32_t dlen = 0; memcpy(&dlen, pm.payload.data() + dataLenOff, 4);
        size_t dstart = dataLenOff + 4;
        if (dstart + dlen > pm.payload.size()) continue;
        out.assign(pm.payload.begin() + dstart, pm.payload.begin() + dstart + dlen);
        return true;
    }
    err = "virtual file not found: " + name;
    return false;
}

} // namespace np
