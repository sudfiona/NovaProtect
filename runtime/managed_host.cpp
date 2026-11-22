#include <windows.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <cpuid.h>
#include "../include/vmp_markers.h"
#include "../include/managed_envelope.h"

#pragma pack(push, 1)
struct ManagedTrailer {
    char magic[8];
    uint32_t version;
    uint32_t flags;
    uint64_t payload_offset;
    uint64_t payload_size;
    uint64_t original_size;
    uint64_t integrity;
    uint64_t nonce;
    uint8_t masked_key[16];
    uint32_t original_name_length;
    char original_name[260];
    // v3 gate block (absent on v2 trailers; the host zero-fills then).
    uint32_t gate_flags;
    uint32_t anti_debug_level;
    uint32_t anti_vm_level;
    uint64_t license_hash;
    uint64_t activation_machine;
    uint32_t min_cpu_count;
    uint32_t min_ram_mb;
    uint32_t min_uptime_ms;
    uint32_t min_screen_width;
    uint32_t min_screen_height;
    uint32_t min_monitor_count;
    uint32_t sandbox_score_threshold;
    uint32_t env_score_threshold;
    uint32_t license_key_length;
    uint8_t  license_key_masked[32];
};
#pragma pack(pop)

static constexpr std::array<uint8_t, 16> kKeyMask = {
    0x4E, 0x6F, 0x76, 0x61, 0x50, 0x72, 0x6F, 0x74,
    0x65, 0x63, 0x74, 0x32, 0x2E, 0x30, 0x21, 0xA7
};

static uint64_t fnv1a64(const uint8_t* data, size_t size) {
    uint64_t hash = 0xCBF29CE484222325ull;
    for (size_t i = 0; i < size; ++i) {
        hash ^= data[i];
        hash *= 0x100000001B3ull;
    }
    return hash;
}

static void xteaBlock(uint32_t& left, uint32_t& right, const uint32_t key[4]) {
    VMProtectBeginUltra("NovaProtect.ManagedPayloadCipher");
    uint32_t sum = 0;
    constexpr uint32_t delta = 0x9E3779B9u;
    for (int round = 0; round < 32; ++round) {
        left += (((right << 4) ^ (right >> 5)) + right) ^ (sum + key[sum & 3]);
        sum += delta;
        right += (((left << 4) ^ (left >> 5)) + left) ^ (sum + key[(sum >> 11) & 3]);
    }
    VMProtectEnd();
}

static void cryptPayload(std::vector<uint8_t>& data, const std::array<uint8_t, 16>& keyBytes, uint64_t nonce) {
    uint32_t key[4]{};
    std::memcpy(key, keyBytes.data(), sizeof(key));
    for (uint64_t offset = 0, counter = 0; offset < data.size(); offset += 8, ++counter) {
        uint32_t left = static_cast<uint32_t>(nonce ^ counter);
        uint32_t right = static_cast<uint32_t>((nonce >> 32) ^ (counter * 0x9E3779B9ull));
        xteaBlock(left, right, key);
        uint8_t stream[8];
        std::memcpy(stream, &left, 4);
        std::memcpy(stream + 4, &right, 4);
        const size_t count = std::min<size_t>(8, data.size() - static_cast<size_t>(offset));
        for (size_t i = 0; i < count; ++i) data[static_cast<size_t>(offset) + i] ^= stream[i];
    }
}

static std::wstring modulePath() {
    std::wstring path(32768, L'\0');
    const DWORD length = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
    path.resize(length);
    return path;
}

static std::wstring utf8ToWide(const char* data, int length) {
    const int required = MultiByteToWideChar(CP_UTF8, 0, data, length, nullptr, 0);
    if (required <= 0) return L"managed-payload.exe";
    std::wstring value(required, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, data, length, value.data(), required);
    const size_t slash = value.find_last_of(L"\\/");
    if (slash != std::wstring::npos) value.erase(0, slash + 1);
    return value.empty() ? L"managed-payload.exe" : value;
}

static const wchar_t* commandLineTail(const wchar_t* line) {
    if (!line) return L"";
    bool quoted = false;
    while (*line) {
        if (*line == L'"') quoted = !quoted;
        else if (!quoted && (*line == L' ' || *line == L'\t')) break;
        ++line;
    }
    while (*line == L' ' || *line == L'\t') ++line;
    return line;
}

// ---- machine identity (must match src/main.cpp current_machine_id) --------
static uint64_t fnv64_bytes(const void* bytes, size_t size, uint64_t hash = 0xCBF29CE484222325ull) {
    const auto* p = static_cast<const uint8_t*>(bytes);
    for (size_t i = 0; i < size; ++i) {
        hash ^= p[i];
        hash *= 0x100000001B3ull;
    }
    return hash;
}

static uint64_t volumeSerial() {
    wchar_t sysDir[MAX_PATH]{};
    if (GetSystemDirectoryW(sysDir, MAX_PATH) == 0) return 0;
    wchar_t root[4] = { sysDir[0], L':', L'\\', 0 };
    DWORD serial = 0;
    if (!GetVolumeInformationW(root, nullptr, 0, &serial, nullptr, nullptr, nullptr, 0)) return 0;
    return serial;
}

static uint64_t machineGuidHash() {
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SOFTWARE\\Microsoft\\Cryptography",
                      0, KEY_READ | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS) return 0;
    wchar_t guid[64]{};
    DWORD size = sizeof(guid) - sizeof(wchar_t);
    DWORD type = 0;
    const LSTATUS rc = RegQueryValueExW(key, L"MachineGuid", nullptr, &type,
                                        reinterpret_cast<LPBYTE>(guid), &size);
    RegCloseKey(key);
    if (rc != ERROR_SUCCESS || type != REG_SZ) return 0;
    uint64_t h = 0xCBF29CE484222325ull;
    for (DWORD i = 0; i < size / sizeof(wchar_t) && guid[i]; ++i) {
        const uint8_t lo = static_cast<uint8_t>(guid[i] & 0xFF);
        const uint8_t hi = static_cast<uint8_t>((guid[i] >> 8) & 0xFF);
        h = fnv64_bytes(&lo, 1, h);
        h = fnv64_bytes(&hi, 1, h);
    }
    return h;
}

static uint64_t currentMachineId() {
    unsigned int a = 0, b = 0, c = 0, d = 0;
    uint64_t h = 0xCBF29CE484222325ull;
    if (__get_cpuid(0, &a, &b, &c, &d)) {
        h = fnv64_bytes(&b, sizeof(b), h);
        h = fnv64_bytes(&d, sizeof(d), h);
        h = fnv64_bytes(&c, sizeof(c), h);
    }
    if (__get_cpuid(1, &a, &b, &c, &d)) {
        h = fnv64_bytes(&a, sizeof(a), h);
        h = fnv64_bytes(&c, sizeof(c), h);
        h = fnv64_bytes(&d, sizeof(d), h);
    }
    if (__get_cpuid_count(7, 0, &a, &b, &c, &d)) {
        h = fnv64_bytes(&b, sizeof(b), h);
        h = fnv64_bytes(&c, sizeof(c), h);
        h = fnv64_bytes(&d, sizeof(d), h);
    }
    const uint64_t vs = volumeSerial();
    const uint64_t mg = machineGuidHash();
    h = fnv64_bytes(&vs, sizeof(vs), h);
    h = fnv64_bytes(&mg, sizeof(mg), h);
    return h;
}

// ---- runtime gates --------------------------------------------------------
// Fail-closed: any gate that was baked into the trailer must pass before the
// CLR payload is written to disk. Exit codes in the 80s are gate failures so
// they are distinguishable from trailer/IO errors (70-77).

static bool gateAntiDebug(uint32_t level) {
    if (level == 0) return true;
    // x64 PEB lives at gs:[0x60] (x86 used fs:[0x30]).
    const auto* peb = reinterpret_cast<const uint8_t*>(__readgsqword(0x60));
    if (!peb) return false;
    if (peb[2] != 0) return false;                       // BeingDebugged
    const uint32_t ntGlobal = *reinterpret_cast<const uint32_t*>(peb + 0xBC);
    if ((ntGlobal & 0x70) == 0x70) return false;         // NtGlobalFlag
    // PEB.ProcessHeap is at +0x30 on x64; Heap.Flags at +0x70, ForceFlags at +0x74.
    const auto* heap = *reinterpret_cast<uint8_t* const*>(peb + 0x30);
    if (heap) {
        const uint32_t forceFlags = *reinterpret_cast<const uint32_t*>(heap + 0x74);
        if (forceFlags != 0) return false;
    }
    if (level >= 2) {
        // Coarse timing: a breakpoint-stepped run inflates the CPUID+RDTSC gap.
        LARGE_INTEGER f, c0, c1;
        QueryPerformanceFrequency(&f);
        QueryPerformanceCounter(&c0);
        for (int i = 0; i < 64; ++i) {
            unsigned int a, b, c, d;
            (void)__get_cpuid(0, &a, &b, &c, &d);
        }
        QueryPerformanceCounter(&c1);
        const double ms = (c1.QuadPart - c0.QuadPart) * 1000.0 / f.QuadPart;
        if (ms > 50.0) return false;
    }
    return true;
}

static bool gateAntiVm(uint32_t level) {
    if (level == 0) return true;
    // Block third-party hypervisors only; Microsoft Hv (VBS/Memory Integrity)
    // is allowed so ordinary physical hosts keep working.
    unsigned int a = 0, b = 0, c = 0, d = 0;
    if (!__get_cpuid(0x40000000, &a, &b, &c, &d)) return true;
    const uint32_t ebx = b;
    const uint32_t ecx = c;
    const uint32_t edx = d;
    struct { uint32_t b, c, d; } vendors[] = {
        { 0x61774D56u, 0x4D567265u, 0x65726177u }, // VMware
        { 0x4B4D564Bu, 0x564B4D56u, 0x0000004Du }, // KVM
        { 0x566E6558u, 0x65584D4Du, 0x4D4D566Eu }, // Xen
        { 0x786F4256u, 0x786F4256u, 0x786F4256u }, // VBox
        { 0x206C7270u, 0x65707968u, 0x20207672u }, // bhyve
    };
    for (const auto& v : vendors) {
        if (ebx == v.b && ecx == v.c && edx == v.d) return false;
    }
    return true;
}

static bool gateLicense(const ManagedTrailer& t) {
    if (!(t.gate_flags & np::kManagedLicense)) return true;
    if (t.license_hash == 0) return true; // key-less build: gate disarmed
    // The trailer carries FNV-1a64 of the plaintext key. The host recomputes
    // the same fold over the masked key material that rides next to it, so the
    // plaintext never appears in the file.
    uint8_t key[32]{};
    const uint32_t len = t.license_key_length > 32 ? 32 : t.license_key_length;
    for (uint32_t i = 0; i < len; ++i) key[i] = t.license_key_masked[i] ^ 0xA5u;
    if (len == 0) return false;
    return fnv1a64(key, len) == t.license_hash;
}

static bool gateActivation(uint64_t expected) {
    if (expected == 0) return true;
    return currentMachineId() == expected;
}

static bool gateEnv(const ManagedTrailer& t) {
    if (!(t.gate_flags & np::kManagedEnvCheck)) return true;
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    if (si.dwNumberOfProcessors < t.min_cpu_count) return false;
    MEMORYSTATUSEX ms{ sizeof(ms) };
    if (GlobalMemoryStatusEx(&ms) && ms.ullTotalPhys / (1024ull * 1024ull) < t.min_ram_mb) return false;
    const ULONGLONG tick = GetTickCount64();
    if (tick < t.min_uptime_ms) return false;
    const int sx = GetSystemMetrics(SM_CXSCREEN);
    const int sy = GetSystemMetrics(SM_CYSCREEN);
    if (sx < static_cast<int>(t.min_screen_width) || sy < static_cast<int>(t.min_screen_height)) return false;
    if (GetSystemMetrics(SM_CMONITORS) < static_cast<int>(t.min_monitor_count)) return false;
    // Interactive desktop: a window station without a visible desktop scores.
    if (GetSystemMetrics(SM_CMOUSEBUTTONS) <= 0) return false;
    return true;
}

static bool gateSandbox(const ManagedTrailer& t) {
    if (!(t.gate_flags & np::kManagedSandboxGuard)) return true;
    int score = 0;
    // Coarse host score: each signal adds weight; threshold from the trailer.
    wchar_t computer[MAX_COMPUTERNAME_LENGTH + 1]{};
    DWORD n = MAX_COMPUTERNAME_LENGTH + 1;
    if (GetComputerNameW(computer, &n)) {
        const std::wstring name(computer);
        if (name.find(L"DESKTOP-") == 0) score += 5;
        if (name.find(L"WIN-") == 0) score += 15;
        if (name.find(L"TEST") != std::wstring::npos ||
            name.find(L"VIRUS") != std::wstring::npos ||
            name.find(L"SANDBOX") != std::wstring::npos) score += 40;
    }
    wchar_t user[64]{};
    n = 64;
    if (GetUserNameW(user, &n)) {
        const std::wstring u(user);
        if (u == L"admin" || u == L"CurrentUser" || u == L"User") score += 15;
    }
    // Few visible windows is a classic sandbox tell.
    if (GetWindowTextW(GetDesktopWindow(), nullptr, 0) == 0) score += 10;
    return score < static_cast<int>(t.sandbox_score_threshold ? t.sandbox_score_threshold : 40);
}

static bool gateAntiDump() {
    // Cheap sanity: the image we are running from must still look like a PE
    // with a plausible size. A mid-flight dump-and-patch usually breaks this.
    const auto self = modulePath();
    HANDLE h = CreateFileW(self.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER sz{};
    const BOOL ok = GetFileSizeEx(h, &sz);
    CloseHandle(h);
    if (!ok || sz.QuadPart < 4096 || sz.QuadPart > 256ll * 1024 * 1024) return false;
    const auto* base = reinterpret_cast<const uint8_t*>(GetModuleHandleW(nullptr));
    if (!base || base[0] != 'M' || base[1] != 'Z') return false;
    return true;
}

int wmain() {
    const std::wstring self = modulePath();
    HANDLE file = CreateFileW(self.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (file == INVALID_HANDLE_VALUE) return 70;

    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file, &size) || size.QuadPart < static_cast<LONGLONG>(sizeof(ManagedTrailer))) {
        CloseHandle(file);
        return 71;
    }
    ManagedTrailer trailer{};
    LARGE_INTEGER trailerOffset{};
    trailerOffset.QuadPart = size.QuadPart - sizeof(trailer);
    SetFilePointerEx(file, trailerOffset, nullptr, FILE_BEGIN);
    DWORD read = 0;
    if (!ReadFile(file, &trailer, sizeof(trailer), &read, nullptr) || read != sizeof(trailer) ||
        std::memcmp(trailer.magic, "NVPE2\0\0", 8) != 0 ||
        (trailer.version != 2 && trailer.version != 3) ||
        trailer.payload_offset + trailer.payload_size > static_cast<uint64_t>(trailerOffset.QuadPart)) {
        CloseHandle(file);
        SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
        RaiseFailFastException(nullptr, nullptr, 0);
        TerminateProcess(GetCurrentProcess(), 0xC0000409);
        return 72;
    }
    // v2 trailers carry no gate block: zero it so the checks below no-op.
    if (trailer.version < 3) {
        trailer.gate_flags = 0;
        trailer.anti_debug_level = 0;
        trailer.anti_vm_level = 0;
        trailer.license_hash = 0;
        trailer.activation_machine = 0;
    }

    // ---- gates run BEFORE the payload is materialised on disk -------------
    if (!gateAntiDebug(trailer.anti_debug_level)) return 80;
    if (!gateAntiVm(trailer.anti_vm_level)) return 81;
    if ((trailer.gate_flags & np::kManagedLicense) && !gateLicense(trailer)) return 82;
    if ((trailer.gate_flags & np::kManagedActivation) && !gateActivation(trailer.activation_machine)) return 83;
    if (!gateEnv(trailer)) return 84;
    if (!gateSandbox(trailer)) return 85;
    if ((trailer.gate_flags & np::kManagedAntiDump) && !gateAntiDump()) return 86;

    std::vector<uint8_t> payload(static_cast<size_t>(trailer.payload_size));
    LARGE_INTEGER payloadOffset{};
    payloadOffset.QuadPart = static_cast<LONGLONG>(trailer.payload_offset);
    SetFilePointerEx(file, payloadOffset, nullptr, FILE_BEGIN);
    if (!ReadFile(file, payload.data(), static_cast<DWORD>(payload.size()), &read, nullptr) || read != payload.size()) {
        CloseHandle(file);
        return 73;
    }
    CloseHandle(file);

    std::array<uint8_t, 16> key{};
    for (size_t i = 0; i < key.size(); ++i) key[i] = trailer.masked_key[i] ^ kKeyMask[i];
    cryptPayload(payload, key, trailer.nonce);
    if (payload.size() != trailer.original_size || fnv1a64(payload.data(), payload.size()) != trailer.integrity) return 74;

    const size_t slash = self.find_last_of(L"\\/");
    const std::wstring directory = slash == std::wstring::npos ? L"." : self.substr(0, slash);
    const std::wstring originalName = utf8ToWide(trailer.original_name,
        static_cast<int>(std::min<uint32_t>(trailer.original_name_length, sizeof(trailer.original_name))));
    wchar_t cacheName[96]{};
    std::swprintf(cacheName, 96, L".novaprotect-%016llX-", static_cast<unsigned long long>(trailer.integrity));
    const std::wstring extracted = directory + L"\\" + cacheName + originalName;

    HANDLE output = CreateFileW(extracted.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                                FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_TEMPORARY, nullptr);
    if (output == INVALID_HANDLE_VALUE) return 75;
    DWORD written = 0;
    const bool wrote = WriteFile(output, payload.data(), static_cast<DWORD>(payload.size()), &written, nullptr) &&
                       written == payload.size();
    FlushFileBuffers(output);
    CloseHandle(output);
    if (!wrote) {
        DeleteFileW(extracted.c_str());
        return 76;
    }

    std::wstring childCommand = L"\"" + extracted + L"\"";
    const wchar_t* tail = commandLineTail(GetCommandLineW());
    if (tail && *tail) childCommand += L" " + std::wstring(tail);
    std::vector<wchar_t> command(childCommand.begin(), childCommand.end());
    command.push_back(L'\0');

    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    const BOOL started = CreateProcessW(extracted.c_str(), command.data(), nullptr, nullptr, TRUE, 0, nullptr,
                                        directory.c_str(), &startup, &process);
    if (!started) {
        DeleteFileW(extracted.c_str());
        return 77;
    }
    WaitForSingleObject(process.hProcess, INFINITE);
    DWORD exitCode = 1;
    GetExitCodeProcess(process.hProcess, &exitCode);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    for (int attempt = 0; attempt < 20 && !DeleteFileW(extracted.c_str()); ++attempt) Sleep(50);
    return static_cast<int>(exitCode);
}
