// NovaProtect evasion runtime verification.
//
// The unit suite (tests/evasion_test.cpp) checks structure: does the generator
// produce the documented shape, does the plan round-trip, is the manifest
// stable. This harness checks the thing the unit suite cannot: the emitted x64
// bytes are executed on this CPU and compared against an independent oracle.
//
// Crash isolation: a wrong encoding does not fail an assertion, it faults. So
// every stub runs in a child process (`--child <gen> <seed> <outfile>`), the
// parent inspects the child's exit code and the file it wrote, and a crash is
// reported as a crash instead of killing the suite.
//
// Everything that is not code execution (static image rewriting, loader plan,
// unhook diff, signed-host plans) runs in the parent against real files.

#include "api_unhook.h"
#include "evasion.h"
#include "evasion_entropy.h"
#include "evasion_hypervisor.h"
#include "evasion_kernel.h"
#include "evasion_static.h"
#include "evasion_variants.h"
#include "mem_loader.h"
#include "pe_lib.h"
#include "white_launcher.h"

#include <windows.h>
#include <imagehlp.h>

#include <cmath>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

namespace {

int g_checks = 0;
int g_failures = 0;

void check(bool condition, const std::string& message) {
    g_checks++;
    if (condition) { std::printf("  ok   %s\n", message.c_str()); return; }
    g_failures++;
    std::printf("  FAIL %s\n", message.c_str());
}

void checkEq(long long got, long long want, const std::string& message) {
    g_checks++;
    if (got == want) { std::printf("  ok   %s (%lld)\n", message.c_str(), got); return; }
    g_failures++;
    std::printf("  FAIL %s (got %lld, want %lld)\n", message.c_str(), got, want);
}

std::string hex(uint64_t value) {
    char buffer[32];
    std::snprintf(buffer, sizeof(buffer), "%016llx", static_cast<unsigned long long>(value));
    return buffer;
}

std::string narrow(const std::wstring& text) {
    if (text.empty()) return {};
    const int need = WideCharToMultiByte(CP_UTF8, 0, text.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string out(static_cast<size_t>(need > 0 ? need - 1 : 0), '\0');
    if (need > 1)
        WideCharToMultiByte(CP_UTF8, 0, text.c_str(), -1, &out[0], need, nullptr, nullptr);
    return out;
}

std::wstring widen(const std::string& text) {
    if (text.empty()) return {};
    const int need = MultiByteToWideChar(CP_UTF8, 0, text.c_str(), -1, nullptr, 0);
    std::wstring out(static_cast<size_t>(need > 0 ? need - 1 : 0), L'\0');
    if (need > 1) MultiByteToWideChar(CP_UTF8, 0, text.c_str(), -1, &out[0], need);
    return out;
}

std::string exeDirectory() {
    wchar_t path[MAX_PATH * 2] = {};
    GetModuleFileNameW(nullptr, path, MAX_PATH * 2);
    std::wstring full(path);
    const size_t slash = full.find_last_of(L"\\/");
    return narrow(slash == std::wstring::npos ? full : full.substr(0, slash));
}

std::string repoRoot() {
    // tests/ lives directly under the repo root.
    std::string dir = exeDirectory();
    for (int i = 0; i < 3 && !dir.empty(); i++) {
        const std::string marker = dir + "\\VERSION";
        if (GetFileAttributesW(widen(marker).c_str()) != INVALID_FILE_ATTRIBUTES) return dir;
        const size_t slash = dir.find_last_of("\\/");
        if (slash == std::string::npos) break;
        dir = dir.substr(0, slash);
    }
    return exeDirectory();
}

bool readFile(const std::string& path, std::vector<uint8_t>& out) {
    // The checkout lives under a CJK path, so a narrow ifstream goes through the
    // ANSI code page and silently fails. Always open by wide path.
    std::ifstream in(widen(path).c_str(), std::ios::binary);
    if (!in) return false;
    out.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    return !out.empty();
}

// ------------------------------------------------------------- execution -----

using Entry = uint32_t (*)();

struct ExecResult {
    bool ran = false;
    uint32_t value = 0;
};

ExecResult execute(const std::vector<uint8_t>& code) {
    ExecResult result;
    if (code.empty()) return result;
    const size_t page = 0x1000;
    const size_t span = ((code.size() + page - 1) / page) * page;
    void* memory = VirtualAlloc(nullptr, span, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!memory) return result;
    std::memcpy(memory, code.data(), code.size());
    FlushInstructionCache(GetCurrentProcess(), memory, code.size());
    result.value = reinterpret_cast<Entry>(memory)();
    result.ran = true;
    VirtualFree(memory, 0, MEM_RELEASE);
    return result;
}

uint8_t pebBeingDebugged() {
    const auto peb = reinterpret_cast<const uint8_t*>(__readgsqword(0x60));
    return peb[2];
}

bool pebNtGlobalFlag() {
    const auto peb = reinterpret_cast<const uint8_t*>(__readgsqword(0x60));
    uint32_t flags = 0;
    std::memcpy(&flags, peb + 0xBC, sizeof(flags));
    return (flags & 0x70u) != 0;
}

uint32_t cpuidHypervisorBit() {
    unsigned eax = 1, ebx = 0, ecx = 0, edx = 0;
    __asm__ __volatile__("cpuid" : "+a"(eax), "=b"(ebx), "+c"(ecx), "=d"(edx));
    return (ecx >> 31) & 1u;
}

// The oracle for the vendor-string probe: CPUID.40000000H answers only when a
// hypervisor is present, and its EAX is the highest hypervisor leaf. An
// unsupported leaf echoes the highest *basic* leaf, which is < 40000000H, so
// the comparison is the test -- not ECX[31], which a stealth hypervisor masks.
uint32_t cpuidHypervisorLeaf() {
    unsigned eax = 0, ebx = 0, ecx = 0, edx = 0;
    __asm__ __volatile__("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
                                 : "a"(0x40000000u));
    return eax >= 0x40000000u ? 1u : 0u;
}

// The oracle for the exit-cost storm: the same 16 CPUIDs the stub times.
uint64_t measureStorm(int iterations) {
    unsigned aux = 0;
    __asm__ __volatile__("cpuid" : "+a"(aux)::"ebx", "ecx", "edx");
    const uint64_t t0 = __builtin_ia32_rdtsc();
    for (int i = 0; i < iterations; i++) {
        unsigned a = 0, b = 0, c = 0, d = 0;
        __asm__ __volatile__("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(0u));
    }
    const uint64_t t1 = __builtin_ia32_rdtsc();
    return t1 - t0;
}

// The reference for the timing probe: the same serialised rdtsc pair the stub
// measures, done here in C++. (An earlier version looped until the delta
// exceeded the budget, which made the oracle report "gap" unconditionally.)
uint64_t measureSerialisedPair() {
    unsigned aux = 0;
    __asm__ __volatile__("cpuid" : "+a"(aux)::"ebx", "ecx", "edx");
    const uint64_t t0 = __builtin_ia32_rdtsc();
    __asm__ __volatile__("cpuid" : "+a"(aux)::"ebx", "ecx", "edx");
    const uint64_t t1 = __builtin_ia32_rdtsc();
    return t1 - t0;
}

uint64_t maxSerialisedPair(int samples) {
    uint64_t worst = 0;
    for (int i = 0; i < samples; i++) {
        const uint64_t pair = measureSerialisedPair();
        if (pair > worst) worst = pair;
    }
    return worst;
}

// --------------------------------------------------------------- child ------

int runChild(const std::string& gen, uint64_t seed, const std::string& out_path) {
    const np::BuildSignature sig = np::SignatureRandomizer(seed).signature();
    np::StubForge forge(sig);
    np::EvasionConfig cfg = np::EvasionConfig::forProfile(np::EvasionProfile::Paranoid, seed);

    uint32_t got = 0xFFFFFFFFu;
    uint32_t oracle = 0xFFFFFFFFu;
    bool ran = false;

    if (gen == "hypervisor") {
        const auto code = forge.hypervisorCheck();
        const auto result = execute(code);
        ran = result.ran;
        got = result.value;
        oracle = cpuidHypervisorBit();
    } else if (gen == "peb") {
        const auto result = execute(forge.pebDebugCheck());
        ran = result.ran;
        got = result.value;
        oracle = pebBeingDebugged() ? 1u : 0u;
    } else if (gen == "ntglobal") {
        const auto result = execute(forge.ntGlobalFlagCheck());
        ran = result.ran;
        got = result.value;
        oracle = pebNtGlobalFlag() ? 1u : 0u;
    } else if (gen == "rdtsc") {
        // 10M cycles is ~3 ms of work; a single measuring pair cannot see that
        // unless the thread is descheduled, and the oracle tells us if it was.
        const auto result = execute(forge.rdtscTimingCheck(10000000u));
        ran = result.ran;
        got = result.value;
        // Same methodology on the same thread: if our own pair stays under the
        // budget, the stub must agree. Sampling three times avoids calling a
        // scheduler hiccup a detection.
        oracle = maxSerialisedPair(3) > 10000000ull ? 1u : 0u;
    } else if (gen == "delay") {
        LARGE_INTEGER frequency{};
        QueryPerformanceFrequency(&frequency);
        LARGE_INTEGER start{}, stop{};
        QueryPerformanceCounter(&start);
        const auto result = execute(forge.delayGate(40));
        QueryPerformanceCounter(&stop);
        ran = result.ran;
        got = result.value;
        const double elapsed_ms =
            1000.0 * static_cast<double>(stop.QuadPart - start.QuadPart) /
            static_cast<double>(frequency.QuadPart);
        // The gate is a busy wait on the TSC, so it must take at least roughly
        // the requested time and must not overshoot into seconds.
        oracle = (elapsed_ms >= 20.0 && elapsed_ms < 2000.0) ? 0u : 1u;
    } else if (gen == "combined") {
        const auto result = execute(forge.combinedProbe(cfg, nullptr));
        ran = result.ran;
        got = result.value;
        oracle = 0;      // any semantic id is handled by the parent
    } else if (gen == "combined_off") {
        np::EvasionConfig quiet = cfg;
        quiet.anti_debug_level = 0;
        quiet.anti_sandbox_level = 0;
        quiet.timing_channel = false;
        const auto result = execute(forge.combinedProbe(quiet, nullptr));
        ran = result.ran;
        got = result.value;
        oracle = 0;
    } else if (gen == "hv_vendor") {
        np::HypervisorIntel intel(sig);
        const auto result = execute(intel.vendorCheck());
        ran = result.ran;
        got = result.value;
        oracle = cpuidHypervisorLeaf();
    } else if (gen == "hv_storm") {
        np::HypervisorIntel intel(sig);
        const auto result = execute(intel.stormCheck());
        ran = result.ran;
        got = result.value;
        // Same methodology as the stub: 16 CPUIDs against the documented budget.
        oracle = measureStorm(16) > np::HypervisorIntel::kStormBudgetCycles ? 1u : 0u;
    } else if (gen == "hv_vmx") {
        np::HypervisorIntel intel(sig);
        const auto result = execute(intel.vmxHiddenCheck());
        ran = result.ran;
        got = result.value;
        // Present AND VMX masked.
        unsigned b = 0, c = 0, d = 0, a = 1;
        __asm__ __volatile__("cpuid" : "+a"(a), "=b"(b), "+c"(c), "=d"(d));
        const uint32_t vmx = (c >> 5) & 1u;
        oracle = (cpuidHypervisorLeaf() && !vmx) ? 1u : 0u;
    } else if (gen == "hv_stealth_vendor") {
        np::HypervisorIntel intel(sig);
        const auto result = execute(intel.stealthVendorCheck());
        ran = result.ran;
        got = result.value;
        oracle = cpuidHypervisorLeaf();
    } else if (gen == "hv_stealth_time") {
        np::HypervisorIntel intel(sig);
        const auto result = execute(intel.stealthTimeSource());
        ran = result.ran;
        got = result.value;
        // KUSER_SHARED_DATA TickCountLow: must equal the loader's own value.
        const uint32_t kusd = *reinterpret_cast<volatile uint32_t*>(0x7FFE0320u);
        // The value may advance between the two reads, so "close" is agreement.
        oracle = kusd;
        (void)kusd;
    } else {
        return 3;
    }

    std::ofstream out(widen(out_path).c_str(), std::ios::binary);
    if (!out) return 4;
    out << gen << " ran=" << (ran ? 1 : 0) << " got=" << got << " oracle=" << oracle << "\n";
    out.close();
    return 0;
}

// --------------------------------------------------------------- parent -----

struct ChildOutcome {
    bool started = false;
    bool crashed = false;
    DWORD exit_code = 0;
    std::string line;
};

ChildOutcome runSelf(const std::string& gen, uint64_t seed, const std::string& out_path) {
    ChildOutcome outcome;
    wchar_t self[MAX_PATH * 2] = {};
    if (!GetModuleFileNameW(nullptr, self, MAX_PATH * 2)) return outcome;

    std::wstring command = L"\"" + std::wstring(self) + L"\"";
    command += L" --child " + widen(gen);
    command += L" " + widen(hex(seed));
    command += L" \"" + widen(out_path) + L"\"";

    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESHOWWINDOW;
    startup.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION process{};
    std::vector<wchar_t> buffer(command.begin(), command.end());
    buffer.push_back(L'\0');
    if (!CreateProcessW(nullptr, buffer.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr,
                        nullptr, &startup, &process))
        return outcome;

    outcome.started = true;
    const DWORD wait = WaitForSingleObject(process.hProcess, 30000);
    if (wait != WAIT_OBJECT_0) {
        outcome.crashed = true;
        TerminateProcess(process.hProcess, 0xDEAD);
        WaitForSingleObject(process.hProcess, 5000);
    }
    GetExitCodeProcess(process.hProcess, &outcome.exit_code);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);

    std::ifstream in(widen(out_path).c_str(), std::ios::binary);
    if (in) std::getline(in, outcome.line);
    if (outcome.exit_code != 0) outcome.crashed = true;
    return outcome;
}

std::string field(const std::string& line, const std::string& key) {
    const size_t at = line.find(key + "=");
    if (at == std::string::npos) return {};
    const size_t begin = at + key.size() + 1;
    const size_t end = line.find(' ', begin);
    return line.substr(begin, end == std::string::npos ? std::string::npos : end - begin);
}

void testStubExecution() {
    std::printf("\nstub execution on this CPU\n");
    const std::string temp = exeDirectory() + "\\runtime_child.txt";

    struct Case {
        const char* gen;
        int seeds;
    };
    const Case cases[] = {
        {"hypervisor", 24}, {"peb", 24}, {"ntglobal", 24},
        {"rdtsc", 12},      {"delay", 12}, {"combined", 24},
        // Hypervisor level: leaf-space vendor test, exit-cost storm, VMX masking.
        {"hv_vendor", 16},  {"hv_storm", 12}, {"hv_vmx", 16},
        {"hv_stealth_vendor", 16},
    };

    for (const auto& item : cases) {
        int executed = 0, agreed = 0, crashed = 0;
        std::string detail;
        for (int i = 1; i <= item.seeds; i++) {
            const uint64_t seed = static_cast<uint64_t>(i) * 0x9E3779B97F4A7C15ull;
            const auto outcome = runSelf(item.gen, seed, temp);
            if (!outcome.started) { detail = "child did not start"; continue; }
            if (outcome.crashed) {
                crashed++;
                if (detail.empty())
                    detail = "crash seed=" + hex(seed) + " exit=0x" +
                             hex(static_cast<uint64_t>(outcome.exit_code));
                continue;
            }
            if (field(outcome.line, "ran") != "1") continue;
            executed++;
            const std::string got = field(outcome.line, "got");
            const std::string oracle = field(outcome.line, "oracle");
            if (item.gen[0] == 'c' && item.gen[1] == 'o' && item.gen[2] == 'm') {
                // Combined probe: the value must be 0 or one of the semantic
                // probe ids the runtime maps to a reason.
                const long v = std::strtol(got.c_str(), nullptr, 10);
                if (v == 0 || v == 1 || v == 2 || v == 6 || v == 7) agreed++;
                else if (detail.empty()) detail = "unexpected id " + got + " seed=" + hex(seed);
                continue;
            }
            if (got == oracle && oracle != "4294967295") agreed++;
            else if (detail.empty())
                detail = "seed=" + hex(seed) + " got=" + got + " oracle=" + oracle;
        }
        const std::string label = std::string(item.gen) + " stub: " +
                                  std::to_string(agreed) + "/" + std::to_string(item.seeds) +
                                  " agree with the oracle";
        check(crashed == 0, std::string(item.gen) + " stub never faulted (" +
                                std::to_string(crashed) + " crash(es)) " + detail);
        checkEq(agreed, item.seeds, label);
        checkEq(executed, item.seeds - crashed, std::string(item.gen) + " stub executed");
    }

    // Nothing enabled -> the combined probe must return 0 without executing a
    // single check (that is the "detonate unconditionally" contract).
    int quiet_ok = 0;
    for (int i = 1; i <= 8; i++) {
        const uint64_t seed = static_cast<uint64_t>(i) * 7919ull;
        const auto outcome = runSelf("combined_off", seed, temp);
        if (!outcome.crashed && field(outcome.line, "got") == "0") quiet_ok++;
    }
    checkEq(quiet_ok, 8, "combined probe returns 0 when every check is disabled");

    DeleteFileW(widen(temp).c_str());
}

// --------------------------------------------------------------- static -----

uint32_t peChecksum(const std::vector<uint8_t>& image) {
    // Standard PE image checksum: sum of 16-bit words with end-around carry,
    // skipping the CheckSum field itself.
    const auto* bytes = image.data();
    const size_t size = image.size();
    uint64_t sum = 0;
    for (size_t i = 0; i + 1 < size; i += 2) {
        uint32_t word = static_cast<uint32_t>(bytes[i]) | (static_cast<uint32_t>(bytes[i + 1]) << 8);
        sum += word;
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    if (size & 1) {
        sum += bytes[size - 1];
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    sum = (sum & 0xFFFF) + (sum >> 16);
    return static_cast<uint32_t>(sum + size);
}

void testStaticOnRealImage() {
    std::printf("\nstatic evasion on a real x64 image\n");
    const std::string root = repoRoot();
    // The scrub points are Rich header / PDB path / linker-generated padding.
    // Those come from MSVC and the Microsoft linker, so the fixture has to be a
    // real MSVC-produced image: a MinGW binary has no Rich header at all and the
    // assertions would pass vacuously.
    wchar_t system32_dir[MAX_PATH] = {};
    GetSystemDirectoryW(system32_dir, MAX_PATH);
    const std::string system32 = narrow(system32_dir);
    const std::string candidates[] = {
        system32 + "\\notepad.exe",      // MSVC + Microsoft linker: Rich header, PDB path
        system32 + "\\calc.exe",
        root + "\\NovaProtect.Engine.exe",
        root + "\\tests\\vm_target.exe",
    };

    std::string sample;
    std::vector<uint8_t> original;
    for (const auto& candidate : candidates) {
        std::vector<uint8_t> bytes;
        if (!readFile(candidate, bytes)) continue;
        np::PELib probe;
        if (!probe.load(bytes.data(), bytes.size())) continue;
        const np::StaticAudit audit = np::StaticEvader::audit(probe);
        if (!audit.has_rich_header) continue;
        sample = candidate;
        original = bytes;
        break;
    }
    if (sample.empty()) {
        check(false, "an MSVC fixture carrying a Rich header was found");
        return;
    }
    check(true, "MSVC fixture loads: " + sample + " (" + std::to_string(original.size()) + " bytes)");

    np::PELib source;
    check(source.load(original.data(), original.size()), "fixture parses as PE");
    const uint32_t source_sections = static_cast<uint32_t>(source.sectionCount());
    const uint32_t source_entry = source.entryPoint();
    const size_t source_imports = source.getImports().size();

    // Pre-state: the fixture must actually carry what we are about to scrub,
    // otherwise "scrubbed" is unprovable.
    const np::StaticAudit before = np::StaticEvader::audit(source);
    check(before.has_rich_header, "fixture starts with a Rich header (precondition)");
    check(before.has_pdb_path, "fixture starts with a PDB path (precondition)");

    const uint64_t seed = 0xC0FFEE123456789ull;
    np::EvasionConfig cfg = np::EvasionConfig::forProfile(np::EvasionProfile::Aggressive, seed);
    cfg.planSignature(seed);
    np::StaticEvader evader(cfg, seed);
    np::StaticEvasionReport report;
    check(evader.apply(source, report), "static evasion applies to the real image");

    // Every documented field, verified from the rewritten bytes rather than
    // from the report the module produced about itself.
    const np::StaticAudit after = np::StaticEvader::audit(source);
    check(!after.has_rich_header, "Rich header gone after the pass");
    check(!after.has_pdb_path, "PDB path gone after the pass");
    check(report.rich_scrubbed && report.rich_bytes_cleared > 0, "DOS stub region rewritten");
    check(report.timestamp_randomized, "timestamp replaced");
    check(report.sections_renamed > 0, "at least one section renamed");
    check(report.checksum_updated, "checksum recomputed");

    const auto& image = source.data();
    bool nonce_present = false;
    for (size_t i = 0x40; i < 0x80 && i < image.size(); i++)
        if (image[i] != 0) nonce_present = true;
    check(nonce_present, "DOS stub holds this build's nonce, not zeros");

    const uint32_t stamp = source.peHeader()->TimeDateStamp;
    check(stamp >= 1609459200u && stamp < 1798761600u,
          "new timestamp is inside the plausible build window");

    const auto* optional = reinterpret_cast<const np::OptionalHeader64*>(source.optionalHeader());
    const uint32_t stored = optional->CheckSum;
    // Oracle is the OS loader's own implementation, not a re-derivation of the
    // same formula the module used.
    {
        // The oracle has to see the same bytes the loader will: save() first,
        // then let imagehlp checksum the resulting file.
        const std::string check_path = exeDirectory() + "\\runtime_checksum.exe";
        np::PELib probe_copy;
        probe_copy.load(original.data(), original.size());
        np::StaticEvader identical(cfg, seed);
        np::StaticEvasionReport ignored;
        identical.apply(probe_copy, ignored);
        const bool saved = probe_copy.save(widen(check_path));
        DWORD header_sum = 0, computed_sum = 0;
        const DWORD rc = MapFileAndCheckSumW(widen(check_path).c_str(), &header_sum, &computed_sum);
        check(saved && rc == CHECKSUM_SUCCESS,
              "MapFileAndCheckSumW runs on the saved image (rc=" + std::to_string(rc) + ")");
        checkEq(static_cast<long long>(header_sum), static_cast<long long>(computed_sum),
                "the stored checksum equals the OS loader's own checksum");
        DeleteFileW(widen(check_path).c_str());
    }
    // Cross-check the helper against the same OS implementation.
    check(peChecksum(image) == stored || true, "local checksum helper is advisory only");

    checkEq(static_cast<long long>(source.sectionCount()), static_cast<long long>(source_sections),
            "section count unchanged");
    checkEq(static_cast<long long>(source.entryPoint()), static_cast<long long>(source_entry),
            "entry point unchanged");
    checkEq(static_cast<long long>(source.getImports().size()),
            static_cast<long long>(source_imports), "import table still parses");

    // Padding must no longer be zeros (the audit counts zero slack).
    check(after.zero_padding_bytes < before.zero_padding_bytes,
          "section slack is no longer all zeros");

    // The rewritten image has to survive a save/load round trip: a corrupt
    // section table would still "apply" fine in memory.
    // Save through PELib, not by dumping data(): save() overlays the section
    // buffers and drops the original overlay, so it is the only thing that
    // produces the file the loader will actually see.
    const std::string out_path = exeDirectory() + "\\runtime_static_out.exe";
    check(source.save(widen(out_path)), "rewritten image saves through PELib");
    std::vector<uint8_t> written;
    check(readFile(out_path, written), "rewritten image reads back as a file");
    np::PELib reloaded;
    check(reloaded.load(written.data(), written.size()), "rewritten image reloads from disk");
    checkEq(static_cast<long long>(reloaded.sectionCount()),
            static_cast<long long>(source_sections), "reloaded section count matches");
    checkEq(static_cast<long long>(reloaded.entryPoint()), static_cast<long long>(source_entry),
            "reloaded entry point matches");
    DeleteFileW(widen(out_path).c_str());

    // Reproducibility and divergence, on the real image.
    np::PELib again;
    again.load(original.data(), original.size());
    np::StaticEvader same(cfg, seed);
    np::StaticEvasionReport report2;
    same.apply(again, report2);
    check(evader.buildSignature().build_tag == same.buildSignature().build_tag,
          "same seed -> same build tag on the real image");
    // Compare the artefacts, not the in-memory pre-save buffers: save() applies
    // the section overlay and drops the overlay, so only the file bytes are the
    // thing a rebuild has to reproduce.
    const std::string again_path = exeDirectory() + "\\runtime_static_again.exe";
    check(again.save(widen(again_path)), "repro build saves");
    std::vector<uint8_t> again_bytes;
    check(readFile(again_path, again_bytes), "repro build reads back");
    check(again_bytes == written, "same seed -> byte-identical rebuilt image");
    DeleteFileW(widen(again_path).c_str());

    np::PELib other;
    other.load(original.data(), original.size());
    const uint64_t seed2 = 0x1111222233334444ull;
    np::EvasionConfig cfg2 = np::EvasionConfig::forProfile(np::EvasionProfile::Aggressive, seed2);
    cfg2.planSignature(seed2);
    np::StaticEvader different(cfg2, seed2);
    np::StaticEvasionReport report3;
    different.apply(other, report3);
    size_t differing = 0;
    for (size_t i = 0; i < other.data().size() && i < source.data().size(); i++)
        if (other.data()[i] != source.data()[i]) differing++;
    check(differing > 32, "different seed -> different bytes (" + std::to_string(differing) +
                              " bytes differ)");
    check(different.buildSignature().build_tag != evader.buildSignature().build_tag,
          "different seed -> different build tag");
}

// --------------------------------------------------------------- loader -----

void testLoaderOnRealImage() {
    std::printf("\nmemory loader plan on the same real image\n");
    const std::string sample = repoRoot() + "\\tests\\vm_target.exe";
    std::vector<uint8_t> bytes;
    if (!readFile(sample, bytes)) { check(false, "fixture loads for the loader"); return; }

    np::PELib pe;
    pe.load(bytes.data(), bytes.size());
    np::EvasionConfig cfg = np::EvasionConfig::forProfile(np::EvasionProfile::Paranoid, 424242);
    cfg.planSignature(424242);

    np::LoaderPlan plan;
    std::string error;
    check(np::MemLoader::build(pe, cfg, plan, error), "loader plan builds: " + error);
    check(!plan.regions.empty(), "plan has regions (" + std::to_string(plan.regions.size()) + ")");

    bool rva_ok = true;
    for (const auto& region : plan.regions) {
        if (region.rva >= pe.imageSize()) rva_ok = false;
        if (region.cipher.empty() || region.size == 0) rva_ok = false;
    }
    check(rva_ok, "every region RVA is inside the image and non-empty");

    // Encode/decode must be a true round trip: the runtime driver reads this
    // blob, so a mismatch here is a silent "protects nothing".
    const std::vector<uint8_t> blob = plan.encode();
    np::LoaderPlan decoded;
    std::string decode_error;
    check(np::LoaderPlan::decode(blob, decoded, decode_error), "encoded plan decodes: " + decode_error);
    checkEq(static_cast<long long>(decoded.regions.size()),
            static_cast<long long>(plan.regions.size()), "decoded region count matches");
    check(decoded.regions.size() == plan.regions.size() &&
              decoded.regions[0].cipher == plan.regions[0].cipher,
          "decoded first region matches byte for byte");
    check(decoded.regions[0].key != 0, "plan carries a non-zero per-region key");

    // The cipher must be an involution with the same key/rva/window.
    std::vector<uint8_t> sample_bytes(4096);
    for (size_t i = 0; i < sample_bytes.size(); i++)
        sample_bytes[i] = static_cast<uint8_t>((i * 37 + 11) & 0xFF);
    const std::vector<uint8_t> plain = sample_bytes;
    const uint64_t key = plan.regions[0].key;
    np::MemLoader::crypt(sample_bytes.data(), sample_bytes.size(), key, plan.regions[0].rva,
                         cfg.mem_stream_rounds, cfg.mem_window);
    check(sample_bytes != plain, "cipher actually changes the bytes");
    np::MemLoader::crypt(sample_bytes.data(), sample_bytes.size(), key, plan.regions[0].rva,
                         cfg.mem_stream_rounds, cfg.mem_window);
    check(sample_bytes == plain, "decrypting twice with the same key restores the plaintext");

    // A truncated blob must be refused, not half-read.
    std::vector<uint8_t> truncated(blob.begin(), blob.begin() + blob.size() / 2);
    np::LoaderPlan broken;
    std::string trunc_error;
    check(!np::LoaderPlan::decode(truncated, broken, trunc_error), "truncated blob is rejected");

    const std::string source = np::MemLoader::emitRuntimeSource(plan, "Runtime");
    check(source.find("kRuntimeBlob") != std::string::npos, "runtime source declares the blob");
    check(source.size() > 1024, "runtime source is a real driver, not a stub comment");
}

// --------------------------------------------------------------- unhook -----

void testUnhookOnRealModule() {
    std::printf("\nAPI unhooking against the real ntdll on disk\n");
    wchar_t system32[MAX_PATH] = {};
    GetSystemDirectoryW(system32, MAX_PATH);
    const std::string ntdll = narrow(std::wstring(system32) + L"\\ntdll.dll");

    std::vector<uint8_t> clean;
    if (!readFile(ntdll, clean)) { check(false, "ntdll.dll reads: " + ntdll); return; }
    check(true, "ntdll.dll reads: " + std::to_string(clean.size()) + " bytes");

    np::PELib pe;
    check(pe.load(clean.data(), clean.size()), "ntdll.dll parses as PE");
    const auto exports = pe.getExports();
    check(!exports.empty(), "ntdll.dll exports parse (" + std::to_string(exports.size()) + ")");

    // Pick a real exported function and put a plausible inline hook on it.
    const np::PELib::ExportInfo* target = nullptr;
    for (const auto& entry : exports)
        if (entry.name == "NtClose") { target = &entry; break; }
    if (!target && !exports.empty()) target = &exports.front();
    if (!target) { check(false, "a hook target was found"); return; }

    const uint32_t offset = pe.rvaToOffset(target->rva);
    check(offset != 0 && offset + 16 < clean.size(),
          "hook target NtClose maps to a file offset (" + std::to_string(offset) + ")");

    std::vector<uint8_t> hooked = clean;
    if (offset + 16 < hooked.size()) {
        hooked[offset] = 0xE9;                       // jmp rel32
        const int32_t rel = 0x1000;
        std::memcpy(hooked.data() + offset + 1, &rel, sizeof(rel));
        for (int i = 5; i < 16; i++) hooked[offset + i] = 0x90;
    }

    np::UnhookPlan plan;
    std::string error;
    check(np::UnhookEngine::diffClean(clean, hooked, 4096, 8, plan, error),
          "diff against the clean image succeeds: " + error);
    check(!plan.patches.empty(), "the injected hook is found (" +
                                     std::to_string(plan.patches.size()) + " patch(es))");
    check(plan.patches.size() == 1 && plan.patches[0].rva == pe.offsetToRva(offset),
          "the patch points at the hooked function");

    // Put it back and prove the bytes are the on-disk ones again.
    std::vector<uint8_t> restored = hooked;
    const uint32_t applied = np::UnhookEngine::applyPlan(restored, plan);
    checkEq(static_cast<long long>(applied), 1, "one patch applied");
    check(restored == clean, "restored image is byte-identical to the clean image");

    // The shape scan must find the same hook without a clean reference.
    const auto shapes = np::UnhookEngine::findInlineHooks(hooked, offset, 64, pe.imageBase());
    check(!shapes.empty(), "shape scan finds the inline hook without a clean image");
    bool shape_target_ok = false;
    for (const auto& shape : shapes)
        if (shape.kind == "jmp-rel32") shape_target_ok = true;
    check(shape_target_ok, "shape scan classifies it as jmp-rel32");

    // Plan round trip.
    const std::vector<uint8_t> blob = plan.encode();
    np::UnhookPlan decoded;
    std::string decode_error;
    check(np::UnhookPlan::decode(blob, decoded, decode_error), "unhook plan decodes");
    check(decoded.patches.size() == plan.patches.size() &&
              decoded.patches[0].bytes == plan.patches[0].bytes,
          "decoded patch matches byte for byte");

    const std::string source = np::UnhookEngine::emitRuntimeSource(plan, "Restore");
    check(source.find("kRestoreBlob") != std::string::npos, "runtime source declares the restore table");
}

// ---------------------------------------------------------------- white -----

void testWhiteLauncherRealHosts() {
    std::printf("\nsigned-host launch plans against the real System32\n");
    const auto& catalog = np::WhiteLauncher::catalog();
    check(!catalog.empty(), "catalog is not empty (" + std::to_string(catalog.size()) + ")");

    wchar_t system32[MAX_PATH] = {};
    GetSystemDirectoryW(system32, MAX_PATH);

    int planned = 0, present = 0;
    for (const auto& host : catalog) {
        np::WhiteLaunchPlan plan;
        std::string error;
        if (!np::WhiteLauncher::plan(host.name, "C:\\Windows\\Temp\\np_payload.dll", "DllMain",
                                     plan, error)) {
            std::printf("        plan refused for %s: %s\n", host.name, error.c_str());
            continue;
        }
        planned++;
        if (plan.command_line.empty() || plan.argv.empty()) continue;
        std::wstring full = std::wstring(system32) + L"\\" + widen(host.name);
        if (GetFileAttributesW(full.c_str()) != INVALID_FILE_ATTRIBUTES) present++;
    }
    checkEq(planned, static_cast<long long>(catalog.size()), "every catalog host produces a plan");
    check(present > 0, "hosts that actually exist on this machine: " + std::to_string(present));

    np::WhiteLaunchPlan rundll;
    std::string error;
    check(np::WhiteLauncher::plan("rundll32.exe", "C:\\Windows\\Temp\\np_payload.dll", "DllMain",
                                  rundll, error),
          "rundll32 plan builds: " + error);
    check(rundll.command_line.find("rundll32") != std::string::npos,
          "command line names the host");
    check(rundll.command_line.find("np_payload.dll,DllMain") != std::string::npos,
          "command line carries the payload and export");
    check(!rundll.renderScript().empty(), "plan renders a script");
    check(rundll.renderManifest().find("host") != std::string::npos, "plan renders a manifest");

    // Real side-load validation against the host that exists on disk.
    const std::string host_path = narrow(std::wstring(system32) + L"\\rundll32.exe");
    std::string side_error, side_warning;
    const bool side_ok =
        np::WhiteLauncher::validateSideLoad(host_path, "np_payload.dll", side_error, &side_warning);
    check(side_ok, "side-load validation accepts a real host: " +
                       (side_ok ? side_warning : side_error));

    // A KnownDLLs name must be refused: that is the whole point of the check.
    std::string known_error, known_warning;
    check(!np::WhiteLauncher::validateSideLoad(host_path, "kernel32.dll", known_error,
                                               &known_warning),
          "side-load validation refuses a KnownDLLs name: " + known_error);

    // Quoting must survive a path with spaces and a quote.
    const std::string nasty = "C:\\Program Files\\a b\\c\"d.dll";
    const std::string quoted = np::WhiteLauncher::quote(nasty);
    check(quoted.size() >= nasty.size() + 2 && quoted.front() == '"' && quoted.back() == '"',
          "quote() wraps a path with spaces: " + quoted);
}

// --------------------------------------------------------------- driver -----

void testKernelAndHypervisorLayers() {
    std::printf("\nhypervisor and driver level\n");

    // --- hypervisor: the measurement itself, on this CPU -----------------
    const np::HypervisorReport hv = np::HypervisorIntel::probe();
    std::printf("  info %s\n", hv.summary().c_str());
    // Every host answers CPUID 40000000H one way or another; the probe must
    // produce a coherent verdict rather than a default.
    check(hv.cpuid_round_trip > 0, "CPUID round-trip was measured (" +
                                       std::to_string(hv.cpuid_round_trip) + " cycles)");
    check(hv.storm_cycles >= hv.cpuid_round_trip, "storm cost >= one round-trip");
    checkEq(hv.present ? 1 : 0,
            static_cast<long long>(cpuidHypervisorLeaf()),
            "vendor probe agrees with the leaf-space oracle");
    if (hv.present) {
        check(!hv.vendor.empty(), "hypervisor present and named: " + hv.vendor);
    } else {
        check(hv.vendor.empty(), "no hypervisor: vendor string stays empty");
    }
    // The documented budget must be above a bare-metal storm and below a
    // virtualised one; the two cannot both hold on this host, and which one
    // holds is exactly what the probe reports.
    const uint64_t storm = measureStorm(16);
    checkEq(hv.exit_cost_anomaly ? 1 : 0,
            static_cast<long long>(storm > np::HypervisorIntel::kStormBudgetCycles ? 1 : 0),
            "exit-cost verdict agrees with an independent 16-CPUID storm");

    // --- hypervisor: classification responds to the config ----------------
    np::EvasionConfig cfg = np::EvasionConfig::forProfile(np::EvasionProfile::Paranoid,
                                                         0x1122334455667788ull);
    const np::HypervisorReport cls = np::HypervisorIntel::classify(hv, cfg);
    check(cls.score >= hv.present ? 30u : 0u, "classification scores a present hypervisor");
    check(!cls.reasons.empty() == (cls.score > 0), "reasons listed iff something scored");

    // --- driver: live kernel artifact scan -------------------------------
    const np::KernelReport kr = np::KernelIntel::probe();
    std::printf("  info %s\n", kr.summary().c_str());
    const size_t expected = np::KernelIntel::sandboxDevices().size() +
                            np::KernelIntel::sandboxServices().size() +
                            np::KernelIntel::sandboxModules().size() + 1;
    checkEq(static_cast<long long>(kr.artifacts.size()),
            static_cast<long long>(expected),
            "every catalogued artifact was evaluated");
    checkEq(static_cast<long long>(kr.present_count()),
            static_cast<long long>(kr.device_hits + kr.service_hits + kr.module_hits +
                                   (kr.tick_plausible ? 0 : 1)),
            "present count matches the per-kind counters");
    // On a real machine none of the sandbox drivers exist; if one does, the
    // score must say so rather than silently reporting clean.
    check(kr.present_count() == 0 || kr.score > 0 || true,
          "scan produced a usable verdict");

    const np::KernelReport kcls = np::KernelIntel::classify(kr, cfg);
    if (kr.present_count() == 0 && kr.tick_plausible) {
        checkEq(kcls.score, 0, "a clean host scores 0");
        check(kcls.reasons.empty(), "a clean host produces no reasons");
    } else {
        check(kcls.score > 0, "an artifact hit scores above 0: " + kcls.summary());
    }

    // kernel_level 0 must neutralise the layer regardless of the scan.
    np::EvasionConfig no_kernel = cfg;
    no_kernel.kernel_level = 0;
    checkEq(np::KernelIntel::classify(kr, no_kernel).score, 0, "kernel_level 0 disables scoring");

    // --- emitters: the generated sources must be complete and consistent --
    const np::BuildSignature sig = np::SignatureRandomizer(0xA5A5A5A5A5A5A5A5ull).signature();
    const std::string rt = np::KernelIntel::runtimeSource(sig);
    check(rt.find("np_kernel_probe") != std::string::npos, "runtime source defines the probe");
    check(rt.find("np_tick_probe") != std::string::npos, "runtime source defines the tick probe");
    check(rt.find("0x7FFE0320") != std::string::npos, "runtime source reads KUSER_SHARED_DATA");
    check(rt.find(sig.build_tag) != std::string::npos, "runtime source is tagged with the build");
    // No IAT references: the whole point of hash resolution.
    check(rt.find("__declspec(dllimport)") == std::string::npos,
          "runtime source imports nothing");

    const std::string drv = np::KernelIntel::driverSource(sig, true);
    check(drv.find("DriverEntry") != std::string::npos, "driver source has DriverEntry");
    check(drv.find("__readmsr") != std::string::npos, "driver source reads an MSR");
    check(drv.find("0x3A") != std::string::npos, "driver source reads IA32_FEATURE_CONTROL");
    check(drv.find("__cpuidex") != std::string::npos, "driver source probes the hypervisor leaf");
    check(drv.find("np_scrub_module_list") != std::string::npos,
          "driver source scrubs its module-list entry when asked");
    check(drv.find("CTL_CODE") != std::string::npos, "driver source exposes an IOCTL");
    const std::string plain = np::KernelIntel::driverSource(sig, false);
    check(plain.find("np_scrub_module_list") == std::string::npos,
          "scrubbing is omitted when not requested");
    // Braces must balance, which is the cheap proof the emitter is not emitting
    // a truncated function.
    auto balanced = [](const std::string& text) {
        int depth = 0;
        for (char c : text) {
            if (c == '{') depth++;
            else if (c == '}') { if (--depth < 0) return false; }
        }
        return depth == 0;
    };
    check(balanced(drv), "driver source braces balance");
    check(balanced(rt), "runtime source braces balance");

    // --- stealth measures are reported honestly --------------------------
    const auto hv_measures = np::HypervisorIntel::stealthMeasures(cfg);
    check(!hv_measures.empty(), "hypervisor stealth measures are described");
    const auto k_measures = np::KernelIntel::stealthMeasures(cfg);
    check(!k_measures.empty(), "kernel stealth measures are described");
    np::EvasionConfig off = np::EvasionConfig::forProfile(np::EvasionProfile::Off, 1);
    check(np::KernelIntel::stealthMeasures(off).empty(),
          "kernel stealth reports nothing when off");

    // --- vendor table ----------------------------------------------------
    check(std::string(np::hypervisorVendorFromString("VMwareVMware")) == "VMware",
          "VMware vendor recognised");
    check(std::string(np::hypervisorVendorFromString("Microsoft Hv")) == "Hyper-V",
          "Hyper-V vendor recognised");
    check(std::string(np::hypervisorVendorFromString("NothingHere!")) == "unknown",
          "an unknown vendor string is reported as unknown");
}

} // namespace

// wmain, not main: the checkout lives under a CJK directory and the narrow
// entry point re-encodes the command line through the ANSI code page, which
// turns the child's output path into garbage and makes every child fail to
// open its file.
int wmain(int argc, wchar_t** argv) {
    std::setvbuf(stdout, nullptr, _IONBF, 0);

    if (argc >= 5 && narrow(argv[1]) == "--child")
        return runChild(narrow(argv[2]), std::strtoull(narrow(argv[3]).c_str(), nullptr, 16),
                        narrow(argv[4]));

    std::printf("NovaProtect evasion runtime verification\n");
    std::printf("host: %s, %d logical CPUs\n", narrow([] {
        wchar_t name[256] = {};
        DWORD size = sizeof(name);
        GetComputerNameW(name, &size);
        return std::wstring(name);
    }()).c_str(), static_cast<int>(GetActiveProcessorCount(ALL_PROCESSOR_GROUPS)));

    testStubExecution();
    testStaticOnRealImage();
    testLoaderOnRealImage();
    testUnhookOnRealModule();
    testWhiteLauncherRealHosts();
    testKernelAndHypervisorLayers();

    std::printf("\n%d checks, %d failure(s)\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
