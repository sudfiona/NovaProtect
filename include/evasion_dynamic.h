#pragma once
// NovaProtect dynamic evasion: host classification model plus hand-encoded
// x64 anti-analysis stubs.
//
// The stubs follow the same contract as anti_debug.h --
//
//     uint32_t fn(void);      // 0 = clean, 1 = detected, 2 = unavailable
//
// -- use no import table entries (no IAT walk required, no fixups), preserve
// every non-volatile register (rbx, rbp, rsi, rdi, r12-r15) and only clobber
// the volatile set (rax, rcx, rdx, r8-r11).

#include "evasion.h"

#include <cstdint>
#include <string>
#include <vector>

namespace np {

// Measured host facts. A field left at its "unknown" value must not score:
// a missing measurement is not evidence.
struct HostSignals {
    bool hypervisor_cpuid = false;
    uint32_t logical_cpus = 0;         // 0 = unknown
    uint64_t ram_mb = 0;               // 0 = unknown
    uint32_t process_count = 0;        // 0 = unknown
    uint32_t uptime_ms = 0;            // 0 = unknown
    int32_t mouse_idle_ms = -1;        // -1 = unknown
    uint32_t screen_width = 0;
    uint32_t screen_height = 0;
    uint32_t monitor_count = 0;
    bool template_hostname = false;    // WIN-XXXX / DESKTOP-XXXX style
    bool vendor_module_present = false;// analysis vendor DLL in the process
    bool debug_heap = false;           // PEB->NtGlobalFlag & 0x70
    bool debugger_attached = false;
    uint32_t suspicious_module_paths = 0;
};

struct HostVerdict {
    uint32_t score = 0;
    uint32_t threshold = 0;
    bool blocked = false;
    bool strong_evidence = false;
    std::vector<std::string> reasons;

    std::string summary() const;
};

// Reference implementation of the weighted score the runtime blob applies.
// Keeping it in the engine makes the weights testable and lets the UI show the
// same number the protected image will compute.
class DynamicEvader {
public:
    explicit DynamicEvader(const EvasionConfig& cfg = EvasionConfig::forProfile(EvasionProfile::Balanced));

    HostVerdict classify(const HostSignals& host) const;

    // --- x64 stubs -------------------------------------------------------
    std::vector<uint8_t> emitHypervisorCheck() const;        // CPUID leaf 1 ECX bit 31
    std::vector<uint8_t> emitPebDebugCheck() const;          // PEB->BeingDebugged
    std::vector<uint8_t> emitNtGlobalFlagCheck() const;      // PEB->NtGlobalFlag & 0x70
    std::vector<uint8_t> emitRdtscTimingCheck(uint32_t cycles) const;
    std::vector<uint8_t> emitDelayGate(uint32_t ms) const;   // busy wait, returns 0

    // Compose the enabled stubs into one routine. Returns the check id of the
    // first tripped probe (0 when clean), matching the runtime's id table.
    std::vector<uint8_t> emitCombinedProbe(std::vector<uint32_t>* ids_out = nullptr) const;

    // Structural verifier (single trailing RET, no early RET, no INT3).
    static bool verifyStub(const std::vector<uint8_t>& code, std::string* why = nullptr);

    const EvasionConfig& config() const { return cfg_; }

private:
    EvasionConfig cfg_;
};

} // namespace np
