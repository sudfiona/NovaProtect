#pragma once

#include <cstdint>
#include <string>
#include <windows.h>

namespace np {

// Runtime gate flags written into the managed trailer. Bit meanings match the
// native NPP1 flag word where they overlap, so the UI/CLI wording stays true
// across both paths.
enum ManagedGateFlags : uint32_t {
    kManagedAntiDebug     = 1u << 0,  // PEB / NtGlobalFlag / heap checks
    kManagedAntiVm        = 1u << 1,  // third-party hypervisor vendor probe
    kManagedMemoryGuard   = 1u << 2,  // payload integrity re-check before launch
    kManagedLicense       = 1u << 3,  // license key hash gate
    kManagedActivation    = 1u << 4,  // machine-id binding gate
    kManagedSandboxGuard  = 1u << 5,  // coarse host-score gate
    kManagedAntiDump      = 1u << 6,  // module-list / image-size sanity
    kManagedEnvCheck      = 1u << 7,  // interactive-desktop minimums
};

struct ManagedProtectOptions {
    uint32_t gate_flags = 0;
    uint8_t  anti_debug_level = 0;   // 0-3
    uint8_t  anti_vm_level = 0;      // 0-2
    // License: FNV-1a64 of the plaintext key plus the XOR-masked key bytes so
    // the host can re-verify without the plaintext ever hitting disk.
    uint64_t license_hash = 0;
    uint32_t license_key_length = 0;
    uint8_t  license_key_masked[32] = {};
    // Activation: expected machine id (same algorithm as native -machineid).
    uint64_t activation_machine = 0;
    // Environment minimums used when the corresponding gate flag is set.
    uint32_t min_cpu_count = 2;
    uint32_t min_ram_mb = 4096;
    uint32_t min_uptime_ms = 3000;
    uint32_t min_screen_width = 1024;
    uint32_t min_screen_height = 768;
    uint32_t min_monitor_count = 1;
    uint32_t sandbox_score_threshold = 40;
    uint32_t env_score_threshold = 7;
};

// Encrypt `input` into a native host + payload + trailer envelope written to
// `output`. Gate options are baked into the trailer; the host enforces them
// before the CLR payload is materialised.
bool protectManagedExecutable(const std::wstring& input_path,
                              const std::wstring& output_path,
                              const ManagedProtectOptions& options,
                              std::string& error);

}
