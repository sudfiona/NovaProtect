#pragma once
// NovaProtect driver-level (kernel) evasion.
//
// Two halves, both real code rather than a description of code:
//
//   detection  what a sandbox leaves behind in the kernel even when it hides
//              its user-mode process: driver services, device objects, loaded
//              .sys modules, and the KUSER_SHARED_DATA tick it cannot fake
//              without breaking every guest clock.
//   evasion    kernel_stealth: how the protected image's own probes avoid
//              creating the artifacts a monitor looks for -- no IAT imports
//              (export hashing), no driver load, no registry writes.
//
// `driverSource()` emits a complete WDK-compilable driver that runs the things
// a ring-3 probe cannot: RDMSR of IA32_FEATURE_CONTROL, a VMXON attempt to tell
// VMX root from a guest, and scrubbing of the driver's own
// PsLoadedModuleList/DriverObject trace. It is emitted as source text, not
// compiled here: the engine has no WDK and inventing one would be a lie.

#include "evasion.h"

#include <cstdint>
#include <string>
#include <vector>

namespace np {

struct KernelArtifact {
    std::string kind;      // "device" | "service" | "module" | "shared-data"
    std::string name;
    bool present = false;
    std::string note;
};

struct KernelReport {
    std::vector<KernelArtifact> artifacts;
    uint32_t device_hits = 0;
    uint32_t service_hits = 0;
    uint32_t module_hits = 0;
    bool tick_plausible = false;
    uint32_t score = 0;
    std::vector<std::string> reasons;

    size_t present_count() const;
    std::string summary() const;
};

class KernelIntel {
public:
    // Live scan of this machine. Device objects are opened, services read from
    // the registry, kernel modules enumerated through NtQuerySystemInformation.
    static KernelReport probe();
    static const KernelReport& cached();

    static KernelReport classify(const KernelReport& measured, const EvasionConfig& cfg);

    // Names the scan looks for, exposed so a test can assert the tables rather
    // than trusting the scan's own count.
    static const std::vector<std::string>& sandboxDevices();
    static const std::vector<std::string>& sandboxServices();
    static const std::vector<std::string>& sandboxModules();

    // Freestanding C for the protected image: resolves ntdll exports by hash
    // (no IAT entry, nothing for an import scanner to match) and re-runs the
    // same three checks in-process. Meant to be compiled into the runtime blob.
    static std::string runtimeSource(const BuildSignature& signature);

    // Complete WDK driver: RDMSR IA32_FEATURE_CONTROL, VMXON root/guest probe,
    // and optional self-scrubbing of the driver's module-list entry.
    static std::string driverSource(const BuildSignature& signature, bool scrub_self);

    // What the kernel_stealth switch actually changes, in words.
    static std::vector<std::string> stealthMeasures(const EvasionConfig& cfg);
};

} // namespace np
