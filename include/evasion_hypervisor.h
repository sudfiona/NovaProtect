#pragma once
// NovaProtect hypervisor-level evasion.
//
// The ring-3 probes in evasion_dynamic.h answer "am I being watched". This layer
// answers "am I running *inside* something", without trusting the bit the
// hypervisor publishes about itself:
//
//   vendor      CPUID.40000000H.EAX >= 40000000H and the 12-byte vendor string
//               -- the standard present test, and the one a stealth hypervisor
//               forgets to mask once EAX is checked instead of ECX[31].
//   capability  CPUID.1:ECX[5] (VMX) / CPUID.8000000AH:EAX[2] (SVM): what the
//               CPU can do, which tells a masked guest from a bare-metal host.
//   exit cost   a storm of serialised CPUID round-trips. Every one of them is a
//               VM exit under a hypervisor (~1000-5000 cycles) and ~100-200
//               cycles on bare metal. This is the probe that survives a
//               hypervisor configured to hide its own CPUID leaves.
//
// The evasion side is the mirror image: the runtime must not hand the monitor
// free VM exits. `stealthTimeSource()` and `stealthVendorCheck()` emit probe
// variants that read KUSER_SHARED_DATA instead of issuing a syscall and take
// exactly one CPUID instead of four.

#include "evasion.h"
#include "evasion_entropy.h"

#include <cstdint>
#include <string>
#include <vector>

namespace np {

struct HypervisorReport {
    bool present = false;
    std::string vendor;              // "VMwareVMware", "Microsoft Hv", ...
    uint32_t max_hypervisor_leaf = 0;
    bool bit31_published = false;    // CPUID.1:ECX[31]
    bool vmx_supported = false;      // CPUID.1:ECX[5]
    bool svm_supported = false;      // CPUID.8000000AH:EAX[2]
    uint64_t cpuid_round_trip = 0;   // cycles for one serialised CPUID
    uint64_t storm_cycles = 0;       // 16 serialised CPUIDs
    bool exit_cost_anomaly = false;  // storm cost above the bare-metal budget
    uint32_t brand_cpus = 0;

    // 0 = bare metal, 1..n = weighted evidence. The runtime uses the same
    // thresholds, so a UI reading this number shows what the image will decide.
    uint32_t score = 0;
    std::vector<std::string> reasons;

    std::string summary() const;
};

class HypervisorIntel {
public:
    // Measures the live CPU. Results are cached per process: the numbers are
    // host properties, not per-build ones.
    static HypervisorReport probe();
    static const HypervisorReport& cached();

    // Fills in score/reasons from the measured facts and the config levels.
    static HypervisorReport classify(const HypervisorReport& measured, const EvasionConfig& cfg);

    // Cycles below which a 16-CPUID storm is considered bare metal. 16 * 400 is
    // a generous native budget; the cheapest hypervisor exit already blows it.
    static constexpr uint32_t kStormBudgetCycles = 16u * 400u;

    // --- x64 probe stubs (freestanding, volatile registers only) ----------
    // Contract of every stub: uint32_t fn(void), 0 clean / 1 detected /
    // 2 unavailable, exactly one trailing RET, RBX and R12 preserved.
    std::vector<uint8_t> vendorCheck();          // CPUID.40000000H.EAX test
    std::vector<uint8_t> stormCheck();           // 16 serialised CPUIDs vs budget
    std::vector<uint8_t> vmxHiddenCheck();       // hypervisor present but VMX masked

    // --- evasion side -----------------------------------------------------
    // Reads KUSER_SHARED_DATA (0x7FFE0320 TickCountLow) instead of calling
    // GetTickCount: no syscall, therefore no VM exit for the monitor to log.
    std::vector<uint8_t> stealthTimeSource();
    // One CPUID, vendor taken from EAX only, no second round-trip.
    std::vector<uint8_t> stealthVendorCheck();

    // Human-readable list of the evasion measures this profile applies, shown
    // in the build log so nobody has to guess what "hypervisor stealth" meant.
    static std::vector<std::string> stealthMeasures(const EvasionConfig& cfg);

    explicit HypervisorIntel(const BuildSignature& signature)
        : signature_(signature), rng_(signature.seed ^ 0x4859504552564953ull) {}

    static constexpr int kVendorEncodings = 5;
    static constexpr int kStormEncodings = 4;

private:
    std::vector<uint8_t> prologue();
    void epilogue(std::vector<uint8_t>& out);

    BuildSignature signature_;
    Rng rng_;
};

const char* hypervisorVendorFromString(const char* vendor12);

} // namespace np
