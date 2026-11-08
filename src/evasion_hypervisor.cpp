// NovaProtect hypervisor-level evasion: CPUID/vendor/exit-cost measurement plus
// the stubs and stealth variants the protected image emits.
#include "evasion_hypervisor.h"

#include <algorithm>
#include <cstring>
#include <sstream>

namespace np {
namespace {

void put32(std::vector<uint8_t>& out, uint32_t value) {
    out.push_back(static_cast<uint8_t>(value & 0xFF));
    out.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
}

void app(std::vector<uint8_t>& out, std::initializer_list<uint8_t> bytes) {
    out.insert(out.end(), bytes.begin(), bytes.end());
}

struct CpuidResult {
    uint32_t a = 0, b = 0, c = 0, d = 0;
};

CpuidResult cpuid(uint32_t leaf) {
    CpuidResult r;
    __asm__ __volatile__("cpuid" : "=a"(r.a), "=b"(r.b), "=c"(r.c), "=d"(r.d) : "a"(leaf));
    return r;
}


std::string vendorString(const CpuidResult& r) {
    char text[13] = {};
    std::memcpy(text + 0, &r.b, 4);
    std::memcpy(text + 4, &r.c, 4);
    std::memcpy(text + 8, &r.d, 4);
    // Trailing NULs are part of the ABI, not part of the name.
    size_t len = 0;
    while (len < 12 && text[len]) len++;
    return std::string(text, len);
}

} // namespace

const char* hypervisorVendorFromString(const char* vendor12) {
    if (!vendor12) return "unknown";
    struct Known {
        const char* prefix;
        const char* name;
    };
    static const Known kKnown[] = {
        {"VMware", "VMware"},
        {"Microsoft Hv", "Hyper-V"},
        {"KVMKVMKVM", "KVM"},
        {"XenVMMXenVMM", "Xen"},
        {"VBoxVBoxVBox", "VirtualBox"},
        {"prl hyperv", "Parallels"},
        {"TCGLTCGLTCGL", "QEMU TCG"},
        {"bhyve bhyve", "bhyve"},
        {"ACRNACRNACRN", "ACRN"},
        {"Linux KVM", "KVM (Linux host)"},
    };
    for (const auto& entry : kKnown)
        if (std::strncmp(vendor12, entry.prefix, std::strlen(entry.prefix)) == 0) return entry.name;
    return "unknown";
}

std::string HypervisorReport::summary() const {
    std::ostringstream os;
    os << "hypervisor " << (present ? "PRESENT" : "absent");
    if (present) os << " vendor=" << (vendor.empty() ? "?" : vendor);
    os << " cpuid=" << cpuid_round_trip << "c storm=" << storm_cycles << "c";
    if (exit_cost_anomaly) os << " EXIT-COST-ANOMALY";
    if (vmx_supported) os << " vmx";
    if (svm_supported) os << " svm";
    os << " score=" << score;
    if (!reasons.empty()) {
        os << " [";
        for (size_t i = 0; i < reasons.size(); i++) {
            if (i) os << "; ";
            os << reasons[i];
        }
        os << "]";
    }
    return os.str();
}

HypervisorReport HypervisorIntel::probe() {
    HypervisorReport report;

    unsigned a = 0, b = 0, c = 0, d = 0;
    __asm__ __volatile__("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(0u));
    report.brand_cpus = a;

    const CpuidResult feats = cpuid(1);
    report.bit31_published = (feats.c & (1u << 31)) != 0;
    report.vmx_supported = (feats.c & (1u << 5)) != 0;

    const CpuidResult hv = cpuid(0x40000000u);
    // Unsupported leaves echo the highest basic leaf on Intel, so EAX is the
    // only field that distinguishes "hypervisor answered" from "no hypervisor".
    report.present = hv.a >= 0x40000000u;
    report.max_hypervisor_leaf = report.present ? hv.a : 0;
    if (report.present) report.vendor = vendorString(hv);

    const CpuidResult ext = cpuid(0x80000000u);
    if (ext.a >= 0x8000000Au) {
        const CpuidResult svm = cpuid(0x8000000Au);
        report.svm_supported = (svm.a & (1u << 2)) != 0;
    }

    // Exit-cost measurement. Serialise with a CPUID, then time 16 of them; on
    // bare metal each is 100-200 cycles, under a hypervisor every one is a VM
    // exit and the total lands an order of magnitude higher.
    unsigned lo = 0, hi = 0;
    (void)cpuid(0);                       // serialise before the first read
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    const uint64_t t0 = (static_cast<uint64_t>(hi) << 32) | lo;
    for (int i = 0; i < 16; i++) {
        unsigned sa = 0, sb = 0, sc = 0, sd = 0;
        __asm__ __volatile__("cpuid" : "=a"(sa), "=b"(sb), "=c"(sc), "=d"(sd) : "a"(0u));
    }
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    const uint64_t t1 = (static_cast<uint64_t>(hi) << 32) | lo;
    report.storm_cycles = t1 - t0;
    report.cpuid_round_trip = report.storm_cycles / 16;
    report.exit_cost_anomaly = report.storm_cycles > kStormBudgetCycles;

    return report;
}

const HypervisorReport& HypervisorIntel::cached() {
    static const HypervisorReport report = probe();
    return report;
}

HypervisorReport HypervisorIntel::classify(const HypervisorReport& measured, const EvasionConfig& cfg) {
    HypervisorReport out = measured;
    const uint8_t level = cfg.anti_sandbox_level;

    if (measured.present) {
        out.score += 30;
        out.reasons.push_back("hypervisor leaf answered (vendor " +
                              (measured.vendor.empty() ? std::string("unknown") : measured.vendor) + ")");
    }
    if (measured.exit_cost_anomaly) {
        out.score += 40;
        out.reasons.push_back("CPUID storm cost " + std::to_string(measured.storm_cycles) +
                              "c, above the bare-metal budget of " +
                              std::to_string(kStormBudgetCycles) + "c");
    }
    if (measured.present && !measured.vmx_supported && !measured.svm_supported) {
        out.score += 15;
        out.reasons.push_back("hypervisor present while hardware virtualisation is masked");
    }
    if (measured.bit31_published && !measured.present) {
        // The published bit contradicts the leaf space: a hypervisor that hides
        // its vendor but forgets ECX[31].
        out.score += 25;
        out.reasons.push_back("CPUID.1:ECX[31] set but 40000000H does not answer");
    }
    if (level < 2) out.score = std::min<uint32_t>(out.score, 30u);
    return out;
}

// ---------------------------------------------------------------- stubs

void HypervisorIntel::epilogue(std::vector<uint8_t>& out) {
    app(out, {0x5B});                 // pop rbx
    app(out, {0xC3});                 // ret
}

std::vector<uint8_t> HypervisorIntel::vendorCheck() {
    // Two CPUID round-trips: extended-max first (cheap rejection on bare metal),
    // then the hypervisor leaf and its vendor string.
    std::vector<uint8_t> out;
    app(out, {0x53});                             // push rbx
    app(out, {0xB8});
    put32(out, 0x80000000u);                      // mov eax, 80000000H
    app(out, {0x0F, 0xA2});                       // cpuid
    app(out, {0x3D});
    put32(out, 0x40000000u);                      // cmp eax, 40000000H
    app(out, {0x0F, 0x82});                       // jb clean
    const size_t jb_pos = out.size();
    put32(out, 0);

    app(out, {0xB8});
    put32(out, 0x40000000u);                      // mov eax, 40000000H
    app(out, {0x0F, 0xA2});                       // cpuid

    // Vendor presence: EBX holds the first four bytes of the vendor string.
    // A hypervisor that answers the leaf always answers with a name.
    const int variant = static_cast<int>(rng_.below(4));
    switch (variant) {
    case 0:
        app(out, {0x31, 0xC0});                   // xor eax, eax
        app(out, {0x85, 0xDB});                   // test ebx, ebx
        app(out, {0x0F, 0x95, 0xC1});             // setne cl
        app(out, {0x0F, 0xB6, 0xC1});             // movzx eax, cl
        break;
    case 1:
        app(out, {0x31, 0xC0});
        app(out, {0x85, 0xDB});
        app(out, {0x0F, 0x95, 0xC2});             // setne dl
        app(out, {0x0F, 0xB6, 0xC2});             // movzx eax, dl
        break;
    case 2:
        app(out, {0x89, 0xD8});                   // mov eax, ebx
        app(out, {0x31, 0xDB});                   // xor ebx, ebx (already saved on stack)
        app(out, {0x85, 0xC0});                   // test eax, eax
        app(out, {0x0F, 0x95, 0xC0});             // setne al
        app(out, {0x0F, 0xB6, 0xC0});             // movzx eax, al
        break;
    default:
        app(out, {0x85, 0xDB});                   // test ebx, ebx
        app(out, {0x0F, 0x95, 0xC0});             // setne al
        app(out, {0x0F, 0xB6, 0xC0});             // movzx eax, al
        break;
    }

    epilogue(out);

    // clean:
    const size_t clean_pos = out.size();
    app(out, {0x31, 0xC0});
    epilogue(out);

    const int32_t delta = static_cast<int32_t>(clean_pos) - static_cast<int32_t>(jb_pos + 4);
    std::memcpy(out.data() + jb_pos, &delta, 4);
    return out;
}

std::vector<uint8_t> HypervisorIntel::stormCheck() {
    // r12 holds t0 and r9d the counter: CPUID clobbers EAX/EBX/ECX/EDX, so
    // neither can live in a register the instruction touches.
    std::vector<uint8_t> out;
    app(out, {0x53});                             // push rbx
    app(out, {0x41, 0x54});                       // push r12

    app(out, {0x31, 0xC0});                       // xor eax, eax
    app(out, {0x0F, 0xA2});                       // cpuid  (serialise)
    app(out, {0x0F, 0x31});                       // rdtsc
    app(out, {0x41, 0x89, 0xC4});                 // mov r12d, eax

    const int variant = static_cast<int>(rng_.below(4));
    const uint32_t iterations = variant >= 2 ? 24u : 16u;
    app(out, {0x41, 0xB9});
    put32(out, iterations);                       // mov r9d, iterations

    const size_t loop_pos = out.size();
    app(out, {0x31, 0xC0});                       // xor eax, eax
    app(out, {0x0F, 0xA2});                       // cpuid
    app(out, {0x41, 0xFF, 0xC9});                 // dec r9d
    app(out, {0x75});                             // jnz loop
    const int8_t back = static_cast<int8_t>(static_cast<int>(loop_pos) -
                                            static_cast<int>(out.size() + 1));
    out.push_back(static_cast<uint8_t>(back));

    app(out, {0x0F, 0x31});                       // rdtsc
    app(out, {0x44, 0x29, 0xE0});                 // sub eax, r12d

    const uint32_t budget = kStormBudgetCycles * iterations / 16u;
    if (variant == 1 || variant == 3) {
        app(out, {0x05});
        put32(out, static_cast<uint32_t>(0u - budget));   // add eax, -budget
        app(out, {0xC1, 0xE8, 0x1F});                      // shr eax, 31 (0 = over budget)
        app(out, {0x83, 0xF0, 0x01});                      // xor eax, 1
    } else {
        app(out, {0x3D});
        put32(out, budget);                       // cmp eax, budget
        app(out, {0x0F, 0x97, 0xC0});             // seta al
        app(out, {0x0F, 0xB6, 0xC0});             // movzx eax, al
    }

    app(out, {0x41, 0x5C});                       // pop r12
    epilogue(out);
    return out;
}

std::vector<uint8_t> HypervisorIntel::vmxHiddenCheck() {
    std::vector<uint8_t> out;
    app(out, {0x53});                             // push rbx
    app(out, {0xB8});
    put32(out, 1u);                               // mov eax, 1
    app(out, {0x0F, 0xA2});                       // cpuid
    app(out, {0xC1, 0xE9, 0x05});                 // shr ecx, 5
    app(out, {0x83, 0xE1, 0x01});                 // and ecx, 1
    app(out, {0x83, 0xF1, 0x01});                 // xor ecx, 1   (1 = masked)
    app(out, {0x41, 0x89, 0xCA});                 // mov r10d, ecx
    app(out, {0xB8});
    put32(out, 0x40000000u);                      // mov eax, 40000000H
    app(out, {0x0F, 0xA2});                       // cpuid
    app(out, {0x3D});
    put32(out, 0x40000000u);                      // cmp eax, 40000000H
    app(out, {0x0F, 0x93, 0xC0});                 // setae al
    app(out, {0x0F, 0xB6, 0xC0});                 // movzx eax, al
    app(out, {0x44, 0x21, 0xD0});                 // and eax, r10d
    epilogue(out);
    return out;
}

// ---------------------------------------------------------------- stealth

std::vector<uint8_t> HypervisorIntel::stealthTimeSource() {
    // KUSER_SHARED_DATA is mapped read-only into every process at 7FFE0000H.
    // TickCountLow lives at +320H. Reading it costs a load, not a syscall, so a
    // monitor watching for VM exits or for the syscall pattern sees nothing.
    std::vector<uint8_t> out;
    app(out, {0xA1});
    put32(out, 0x7FFE0320u);                      // mov eax, ds:[7FFE0320H]
    app(out, {0xC3});
    return out;
}

std::vector<uint8_t> HypervisorIntel::stealthVendorCheck() {
    // One CPUID instead of two: the extended-max probe in vendorCheck() is a
    // free VM exit for a monitor, and the EAX comparison alone already tells a
    // guest from a host.
    std::vector<uint8_t> out;
    app(out, {0x53});                             // push rbx
    app(out, {0xB8});
    put32(out, 0x40000000u);
    app(out, {0x0F, 0xA2});                       // cpuid
    app(out, {0x3D});
    put32(out, 0x40000000u);
    app(out, {0x0F, 0x93, 0xC0});                 // setae al
    app(out, {0x0F, 0xB6, 0xC0});                 // movzx eax, al
    epilogue(out);
    return out;
}

std::vector<std::string> HypervisorIntel::stealthMeasures(const EvasionConfig& cfg) {
    std::vector<std::string> out;
    if (cfg.hypervisor_stealth_time) {
        out.push_back("time source reads KUSER_SHARED_DATA (7FFE0320H) instead of a syscall");
    }
    if (cfg.hypervisor_stealth_single_cpuid) {
        out.push_back("vendor probe collapsed to a single CPUID round-trip");
    }
    if (cfg.hypervisor_stealth_avoid_rdtscp) {
        out.push_back("no RDTSCP/RDPMC: only RDTSC, which exits once per measurement");
    }
    if (cfg.kernel_stealth) {
        out.push_back("kernel probes go through ntdll-export hashing, not the IAT");
    }
    return out;
}

} // namespace np
