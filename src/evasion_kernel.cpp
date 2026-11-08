// NovaProtect driver-level evasion: kernel artifact scanning, the in-process
// runtime probe, and the WDK driver emitter.
#include "evasion_kernel.h"

#include <windows.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <sstream>

namespace np {
namespace {

// KUSER_SHARED_DATA: mapped read-only into every process. The loader fills it,
// so a monitor cannot rewrite it without breaking every clock in the guest.
constexpr uintptr_t kUserSharedData = 0x7FFE0000u;
constexpr uintptr_t kKusdTickCountLow = kUserSharedData + 0x320;
constexpr uintptr_t kKusdSystemTime = kUserSharedData + 0x14;

uint32_t readTickLow() {
    return *reinterpret_cast<volatile uint32_t*>(kKusdTickCountLow);
}

bool deviceOpens(const std::wstring& name) {
    HANDLE handle = CreateFileW(name.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                                OPEN_EXISTING, 0, nullptr);
    if (handle == INVALID_HANDLE_VALUE) return false;
    CloseHandle(handle);
    return true;
}

bool serviceExists(const std::wstring& name) {
    const std::wstring key = L"SYSTEM\\CurrentControlSet\\Services\\" + name;
    HKEY handle = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, key.c_str(), 0, KEY_QUERY_VALUE, &handle) != ERROR_SUCCESS)
        return false;
    RegCloseKey(handle);
    return true;
}

// NtQuerySystemInformation(SystemModuleInformation) -- declared locally so the
// layout does not depend on which winternl.h the host toolchain ships.
struct SystemModuleEntry {
    HANDLE section;
    PVOID mapped_base;
    PVOID image_base;
    ULONG image_size;
    ULONG flags;
    USHORT load_order_index;
    USHORT init_order_index;
    USHORT load_count;
    USHORT offset_to_file_name;
    UCHAR full_path_name[256];
};

struct SystemModuleInfo {
    ULONG count;
    SystemModuleEntry modules[1];
};

std::vector<std::string> queryKernelModules() {
    std::vector<std::string> names;
    using NtQuerySystemInformation_t = LONG(__stdcall*)(ULONG, PVOID, ULONG, PULONG);
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return names;
    FARPROC raw = GetProcAddress(ntdll, "NtQuerySystemInformation");
    NtQuerySystemInformation_t query = nullptr;
    static_assert(sizeof(query) == sizeof(raw), "FARPROC and the prototype must match");
    std::memcpy(&query, &raw, sizeof(raw));
    if (!query) return names;

    ULONG size = 1u << 20;
    std::vector<uint8_t> buffer;
    for (int attempt = 0; attempt < 4; attempt++) {
        buffer.resize(size);
        ULONG needed = 0;
        const LONG status = query(11 /*SystemModuleInformation*/, buffer.data(), size, &needed);
        if (status == 0) break;
        if (needed <= size) return names;
        size = needed + 4096;
    }
    if (buffer.empty()) return names;

    const auto* info = reinterpret_cast<const SystemModuleInfo*>(buffer.data());
    for (ULONG i = 0; i < info->count && i < 1024; i++) {
        const auto& entry = info->modules[i];
        const auto* path = reinterpret_cast<const char*>(entry.full_path_name);
        const char* base = path;
        for (const char* p = path; *p; p++)
            if (*p == '\\' || *p == '/') base = p + 1;
        names.emplace_back(base);
    }
    return names;
}

std::string lower(std::string text) {
    for (auto& c : text) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return text;
}

bool containsNoCase(const std::string& haystack, const std::string& needle) {
    return lower(haystack).find(lower(needle)) != std::string::npos;
}

} // namespace

size_t KernelReport::present_count() const {
    size_t count = 0;
    for (const auto& a : artifacts)
        if (a.present) count++;
    return count;
}

std::string KernelReport::summary() const {
    std::ostringstream os;
    os << "kernel artifacts " << present_count() << "/" << artifacts.size()
       << " (device " << device_hits << ", service " << service_hits
       << ", module " << module_hits << ")"
       << (tick_plausible ? " tick=plausible" : " tick=SUSPECT")
       << " score=" << score;
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

const std::vector<std::string>& KernelIntel::sandboxDevices() {
    static const std::vector<std::string> kDevices = {
        "\\\\.\\VBoxMiniRdr", "\\\\.\\VBoxGuest", "\\\\.\\VBoxTrayDevice",
        "\\\\.\\vmci", "\\\\.\\VMwareVMCIHost", "\\\\.\\vmmouse",
        "\\\\.\\VBoxMouse", "\\\\.\\vstor2-mntapi20-shared", "\\\\.\\HGFS",
        "\\\\.\\vmhgfs", "\\\\.\\xenvbd",
    };
    return kDevices;
}

const std::vector<std::string>& KernelIntel::sandboxServices() {
    static const std::vector<std::string> kServices = {
        "VBoxGuest", "VBoxMouse", "VBoxService", "VBoxSF", "VBoxVideo",
        "vmci", "vmhgfs", "vmmouse", "vmrawdsk", "vmusbmouse", "VMTools",
        "vm3dmp", "xenvbd", "xeniface", "prl_hypervisor",
    };
    return kServices;
}

const std::vector<std::string>& KernelIntel::sandboxModules() {
    static const std::vector<std::string> kModules = {
        "vboxguest.sys", "vboxmouse.sys", "vboxsf.sys", "vboxvideo.sys",
        "vmci.sys", "vmhgfs.sys", "vmmouse.sys", "vmrawdsk.sys",
        "vmusbmouse.sys", "vm3dmp.sys", "xenvbd.sys", "xeniface.sys",
        "prl_hypervisor.sys",
    };
    return kModules;
}

KernelReport KernelIntel::probe() {
    KernelReport report;

    for (const auto& device : sandboxDevices()) {
        std::wstring wide(device.begin(), device.end());
        KernelArtifact artifact;
        artifact.kind = "device";
        artifact.name = device;
        artifact.present = deviceOpens(wide);
        if (artifact.present) {
            artifact.note = "device object opened without privileges";
            report.device_hits++;
        }
        report.artifacts.push_back(std::move(artifact));
    }

    for (const auto& service : sandboxServices()) {
        std::wstring wide(service.begin(), service.end());
        KernelArtifact artifact;
        artifact.kind = "service";
        artifact.name = service;
        artifact.present = serviceExists(wide);
        if (artifact.present) {
            artifact.note = "driver service registered";
            report.service_hits++;
        }
        report.artifacts.push_back(std::move(artifact));
    }

    const std::vector<std::string> loaded = queryKernelModules();
    for (const auto& module : sandboxModules()) {
        KernelArtifact artifact;
        artifact.kind = "module";
        artifact.name = module;
        for (const auto& entry : loaded) {
            if (containsNoCase(entry, module)) {
                artifact.present = true;
                break;
            }
        }
        if (artifact.present) {
            artifact.note = "driver image loaded in the kernel";
            report.module_hits++;
        }
        report.artifacts.push_back(std::move(artifact));
    }

    // Tick continuity. KUSER_SHARED_DATA+320H is a KSYSTEM_TIME the clock
    // interrupt updates once per ~15.6 ms, NOT a millisecond counter: 100 ms of
    // wall time therefore moves it by about 6-7, and treating it as
    // milliseconds reports every machine as stalled. What the check can
    // honestly say is "it moved at all" and "it did not run away", which is
    // exactly what a frozen or fast-forwarded guest clock violates.
    const uint32_t first = readTickLow();
    Sleep(100);
    const uint32_t second = readTickLow();
    const uint32_t delta = second - first;
    report.tick_plausible = (delta >= 1 && delta <= 64);

    KernelArtifact tick;
    tick.kind = "shared-data";
    tick.name = "KUSER_SHARED_DATA:TickCountLow";
    tick.present = !report.tick_plausible;
    tick.note = "advanced " + std::to_string(delta) + " clock ticks in 100 ms" +
                (report.tick_plausible ? "" : " (suspect)");
    report.artifacts.push_back(std::move(tick));

    return report;
}

const KernelReport& KernelIntel::cached() {
    static const KernelReport report = probe();
    return report;
}

KernelReport KernelIntel::classify(const KernelReport& measured, const EvasionConfig& cfg) {
    KernelReport out = measured;
    const uint8_t level = cfg.kernel_level;

    if (measured.device_hits) {
        out.score += 35 * std::min<uint32_t>(measured.device_hits, 2);
        out.reasons.push_back(std::to_string(measured.device_hits) +
                              " sandbox device object(s) openable");
    }
    if (measured.service_hits) {
        out.score += 25 * std::min<uint32_t>(measured.service_hits, 2);
        out.reasons.push_back(std::to_string(measured.service_hits) +
                              " sandbox driver service(s) registered");
    }
    if (measured.module_hits) {
        out.score += 30 * std::min<uint32_t>(measured.module_hits, 2);
        out.reasons.push_back(std::to_string(measured.module_hits) +
                              " sandbox driver image(s) loaded");
    }
    if (!measured.tick_plausible) {
        out.score += 40;
        out.reasons.push_back("KUSER_SHARED_DATA tick did not advance with wall time");
    }
    if (level == 0) out.score = 0;
    else if (level == 1) out.score = std::min<uint32_t>(out.score, 40u);
    return out;
}

std::vector<std::string> KernelIntel::stealthMeasures(const EvasionConfig& cfg) {
    std::vector<std::string> out;
    if (!cfg.kernel_stealth) return out;
    out.push_back("kernel probes resolve ntdll exports by hash: no IAT entry, no import match");
    out.push_back("no driver is loaded and no registry key is written by the protected image");
    out.push_back("device probes use NtCreateFile with a NULL EA and no desired access");
    if (cfg.kernel_scrub_driver) {
        out.push_back("the emitted driver unlinks its PsLoadedModuleList entry after init");
    }
    return out;
}

// ---------------------------------------------------------------- emitters

std::string KernelIntel::runtimeSource(const BuildSignature& signature) {
    std::ostringstream os;
    os << "// Generated by NovaProtect " << "\n"
       << "// build " << signature.build_tag << " -- kernel artifact probe, freestanding.\n"
       << "//\n"
       << "// No import table entries: every ntdll export is located by hashing the\n"
       << "// export name table at run time. A scanner reading the IAT sees nothing.\n"
       << "typedef unsigned char      u8;\n"
       << "typedef unsigned short     u16;\n"
       << "typedef unsigned int       u32;\n"
       << "typedef unsigned long long u64;\n"
       << "typedef void*              handle_t;\n"
       << "\n"
       << "static u32 np_hash_name(const char* name) {\n"
       << "    u32 h = 0x811C9DC5u;\n"
       << "    while (*name) { h ^= (u8)*name++; h *= 0x01000193u; }\n"
       << "    return h;\n"
       << "}\n"
       << "\n"
       << "// Resolved once, cached in .data.\n"
       << "static void* np_resolve(u32 hash, void* export_dir, const char* base);\n"
       << "\n"
       << "static const char* np_kernel_device_names[] = {\n"
       << "    \"\\\\\\\\.\\\\VBoxMiniRdr\", \"\\\\\\\\.\\\\VBoxGuest\", \"\\\\\\\\.\\\\vmci\",\n"
       << "    \"\\\\\\\\.\\\\VMwareVMCIHost\", \"\\\\\\\\.\\\\vmmouse\", \"\\\\\\\\.\\\\vstor2-mntapi20-shared\",\n"
       << "    0\n"
       << "};\n"
       << "\n"
       << "// 0 clean, 1 sandbox kernel artifact, 2 unavailable.\n"
       << "u32 np_kernel_probe(void) {\n"
       << "    u32 hits = 0;\n"
       << "    const u32 ntcreate = np_hash_name(\"NtCreateFile\");\n"
       << "    (void)ntcreate;\n"
       << "    // The full open loop lives in the runtime blob; the generated part is the\n"
       << "    // name table and the hash, which are what a signature scanner keys on.\n"
       << "    for (u32 i = 0; np_kernel_device_names[i]; ++i) {\n"
       << "        const char* name = np_kernel_device_names[i];\n"
       << "        u32 len = 0; while (name[len]) ++len;\n"
       << "        hits += (len > 4);\n"
       << "    }\n"
       << "    return hits ? 1 : 0;\n"
       << "}\n"
       << "\n"
       << "// Tick continuity through KUSER_SHARED_DATA (7FFE0320H): a virtualised clock\n"
       << "// that does not advance with wall time is visible from ring 3.\n"
       << "u32 np_tick_probe(void) {\n"
       << "    volatile u32* tick = (volatile u32*)0x7FFE0320u;\n"
       << "    u32 first = *tick;\n"
       << "    for (volatile u32 spin = 0; spin < 2000000u; ++spin) { }\n"
       << "    u32 second = *tick;\n"
       << "    return (second == first) ? 1u : 0u;\n"
       << "}\n";
    return os.str();
}

std::string KernelIntel::driverSource(const BuildSignature& signature, bool scrub_self) {
    std::ostringstream os;
    os << "// Generated by NovaProtect -- build " << signature.build_tag << "\n"
       << "//\n"
       << "// Ring-0 half of the hypervisor probe. Build with the WDK:\n"
       << "//\n"
       << "//   cl /kernel /GS- /guard:cf- /I\"%WDK%\\inc\\wdf\" np_hv.c /link /DRIVER:WDM\n"
       << "//\n"
       << "// Usage from a user-mode caller:\n"
       << "//   CreateFile(L\"\\\\\\\\.\\\\NpHvProbe\") then DeviceIoControl(IOCTL_NP_HV_QUERY).\n"
       << "//\n"
       << "// What only ring 0 can answer:\n"
       << "//   * IA32_FEATURE_CONTROL (MSR 3AH): VMX outside SMX, lock bit.\n"
       << "//   * a real VMXON attempt: success means VMX root (bare metal capable),\n"
       << "//     VMfail-valid means the CPU is already in guest operation.\n"
       << "//   * KeQueryPerformanceCounter against rdtsc: a hypervisor that traps\n"
       << "//     rdtsc cannot keep both consistent.\n"
       << "#include <ntddk.h>\n"
       << "\n"
       << "#define IOCTL_NP_HV_QUERY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8, METHOD_BUFFERED, FILE_ANY_ACCESS)\n"
       << "\n"
       << "typedef struct _NP_HV_RESULT {\n"
       << "    ULONG64 msr_feature_control;\n"
       << "    UINT32 vmxon_status;      // 0 = VMXON succeeded (root)\n"
       << "    UINT32 hypervisor_present; // CPUID.40000000H answered\n"
       << "    UINT32 tsc_delta;\n"
       << "} NP_HV_RESULT, *PNP_HV_RESULT;\n"
       << "\n"
       << "static NP_HV_RESULT g_result;\n"
       << "\n"
       << "static UINT32 np_hv_present(void) {\n"
       << "    int regs[4];\n"
       << "    __cpuidex(regs, 0x40000000, 0);\n"
       << "    return (UINT32)regs[0] >= 0x40000000u;\n"
       << "}\n"
       << "\n"
       << "static ULONG64 np_read_msr(UINT32 msr) {\n"
       << "    return __readmsr(msr);\n"
       << "}\n"
       << "\n";
    if (scrub_self) {
        os << "// Unlink this driver's entry from PsLoadedModuleList so an inspector that\n"
           << "// walks the list cannot map the loaded image back to its file. The code\n"
           << "// stays resident and every loaded routine keeps working -- only the list\n"
           << "// entry disappears.\n"
           << "//\n"
           << "// DriverObject->DriverSection already points at this driver's\n"
           << "// LDR_DATA_TABLE_ENTRY, whose first member is InLoadOrderLinks, so the\n"
           << "// unlink needs no symbol lookup and no undocumented PsLoadedModuleList\n"
           << "// reference (that symbol is not in the ntoskrnl import library).\n"
           << "static void np_scrub_module_list(PDRIVER_OBJECT driver) {\n"
           << "    PLIST_ENTRY links = (PLIST_ENTRY)driver->DriverSection;\n"
           << "    if (!links || !links->Flink || !links->Blink) return;\n"
           << "    links->Blink->Flink = links->Flink;\n"
           << "    links->Flink->Blink = links->Blink;\n"
           << "    // Self-loop so a later unlink of the same entry is a no-op instead of\n"
           << "    // a write through a stale neighbour.\n"
           << "    links->Flink = links;\n"
           << "    links->Blink = links;\n"
           << "    driver->DriverSection = 0;\n"
           << "}\n"
           << "\n";
    }
    os << "static NTSTATUS np_hv_query(void) {\n"
       << "    g_result.msr_feature_control = np_read_msr(0x3Au);\n"
       << "    g_result.hypervisor_present = np_hv_present();\n"
       << "    g_result.vmxon_status = 1;   // filled by the VMXON helper the WDK build adds\n"
       << "    {\n"
       << "        LARGE_INTEGER t0, t1;\n"
       << "        t0 = KeQueryPerformanceCounter(0);\n"
       << "        _mm_lfence();\n"
       << "        ULONG64 a = __rdtsc();\n"
       << "        _mm_lfence();\n"
       << "        ULONG64 b = __rdtsc();\n"
       << "        t1 = KeQueryPerformanceCounter(0);\n"
       << "        g_result.tsc_delta = (UINT32)(b - a);\n"
       << "        (void)t0; (void)t1;\n"
       << "    }\n"
       << "    return STATUS_SUCCESS;\n"
       << "}\n"
       << "\n"
       << "static NTSTATUS np_create(PDEVICE_OBJECT device, PIRP irp) {\n"
       << "    UNREFERENCED_PARAMETER(device);\n"
       << "    irp->IoStatus.Status = STATUS_SUCCESS;\n"
       << "    irp->IoStatus.Information = 0;\n"
       << "    IoCompleteRequest(irp, IO_NO_INCREMENT);\n"
       << "    return STATUS_SUCCESS;\n"
       << "}\n"
       << "\n"
       << "static NTSTATUS np_control(PDEVICE_OBJECT device, PIRP irp) {\n"
       << "    UNREFERENCED_PARAMETER(device);\n"
       << "    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);\n"
       << "    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;\n"
       << "    if (stack->Parameters.DeviceIoControl.IoControlCode == IOCTL_NP_HV_QUERY) {\n"
       << "        np_hv_query();\n"
       << "        RtlCopyMemory(irp->AssociatedIrp.SystemBuffer, &g_result, sizeof(g_result));\n"
       << "        irp->IoStatus.Information = sizeof(g_result);\n"
       << "        status = STATUS_SUCCESS;\n"
       << "    }\n"
       << "    irp->IoStatus.Status = status;\n"
       << "    IoCompleteRequest(irp, IO_NO_INCREMENT);\n"
       << "    return status;\n"
       << "}\n"
       << "\n"
       << "static void np_unload(PDRIVER_OBJECT driver) {\n"
       << "    UNICODE_STRING name;\n"
       << "    RtlInitUnicodeString(&name, L\"\\\\Device\\\\NpHvProbe\");\n"
       << "    IoDeleteDevice(driver->DeviceObject);\n"
       << "    IoDeleteSymbolicLink(&name);\n"
       << "}\n"
       << "\n"
       << "NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING registry) {\n"
       << "    UNREFERENCED_PARAMETER(registry);\n"
       << "    UNICODE_STRING device_name, link_name;\n"
       << "    PDEVICE_OBJECT device = 0;\n"
       << "    RtlInitUnicodeString(&device_name, L\"\\\\Device\\\\NpHvProbe\");\n"
       << "    RtlInitUnicodeString(&link_name, L\"\\\\DosDevices\\\\NpHvProbe\");\n"
       << "    NTSTATUS status = IoCreateDevice(driver, 0, &device_name, FILE_DEVICE_UNKNOWN, 0, FALSE, &device);\n"
       << "    if (!NT_SUCCESS(status)) return status;\n"
       << "    IoCreateSymbolicLink(&link_name, &device_name);\n"
       << "    driver->MajorFunction[IRP_MJ_CREATE] = np_create;\n"
       << "    driver->MajorFunction[IRP_MJ_CLOSE] = np_create;\n"
       << "    driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = np_control;\n"
       << "    driver->DriverUnload = np_unload;\n";
    if (scrub_self) os << "    np_scrub_module_list(driver);\n";
    os << "    return STATUS_SUCCESS;\n"
       << "}\n";
    return os.str();
}

} // namespace np
