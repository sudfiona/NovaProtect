// NovaProtect Evasion Subsystem - profile presets and the runtime policy blob.
#include "evasion.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <sstream>

namespace np {

const char* evasionProfileName(EvasionProfile profile) {
    switch (profile) {
    case EvasionProfile::Off:        return "off";
    case EvasionProfile::Balanced:   return "balanced";
    case EvasionProfile::Aggressive: return "aggressive";
    case EvasionProfile::Paranoid:   return "paranoid";
    }
    return "off";
}

bool parseEvasionProfile(const std::string& text, EvasionProfile& out) {
    std::string lowered = text;
    std::transform(lowered.begin(), lowered.end(), lowered.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (lowered == "off" || lowered == "0" || lowered == "none") { out = EvasionProfile::Off; return true; }
    if (lowered == "balanced" || lowered == "1" || lowered == "light") { out = EvasionProfile::Balanced; return true; }
    if (lowered == "aggressive" || lowered == "2" || lowered == "medium") { out = EvasionProfile::Aggressive; return true; }
    if (lowered == "paranoid" || lowered == "3" || lowered == "max") { out = EvasionProfile::Paranoid; return true; }
    return false;
}

void EvasionConfig::planSignature(uint64_t forced_seed) {
    // Precedence: an explicit seed always wins (that is the reproducibility
    // contract); otherwise a reseed request draws fresh entropy; otherwise the
    // stored seed is reused.
    uint64_t chosen = forced_seed;
    if (chosen == 0 && !reseed) chosen = seed;
    if (chosen == 0) chosen = systemEntropy();
    seed = chosen;
    build = SignatureRandomizer(chosen).signature();
}

bool EvasionConfig::applyManifest(const std::string& text, std::string* error) {
    BuildSignature loaded;
    if (!BuildSignature::FromJson(text, loaded, error)) return false;
    build = loaded;
    seed = loaded.seed;
    reseed = false;
    if (error) error->clear();
    return true;
}

EvasionConfig EvasionConfig::forProfile(EvasionProfile profile, uint64_t seed) {
    EvasionConfig cfg;
    cfg.profile = profile;
    cfg.seed = seed;

    if (profile == EvasionProfile::Off) {
        cfg.static_rich_scrub = false;
        cfg.static_timestamp = false;
        cfg.static_section_rename = false;
        cfg.static_strip_pdb = false;
        cfg.static_pad_fill = false;
        cfg.static_drop_signature = false;
        cfg.static_checksum = false;
        cfg.junk_density = 0;
        cfg.anti_sandbox_level = 0;
        cfg.anti_debug_level = 0;
        cfg.detonate_delay_ms = 0;
        cfg.presence_gate = false;
        cfg.timing_channel = false;
        cfg.loader_split_regions = false;
        cfg.loader_no_rwx = false;
        cfg.mem_stream_rounds = 0;
        cfg.unhook_text_restore = false;
        cfg.unhook_iat_sweep = false;
        cfg.hypervisor_vendor_probe = false;
        cfg.hypervisor_exit_cost = false;
        cfg.hypervisor_stealth_time = false;
        cfg.hypervisor_stealth_single_cpuid = false;
        cfg.hypervisor_stealth_avoid_rdtscp = false;
        cfg.kernel_level = 0;
        cfg.kernel_stealth = false;
        cfg.kernel_scrub_driver = false;
        cfg.planSignature(seed);
        return cfg;
    }

    // Static scrubbing is on for every non-off profile: leaving the Rich
    // header, the original timestamp and the linker's PDB path in a "protected"
    // image defeats the rest of the work, and none of it is cost-bearing.
    cfg.static_rich_scrub = true;
    cfg.static_timestamp = true;
    cfg.static_section_rename = true;
    cfg.static_strip_pdb = true;
    cfg.static_pad_fill = true;
    cfg.static_drop_signature = true;
    cfg.static_checksum = true;
    cfg.loader_split_regions = true;
    cfg.loader_no_rwx = true;
    cfg.presence_gate = true;
    cfg.timing_channel = true;

    switch (profile) {
    case EvasionProfile::Balanced:
        cfg.junk_density = 1;
        cfg.junk_opaque = true;
        cfg.junk_decoy_strings = false;
        cfg.anti_sandbox_level = 1;
        cfg.anti_debug_level = 1;
        cfg.detonate_delay_ms = 1500;
        cfg.mem_stream_rounds = 1;
        cfg.mem_window = 4096;
        cfg.unhook_text_restore = true;
        cfg.unhook_iat_sweep = false;
        cfg.hypervisor_vendor_probe = true;
        cfg.hypervisor_exit_cost = false;
        cfg.kernel_level = 1;
        cfg.kernel_stealth = true;
        cfg.kernel_scrub_driver = false;
        break;
    case EvasionProfile::Aggressive:
        cfg.junk_density = 3;
        cfg.junk_opaque = true;
        cfg.junk_decoy_strings = true;
        cfg.anti_sandbox_level = 2;
        cfg.anti_debug_level = 2;
        cfg.detonate_delay_ms = 3000;
        cfg.mem_stream_rounds = 2;
        cfg.mem_window = 4096;
        cfg.unhook_text_restore = true;
        cfg.unhook_iat_sweep = true;
        cfg.hypervisor_vendor_probe = true;
        cfg.hypervisor_exit_cost = true;
        cfg.kernel_level = 2;
        cfg.kernel_stealth = true;
        cfg.kernel_scrub_driver = false;
        break;
    case EvasionProfile::Paranoid:
        cfg.junk_density = 5;
        cfg.junk_opaque = true;
        cfg.junk_decoy_strings = true;
        cfg.anti_sandbox_level = 3;
        cfg.anti_debug_level = 3;
        cfg.detonate_delay_ms = 5000;
        cfg.host_score_threshold = 30;
        cfg.mem_stream_rounds = 3;
        cfg.mem_window = 2048;
        cfg.unhook_text_restore = true;
        cfg.unhook_iat_sweep = true;
        cfg.hypervisor_vendor_probe = true;
        cfg.hypervisor_exit_cost = true;
        cfg.kernel_level = 3;
        cfg.kernel_stealth = true;
        cfg.kernel_scrub_driver = true;
        break;
    default:
        break;
    }
    cfg.planSignature(seed);
    return cfg;
}

std::string EvasionConfig::describe() const {
    if (!enabled()) return "evasion: off";
    std::ostringstream os;
    os << "evasion: " << evasionProfileName(profile)
       << " build=" << (build.build_tag.empty() ? "unplanned" : build.build_tag)
       << " static=" << (static_rich_scrub ? "rich" : "-")
       << (static_timestamp ? ",ts" : "")
       << (static_section_rename ? ",sect" : "")
       << (static_strip_pdb ? ",pdb" : "")
       << (static_pad_fill ? ",pad" : "")
       << " junk=" << static_cast<int>(junk_density)
       << " sbx=" << static_cast<int>(anti_sandbox_level)
       << " adbg=" << static_cast<int>(anti_debug_level)
       << " delay=" << detonate_delay_ms << "ms"
       << " memrounds=" << static_cast<int>(mem_stream_rounds)
       << " unhook=" << (unhook_text_restore ? "1" : "0")
       << " hv=" << (hypervisor_vendor_probe ? "v" : "-")
       << (hypervisor_exit_cost ? "x" : "")
       << (hypervisor_stealth_time ? "s" : "")
       << " kern=" << static_cast<int>(kernel_level)
       << (kernel_stealth ? "s" : "")
       << (kernel_scrub_driver ? "c" : "");
    return os.str();
}

std::string EvasionConfig::runtimePolicy() const {
    std::ostringstream os;
    os << "profile=" << evasionProfileName(profile) << '\n';
    os << "seed=" << std::hex << seed << std::dec << '\n';
    os << "build_tag=" << build.build_tag << '\n';
    os << "key_salt=" << std::hex << build.key_salt << std::dec << '\n';
    os << "anti_sandbox_level=" << static_cast<int>(anti_sandbox_level) << '\n';
    os << "anti_debug_level=" << static_cast<int>(anti_debug_level) << '\n';
    os << "host_score_threshold=" << host_score_threshold << '\n';
    os << "detonate_delay_ms=" << detonate_delay_ms << '\n';
    os << "presence_gate=" << (presence_gate ? 1 : 0) << '\n';
    os << "timing_channel=" << (timing_channel ? 1 : 0) << '\n';
    os << "junk_density=" << static_cast<int>(junk_density) << '\n';
    os << "loader_split_regions=" << (loader_split_regions ? 1 : 0) << '\n';
    os << "loader_no_rwx=" << (loader_no_rwx ? 1 : 0) << '\n';
    os << "mem_window=" << mem_window << '\n';
    os << "mem_stream_rounds=" << static_cast<int>(mem_stream_rounds) << '\n';
    os << "unhook_text_restore=" << (unhook_text_restore ? 1 : 0) << '\n';
    os << "unhook_iat_sweep=" << (unhook_iat_sweep ? 1 : 0) << '\n';
    os << "hypervisor_vendor_probe=" << (hypervisor_vendor_probe ? 1 : 0) << '\n';
    os << "hypervisor_exit_cost=" << (hypervisor_exit_cost ? 1 : 0) << '\n';
    os << "hypervisor_stealth_time=" << (hypervisor_stealth_time ? 1 : 0) << '\n';
    os << "hypervisor_stealth_single_cpuid=" << (hypervisor_stealth_single_cpuid ? 1 : 0) << '\n';
    os << "kernel_level=" << static_cast<int>(kernel_level) << '\n';
    os << "kernel_stealth=" << (kernel_stealth ? 1 : 0) << '\n';
    os << "kernel_scrub_driver=" << (kernel_scrub_driver ? 1 : 0) << '\n';
    return os.str();
}

} // namespace np
