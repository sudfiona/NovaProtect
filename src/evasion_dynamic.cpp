// NovaProtect dynamic evasion - host scoring model and x64 probe stubs.
#include "evasion_dynamic.h"
#include "disasm.h"

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

void append(std::vector<uint8_t>& out, std::initializer_list<uint8_t> bytes) {
    out.insert(out.end(), bytes.begin(), bytes.end());
}

// mov rax, gs:[0x60] -- the TEB self pointer, i.e. the PEB address.
constexpr uint8_t kLoadPeb[] = {0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00};

// cycles per millisecond assumed by the delay gate: a 3 GHz core. The gate is
// a lower bound on elapsed time, and the probe that follows re-measures with
// RDTSC anyway, so an inaccurate constant costs patience, not correctness.
constexpr uint32_t kCyclesPerMs = 3000000u;

} // namespace

std::string HostVerdict::summary() const {
    std::ostringstream os;
    os << "host score " << score << "/" << threshold
       << (blocked ? " BLOCK" : " pass")
       << (strong_evidence ? " (strong)" : "");
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

DynamicEvader::DynamicEvader(const EvasionConfig& cfg) : cfg_(cfg) {}

HostVerdict DynamicEvader::classify(const HostSignals& host) const {
    HostVerdict verdict;
    verdict.threshold = cfg_.host_score_threshold;
    uint32_t score = 0;
    bool strong = false;
    const uint8_t level = cfg_.anti_sandbox_level;

    auto add = [&](uint32_t weight, const char* reason) {
        score += weight;
        verdict.reasons.push_back(reason);
    };

    // Level 1 and above: hardware and process-scale signals. Each one is a
    // single measurement, so each is weighted below the default threshold on
    // its own -- a thin cloud VM is not an analysis host.
    if (host.hypervisor_cpuid) add(level >= 3 ? 30u : 25u, "hypervisor CPUID bit");
    if (host.logical_cpus && host.logical_cpus < 2) add(10, "single logical CPU");
    if (host.ram_mb && host.ram_mb < 2048) add(15, "less than 2 GB RAM");
    if (host.process_count && host.process_count < 30) add(12, "process count below 30");
    if (host.uptime_ms && host.uptime_ms < 60000) add(12, "uptime below 60 s");
    if (host.screen_width && host.screen_height &&
        (host.screen_width < 1024 || host.screen_height < 768)) add(10, "small desktop");
    if (host.monitor_count && host.monitor_count < 1) add(6, "no monitor attached");

    // Level 2 and above: input and interactive-desktop evidence.
    if (level >= 2) {
        if (host.mouse_idle_ms >= 0 && host.mouse_idle_ms > 120000)
            add(14, "no user input for over 120 s");
        // A template machine name and an analysis-vendor module are the two
        // signals that do not occur on an ordinary desktop, so they count as
        // strong evidence from level 2 on.
        if (host.template_hostname) { add(20, "template machine name"); strong = true; }
        if (host.vendor_module_present) { add(25, "analysis vendor module"); strong = true; }
        if (host.suspicious_module_paths)
            add(std::min<uint32_t>(20, 10 * host.suspicious_module_paths), "module from a writable path");
    }

    // Level 3: debugger evidence, which blocks on its own.
    if (level >= 3) {
        if (host.debugger_attached) { add(30, "debugger attached"); strong = true; }
        if (host.debug_heap) add(18, "debug heap flags");
    }

    verdict.score = std::min<uint32_t>(score, 100);
    // Blocking needs the score AND at least one signal that cannot be
    // explained by a minimal VM: matching the runtime's documented rule.
    verdict.strong_evidence = strong;
    verdict.blocked = verdict.score >= verdict.threshold && strong;
    if (verdict.score > 100) verdict.score = 100;
    return verdict;
}

std::vector<uint8_t> DynamicEvader::emitHypervisorCheck() const {
    std::vector<uint8_t> out;
    append(out, {0x53});                        // push rbx
    append(out, {0xB8, 0x01, 0x00, 0x00, 0x00}); // mov eax, 1
    append(out, {0x0F, 0xA2});                  // cpuid
    append(out, {0x89, 0xC8});                  // mov eax, ecx
    append(out, {0xC1, 0xE8, 0x1F});            // shr eax, 31
    append(out, {0x5B});                        // pop rbx
    append(out, {0xC3});                        // ret
    return out;
}

std::vector<uint8_t> DynamicEvader::emitPebDebugCheck() const {
    std::vector<uint8_t> out;
    append(out, {kLoadPeb[0], kLoadPeb[1], kLoadPeb[2], kLoadPeb[3], kLoadPeb[4],
                 kLoadPeb[5], kLoadPeb[6], kLoadPeb[7], kLoadPeb[8]});  // mov rax, gs:[0x60]
    append(out, {0x0F, 0xB6, 0x40, 0x02});      // movzx eax, byte [rax+2]
    append(out, {0xC3});
    return out;
}

std::vector<uint8_t> DynamicEvader::emitNtGlobalFlagCheck() const {
    std::vector<uint8_t> out;
    append(out, {kLoadPeb[0], kLoadPeb[1], kLoadPeb[2], kLoadPeb[3], kLoadPeb[4],
                 kLoadPeb[5], kLoadPeb[6], kLoadPeb[7], kLoadPeb[8]});
    append(out, {0x8B, 0x80, 0xBC, 0x00, 0x00, 0x00});  // mov eax, [rax+0xBC]
    append(out, {0x25, 0x70, 0x00, 0x00, 0x00});        // and eax, 0x70
    append(out, {0x0F, 0x95, 0xC0});                    // setne al
    append(out, {0x0F, 0xB6, 0xC0});                    // movzx eax, al
    append(out, {0xC3});
    return out;
}

std::vector<uint8_t> DynamicEvader::emitRdtscTimingCheck(uint32_t cycles) const {
    std::vector<uint8_t> out;
    append(out, {0x0F, 0x31});                  // rdtsc
    append(out, {0x48, 0xC1, 0xE2, 0x20});      // shl rdx, 32
    append(out, {0x48, 0x09, 0xD0});            // or rax, rdx      (t0)
    append(out, {0x49, 0x89, 0xC1});            // mov r9, rax
    append(out, {0x53});                        // push rbx         (cpuid clobbers ebx)
    append(out, {0xB8, 0x00, 0x00, 0x00, 0x00}); // mov eax, 0
    append(out, {0x0F, 0xA2});                  // cpuid            (serialise)
    append(out, {0x5B});                        // pop rbx
    append(out, {0x0F, 0x31});                  // rdtsc
    append(out, {0x48, 0xC1, 0xE2, 0x20});      // shl rdx, 32
    append(out, {0x48, 0x09, 0xD0});            // or rax, rdx      (t1)
    append(out, {0x4C, 0x29, 0xC8});            // sub rax, r9
    append(out, {0x48, 0x3D});                  // cmp rax, imm32
    put32(out, cycles);
    append(out, {0x0F, 0x97, 0xC0});            // seta al
    append(out, {0x0F, 0xB6, 0xC0});            // movzx eax, al
    append(out, {0xC3});
    return out;
}

std::vector<uint8_t> DynamicEvader::emitDelayGate(uint32_t ms) const {
    std::vector<uint8_t> out;
    append(out, {0x53});                        // push rbx
    append(out, {0x0F, 0x31});                  // rdtsc
    append(out, {0x48, 0xC1, 0xE2, 0x20});      // shl rdx, 32
    append(out, {0x48, 0x09, 0xD0});            // or rax, rdx
    append(out, {0x49, 0x89, 0xC1});            // mov r9, rax     (start)
    append(out, {0xB8});                        // mov eax, ms
    put32(out, ms);
    append(out, {0x48, 0x69, 0xC0});            // imul rax, rax, imm32
    put32(out, kCyclesPerMs);
    append(out, {0x49, 0x01, 0xC1});            // add r9, rax     (deadline)

    const size_t loop_start = out.size();
    append(out, {0xF3, 0x90});                  // pause
    append(out, {0x0F, 0x31});                  // rdtsc
    append(out, {0x48, 0xC1, 0xE2, 0x20});      // shl rdx, 32
    append(out, {0x48, 0x09, 0xD0});            // or rax, rdx
    append(out, {0x4C, 0x39, 0xC8});            // cmp rax, r9
    append(out, {0x72});                        // jb loop_start (rel8, patched below)
    const size_t rel8_pos = out.size();
    out.push_back(0x00);
    const int delta = static_cast<int>(loop_start) - static_cast<int>(out.size());
    if (delta < -128 || delta > 127) return {};  // cannot happen, but never emit a blind rel8
    out[rel8_pos] = static_cast<uint8_t>(static_cast<int8_t>(delta));

    append(out, {0x5B});                        // pop rbx
    append(out, {0x31, 0xC0});                  // xor eax, eax
    append(out, {0xC3});                        // ret
    return out;
}

std::vector<uint8_t> DynamicEvader::emitCombinedProbe(std::vector<uint32_t>* ids_out) const {
    struct Probe { uint32_t id; std::vector<uint8_t> body; };
    std::vector<Probe> probes;

    // Ids match runtime/prot64.c: 1 = PEB BeingDebugged, 2 = NtGlobalFlag,
    // 7 = CPUID hypervisor, 6 = timing.
    if (cfg_.anti_debug_level >= 1) probes.push_back({1, emitPebDebugCheck()});
    if (cfg_.anti_debug_level >= 2) probes.push_back({2, emitNtGlobalFlagCheck()});
    if (cfg_.anti_sandbox_level >= 1) probes.push_back({7, emitHypervisorCheck()});
    if (cfg_.timing_channel) probes.push_back({6, emitRdtscTimingCheck(100000u)});

    std::vector<uint8_t> out;
    std::vector<uint32_t> ids;
    for (const auto& probe : probes) {
        // Strip the stub's own RET; the combined routine needs to fall through
        // to the next probe instead.
        std::vector<uint8_t> body = probe.body;
        if (!body.empty() && body.back() == 0xC3) body.pop_back();
        out.insert(out.end(), body.begin(), body.end());
        append(out, {0x85, 0xC0});              // test eax, eax
        append(out, {0x0F, 0x84});              // je next_probe
        const size_t rel_pos = out.size();
        put32(out, 0);
        append(out, {0xB8});                    // mov eax, id
        put32(out, probe.id);
        append(out, {0xC3});                    // ret
        // Patch the displacement: jump to the byte just after this block.
        const uint32_t distance = static_cast<uint32_t>(out.size() - (rel_pos + 4));
        std::memcpy(out.data() + rel_pos, &distance, 4);
        ids.push_back(probe.id);
    }
    append(out, {0x31, 0xC0});                  // xor eax, eax
    append(out, {0xC3});                        // ret
    if (ids_out) *ids_out = ids;
    return out;
}

bool DynamicEvader::verifyStub(const std::vector<uint8_t>& code, std::string* why) {
    auto fail = [&](const char* reason) {
        if (why) *why = reason;
        return false;
    };
    if (code.size() < 2) return fail("stub too short");
    if (code.back() != 0xC3) return fail("stub does not end in RET");
    for (uint8_t b : code)
        if (b == 0xCC) return fail("stub contains INT3");

    // Linear decode instead of byte scanning: a raw 0xE8 byte is also the
    // modrm extension of `shr eax, imm8` (C1 E8 ..), so scanning for it
    // rejected perfectly good stubs. Only real instruction boundaries count.
    //
    // The repo's disassembler covers the common encoding space, not all of it:
    // an Unknown instruction means "no opinion", never "reject". Failing on it
    // would turn decoder gaps into false rejections of valid randomised code.
    Disassembler disassembler;
    size_t pc = 0;
    while (pc < code.size()) {
        DisasmInsn insn{};
        const uint32_t len = disassembler.disassemble(code.data() + pc, code.size() - pc, insn);
        if (len == 0) return fail("stub has an undecodable byte");
        const bool is_last = (pc + len == code.size());
        if (insn.category != InsnCategory::Unknown) {
            if (insn.category == InsnCategory::CALL) return fail("stub contains CALL (needs a fixup)");
            if (insn.category == InsnCategory::RET && !is_last) return fail("stub returns early");
            if (insn.category == InsnCategory::JMP && !is_last) return fail("stub jumps out of itself");
        }
        pc += len;
    }
    if (why) why->clear();
    return true;
}

} // namespace np
