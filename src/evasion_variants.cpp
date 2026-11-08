// NovaProtect randomised x64 stub forge - implementation.
#include "evasion_variants.h"

#include <cstring>

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

void app3(std::vector<uint8_t>& out, const uint8_t (&bytes)[3]) {
    out.insert(out.end(), bytes, bytes + 3);
}

// mov rax, gs:[0x60] -- TEB self pointer, i.e. the PEB address.
constexpr uint8_t kPeb[] = {0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00};

void peb(std::vector<uint8_t>& out) {
    out.insert(out.end(), kPeb, kPeb + sizeof(kPeb));
}

// 3 GHz assumption for the delay gate; the timing probe re-measures anyway.
constexpr uint32_t kCyclesPerMs = 3000000u;

// Domain tags keep the derived streams independent of each other.
constexpr uint64_t kDomainJunk     = 0x4A554E4B5F444F4Dull;
constexpr uint64_t kDomainStub     = 0x535455425F444F4Dull;

} // namespace

StubForge::StubForge(const BuildSignature& signature)
    : signature_(signature),
      rng_(mix64(signature.seed ^ kDomainStub)),
      junk_(mix64(signature.seed ^ kDomainJunk)) {}

std::vector<uint8_t> StubForge::junkBlock() { return junk_.block(); }

std::vector<uint8_t> StubForge::junkPrologue() {
    std::vector<uint8_t> out;
    if (signature_.junk_budget == 0) return out;
    const uint32_t count = rng_.below(static_cast<uint32_t>(signature_.junk_budget) + 1);
    for (uint32_t i = 0; i < count; i++) {
        const auto block = junkBlock();
        out.insert(out.end(), block.begin(), block.end());
    }
    return out;
}

std::vector<uint8_t> StubForge::hypervisorCheck() {
    std::vector<uint8_t> out = junkPrologue();
    app(out, {0x53});                                   // push rbx (cpuid clobbers ebx)
    switch (rng_.below(kHypervisorEncodings)) {
    case 0:
        app(out, {0xB8, 0x01, 0x00, 0x00, 0x00});       // mov eax, 1
        app(out, {0x0F, 0xA2});                         // cpuid
        app(out, {0x89, 0xC8});                         // mov eax, ecx
        app(out, {0xC1, 0xE8, 0x1F});                   // shr eax, 31
        break;
    case 1:
        app(out, {0xB8, 0x01, 0x00, 0x00, 0x00});
        app(out, {0x0F, 0xA2});
        app(out, {0x0F, 0xBA, 0xE1, 0x1F});             // bt ecx, 31
        app(out, {0x0F, 0x92, 0xC0});                   // setc al
        app(out, {0x0F, 0xB6, 0xC0});                   // movzx eax, al
        break;
    case 2:
        app(out, {0x31, 0xC0});                         // xor eax, eax
        app(out, {0xFF, 0xC0});                         // inc eax  (= 1, different bytes)
        app(out, {0x0F, 0xA2});
        app(out, {0xF7, 0xC1, 0x00, 0x00, 0x00, 0x80}); // test ecx, 0x80000000
        app(out, {0x0F, 0x95, 0xC0});                   // setne al
        app(out, {0x0F, 0xB6, 0xC0});                   // movzx eax, al
        break;
    default:
        app(out, {0xB8, 0x01, 0x00, 0x00, 0x00});
        app(out, {0x0F, 0xA2});
        app(out, {0xC1, 0xE9, 0x1F});                   // shr ecx, 31
        app(out, {0x89, 0xC8});                         // mov eax, ecx
        break;
    }
    app(out, {0x5B});                                   // pop rbx
    app(out, {0xC3});
    return out;
}

std::vector<uint8_t> StubForge::pebDebugCheck() {
    std::vector<uint8_t> out = junkPrologue();
    peb(out);
    switch (rng_.below(kPebEncodings)) {
    case 0:
        app(out, {0x0F, 0xB6, 0x40, 0x02});             // movzx eax, byte [rax+2]
        break;
    case 1:
        app(out, {0x8A, 0x40, 0x02});                   // mov al, byte [rax+2]
        app(out, {0x0F, 0xB6, 0xC0});                   // movzx eax, al
        break;
    case 2:
        app(out, {0x0F, 0xB6, 0x48, 0x02});             // movzx ecx, byte [rax+2]
        app(out, {0x89, 0xC8});                         // mov eax, ecx
        break;
    default:
        app(out, {0x6A, 0x00});                         // push 0
        app(out, {0x59});                               // pop rcx
        app(out, {0x8A, 0x48, 0x02});                   // mov cl, byte [rax+2]
        app(out, {0x89, 0xC8});                         // mov eax, ecx
        break;
    }
    app(out, {0xC3});
    return out;
}

std::vector<uint8_t> StubForge::ntGlobalFlagCheck() {
    std::vector<uint8_t> out = junkPrologue();
    peb(out);
    switch (rng_.below(kNtGlobalEncodings)) {
    case 0:
        app(out, {0x8B, 0x80, 0xBC, 0x00, 0x00, 0x00}); // mov eax, [rax+0xBC]
        app(out, {0x25, 0x70, 0x00, 0x00, 0x00});       // and eax, 0x70
        break;
    case 1:
        app(out, {0xF6, 0x80, 0xBC, 0x00, 0x00, 0x00, 0x70});  // test byte [rax+0xBC], 0x70
        break;
    case 2:
        app(out, {0x8B, 0x88, 0xBC, 0x00, 0x00, 0x00}); // mov ecx, [rax+0xBC]
        app(out, {0x83, 0xE1, 0x70});                   // and ecx, 0x70
        break;
    default:
        app(out, {0x8A, 0x80, 0xBC, 0x00, 0x00, 0x00}); // mov al, [rax+0xBC]
        app(out, {0xA8, 0x70});                         // test al, 0x70
        break;
    }
    app(out, {0x0F, 0x95, 0xC0});                       // setne al
    app(out, {0x0F, 0xB6, 0xC0});                       // movzx eax, al
    app(out, {0xC3});
    return out;
}

std::vector<uint8_t> StubForge::rdtscTimingCheck(uint32_t cycles) {
    std::vector<uint8_t> out = junkPrologue();

    // Holder register choice: r9 / r10 / r11 all keep the same encoding shape
    // with different REX bytes, which is free divergence.
    const struct { uint8_t mov_holder[3]; uint8_t sub_holder[3]; } holders[] = {
        {{0x49, 0x89, 0xC1}, {0x4C, 0x29, 0xC8}},   // r9
        {{0x49, 0x89, 0xC2}, {0x4C, 0x29, 0xD0}},   // r10
        {{0x49, 0x89, 0xC3}, {0x4C, 0x29, 0xD8}},   // r11
    };
    const auto& holder = holders[rng_.below(3)];
    const bool use_add = rng_.chance(50);
    const uint8_t recombine[3] = {0x48, static_cast<uint8_t>(use_add ? 0x01 : 0x09), 0xD0};

    app(out, {0x0F, 0x31});                             // rdtsc
    app(out, {0x48, 0xC1, 0xE2, 0x20});                 // shl rdx, 32
    app3(out, recombine);                               // or/add rax, rdx
    app3(out, holder.mov_holder);

    // Serialisation before the second reading. `cpuid` is the only
    // fully-serialising instruction whose encoding the repo's disassembler
    // models end to end; `lfence` (0F AE E8) is not, and the leftover E8 byte
    // then reads as a CALL to a linear decoder. Same barrier, two encodings.
    app(out, {0x53});                                   // push rbx
    if (rng_.chance(50)) {
        app(out, {0xB8, 0x00, 0x00, 0x00, 0x00});       // mov eax, 0
    } else {
        app(out, {0x31, 0xC0});                         // xor eax, eax
    }
    app(out, {0x0F, 0xA2});                             // cpuid
    app(out, {0x5B});                                   // pop rbx

    app(out, {0x0F, 0x31});
    app(out, {0x48, 0xC1, 0xE2, 0x20});
    app3(out, recombine);
    app3(out, holder.sub_holder);

    if (rng_.chance(50)) {
        app(out, {0x48, 0x3D});                         // cmp rax, imm32
        put32(out, cycles);
    } else {
        // Same comparison through a scratch register: different bytes, same
        // flags, so the setcc below cannot tell the two encodings apart.
        // `mov ecx, imm32` zero-extends and the cycle budget is positive, so
        // rcx holds exactly the same value as the immediate form above.
        app(out, {0xB9});                               // mov ecx, imm32
        put32(out, cycles);
        app(out, {0x48, 0x39, 0xC8});                   // cmp rax, rcx
    }
    app(out, {0x0F, 0x97, 0xC0});                       // seta al
    app(out, {0x0F, 0xB6, 0xC0});                       // movzx eax, al
    app(out, {0xC3});
    return out;
}

std::vector<uint8_t> StubForge::delayGate(uint32_t ms) {
    std::vector<uint8_t> out = junkPrologue();
    const struct { uint8_t mov_holder[3]; uint8_t add_holder[3]; uint8_t cmp_holder[3]; } holders[] = {
        {{0x49, 0x89, 0xC1}, {0x49, 0x01, 0xC1}, {0x4C, 0x39, 0xC8}},
        {{0x49, 0x89, 0xC2}, {0x49, 0x01, 0xC2}, {0x4C, 0x39, 0xD0}},
        {{0x49, 0x89, 0xC3}, {0x49, 0x01, 0xC3}, {0x4C, 0x39, 0xD8}},
    };
    const auto& holder = holders[rng_.below(3)];

    app(out, {0x53});                                   // push rbx
    app(out, {0x0F, 0x31});
    app(out, {0x48, 0xC1, 0xE2, 0x20});
    app(out, {0x48, 0x09, 0xD0});
    app3(out, holder.mov_holder);
    app(out, {0xB8});                                   // mov eax, ms
    put32(out, ms);
    app(out, {0x48, 0x69, 0xC0});                       // imul rax, rax, imm32
    put32(out, kCyclesPerMs);
    app3(out, holder.add_holder);

    const size_t loop_start = out.size();
    switch (rng_.below(3)) {
    case 0: app(out, {0xF3, 0x90}); break;              // pause
    case 1: app(out, {0x66, 0x90}); break;              // two-byte nop
    default: app(out, {0x0F, 0x1F, 0x00}); break;       // three-byte nop
    }
    app(out, {0x0F, 0x31});
    app(out, {0x48, 0xC1, 0xE2, 0x20});
    app(out, {0x48, 0x09, 0xD0});
    app3(out, holder.cmp_holder);
    app(out, {0x72});                                   // jb loop_start
    const size_t rel8_pos = out.size();
    out.push_back(0x00);
    const int delta = static_cast<int>(loop_start) - static_cast<int>(out.size());
    if (delta < -128 || delta > 127) return {};         // never emit a blind rel8
    out[rel8_pos] = static_cast<uint8_t>(static_cast<int8_t>(delta));

    app(out, {0x5B});                                   // pop rbx
    app(out, {0x31, 0xC0});                             // xor eax, eax
    app(out, {0xC3});
    return out;
}

std::vector<uint8_t> StubForge::combinedProbe(const EvasionConfig& cfg,
                                              std::vector<uint32_t>* ids_out) {
    // Index meaning inside the plan: 0 PEB, 1 NtGlobalFlag, 2 hypervisor,
    // 3 timing. Runtime ids stay semantic (1/2/7/6) because the loader maps
    // them to the reported reason; only the order and encoding vary.
    struct Probe {
        int index = 0;
        uint32_t id = 0;
        bool enabled = false;
    };
    Probe probes[4];
    probes[0] = {0, 1, cfg.anti_debug_level >= 1};
    probes[1] = {1, 2, cfg.anti_debug_level >= 2};
    probes[2] = {2, 7, cfg.anti_sandbox_level >= 1};
    probes[3] = {3, 6, cfg.timing_channel};

    std::vector<uint8_t> out;
    std::vector<uint32_t> ids;
    for (int slot = 0; slot < 4; slot++) {
        const Probe& probe = probes[signature_.probe_order[slot] % 4];
        if (!probe.enabled) continue;

        std::vector<uint8_t> body;
        switch (probe.index) {
        case 0: body = pebDebugCheck(); break;
        case 1: body = ntGlobalFlagCheck(); break;
        case 2: body = hypervisorCheck(); break;
        default: body = rdtscTimingCheck(100000u); break;
        }
        if (!body.empty() && body.back() == 0xC3) body.pop_back();
        out.insert(out.end(), body.begin(), body.end());

        // Between-probe junk so the dispatch block is not on a fixed offset.
        if (rng_.chance(40)) {
            const auto noise = junkBlock();
            out.insert(out.end(), noise.begin(), noise.end());
        }

        const uint32_t dispatch = rng_.below(4);

        // Build the return-id block first: both jump forms need its length to
        // patch a displacement, and guessing the length was a real bug.
        std::vector<uint8_t> id_block;
        if (rng_.chance(50)) {
            id_block = {0x6A, static_cast<uint8_t>(probe.id), 0x58, 0xC3};  // push imm8; pop rax; ret
        } else {
            id_block = {0xB8};
            put32(id_block, probe.id);                                       // mov eax, id
            id_block.push_back(0xC3);
        }

        if (dispatch < 2) {
            app(out, dispatch == 0 ? std::initializer_list<uint8_t>{0x85, 0xC0}
                                   : std::initializer_list<uint8_t>{0x09, 0xC0});
            app(out, {0x0F, 0x84});                     // je rel32
            const size_t rel_pos = out.size();
            put32(out, 0);
            const uint32_t distance = static_cast<uint32_t>(id_block.size());
            std::memcpy(out.data() + rel_pos, &distance, 4);
        } else {
            app(out, dispatch == 2 ? std::initializer_list<uint8_t>{0x85, 0xC0}
                                   : std::initializer_list<uint8_t>{0x09, 0xC0});
            app(out, {0x74});                           // jz rel8
            const int delta = static_cast<int>(id_block.size());
            if (delta > 127) return {};
            out.push_back(static_cast<uint8_t>(static_cast<int8_t>(delta)));
        }

        out.insert(out.end(), id_block.begin(), id_block.end());
        ids.push_back(probe.id);
    }

    app(out, {0x31, 0xC0});                             // xor eax, eax
    app(out, {0xC3});
    if (ids_out) *ids_out = ids;
    return out;
}

} // namespace np
