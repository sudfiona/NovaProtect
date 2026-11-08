#pragma once
// NovaProtect randomised x64 stub forge.
//
// The hand-encoded stubs in evasion_dynamic.cpp are fixed byte strings: perfect
// for a regression test, terrible for a scanner, because one signature covers
// every image the product ever shipped. StubForge keeps the same semantics but
// picks the encoding per build:
//
//   * a family of equivalent instruction sequences per probe (register choice,
//     setcc form, serialisation form, recombination form);
//   * a random number of transparent junk blocks spliced in;
//   * a randomised probe order in the combined routine and a randomised
//     dispatch / return-id encoding.
//
// Every emitted stub still satisfies the DynamicEvader contract: only volatile
// registers change, exactly one trailing RET per standalone stub, no imports.

#include "evasion.h"
#include "evasion_entropy.h"
#include "junk_emitter.h"

#include <cstdint>
#include <vector>

namespace np {

class StubForge {
public:
    explicit StubForge(const BuildSignature& signature);

    // Number of distinct encodings each generator can produce on its own.
    // Multiplied out with the junk plan, two seeds collide with probability
    // around 1/(36 * 2^k), which is what the divergence test measures.
    static constexpr int kHypervisorEncodings = 4;
    static constexpr int kPebEncodings = 4;
    static constexpr int kNtGlobalEncodings = 4;
    static constexpr int kTimingEncodings = 12;
    static constexpr int kDelayEncodings = 9;

    std::vector<uint8_t> hypervisorCheck();                  // CPUID leaf 1 ECX bit 31
    std::vector<uint8_t> pebDebugCheck();                    // PEB->BeingDebugged
    std::vector<uint8_t> ntGlobalFlagCheck();                // PEB->NtGlobalFlag & 0x70
    std::vector<uint8_t> rdtscTimingCheck(uint32_t cycles);
    std::vector<uint8_t> delayGate(uint32_t ms);

    // Combined routine, probe order and dispatch encoding randomised. Returns
    // the check id of the first tripped probe (0 = clean).
    std::vector<uint8_t> combinedProbe(const EvasionConfig& cfg, std::vector<uint32_t>* ids_out);

    const BuildSignature& signature() const { return signature_; }

private:
    std::vector<uint8_t> junkPrologue();
    std::vector<uint8_t> junkBlock();

    BuildSignature signature_;
    Rng rng_;
    JunkEmitter junk_;
};

} // namespace np
