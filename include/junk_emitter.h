#pragma once
// NovaProtect junk-code ("flower instruction") emitter for x64.
//
// Contract for every emitted block:
//
//   * register transparent - no general purpose register keeps a different
//     value on exit than on entry;
//   * flag transparent - RFLAGS is saved and restored around anything that
//     writes it, so the block can be spliced between two arbitrary
//     instructions of a function body;
//   * memory transparent - only the transient stack slot the block itself
//     pushed is touched;
//   * never transfers control outside the block.
//
// Blocks exist to break byte-pattern signatures and to raise the amount of
// work a linear-sweep disassembler has to do. They are not a protection
// primitive on their own and are counted in the build report as such.

#include <cstdint>
#include <random>
#include <vector>

namespace np {

class JunkEmitter {
public:
    // Six distinct encodings; see the variant table in junk_emitter.cpp.
    static constexpr uint8_t kVariants = 6;

    explicit JunkEmitter(uint64_t seed = 0x4A554E4B5F434F44ull);

    // One block. variant 0 selects a random variant; 1..kVariants select a
    // specific one, which keeps test output reproducible.
    std::vector<uint8_t> block(uint8_t variant = 0);

    // A never-taken branch whose skipped body is `decoy`. Used to plant dead
    // strings so naive "extract printable runs" triage pulls out garbage.
    std::vector<uint8_t> deadBranch(const std::vector<uint8_t>& decoy);

    // Function-entry flavour: two stacked blocks with different encodings.
    std::vector<uint8_t> prologue();

    // Fill up to `bytes` with whole blocks (single-byte NOPs in the tail).
    std::vector<uint8_t> pad(size_t bytes);

    uint32_t emitted() const { return emitted_; }

    // Structural verifier used by the tests: starts with pushfq (or balances
    // push/pop), ends with popfq or ret-free tail, contains no call/int3/ret.
    static bool isTransparent(const std::vector<uint8_t>& code);

private:
    std::mt19937_64 rng_;
    uint32_t emitted_ = 0;
};

} // namespace np
