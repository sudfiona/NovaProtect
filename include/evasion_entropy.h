#pragma once
// NovaProtect per-build signature randomisation.
//
// Goal: two images built from different seeds must not share a byte pattern a
// scanner can key on. Everything a generator emits -- probe encodings, junk
// plan, filler bytes, section names, the DOS-stub nonce, loader keys -- is
// derived from one 64-bit seed, so:
//
//   * a fresh build (seed 0 -> system entropy) differs from every earlier build;
//   * an explicit seed reproduces a build byte for byte, which is what makes
//     the divergence claim testable instead of a slogan.
//
// Honest boundary: this raises the cost of static and heuristic detection. It
// is randomness with a documented plan, not a proof of undetectability; whether
// a given sample is flagged depends on the scanner, the payload and the day.

#include <cstdint>
#include <string>
#include <vector>

namespace np {

// 64 bits of entropy from the platform plus timing jitter. Never returns 0.
uint64_t systemEntropy();

// splitmix64 finaliser: used both as the stream and as a key-derivation mix.
uint64_t mix64(uint64_t x);

// Deterministic PRNG stream. Same seed -> same sequence, everywhere.
class Rng {
public:
    explicit Rng(uint64_t seed = 0x4E4F564150524F54ull);

    uint64_t next();
    uint32_t below(uint32_t bound);                 // [0, bound)
    uint32_t range(uint32_t lo, uint32_t hi);       // [lo, hi]
    uint8_t byte();
    bool chance(uint32_t percent);

    template <typename T>
    const T& pick(const std::vector<T>& items) {
        return items[below(static_cast<uint32_t>(items.size()))];
    }

    template <typename T>
    void shuffle(std::vector<T>& items) {
        for (size_t i = items.size(); i > 1; i--) {
            const size_t j = below(static_cast<uint32_t>(i));
            const T tmp = items[i - 1];
            items[i - 1] = items[j];
            items[j] = tmp;
        }
    }

    uint64_t state() const { return state_; }
    void setState(uint64_t state) { state_ = state ? state : 0x4E4F564150524F54ull; }

private:
    uint64_t state_;
};

// Everything derived from the seed, in one serialisable record. The record is
// what the build log and the UI show, and what a repro build consumes.
struct BuildSignature {
    uint64_t seed = 0;
    std::string build_tag;        // 16 hex chars, unique per seed
    std::string section_suffix;   // 2 hex chars appended to renamed sections
    uint8_t filler_byte = 0x90;   // tail filler used after whole junk blocks
    uint8_t junk_budget = 2;      // max junk blocks spliced into one stub
    uint8_t probe_order[4] = {0, 1, 2, 3};  // slot -> probe index
    uint32_t nonce[4] = {0, 0, 0, 0};       // 16 bytes stamped into the DOS stub
    uint32_t timestamp = 0;                 // chosen TimeDateStamp
    uint64_t key_salt = 0;                  // mixed into loader/unhook key material

    // Round-trip used by `-evasion-manifest` / `-evasion-manifest-in`.
    std::string ToJson() const;
    static bool FromJson(const std::string& text, BuildSignature& out, std::string* error = nullptr);
};

// Plans a BuildSignature from a seed and hands out the derived stream.
class SignatureRandomizer {
public:
    explicit SignatureRandomizer(uint64_t seed);

    static SignatureRandomizer fromSystemEntropy();

    void reseed(uint64_t seed);

    const BuildSignature& signature() const { return signature_; }
    const std::string& buildTag() const { return signature_.build_tag; }
    uint64_t seed() const { return signature_.seed; }
    Rng& rng() { return rng_; }

    std::string manifest() const { return signature_.ToJson(); }

    // Deterministic derived streams: generators take their own sub-stream so
    // that adding a generator later does not shift the bytes of the others.
    Rng derive(uint64_t domain) const;

private:
    void plan(uint64_t seed);

    Rng rng_;
    BuildSignature signature_;
};

} // namespace np
