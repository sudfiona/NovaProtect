// NovaProtect per-build signature randomisation - implementation.
#include "evasion_entropy.h"

#include <cstdio>
#include <cstring>
#include <random>
#include <sstream>

#ifdef _WIN32
#  include <windows.h>
#  include <bcrypt.h>
#  include <process.h>
#else
#  include <unistd.h>
#  include <chrono>
#endif

namespace np {

uint64_t mix64(uint64_t x) {
    x += 0x9E3779B97F4A7C15ull;
    uint64_t z = x;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    return z ^ (z >> 31);
}

namespace {

uint64_t timingJitter() {
    uint64_t acc = 0;
#ifdef _WIN32
    LARGE_INTEGER qpc{};
    if (QueryPerformanceCounter(&qpc)) acc ^= static_cast<uint64_t>(qpc.QuadPart);
    acc = mix64(acc ^ static_cast<uint64_t>(GetTickCount64()));
    acc ^= static_cast<uint64_t>(GetCurrentProcessId()) << 17;
    acc ^= static_cast<uint64_t>(GetCurrentThreadId()) << 41;
#  if defined(_MSC_VER)
    acc ^= __rdtsc();
#  elif defined(__GNUC__) && (defined(__x86_64__) || defined(__i386__))
    acc ^= __builtin_ia32_rdtsc();
#  endif
#else
    const auto now = std::chrono::high_resolution_clock::now().time_since_epoch().count();
    acc ^= static_cast<uint64_t>(now);
    acc ^= static_cast<uint64_t>(::getpid()) << 19;
#endif
    return acc;
}

// Small deterministic JSON reader: the manifest is a flat object of numbers and
// strings, so a full JSON parser would be a dependency for no benefit.
bool findNumber(const std::string& text, const char* key, uint64_t& out) {
    const std::string needle = std::string("\"") + key + "\"";
    size_t pos = text.find(needle);
    if (pos == std::string::npos) return false;
    pos = text.find(':', pos + needle.size());
    if (pos == std::string::npos) return false;
    pos++;
    while (pos < text.size() && (text[pos] == ' ' || text[pos] == '\t')) pos++;
    char* end = nullptr;
    const unsigned long long value = std::strtoull(text.c_str() + pos, &end, 10);
    if (end == text.c_str() + pos) return false;
    out = static_cast<uint64_t>(value);
    return true;
}

bool findString(const std::string& text, const char* key, std::string& out) {
    const std::string needle = std::string("\"") + key + "\"";
    size_t pos = text.find(needle);
    if (pos == std::string::npos) return false;
    pos = text.find(':', pos + needle.size());
    if (pos == std::string::npos) return false;
    pos = text.find('"', pos);
    if (pos == std::string::npos) return false;
    const size_t end = text.find('"', pos + 1);
    if (end == std::string::npos) return false;
    out = text.substr(pos + 1, end - pos - 1);
    return true;
}

std::string hex64(uint64_t value, int digits) {
    char buffer[32];
    std::snprintf(buffer, sizeof(buffer), "%0*llx", digits,
                  static_cast<unsigned long long>(value));
    return std::string(buffer);
}

} // namespace

uint64_t systemEntropy() {
    uint64_t acc = 0;

#ifdef _WIN32
    uint8_t buffer[32] = {};
    if (BCryptGenRandom(nullptr, buffer, sizeof(buffer), BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0) {
        for (size_t i = 0; i < sizeof(buffer); i += 8) {
            uint64_t chunk = 0;
            std::memcpy(&chunk, buffer + i, 8);
            acc ^= mix64(chunk + i);
        }
    }
#endif

    acc ^= timingJitter();
    acc ^= static_cast<uint64_t>(std::random_device{}()) << 23;
    acc = mix64(acc);
    // A zero seed means "derive one", so entropy must never return zero.
    return acc ? acc : 0x5354442D454E5452ull;
}

Rng::Rng(uint64_t seed) : state_(seed ? seed : 0x4E4F564150524F54ull) {}

uint64_t Rng::next() { return mix64(state_ += 0x9E3779B97F4A7C15ull); }

uint32_t Rng::below(uint32_t bound) {
    if (bound <= 1) return 0;
    // Multiply-shift: unbiased enough for encoding choices and avoids the
    // modulo bias that would skew variant selection over many builds.
    const uint64_t product = (next() >> 32) * static_cast<uint64_t>(bound);
    return static_cast<uint32_t>(product >> 32);
}

uint32_t Rng::range(uint32_t lo, uint32_t hi) {
    if (hi <= lo) return lo;
    return lo + below(hi - lo + 1);
}

uint8_t Rng::byte() { return static_cast<uint8_t>(next() & 0xFF); }

bool Rng::chance(uint32_t percent) { return below(100) < percent; }

std::string BuildSignature::ToJson() const {
    std::ostringstream os;
    os << "{\n";
    os << "  \"seed\": " << seed << ",\n";
    os << "  \"build_tag\": \"" << build_tag << "\",\n";
    os << "  \"section_suffix\": \"" << section_suffix << "\",\n";
    os << "  \"filler_byte\": " << static_cast<int>(filler_byte) << ",\n";
    os << "  \"junk_budget\": " << static_cast<int>(junk_budget) << ",\n";
    os << "  \"probe_order\": [" << static_cast<int>(probe_order[0]) << ", "
       << static_cast<int>(probe_order[1]) << ", " << static_cast<int>(probe_order[2]) << ", "
       << static_cast<int>(probe_order[3]) << "],\n";
    os << "  \"nonce\": [" << nonce[0] << ", " << nonce[1] << ", " << nonce[2] << ", "
       << nonce[3] << "],\n";
    os << "  \"timestamp\": " << timestamp << ",\n";
    os << "  \"key_salt\": " << key_salt << "\n";
    os << "}\n";
    return os.str();
}

bool BuildSignature::FromJson(const std::string& text, BuildSignature& out, std::string* error) {
    auto fail = [&](const char* reason) {
        if (error) *error = reason;
        return false;
    };
    uint64_t seed = 0;
    if (!findNumber(text, "seed", seed)) return fail("manifest has no seed");
    if (seed == 0) return fail("manifest seed must be non-zero");

    SignatureRandomizer randomizer(seed);
    out = randomizer.signature();

    // The derived fields are recomputed from the seed; only the human-facing
    // scalars are read back so a hand-edited manifest cannot desync the bytes.
    uint64_t value = 0;
    if (findNumber(text, "timestamp", value)) {
        out.timestamp = static_cast<uint32_t>(value);
    } else {
        out.timestamp = randomizer.signature().timestamp;
    }
    std::string tag;
    if (findString(text, "build_tag", tag) && !tag.empty()) out.build_tag = tag;
    if (error) error->clear();
    return true;
}

SignatureRandomizer::SignatureRandomizer(uint64_t seed) : rng_(seed) { plan(seed); }

SignatureRandomizer SignatureRandomizer::fromSystemEntropy() {
    return SignatureRandomizer(systemEntropy());
}

void SignatureRandomizer::reseed(uint64_t seed) {
    rng_.setState(seed);
    plan(seed);
}

void SignatureRandomizer::plan(uint64_t seed) {
    if (seed == 0) seed = systemEntropy();
    rng_.setState(seed);
    signature_ = BuildSignature{};
    signature_.seed = seed;

    // Domain-separated draws: each field pulls from the same stream, so the
    // record is reproducible but the fields are independent.
    signature_.build_tag = hex64(rng_.next(), 16);
    signature_.section_suffix = hex64(rng_.next(), 2);

    // Tail filler after whole junk blocks. All of these are single-byte
    // "nothing happens" encodings when they land outside VirtualSize.
    static const uint8_t kFillers[] = {0x90, 0x66, 0x40, 0x41, 0x42, 0x43};
    signature_.filler_byte = kFillers[rng_.below(sizeof(kFillers))];

    signature_.junk_budget = static_cast<uint8_t>(1 + rng_.below(3));  // 1..3

    for (int i = 0; i < 4; i++) signature_.probe_order[i] = static_cast<uint8_t>(i);
    std::vector<uint8_t> order = {0, 1, 2, 3};
    rng_.shuffle(order);
    for (int i = 0; i < 4; i++) signature_.probe_order[i] = order[i];

    for (int i = 0; i < 4; i++) signature_.nonce[i] = static_cast<uint32_t>(rng_.next());

    // 2021-01-01 .. 2026-12-31, snapped to whole minutes so two builds in the
    // same minute look like the same reproducible build.
    const uint32_t base = 1609459200u;
    const uint32_t span = 1798761600u - base;
    signature_.timestamp = base + (static_cast<uint32_t>(rng_.next() % span) / 60u) * 60u;

    signature_.key_salt = rng_.next();
}

Rng SignatureRandomizer::derive(uint64_t domain) const {
    return Rng(mix64(signature_.seed ^ mix64(domain)));
}

} // namespace np
