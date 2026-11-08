// NovaProtect junk-code ("flower instruction") emitter for x64.
//
// Variant table (each row is a complete, register- and flag-transparent block):
//
//   v1  9C 4883C400 4883EC00 9D                  pushfq; add rsp,0; sub rsp,0; popfq
//   v2  9C 4883FC00 7403 4831C0 9D               opaque predicate (rsp != 0)
//   v3  9C 4885E4   7503 4831C0 9D               opaque predicate (test rsp,rsp)
//   v4  50 488704 24 58                           xchg [rsp],rax round trip
//   v5  9C 4883C000 9D                            add rax,0 under a flag save
//   v6  50 9C 48C1C005 48C1C805 9D 58            rol/ror pair under a flag save
//
// The zero-immediate forms (add rsp,0 / add rax,0) are deliberately unusual
// encodings of "no operation": a byte-perfect nop sled is one of the first
// things a signature engine normalises away.

#include "junk_emitter.h"

#include <algorithm>
#include <cstring>

namespace np {
namespace {

// 48 31 C0 = xor rax, rax. Never executed: it only exists between a
// conditional jump and its landing pad.
constexpr uint8_t kGarbage[] = {0x48, 0x31, 0xC0};

void put32(std::vector<uint8_t>& out, uint32_t value) {
    out.push_back(static_cast<uint8_t>(value & 0xFF));
    out.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
}

} // namespace

JunkEmitter::JunkEmitter(uint64_t seed) : rng_(seed ? seed : 0x4A554E4B5F434F44ull) {}

std::vector<uint8_t> JunkEmitter::block(uint8_t variant) {
    uint8_t pick = variant;
    if (pick == 0) {
        std::uniform_int_distribution<uint32_t> dist(1, kVariants);
        pick = static_cast<uint8_t>(dist(rng_));
    }
    emitted_++;

    std::vector<uint8_t> out;
    switch (pick) {
    case 1: out = {0x9C, 0x48, 0x83, 0xC4, 0x00, 0x48, 0x83, 0xEC, 0x00, 0x9D}; break;
    case 2: out = {0x9C, 0x48, 0x83, 0xFC, 0x00, 0x74, 0x03,
                   kGarbage[0], kGarbage[1], kGarbage[2], 0x9D}; break;
    case 3: out = {0x9C, 0x48, 0x85, 0xE4, 0x75, 0x03,
                   kGarbage[0], kGarbage[1], kGarbage[2], 0x9D}; break;
    case 4: out = {0x50, 0x48, 0x87, 0x04, 0x24, 0x58}; break;
    case 5: out = {0x9C, 0x48, 0x83, 0xC0, 0x00, 0x9D}; break;
    case 6: out = {0x50, 0x9C, 0x48, 0xC1, 0xC0, 0x05,
                   0x48, 0xC1, 0xC8, 0x05, 0x9D, 0x58}; break;
    default: out = {0x9C, 0x48, 0x83, 0xC0, 0x00, 0x9D}; break;
    }
    return out;
}

std::vector<uint8_t> JunkEmitter::deadBranch(const std::vector<uint8_t>& decoy) {
    // pushfq; cmp rsp,0; je <decoy>; <decoy>; popfq
    // rsp is never zero inside a user-mode thread, so the jump is always taken
    // and the decoy bytes are never executed. The 32-bit displacement form is
    // used unconditionally because decoys can be kilobytes long.
    std::vector<uint8_t> out;
    out.push_back(0x9C);
    out.push_back(0x48); out.push_back(0x83); out.push_back(0xFC); out.push_back(0x00);
    out.push_back(0x0F); out.push_back(0x84);
    put32(out, static_cast<uint32_t>(decoy.size()));
    out.insert(out.end(), decoy.begin(), decoy.end());
    out.push_back(0x9D);
    emitted_++;
    return out;
}

std::vector<uint8_t> JunkEmitter::prologue() {
    std::uniform_int_distribution<uint32_t> dist(1, kVariants);
    uint8_t first = static_cast<uint8_t>(dist(rng_));
    uint8_t second = static_cast<uint8_t>(dist(rng_));
    if (second == first) second = static_cast<uint8_t>(first % kVariants + 1);
    std::vector<uint8_t> out = block(first);
    std::vector<uint8_t> tail = block(second);
    out.insert(out.end(), tail.begin(), tail.end());
    return out;
}

std::vector<uint8_t> JunkEmitter::pad(size_t bytes) {
    std::vector<uint8_t> out;
    out.reserve(bytes);
    while (out.size() < bytes) {
        std::vector<uint8_t> blk = block(0);
        if (out.size() + blk.size() > bytes) break;
        out.insert(out.end(), blk.begin(), blk.end());
    }
    // Tail: single-byte NOPs. One byte, no operands, always safe.
    while (out.size() < bytes) out.push_back(0x90);
    return out;
}

bool JunkEmitter::isTransparent(const std::vector<uint8_t>& code) {
    if (code.size() < 4) return false;
    // Reject anything that could transfer control or trap.
    for (uint8_t b : code) {
        if (b == 0xC3 || b == 0xCC || b == 0xE8) return false;
    }
    const uint8_t first = code.front();
    const uint8_t last = code.back();
    // Either "saves flags and restores them" or "pushes a register and pops it".
    if (first != 0x9C && first != 0x50) return false;
    if (last != 0x9D && last != 0x58) return false;
    if (first == 0x9C && last != 0x9D) return false;
    // push rax ... pop rax (v4 / v6) is fine; pushfq ... pop rax is not.
    if (first == 0x50 && last == 0x9D) return false;
    return true;
}

} // namespace np
