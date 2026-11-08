// crypto_stream.h — position-dependent keystream cipher
// ============================================================
// A self-inverse stream cipher whose keystream depends on the byte
// position, not just on a repeating key.  The same routine encrypts and
// decrypts.
//
//     K(i)  = (uint8_t)(rol32(seed, i & 0x1f) + (uint8_t)i)
//     out[i]= K(i) ^ in[i]
//
// The rotation count is masked to five bits, matching the behaviour of
// x86 "rol r32, cl".  Because the key is position dependent, a repeated
// plaintext never produces a repeated ciphertext, and the transformation
// has no fixed points worth relying on.
//
// This is the primitive NovaProtect uses for everything that has to stay
// unreadable in the output image but has to be recovered at runtime:
// import names, loader API names and the detection strings.  Unlike a
// repeating-key XOR it does not leak the length of the plaintext through
// repeating patterns.
//
// The cipher is deliberately weak against a known-plaintext attack: the
// payload also carries an integrity hash, so a wrong keystream is
// detected rather than silently accepted.
#pragma once

#include <cstddef>
#include <cstdint>

namespace np {

// rol32 with the count masked to five bits, like x86 "rol r32, cl".
inline uint8_t streamRotByte(uint32_t seed, uint32_t index) {
    const uint32_t n = index & 0x1F;
    const uint32_t r = n ? ((seed << n) | (seed >> (32 - n))) : seed;
    return (uint8_t)(r + (uint8_t)index);
}

// Encrypts in place.  Calling it twice restores the original bytes.
void streamCrypt(uint8_t* data, size_t len, uint32_t seed);

// Same cipher over 16-bit words, used for the wide-character tables.
void streamCrypt16(uint16_t* data, size_t len, uint32_t seed);

} // namespace np
