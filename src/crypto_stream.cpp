// crypto_stream.cpp — position-dependent keystream cipher
// ============================================================
// See crypto_stream.h for the algorithm.  The implementation is kept in
// its own translation unit so the engine, the packer and the tests all
// agree on one definition.
#include "crypto_stream.h"

namespace np {

void streamCrypt(uint8_t* data, size_t len, uint32_t seed) {
    if (!data || len == 0) return;
    for (size_t i = 0; i < len; i++) {
        data[i] ^= streamRotByte(seed, (uint32_t)i);
    }
}

void streamCrypt16(uint16_t* data, size_t len, uint32_t seed) {
    if (!data || len == 0) return;
    for (size_t i = 0; i < len; i++) {
        const uint16_t k = (uint16_t)((uint16_t)streamRotByte(seed, (uint32_t)i) +
                                       (uint16_t)(uint16_t)i);
        data[i] = (uint16_t)(data[i] ^ k);
    }
}

} // namespace np
