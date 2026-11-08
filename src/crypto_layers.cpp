// crypto_layers.cpp — multi-layer encryption for NovaProtect payloads
// ============================================================
// Three independent layers, each with a key derived from the region
// nonce, RVA and layer index. The layers must be peeled in reverse
// order, and all three keys are needed to recover the plaintext.
//
//   Layer 1: RC4 stream cipher
//   Layer 2: XOR with a derived 8-byte key
//   Layer 3: Additive byte rotation
//
// RC4 is a stream cipher so encrypt == decrypt. XOR is self-inverse.
// Only layer 3 needs an explicit inverse (subtract).
#include "crypto_layers.h"
#include <cstring>

namespace np {

namespace {

// ---- key derivation (FNV-1a based) ------------------------------------
static void deriveKey(uint8_t out[8], uint32_t nonce, uint32_t seed, uint32_t layer) {
    uint64_t h = 0xCBF29CE484222325ull;
    const uint32_t vals[3] = { nonce, seed, layer };
    for (int v = 0; v < 3; v++) {
        for (int b = 0; b < 4; b++) {
            h ^= (uint64_t)((vals[v] >> (b * 8)) & 0xFF);
            h *= 0x100000001B3ull;
        }
    }
    // Extra diffusion round
    for (int i = 0; i < 4; i++) {
        h ^= h >> 29;
        h *= 0xBF58476D1CE4E5B9ull;
    }
    for (int k = 0; k < 8; k++) out[k] = (uint8_t)(h >> (k * 8));
}

// ---- RC4 ---------------------------------------------------------------
struct RC4 {
    uint8_t S[256];
    int i, j;
    void init(const uint8_t* key, size_t keyLen) {
        for (int k = 0; k < 256; k++) S[k] = (uint8_t)k;
        int jj = 0;
        for (int k = 0; k < 256; k++) {
            jj = (jj + S[k] + key[k % keyLen]) & 0xFF;
            uint8_t t = S[k]; S[k] = S[jj]; S[jj] = t;
        }
        i = 0; j = 0;
    }
    void stream(uint8_t* data, size_t len) {
        for (size_t k = 0; k < len; k++) {
            i = (i + 1) & 0xFF;
            j = (j + S[i]) & 0xFF;
            uint8_t t = S[i]; S[i] = S[j]; S[j] = t;
            data[k] ^= S[(S[i] + S[j]) & 0xFF];
        }
    }
};

} // namespace

void layeredEncrypt(uint8_t* data, size_t len, uint32_t nonce, uint32_t seed) {
    if (!data || len == 0) return;

    // Layer 1: RC4
    uint8_t k1[8];
    deriveKey(k1, nonce, seed, 0);
    RC4 rc;
    rc.init(k1, 8);
    rc.stream(data, len);

    // Layer 2: XOR
    uint8_t k2[8];
    deriveKey(k2, nonce, seed, 1);
    for (size_t k = 0; k < len; k++) data[k] ^= k2[k & 7];

    // Layer 3: additive rotation
    uint8_t k3[8];
    deriveKey(k3, nonce, seed, 2);
    for (size_t k = 0; k < len; k++) data[k] = (uint8_t)(data[k] + k3[k & 7]);
}

void layeredDecrypt(uint8_t* data, size_t len, uint32_t nonce, uint32_t seed) {    if (!data || len == 0) return;

    // Layer 3 inverse: subtract
    uint8_t k3[8];
    deriveKey(k3, nonce, seed, 2);
    for (size_t k = 0; k < len; k++) data[k] = (uint8_t)(data[k] - k3[k & 7]);

    // Layer 2 inverse: XOR (self-inverse)
    uint8_t k2[8];
    deriveKey(k2, nonce, seed, 1);
    for (size_t k = 0; k < len; k++) data[k] ^= k2[k & 7];

    // Layer 1 inverse: RC4 (self-inverse for stream ciphers)
    uint8_t k1[8];
    deriveKey(k1, nonce, seed, 0);
    RC4 rc;
    rc.init(k1, 8);
    rc.stream(data, len);
}

// ---- VM bytecode counter-mode keystream --------------------------------
// Must stay bit-identical to np_vm_window() in runtime/prot64.c.
static inline uint64_t vmMix(uint64_t x) {
    x ^= x >> 30; x *= 0xBF58476D1CE4E5B9ull;
    x ^= x >> 27; x *= 0x94D049BB133111EBull;
    x ^= x >> 31;
    return x;
}

static inline uint64_t vmKeystreamWord(uint64_t key, uint32_t rva, uint64_t block) {
    // The RVA is folded into the key so a bytecode blob lifted out of one
    // region and dropped into another decrypts to garbage.
    uint64_t salted = key ^ ((uint64_t)rva * 0x9E3779B97F4A7C15ull);
    return vmMix(salted + block * 0x9E3779B97F4A7C15ull);
}

void vmBytecodeCrypt(uint8_t* data, size_t len, uint64_t key, uint32_t rva) {
    if (!data || len == 0) return;
    uint64_t current = ~0ull;
    uint64_t word = 0;
    for (size_t i = 0; i < len; i++) {
        uint64_t block = (uint64_t)i >> 3;
        if (block != current) { current = block; word = vmKeystreamWord(key, rva, block); }
        data[i] ^= (uint8_t)(word >> ((i & 7u) * 8u));
    }
}

} // namespace np