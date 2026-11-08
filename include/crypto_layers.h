#pragma once
// NovaProtect multi-layer encryption (crypto_layers.cpp)
#include <cstdint>
#include <cstddef>

namespace np {

// Three-layer encryption: RC4 + XOR + additive rotation.
// `nonce` should be random per region; `seed` is typically the region RVA.
// Both functions are deterministic: same (nonce, seed) always produce the
// same result, and layeredDecrypt(layeredEncrypt(x)) == x.
void layeredEncrypt(uint8_t* data, size_t len, uint32_t nonce, uint32_t seed);
void layeredDecrypt(uint8_t* data, size_t len, uint32_t nonce, uint32_t seed);

// Counter-mode keystream for VM bytecode.
//
// Unlike layeredEncrypt() this is randomly addressable: byte i is masked with
// a block derived from (key, rva, i>>3) only, so the interpreter can decode an
// arbitrary offset — including a backwards branch target — without walking the
// stream from the start. That is what lets the runtime decode bytecode one
// window at a time instead of materialising the whole program in memory.
//
// XOR is self-inverse, so this single function both encrypts and decrypts.
// The C runtime (runtime/prot64.c, np_vm_window) must stay bit-identical to
// this implementation; tests/vm_bytecode_crypt_test.cpp pins the vectors.
void vmBytecodeCrypt(uint8_t* data, size_t len, uint64_t key, uint32_t rva);

} // namespace np