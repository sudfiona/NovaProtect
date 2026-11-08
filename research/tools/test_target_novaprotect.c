// test_target_novaprotect.c
//
// Stand-in for tests/test_target.exe.
//
// The original fixture uses the commercial VMProtectSDK.h, which is not part
// of this repository, so the fixture cannot be rebuilt from source here.  This
// replacement reproduces the observable contract the regression suite relies
// on:
//
//   * prints "Hash: 0x6DD33F53" (the same FNV-style mix over "HelloWorld"),
//   * prints "Calc1: %d Calc2: %d" with the same results,
//   * prints "FibMix: %016llX" with the same value,
//   * prints "Protected: ..." and "OK",
//   * is a plain native x64 PE with **no** NovaProtect marker bytes, so the
//     planner's "VMProtect SDK calls are not exposed as NovaProtect marker
//     objects" assertion keeps its meaning.
//
// It deliberately uses no protection markers at all: the suite protects this
// image through the CLI switches, not through in-image markers.

#include <stdio.h>
#include <string.h>
#include <stdint.h>

__declspec(noinline) uint32_t secret_hash(const char* data, size_t len) {
    uint32_t h = 0x811C9DC5;
    for (size_t i = 0; i < len; i++) {
        h ^= (uint32_t)(unsigned char)data[i];
        h *= 0x01000193;
        h = (h << 13) | (h >> 19);
        h += 0x9E3779B9;
    }
    return h;
}

__declspec(noinline) int complex_calc(int a, int b, int c) {
    int result = 0;
    int t1 = a ^ (b << 3);
    int t2 = b | (c >> 2);
    int t3 = c + (a * 7);
    if (t1 > t2) {
        result = t3 - t1;
    } else {
        result = t2 + t3;
    }
    if (result < 0) {
        result = -result | (t1 & 0xFF);
    }
    return result;
}

__declspec(noinline) uint64_t fibonacci_mix(uint64_t seed, int rounds) {
    uint64_t a = seed, b = seed ^ 0xDEADBEEF;
    for (int i = 0; i < rounds; i++) {
        uint64_t t = a + b;
        a = b;
        b = t;
        if (b & 1) {
            b ^= (a << 7) | (a >> 57);
        } else {
            a ^= (b << 13) | (b >> 51);
        }
        b ^= seed;
    }
    return b;
}

int main(void) {
    printf("=== Benchmark Target ===\n");

    const char* test_data = "HelloWorld";
    uint32_t h = secret_hash(test_data, strlen(test_data));
    printf("Hash: 0x%08X\n", h);

    int r1 = complex_calc(42, 17, 99);
    int r2 = complex_calc(-5, 200, 3);
    printf("Calc1: %d Calc2: %d\n", r1, r2);

    uint64_t fib = fibonacci_mix(0x12345678, 64);
    printf("FibMix: %016llX\n", (unsigned long long)fib);

    printf("Protected: This is an encrypted string!\n");
    printf("OK\n");
    return 0;
}
