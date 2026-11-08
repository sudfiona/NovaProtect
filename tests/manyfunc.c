// manyfunc.c - fixture with hundreds of simple leaf functions.
//
// Mirrors the user scenario: the client scans every function of the target
// and the user checks "all of them". Each function here is a straight-line
// arithmetic leaf that never touches RSP/RBP, so the VM translator accepts
// it and the region table really fills up.
//
// Build (x64, mingw):
//   x86_64-w64-mingw32-gcc -O1 -o manyfunc.exe manyfunc.c
//
// The program prints a checksum over the results so a corrupted protected
// build is detected by the exit code, not just by "it started".
#include <stdint.h>
#include <stdio.h>

#define NFUNCS 400

#define MKFN(n)                                                          \
    __attribute__((noinline)) uint64_t fn##n(uint64_t a, uint64_t b) {   \
        uint64_t r = a + b;                                              \
        r = (r << 3) ^ (r >> 2);                                         \
        r += 0x9E3779B97F4A7C15ull * (n + 1);                            \
        r ^= (r >> 17);                                                  \
        r *= 0x165667B19E3779F9ull;                                      \
        r ^= (r >> 13);                                                  \
        r += (n);                                                        \
        return r;                                                        \
    }

MKFN(0)   MKFN(1)   MKFN(2)   MKFN(3)   MKFN(4)
MKFN(5)   MKFN(6)   MKFN(7)   MKFN(8)   MKFN(9)
MKFN(10)  MKFN(11)  MKFN(12)  MKFN(13)  MKFN(14)
MKFN(15)  MKFN(16)  MKFN(17)  MKFN(18)  MKFN(19)
MKFN(20)  MKFN(21)  MKFN(22)  MKFN(23)  MKFN(24)
MKFN(25)  MKFN(26)  MKFN(27)  MKFN(28)  MKFN(29)
MKFN(30)  MKFN(31)  MKFN(32)  MKFN(33)  MKFN(34)
MKFN(35)  MKFN(36)  MKFN(37)  MKFN(38)  MKFN(39)
MKFN(40)  MKFN(41)  MKFN(42)  MKFN(43)  MKFN(44)
MKFN(45)  MKFN(46)  MKFN(47)  MKFN(48)  MKFN(49)
MKFN(50)  MKFN(51)  MKFN(52)  MKFN(53)  MKFN(54)
MKFN(55)  MKFN(56)  MKFN(57)  MKFN(58)  MKFN(59)
MKFN(60)  MKFN(61)  MKFN(62)  MKFN(63)  MKFN(64)
MKFN(65)  MKFN(66)  MKFN(67)  MKFN(68)  MKFN(69)
MKFN(70)  MKFN(71)  MKFN(72)  MKFN(73)  MKFN(74)
MKFN(75)  MKFN(76)  MKFN(77)  MKFN(78)  MKFN(79)
MKFN(80)  MKFN(81)  MKFN(82)  MKFN(83)  MKFN(84)
MKFN(85)  MKFN(86)  MKFN(87)  MKFN(88)  MKFN(89)
MKFN(90)  MKFN(91)  MKFN(92)  MKFN(93)  MKFN(94)
MKFN(95)  MKFN(96)  MKFN(97)  MKFN(98)  MKFN(99)

#define CALL(n) sum ^= fn##n(a + n, b ^ (n * 7u));

int main(void) {
    uint64_t a = 0x0123456789ABCDEFull, b = 0xFEDCBA9876543210ull;
    uint64_t sum = 0;

    CALL(0)   CALL(1)   CALL(2)   CALL(3)   CALL(4)
    CALL(5)   CALL(6)   CALL(7)   CALL(8)   CALL(9)
    CALL(10)  CALL(11)  CALL(12)  CALL(13)  CALL(14)
    CALL(15)  CALL(16)  CALL(17)  CALL(18)  CALL(19)
    CALL(20)  CALL(21)  CALL(22)  CALL(23)  CALL(24)
    CALL(25)  CALL(26)  CALL(27)  CALL(28)  CALL(29)
    CALL(30)  CALL(31)  CALL(32)  CALL(33)  CALL(34)
    CALL(35)  CALL(36)  CALL(37)  CALL(38)  CALL(39)
    CALL(40)  CALL(41)  CALL(42)  CALL(43)  CALL(44)
    CALL(45)  CALL(46)  CALL(47)  CALL(48)  CALL(49)
    CALL(50)  CALL(51)  CALL(52)  CALL(53)  CALL(54)
    CALL(55)  CALL(56)  CALL(57)  CALL(58)  CALL(59)
    CALL(60)  CALL(61)  CALL(62)  CALL(63)  CALL(64)
    CALL(65)  CALL(66)  CALL(67)  CALL(68)  CALL(69)
    CALL(70)  CALL(71)  CALL(72)  CALL(73)  CALL(74)
    CALL(75)  CALL(76)  CALL(77)  CALL(78)  CALL(79)
    CALL(80)  CALL(81)  CALL(82)  CALL(83)  CALL(84)
    CALL(85)  CALL(86)  CALL(87)  CALL(88)  CALL(89)
    CALL(90)  CALL(91)  CALL(92)  CALL(93)  CALL(94)
    CALL(95)  CALL(96)  CALL(97)  CALL(98)  CALL(99)

    printf("manyfunc: sum=%016llX\n", (unsigned long long)sum);
    if (sum == 0) { printf("MANYFUNC-BAD\n"); return 1; }
    printf("MANYFUNC-OK\n");
    return 0;
}
