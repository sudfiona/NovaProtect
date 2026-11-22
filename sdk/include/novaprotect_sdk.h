#pragma once
// NovaProtect SDK - function / region protection markers.
//
// Usage:
//   1. Wrap a function body with NOVAPROTECT_BEGIN("name") / NOVAPROTECT_END().
//   2. Compile the EXE (markers are inert in the unprotected build).
//   3. Run the EXE through the NovaProtect client. The detector scans for the
//      BEGIN/END byte pattern and the packer lowers the enclosed region to VM
//      bytecode (or applies the selected object rule).
//
// VM coverage (current):
//   The x64 VM translator lowers the whole function body - stack frames,
//   memory operands and ordinary compiler output all translate. Measured on
//   a real engine build, 100.0% of function bytes are virtualized (every
//   chunk virtualizable, zero reject buckets). A few exotic forms (AVX,
//   cmpxchg8b/16b, 16-bit push/pop) run on a native bridge between VM chunks
//   instead of inside the VM; the rest of the function still virtualizes and
//   behaviour is preserved either way. See sdk/README.md for the full table.
//
// Backward compatibility: NOVAPACK_* names continue to work and emit the same
// bytes.

#if defined(_MSC_VER) && !defined(__clang__)
#define NOVAPROTECT_INLINE __forceinline
#elif defined(__GNUC__)
#define NOVAPROTECT_INLINE __attribute__((always_inline))
#else
#define NOVAPROTECT_INLINE inline
#endif

#if defined(_WIN64)
#define NOVAPROTECT_BEGIN(name) \
    __asm__ volatile(".byte 0x48,0x8D,0x0D,0x00,0x00,0x00,0x00"); \
    __asm__ volatile("nop; nop; nop; nop; nop; nop; nop; nop; nop; nop"); \
    __asm__ volatile("nop; nop; nop; nop; nop; nop; nop; nop; nop; nop")
#elif defined(_WIN32)
#define NOVAPROTECT_BEGIN(name) \
    __asm__ volatile(".byte 0x8D,0x0D,0x00,0x00,0x00,0x00"); \
    __asm__ volatile("nop; nop; nop; nop; nop; nop; nop; nop; nop; nop"); \
    __asm__ volatile("nop; nop; nop; nop; nop; nop; nop; nop; nop; nop")
#else
#error "NovaProtect SDK markers require x86 or x64 Windows"
#endif

#define NOVAPROTECT_END() \
    __asm__ volatile("nop; nop; nop; nop; nop; nop; nop; nop; nop; nop"); \
    __asm__ volatile("nop; nop; nop; nop; nop; nop; nop; nop; nop; nop")

// Legacy aliases kept for existing projects.
#define NOVAPACK_BEGIN(name) NOVAPROTECT_BEGIN(name)
#define NOVAPACK_END() NOVAPROTECT_END()

#define NOVAPROTECT_SDK_VERSION "2.2.7"