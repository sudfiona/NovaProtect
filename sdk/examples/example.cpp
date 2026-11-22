// NovaProtect SDK example: mark one function for virtualization.
//
// The x64 VM translator covers the whole function body - stack frames and
// memory operands included. This example body is intentionally small so the
// resulting bytecode is easy to follow, not because anything here has to stay
// register-only. Exotic forms (AVX, cmpxchg8b/16b) run on a native bridge
// instead of inside the VM; everything else translates.
#include "novaprotect_sdk.h"
#include <cstdio>

volatile int g_seed = 0x5A5A5A5A;

int secret_calc(int x)
{
    NOVAPROTECT_BEGIN("secret_calc");
    int a = x + 3;
    int b = x - 7;
    int c = a ^ b;
    c = c * 0x9E3779B9 + a;
    c = c ^ g_seed;
    NOVAPROTECT_END();
    return c;
}

int main()
{
    std::printf("result=%d\n", secret_calc(42));
    return 0;
}