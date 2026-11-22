// Driver for the VM example. Build:
//   gcc -O2 example_driver.c example_vm.S -o sdk_vm_example.exe
#include <stdio.h>
#include <stdint.h>

extern uint64_t np_sdk_vm_demo(uint64_t a, uint64_t b);

int main(void)
{
    uint64_t got = np_sdk_vm_demo(0x1122334455667788ull, 0x8877665544332211ull);
    printf("sdk_vm_demo=%016llX\n", (unsigned long long)got);
    return 0;
}