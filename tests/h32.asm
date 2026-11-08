// hostname32_asm.asm - minimal 32-bit PE fixture (GNU as, AT&T syntax).
//
// The regression suite needs tests/hostname32.exe to be a valid native x86
// EXE that prints "sudfiona".  This machine only has a 64-bit MinGW (no
// 32-bit CRT or import libraries), so the fixture is written in assembly and
// linked straight against the 32-bit kernel32.dll with "ld -m i386pe",
// which synthesises the import stubs automatically.
//
// No CRT is needed: the message is written with WriteFile on the standard
// output handle and the process ends with ExitProcess.

    .section .text
    .globl  _mainCRTStartup
_mainCRTStartup:
    pushl   $0                      /* STD_OUTPUT_HANDLE */
    call    GetStdHandle
    pushl   %eax                    /* hStdOutput */
    pushl   $message                /* lpBuffer */
    pushl   $10                     /* nNumberOfBytesToWrite */
    pushl   $written                /* lpNumberOfBytesWritten */
    pushl   $0                      /* lpOverlapped */
    call    WriteFile
    pushl   $0
    call    ExitProcess
    /* ExitProcess never returns; keep a halt for safety. */
    hlt

    .section .rdata
    .globl  message
message:
    .ascii  "sudfiona\r\n"

    .section .data
    .globl  written
written:
    .long   0

    .end
