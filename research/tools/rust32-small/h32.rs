// h32 - minimal native 32-bit Windows fixture for the regression suite.
//
// The suite needs tests/hostname32.exe to be a valid native x86 PE that
// prints "sudfiona".  This machine has no 32-bit C toolchain (the MinGW
// install is x86_64 only) and no MSVC, so the fixture is produced by Rust
// for the i686-pc-windows-msvc target and linked with rust-lld.
//
// It is deliberately no_std: the program does nothing but call WriteFile on
// the standard output handle.  A full runtime (Go, .NET) is not usable here
// because the x86 protection runtime hooks CPUID for its anti-VM check, and
// a managed runtime crashes while probing CPU features at start-up.
//
// Build:
//   rustup target add i686-pc-windows-msvc
//   rustc --target i686-pc-windows-msvc -C linker=rust-lld \
//         -C panic=abort -C opt-level=z -C relocation-model=static \
//         h32.rs -o hostname32.exe

#![no_std]
#![no_main]

use core::panic::PanicInfo;

type HANDLE = isize;
type BOOL = i32;
type DWORD = u32;
type LPVOID = *mut core::ffi::c_void;

// stdcall ("system") so the callee pops the arguments, exactly like the real
// Win32 API.  The import library is generated from a .def file that exports
// both the plain and the decorated spelling, so the linker resolves the
// stdcall symbols.
extern "system" {
    fn GetStdHandle(n_std_handle: DWORD) -> HANDLE;
    fn WriteFile(
        h_file: HANDLE,
        lp_buffer: *const u8,
        n_number_of_bytes_to_write: DWORD,
        lp_number_of_bytes_written: *mut DWORD,
        lp_overlapped: LPVOID,
    ) -> BOOL;
    fn ExitProcess(u_exit_code: DWORD) -> !;
}

const STD_OUTPUT_HANDLE: DWORD = 0xFFFF_FFF5; // (DWORD)-11
const MESSAGE: &[u8] = b"sudfiona\r\n";

// The packer keeps the first 0x1000 bytes of every executable section
// unencrypted (loader metadata may live there), so a fixture whose .text is
// smaller than that has no packable code at all.  The filler therefore sits
// in the same executable section, behind the entry point.
// (no filler: this variant deliberately keeps .text smaller than the loader
// header reserve so the "nothing to pack" path can be exercised)

#[no_mangle]
pub extern "C" fn mainCRTStartup() -> ! {
    unsafe {
        let handle = GetStdHandle(STD_OUTPUT_HANDLE);
        let mut written: DWORD = 0;
        WriteFile(
            handle,
            MESSAGE.as_ptr(),
            MESSAGE.len() as DWORD,
            &mut written,
            core::ptr::null_mut(),
        );
        ExitProcess(0)
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    unsafe { ExitProcess(1) }
}
