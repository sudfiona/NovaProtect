"""Build tests/hostname32.exe - the native x86 fixture for the regression suite.

The suite needs a valid native x86 PE that prints "sudfiona".  This machine
has no 32-bit C toolchain (MinGW is x86_64 only) and no MSVC, so the fixture
is produced by Rust for i686-pc-windows-msvc and linked with rust-lld.

Two adjustments are needed after linking:

  * rust-lld keeps the stdcall decoration ("ExitProcess@4") in the import
    name table; the Windows loader resolves imports by the plain export
    name, so the suffix is stripped from the linked image.
  * the import library is generated from a .def file, because the machine has
    no 32-bit import libraries either.

Usage:  python make-x86-fixture-rust.py [output.exe]
"""
import os
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "rust32", "h32.rs")
DEF = os.path.join(HERE, "rust32", "k32.def")

DEF_TEXT = """LIBRARY kernel32.dll
EXPORTS
_ExitProcess@4=ExitProcess
_GetStdHandle@4=GetStdHandle
_WriteFile@20=WriteFile
"""


def find_rust_lld():
    import glob
    for pattern in (
        os.path.expanduser("~/.rustup/toolchains/*/lib/rustlib/x86_64-pc-windows-msvc/bin/rust-lld.exe"),
        os.path.expanduser("~/.rustup/toolchains/*/lib/rustlib/*/bin/rust-lld.exe"),
    ):
        hits = glob.glob(pattern)
        if hits:
            return hits[0]
    raise SystemExit("rust-lld not found; run: rustup target add i686-pc-windows-msvc")


def strip_decorations(path):
    """Remove the "@N" stdcall suffix from every import name."""
    data = bytearray(open(path, "rb").read())
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    opt = pe + 24
    opt_size = struct.unpack_from("<H", data, pe + 20)[0]
    sec = opt + opt_size
    nsec = struct.unpack_from("<H", data, pe + 6)[0]
    sections = []
    for i in range(nsec):
        o = sec + i * 40
        sections.append((
            struct.unpack_from("<I", data, o + 12)[0],
            struct.unpack_from("<I", data, o + 8)[0],
            struct.unpack_from("<I", data, o + 20)[0],
            struct.unpack_from("<I", data, o + 16)[0],
        ))

    def to_off(rva):
        for vaddr, vsize, raw, rsize in sections:
            if vaddr <= rva < vaddr + max(vsize, rsize):
                return raw + (rva - vaddr)
        return None

    imp_rva = struct.unpack_from("<I", data, opt + 96 + 8)[0]
    off = to_off(imp_rva)
    desc = off
    while off is not None:
        oft, tds, fwd, name_rva, ft = struct.unpack_from("<IIIII", data, desc)
        if oft == 0 and name_rva == 0 and ft == 0:
            break
        thunk = oft or ft
        while True:
            val = struct.unpack_from("<I", data, to_off(thunk))[0]
            if val == 0:
                break
            if not (val & 0x80000000):
                ho = to_off(val)
                end = data.index(b"\0", ho + 2)
                name = bytes(data[ho + 2:end])
                if b"@" in name:
                    plain = name.split(b"@")[0]
                    data[ho + 2:ho + 2 + len(plain)] = plain
                    data[ho + 2 + len(plain):end + 1] = b"\x00" * (end + 1 - ho - 2 - len(plain))
            thunk += 4
        desc += 20
    open(path, "wb").write(bytes(data))


def build(out_path):
    work = os.path.join(HERE, "rust32")
    os.makedirs(work, exist_ok=True)
    with open(DEF, "w", encoding="ascii") as f:
        f.write(DEF_TEXT)

    lld = find_rust_lld()
    lib = os.path.join(work, "k32.lib")
    if os.path.exists(lib):
        os.remove(lib)
    subprocess.run(
        [lld, "-flavor", "link", "/dll", "/def:" + DEF, "/out:" + lib,
         "/machine:i386", "/noentry"],
        check=True, cwd=work,
        env={**os.environ, "MSYS2_ARG_CONV_EXCL": "*"})

    exe = os.path.join(work, "hostname32.exe")
    subprocess.run(
        ["rustc", "--target", "i686-pc-windows-msvc",
         "-C", "linker=rust-lld", "-C", "panic=abort", "-C", "opt-level=z",
         "-C", "relocation-model=static",
         "-C", "link-arg=/libpath:" + work,
         "-C", "link-arg=k32.lib",
         "-C", "link-arg=/subsystem:console",
         "-C", "link-arg=/entry:mainCRTStartup",
         "-C", "link-arg=/nodefaultlib",
         SRC, "-o", exe],
        check=True, cwd=work,
        env={**os.environ, "MSYS2_ARG_CONV_EXCL": "*"})

    strip_decorations(exe)

    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    open(out_path, "wb").write(open(exe, "rb").read())
    print(f"wrote {out_path} ({os.path.getsize(out_path)} bytes)")

    r = subprocess.run([out_path], capture_output=True, timeout=30)
    print(f"run: rc={r.returncode} stdout={r.stdout!r}")
    if r.returncode != 0 or b"sudfiona" not in r.stdout:
        raise SystemExit("fixture did not print sudfiona")


if __name__ == "__main__":
    build(sys.argv[1] if len(sys.argv) > 1 else r"C:\npbuild\tests\hostname32.exe")
