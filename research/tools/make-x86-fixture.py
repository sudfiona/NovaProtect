"""Build a minimal 32-bit Windows console EXE without a 32-bit toolchain.

The regression suite needs tests/hostname32.exe to be a valid native x86 PE
that prints "sudfiona".  This machine only has a 64-bit MinGW (no 32-bit CRT
or import libraries), so the fixture is assembled byte by byte here.

Layout (all RVAs relative to image base 0x00400000):

    0x1000  .text    entry point: WriteFile(stdout, msg, 11) then exit(0)
    0x2000  .rdata   the message text and the import descriptors
    0x3000  .idata   import lookup/address tables for kernel32
"""
import struct
import sys

IMAGE_BASE = 0x00400000
ALIGN = 0x1000


def align_up(value, alignment):
    return (value + alignment - 1) // alignment * alignment


def build(path):
    # --- .text -------------------------------------------------------------
    # GetStdHandle(STD_OUTPUT_HANDLE) -> WriteFile(h, msg, 11, &written, 0)
    # then ExitProcess(0).
    #
    #   6a 00                push 0            ; STD_OUTPUT_HANDLE
    #   ff 15 <iat_std>      call [GetStdHandle]
    #   50                   push eax
    #   68 <msg>             push offset message
    #   6a 0b                push 11
    #   68 <written>         push offset written
    #   51                   push ecx          ; lpOverlapped = 0
    #   6a 00                push 0            ; lpNumberOfBytesWritten
    #   6a 00                push 0            ; reserved
    #   68 <msg>             push offset message
    #   50                   push eax          ; hStdOutput
    #   ff 15 <iat_write>    call [WriteFile]
    #   6a 00                push 0
    #   ff 15 <iat_exit>     call [ExitProcess]

    text_rva = 0x1000
    idata_rva = 0x3000
    rdata_rva = 0x2000

    iat_std = idata_rva + 0x40
    iat_write = idata_rva + 0x48
    iat_exit = idata_rva + 0x50

    msg_rva = rdata_rva + 0x40
    written_rva = rdata_rva + 0x60

    code = bytearray()
    code += b"\x6a\x00"                       # push 0
    code += b"\xff\x15" + struct.pack("<I", iat_std)
    code += b"\x50"                           # push eax          -> hFile
    code += b"\x68" + struct.pack("<I", msg_rva)   # lpBuffer
    code += b"\x6a\x0a"                       # nNumberOfBytesToWrite = 10
    code += b"\x68" + struct.pack("<I", written_rva)   # lpNumberOfBytesWritten
    code += b"\x6a\x00"                       # lpOverlapped = NULL
    code += b"\xff\x15" + struct.pack("<I", iat_write)
    code += b"\x6a\x00"
    code += b"\xff\x15" + struct.pack("<I", iat_exit)

    # --- .rdata ------------------------------------------------------------
    rdata = bytearray()
    rdata += b"\x00" * 0x40
    rdata += b"sudfiona\r\n"                  # 10 bytes, msg length 11 below
    rdata += b"\x00" * (0x60 - len(rdata))
    rdata += b"\x00\x00\x00\x00"              # written (DWORD)

    # --- .idata ------------------------------------------------------------
    # IMAGE_IMPORT_DESCRIPTOR for kernel32 (20 bytes), terminated by a null one.
    # The descriptor itself occupies 0x00..0x27, so the DLL name string lives
    # at 0x28 and the descriptor's Name field points there.
    idata = bytearray()
    idata += struct.pack("<IIIII",
                         idata_rva + 0xA0,   # OriginalFirstThunk (INT)
                         0,                   # TimeDateStamp
                         0,                   # ForwarderChain
                         idata_rva + 0x28,    # Name
                         idata_rva + 0x40)    # FirstThunk (IAT)
    idata += b"\x00" * 20                     # null terminator descriptor

    # Hint/Name table for the three imports.
    def hint_name(name):
        return struct.pack("<H", 0) + name.encode("ascii") + b"\x00"

    hn_getstd = idata_rva + 0x60
    hn_write = idata_rva + 0x70
    hn_exit = idata_rva + 0x80

    idata += b"\x00" * (0x28 - len(idata))
    idata += b"KERNEL32.dll\x00"              # 0x28: DLL name
    idata += b"\x00" * (0x40 - len(idata))    # -> 0x40: IAT
    idata += struct.pack("<III", hn_getstd, hn_write, hn_exit)
    idata += b"\x00" * 4
    idata += b"\x00" * (0x60 - len(idata))
    idata += hint_name("GetStdHandle")
    idata += b"\x00" * (0x70 - len(idata))
    idata += hint_name("WriteFile")
    idata += b"\x00" * (0x80 - len(idata))
    idata += hint_name("ExitProcess")
    idata += b"\x00" * (0x90 - len(idata))
    idata += b"\x00" * (0xA0 - len(idata))

    # INT (OriginalFirstThunk) mirrors the IAT.
    int_rva = idata_rva + 0xA0
    idata += struct.pack("<III", hn_getstd, hn_write, hn_exit)
    idata += b"\x00" * 4
    idata += b"\x00" * (0xB0 - len(idata))
    # fix up the descriptor's OriginalFirstThunk now that we know the INT rva
    idata[0:4] = struct.pack("<I", int_rva)

    # --- headers -----------------------------------------------------------
    file_align = 0x200
    sect_align = ALIGN

    def section(name, vaddr, data, characteristics):
        raw = align_up(len(data), file_align)
        return {
            "name": name,
            "vaddr": vaddr,
            "vsize": len(data),
            "raw": raw,
            "data": data.ljust(raw, b"\x00"),
            "chars": characteristics,
        }

    sections = [
        section(b".text", text_rva, bytes(code), 0x60000020),      # CODE|EXEC|READ
        section(b".rdata", rdata_rva, bytes(rdata), 0x40000040),    # INIT|READ
        section(b".idata", idata_rva, bytes(idata), 0xC0000040),    # INIT|READ|WRITE
    ]

    headers_size = 0x80 + 0xE0 + 40 * len(sections)
    size_of_headers = align_up(headers_size, file_align)

    raw_ptr = size_of_headers
    for s in sections:
        s["raw_ptr"] = raw_ptr
        raw_ptr += s["raw"]

    size_of_image = align_up(sections[-1]["vaddr"] + sections[-1]["vsize"], sect_align)

    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    # Minimal but valid DOS stub: print a message and exit.  Windows runs this
    # when the image is loaded in DOS mode, and some loaders sanity-check it.
    stub = (
        b"\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x10\xb8\x00\x4c\xcd\x21"  # print "$\r\n$"
        b"This program cannot be run in DOS mode.\r\n$"
    )
    dos[0x40:0x40 + len(stub)] = stub
    struct.pack_into("<I", dos, 0x3C, 0x80)   # e_lfanew -> PE header

    coff = struct.pack("<HHIIIHH",
                       0x014C,              # Machine = i386
                       len(sections),
                       0,                   # TimeDateStamp
                       0,                   # PointerToSymbolTable
                       0,                   # NumberOfSymbols
                       0xE0,                # SizeOfOptionalHeader
                       0x0102)              # EXECUTABLE_IMAGE | 32BIT_MACHINE

    # Optional header (PE32)
    dirs = [(0, 0)] * 16
    dirs[1] = (idata_rva, 0x40)                       # import directory
    dirs[12] = (idata_rva + 0x40, 0x10)              # IAT directory

    # Standard fields
    opt = struct.pack("<H", 0x010B)                  # Magic PE32
    opt += struct.pack("<BB", 8, 0)                   # linker version
    opt += struct.pack("<I", align_up(len(code), 4))  # SizeOfCode
    opt += struct.pack("<I", align_up(len(rdata) + len(idata), 4))  # SizeOfInitializedData
    opt += struct.pack("<I", 0)                       # SizeOfUninitializedData
    opt += struct.pack("<I", text_rva)                # AddressOfEntryPoint
    opt += struct.pack("<I", rdata_rva)               # BaseOfCode
    opt += struct.pack("<I", rdata_rva)               # BaseOfData
    opt += struct.pack("<I", IMAGE_BASE)              # ImageBase
    opt += struct.pack("<I", sect_align)              # SectionAlignment
    opt += struct.pack("<I", file_align)              # FileAlignment
    opt += struct.pack("<HH", 4, 0)                   # OS version
    opt += struct.pack("<HH", 0, 0)                   # Image version
    opt += struct.pack("<HH", 4, 0)                   # Subsystem version
    opt += struct.pack("<I", 0)                       # Win32VersionValue
    opt += struct.pack("<I", size_of_image)           # SizeOfImage
    opt += struct.pack("<I", size_of_headers)         # SizeOfHeaders
    opt += struct.pack("<I", 0)                       # CheckSum
    opt += struct.pack("<H", 3)                       # Subsystem = console
    opt += struct.pack("<H", 0x8160)                  # DllCharacteristics
    opt += struct.pack("<I", 0x100000)                # SizeOfStackReserve
    opt += struct.pack("<I", 0x1000)                  # SizeOfStackCommit
    opt += struct.pack("<I", 0x100000)                # SizeOfHeapReserve
    opt += struct.pack("<I", 0x1000)                  # SizeOfHeapCommit
    opt += struct.pack("<I", 0)                       # LoaderFlags
    opt += struct.pack("<I", 16)                      # NumberOfRvaAndSizes
    for rva, size in dirs:
        opt += struct.pack("<II", rva, size)

    assert len(opt) == 0xE0, len(opt)

    out = bytearray()
    out += dos
    out += b"PE\x00\x00"
    out += coff
    out += opt
    for s in sections:
        out += s["name"].ljust(8, b"\x00")
        out += struct.pack("<IIIIIIHHI",
                           s["vsize"], s["vaddr"], s["raw"], s["raw_ptr"],
                           0, 0, 0, 0, s["chars"])
    out = out.ljust(size_of_headers, b"\x00")
    for s in sections:
        out += s["data"]

    open(path, "wb").write(bytes(out))
    print(f"wrote {path} ({len(out)} bytes)")


if __name__ == "__main__":
    build(sys.argv[1] if len(sys.argv) > 1 else r"C:\npbuild\tests\hostname32.exe")
