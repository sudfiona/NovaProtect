"""Post-process a linked PE32: strip the stdcall decoration from the import
names in the import table.

rust-lld keeps the decorated spelling ("ExitProcess@4") in the import
name table.  The Windows loader resolves imports by the plain export name,
so the "@N" suffix has to be removed.  The calling convention itself is
unaffected: the code already issues a plain stdcall sequence.
"""
import struct
import sys


def fix(path):
    data = bytearray(open(path, "rb").read())
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    opt = pe + 24
    opt_size = struct.unpack_from("<H", data, pe + 20)[0]
    sec = opt + opt_size
    nsec = struct.unpack_from("<H", data, pe + 6)[0]

    sections = []
    for i in range(nsec):
        o = sec + i * 40
        vsize = struct.unpack_from("<I", data, o + 8)[0]
        vaddr = struct.unpack_from("<I", data, o + 12)[0]
        rsize = struct.unpack_from("<I", data, o + 16)[0]
        raw = struct.unpack_from("<I", data, o + 20)[0]
        sections.append((vaddr, vsize, raw, rsize))

    def to_off(rva):
        for vaddr, vsize, raw, rsize in sections:
            if vaddr <= rva < vaddr + max(vsize, rsize):
                return raw + (rva - vaddr)
        return None

    dd = opt + 96
    imp_rva = struct.unpack_from("<I", data, dd + 8)[0]
    if not imp_rva:
        print("no import directory")
        return
    off = to_off(imp_rva)
    if off is None:
        print("import directory not mappable")
        return

    fixed = 0
    desc = off
    while True:
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
                    print(f"  fixed import name {name!r} -> {plain!r}")
                    fixed += 1
            thunk += 4
        desc += 20

    open(path, "wb").write(bytes(data))
    print(f"patched {path}: {fixed} import name(s)")


if __name__ == "__main__":
    fix(sys.argv[1])
