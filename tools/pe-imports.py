import struct
import sys


def sections(data):
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    coff = e_lfanew + 4
    num_sec = struct.unpack_from("<H", data, coff + 2)[0]
    opt_size = struct.unpack_from("<H", data, coff + 16)[0]
    opt = coff + 20
    magic = struct.unpack_from("<H", data, opt)[0]
    is64 = magic == 0x20B
    dd = opt + (112 if is64 else 96)
    out = []
    for i in range(num_sec):
        off = opt + opt_size + i * 40
        name = data[off:off + 8].rstrip(b"\0").decode("latin1")
        vsize, va, rsize, rptr = struct.unpack_from("<IIII", data, off + 8)
        ch = struct.unpack_from("<I", data, off + 36)[0]
        out.append(dict(name=name, va=va, vsize=vsize, rsize=rsize, rptr=rptr, ch=ch))
    return is64, dd, out


def rva_to_off(secs, rva):
    for s in secs:
        span = max(s["vsize"], s["rsize"])
        if s["va"] <= rva < s["va"] + span:
            return s["rptr"] + (rva - s["va"])
    return None


def main(path):
    data = open(path, "rb").read()
    is64, dd, secs = sections(data)
    print(f"file      : {path}")
    print(f"size      : {len(data)}")
    print(f"pe        : PE32+ x64" if is64 else "pe        : PE32 x86")
    print("sections  :")
    for s in secs:
        flags = "".join([
            "R" if s["ch"] & 0x40000000 else "-",
            "W" if s["ch"] & 0x80000000 else "-",
            "X" if s["ch"] & 0x20000000 else "-",
        ])
        print(f"  {s['name']:<10} va=0x{s['va']:06X} vsize=0x{s['vsize']:06X} "
              f"raw=0x{s['rsize']:06X} {flags}")

    imp_rva, imp_size = struct.unpack_from("<II", data, dd + 8)
    iat_rva, iat_size = struct.unpack_from("<II", data, dd + 12 * 8)
    print(f"\nimport dir: rva=0x{imp_rva:X} size=0x{imp_size:X}")
    print(f"iat dir   : rva=0x{iat_rva:X} size=0x{iat_size:X}")

    if imp_rva == 0:
        print("!! EMPTY IMPORT TABLE -- this is the empty_import signature")
        return 1

    off = rva_to_off(secs, imp_rva)
    if off is None:
        print("!! import directory does not map into any section")
        return 1

    thunk = 8 if is64 else 4
    fmt = "<Q" if is64 else "<I"
    total = 0
    i = 0
    while True:
        base = off + i * 20
        oft, ts, fc, name_rva, ft = struct.unpack_from("<IIIII", data, base)
        if oft == 0 and name_rva == 0 and ft == 0:
            break
        noff = rva_to_off(secs, name_rva)
        dll = data[noff:data.index(b"\0", noff)].decode("latin1") if noff else "?"
        lookup = oft or ft
        loff = rva_to_off(secs, lookup)
        fns = []
        k = 0
        while loff is not None:
            val = struct.unpack_from(fmt, data, loff + k * thunk)[0]
            if val == 0:
                break
            if val & (1 << (63 if is64 else 31)):
                fns.append(f"#{val & 0xFFFF}")
            else:
                hoff = rva_to_off(secs, val & 0x7FFFFFFF)
                if hoff:
                    end = data.index(b"\0", hoff + 2)
                    fns.append(data[hoff + 2:end].decode("latin1"))
                else:
                    fns.append("?")
            k += 1
        total += len(fns)
        print(f"  {dll:<16} {len(fns):>2} fns: {', '.join(fns)}")
        i += 1

    print(f"\ntotal imported functions: {total}")
    if total == 0:
        print("!! zero functions")
        return 1
    print("RESULT: import table is non-empty and parses")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
