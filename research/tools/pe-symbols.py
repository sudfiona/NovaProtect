"""Find the RVA of a symbol in a PE file by parsing the export table and, as a
fallback, by scanning for the NovaProtect marker byte pattern.

Used by the regression suite to generate a valid -funcfile rule list.
"""
import struct
import sys


def read_u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def read_u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def rva_to_offset(rva, sections):
    for name, vaddr, vsize, raw, rsize in sections:
        if vaddr <= rva < vaddr + max(vsize, rsize):
            return raw + (rva - vaddr)
    return None


def parse(path):
    b = open(path, "rb").read()
    pe = read_u32(b, 0x3C)
    assert b[pe:pe + 4] == b"PE\0\0", "not a PE"
    coff = pe + 4
    nsec = read_u16(b, coff + 2)
    opt = coff + 20
    magic = read_u16(b, opt)
    is64 = magic == 0x20B
    image_base = struct.unpack_from("<Q" if is64 else "<I", b, opt + 24)[0]
    dd = opt + (112 if is64 else 96)
    sec_off = opt + read_u16(b, coff + 16)

    sections = []
    for i in range(nsec):
        o = sec_off + i * 40
        name = b[o:o + 8].rstrip(b"\0").decode("ascii", "replace")
        vsize = read_u32(b, o + 8)
        vaddr = read_u32(b, o + 12)
        rsize = read_u32(b, o + 16)
        raw = read_u32(b, o + 20)
        sections.append((name, vaddr, vsize, raw, rsize))

    exports = []
    exp_rva = read_u32(b, dd)
    if exp_rva:
        eo = rva_to_offset(exp_rva, sections)
        if eo is not None:
            nfuncs = read_u32(b, eo + 20)
            nnames = read_u32(b, eo + 24)
            af = read_u32(b, eo + 28)
            an = read_u32(b, eo + 32)
            ao = read_u32(b, eo + 36)
            afo = rva_to_offset(af, sections)
            ano = rva_to_offset(an, sections)
            aoo = rva_to_offset(ao, sections)
            for i in range(nnames):
                nrva = read_u32(b, ano + i * 4)
                no = rva_to_offset(nrva, sections)
                end = b.index(b"\0", no)
                sym = b[no:end].decode("ascii", "replace")
                ordidx = read_u16(b, aoo + i * 2)
                frva = read_u32(b, afo + ordidx * 4)
                exports.append((sym, frva))

    # Exception directory (.pdata) for x64: gives real function boundaries.
    pdata = []
    if is64:
        p_rva = read_u32(b, dd + 3 * 8)
        p_size = read_u32(b, dd + 3 * 8 + 4)
        if p_rva and p_size:
            po = rva_to_offset(p_rva, sections)
            n = p_size // 12
            for i in range(n):
                o = po + i * 12
                begin = read_u32(b, o)
                end = read_u32(b, o + 4)
                if begin and end > begin:
                    pdata.append((begin, end))
    return b, image_base, sections, exports, pdata


if __name__ == "__main__":
    path = sys.argv[1]
    b, base, sections, exports, pdata = parse(path)
    print(f"file={path} image_base=0x{base:X} exports={len(exports)} pdata={len(pdata)}")
    for sym, rva in exports:
        print(f"  export {sym} rva=0x{rva:X}")
    # Show the first few pdata ranges so we can build rule files.
    for i, (begin, end) in enumerate(pdata[:10]):
        print(f"  pdata[{i}] 0x{begin:X}-0x{end:X} size={end-begin}")
