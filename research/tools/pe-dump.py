"""Dump the PE headers of a file field by field so malformed fixtures are easy
to spot."""
import struct
import sys

path = sys.argv[1]
b = open(path, "rb").read()
print(f"file={path} size={len(b)}")

if b[:2] != b"MZ":
    print("NOT MZ")
    sys.exit(1)
e_lfanew = struct.unpack_from("<I", b, 0x3C)[0]
print(f"e_lfanew=0x{e_lfanew:X}  signature={b[e_lfanew:e_lfanew+4]!r}")
pe = e_lfanew
machine, nsec, tds, psym, nsym, optsize, chars = struct.unpack_from("<HHIIIHH", b, pe + 4)
print(f"machine=0x{machine:04X} nsec={nsec} optsize=0x{optsize:X} chars=0x{chars:04X}")

opt = pe + 24
magic = struct.unpack_from("<H", b, opt)[0]
print(f"magic=0x{magic:04X} ({'PE32' if magic == 0x10B else 'PE32+' if magic == 0x20B else '?'})")
ep = struct.unpack_from("<I", b, opt + 16)[0]
base_code = struct.unpack_from("<I", b, opt + 20)[0]
base_data = struct.unpack_from("<I", b, opt + 24)[0]
image_base = struct.unpack_from("<I", b, opt + 28)[0]
sect_align = struct.unpack_from("<I", b, opt + 32)[0]
file_align = struct.unpack_from("<I", b, opt + 36)[0]
size_image = struct.unpack_from("<I", b, opt + 56)[0]
size_headers = struct.unpack_from("<I", b, opt + 60)[0]
subsystem = struct.unpack_from("<H", b, opt + 68)[0]
nrv = struct.unpack_from("<I", b, opt + 92)[0]
print(f"entrypoint=0x{ep:X} basecode=0x{base_code:X} basedata=0x{base_data:X}")
print(f"imagebase=0x{image_base:X} sect_align=0x{sect_align:X} file_align=0x{file_align:X}")
print(f"size_image=0x{size_image:X} size_headers=0x{size_headers:X} subsystem={subsystem}")
print(f"NumberOfRvaAndSizes={nrv}")
if nrv >= 2:
    imp_rva, imp_size = struct.unpack_from("<II", b, opt + 96 + 8)
    print(f"import dir rva=0x{imp_rva:X} size=0x{imp_size:X}")
if nrv >= 13:
    iat_rva, iat_size = struct.unpack_from("<II", b, opt + 96 + 12 * 8)
    print(f"IAT rva=0x{iat_rva:X} size=0x{iat_size:X}")

sec = opt + optsize
print("\nsections:")
sections = []
for i in range(nsec):
    o = sec + i * 40
    name = b[o:o + 8].rstrip(b"\0").decode("ascii", "replace")
    vsize, vaddr, rsize, raw = struct.unpack_from("<IIII", b, o + 8)
    chars = struct.unpack_from("<I", b, o + 36)[0]
    sections.append((name, vaddr, vsize, raw, rsize))
    print(f"  {name:8} vaddr=0x{vaddr:X} vsize=0x{vsize:X} raw=0x{raw:X} rsize=0x{rsize:X} chars=0x{chars:X}")

def to_off(rva):
    for name, vaddr, vsize, raw, rsize in sections:
        if vaddr <= rva < vaddr + max(vsize, rsize):
            return raw + (rva - vaddr)
    return None

if nrv >= 2:
    imp_rva = struct.unpack_from("<I", b, opt + 96 + 8)[0]
    off = to_off(imp_rva)
    print(f"\nimport descriptors at file offset {off}")
    if off is not None:
        for i in range(4):
            o = off + i * 20
            oft, tds, fwd, name_rva, ft = struct.unpack_from("<IIIII", b, o)
            print(f"  [{i}] OFT=0x{oft:X} Name=0x{name_rva:X} FT=0x{ft:X}")
            if name_rva:
                no = to_off(name_rva)
                if no is not None:
                    end = b.index(b"\0", no)
                    print(f"        dll={b[no:end]!r}")
            if ft:
                fo = to_off(ft)
                if fo is not None:
                    vals = struct.unpack_from("<III", b, fo)
                    print(f"        IAT[0..2]={['0x%X' % v for v in vals]}")
                    for v in vals:
                        if v & 0x80000000:
                            print(f"          ordinal {v & 0xFFFF}")
                        else:
                            ho = to_off(v)
                            if ho is not None:
                                hint = struct.unpack_from("<H", b, ho)[0]
                                end = b.index(b"\0", ho + 2)
                                print(f"          hint={hint} name={b[ho+2:end]!r}")
            if oft == 0 and name_rva == 0 and ft == 0:
                break
