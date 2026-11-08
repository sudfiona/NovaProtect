"""Load the generated 32-bit fixture and report the exact failure point."""
import ctypes
import ctypes.wintypes as wt
import struct

path = r"C:\npbuild\tests\hostname32.exe"

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

# Read the file and map it as the loader would.
data = open(path, "rb").read()
pe = struct.unpack_from("<I", data, 0x3C)[0]
opt = pe + 24
image_base = struct.unpack_from("<I", data, opt + 28)[0]
size_image = struct.unpack_from("<I", data, opt + 56)[0]
entry_rva = struct.unpack_from("<I", data, opt + 16)[0]
nsec = struct.unpack_from("<H", data, pe + 6)[0]
optsize = struct.unpack_from("<H", data, pe + 20)[0]
sec = opt + optsize

sections = []
for i in range(nsec):
    o = sec + i * 40
    name = data[o:o + 8].rstrip(b"\0").decode()
    vsize, vaddr, rsize, raw = struct.unpack_from("<IIII", data, o + 8)
    sections.append((name, vaddr, vsize, raw, rsize))

MAP = 0x10000
kernel32.SetProcessDEPPolicy if False else None

hmap = kernel32.CreateFileMappingW(wt.HANDLE(-1), None, 0x04, 0, 0, None)
if not hmap:
    print("CreateFileMapping failed", ctypes.get_last_error())
    raise SystemExit(1)
base = kernel32.MapViewOfFile(hmap, 0x04, 0, 0, 0)
print(f"mapped base=0x{base:X} (want 0x{image_base:X})")

buf = (ctypes.c_char * len(data)).from_buffer_copy(data)
ctypes.memmove(base, buf, len(data))

# Apply relocations if the image landed elsewhere - we force it to the
# preferred base instead, so there is nothing to fix up.
if base != image_base:
    print("WARNING: image not at preferred base; relocations not applied")

for name, vaddr, vsize, raw, rsize in sections:
    print(f"  section {name} vaddr=0x{vaddr:X} copied")

# Resolve imports manually: walk the import descriptors and fill the IAT.
dd = opt + 96


def rva_to_off(rva):
    for name, vaddr, vsize, raw, rsize in sections:
        if vaddr <= rva < vaddr + max(vsize, rsize):
            return raw + (rva - vaddr)
    return None


imp_rva = struct.unpack_from("<I", data, dd + 8)[0]
off = rva_to_off(imp_rva)
desc = off
while True:
    oft, tds, fwd, name_rva, ft = struct.unpack_from("<IIIII", data, desc)
    if oft == 0 and name_rva == 0 and ft == 0:
        break
    no = rva_to_off(name_rva)
    end = data.index(b"\0", no)
    dll = data[no:end].decode()
    print(f"  import dll={dll} IAT=0x{ft:X}")
    handle = kernel32.LoadLibraryW(dll)
    if not handle:
        print("    LoadLibrary failed", ctypes.get_last_error())
        break
    thunk = oft or ft
    iat_off = rva_to_off(ft)
    while True:
        val = struct.unpack_from("<I", data, rva_to_off(thunk))[0]
        if val == 0:
            break
        if not (val & 0x80000000):
            hn = rva_to_off(val)
            fname_end = data.index(b"\0", hn + 2)
            fname = data[hn + 2:fname_end].decode()
            addr = kernel32.GetProcAddress(handle, fname.encode())
        else:
            addr = kernel32.GetProcAddress(handle, ctypes.c_void_p(val & 0xFFFF))
        struct.pack_into("<I", (ctypes.c_char * (size_image)).from_address(base + ft), 0, 0)
        ctypes.memmove(ctypes.c_void_p(base + ft), ctypes.byref(ctypes.c_uint(addr)), 4)
        thunk += 4
        ft += 4
    desc += 20

print("calling entry point")
entry = base + entry_rva
try:
    kernel32.CreateThread(None, 0, ctypes.c_void_p(entry), None, 0, None)
except Exception as e:
    print("thread create failed", e)
print("done")
