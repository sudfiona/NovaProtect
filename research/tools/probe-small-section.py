"""Reproduce the small-section packing edge case.

The packer keeps the first 0x1000 bytes of every executable section unencrypted
(loader metadata may live there).  A target whose executable sections are all
smaller than that therefore has nothing to pack: the payload ends up empty and
the output image is left with an entry point that no longer reaches the
original code.
"""
import os
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
_spec_path = os.path.join(HERE, "make-x86-fixture.py")
import importlib.util

spec = importlib.util.spec_from_file_location("mkx86", _spec_path)
mkx86 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mkx86)

CORE = r"C:\npbuild\artifacts\test-only-core-2.3.4\CoreRegression.exe"
OUT = r"C:\npbuild\tests\_reg\small_section_probe.exe"

# Build the tiny fixture (text section of a few dozen bytes).
mkx86.build(OUT.replace(".exe", "-input.exe"))

size = os.path.getsize(OUT.replace(".exe", "-input.exe"))
print(f"input fixture: {size} bytes")

os.makedirs(os.path.dirname(OUT), exist_ok=True)
if os.path.exists(OUT):
    os.remove(OUT)

r = subprocess.run([CORE, OUT.replace(".exe", "-input.exe"), "-o", OUT],
                   capture_output=True, text=True, encoding="utf-8", errors="replace")
print("packer output:")
print(r.stdout[-800:])
print(f"packer rc={r.returncode}")

if not os.path.exists(OUT):
    print("RESULT: no output produced")
    sys.exit(0)

# Inspect the produced image.
data = open(OUT, "rb").read()
pe = struct.unpack_from("<I", data, 0x3C)[0]
opt = pe + 24
ep = struct.unpack_from("<I", data, opt + 16)[0]
size_image = struct.unpack_from("<I", data, opt + 56)[0]
nsec = struct.unpack_from("<H", data, pe + 6)[0]
optsize = struct.unpack_from("<H", data, pe + 20)[0]
sec = opt + optsize
print(f"packed image: {len(data)} bytes, entry=0x{ep:X}, size_image=0x{size_image:X}")
for i in range(nsec):
    o = sec + i * 40
    name = data[o:o + 8].rstrip(b"\0").decode("ascii", "replace")
    vsize = struct.unpack_from("<I", data, o + 8)[0]
    vaddr = struct.unpack_from("<I", data, o + 12)[0]
    chars = struct.unpack_from("<I", data, o + 36)[0]
    print(f"  {name:9} vaddr=0x{vaddr:X} vsize=0x{vsize:X} chars=0x{chars:08X}")

run = subprocess.run([OUT], capture_output=True, timeout=30)
print(f"packed run: rc={run.returncode} stdout={run.stdout!r} stderr={run.stderr[:200]!r}")
if run.returncode != 0 or b"sudfiona" not in run.stdout:
    print("RESULT: BROKEN - the packed image does not run correctly")
else:
    print("RESULT: OK")
