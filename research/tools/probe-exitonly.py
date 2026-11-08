"""Isolate why the hand-built PE32 crashes: emit a binary that only calls
ExitProcess(0) and nothing else."""
import importlib.util
import os
import struct
import sys

_here = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("mk", os.path.join(_here, "make-x86-fixture.py"))
mk = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mk)

out = sys.argv[1]
mk.build(out)

# Now patch the .text section in place: replace the body with ExitProcess(0).
data = bytearray(open(out, "rb").read())
pe = struct.unpack_from("<I", data, 0x3C)[0]
opt = pe + 24
opt_size = struct.unpack_from("<H", data, pe + 20)[0]
sec = opt + opt_size
o = sec  # first section header = .text
raw = struct.unpack_from("<I", data, o + 20)[0]
iat_exit = 0x3000 + 0x50
body = b"\x6a\x00" + b"\xff\x15" + struct.pack("<I", iat_exit) + b"\xcc"
data[raw:raw + len(body)] = body
# fix the section virtual size so the loader maps the new body
struct.pack_into("<I", data, o + 8, len(body))
open(out, "wb").write(bytes(data))
print(f"patched {out}: ExitProcess(0) only")
