"""Bisect the PE32 fixture: try variants of the import layout and report which
one actually runs.

Variants:
  A  baseline
  B  no IAT data-directory entry (loader still walks the import directory)
  C  OriginalFirstThunk = 0 (loader uses FirstThunk as the lookup table)
  D  import directory size = 0x28 (exactly one descriptor + terminator)
"""
import importlib.util
import os
import struct
import subprocess
import sys

_here = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("mk", os.path.join(_here, "make-x86-fixture.py"))
mk = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mk)

BASE = r"C:\npbuild\tests\_h32variant"
os.makedirs(BASE, exist_ok=True)


def patch(data, drop_iat_dir=False, zero_oft=False, imp_size=None):
    d = bytearray(data)
    pe = struct.unpack_from("<I", d, 0x3C)[0]
    opt = pe + 24
    opt_size = struct.unpack_from("<H", d, pe + 20)[0]
    sec = opt + opt_size

    if drop_iat_dir:
        struct.pack_into("<II", d, opt + 96 + 12 * 8, 0, 0)
    if imp_size is not None:
        struct.pack_into("<I", d, opt + 96 + 8, imp_size)
    if zero_oft:
        # First descriptor lives in .idata at file offset 0x600.
        struct.pack_into("<I", d, 0x600, 0)
    return bytes(d)


def run(path):
    r = subprocess.run([path], capture_output=True, timeout=20)
    return r.returncode, r.stdout


variants = {
    "A_baseline": {},
    "B_no_iat_dir": {"drop_iat_dir": True},
    "C_zero_oft": {"zero_oft": True},
    "D_imp_size_28": {"imp_size": 0x28},
}

for name, kwargs in variants.items():
    path = os.path.join(BASE, name + ".exe")
    mk.build(path)
    data = patch(open(path, "rb").read(), **kwargs)
    open(path, "wb").write(data)
    try:
        rc, out = run(path)
        print(f"{name:16} rc={rc} stdout={out!r}")
    except Exception as exc:
        print(f"{name:16} EXCEPTION {exc}")
