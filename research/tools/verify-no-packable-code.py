"""Verify the "nothing to pack" fallback end to end.

The packer keeps the first 0x1000 bytes of every executable section
unencrypted, so a target whose executable sections are all smaller than that
has no packable code.  Before the fix the packer still installed the loader
stub, moved the entry point into an empty payload section and reported
success - producing an image Windows refuses to load.

The fixture is a real, runnable x86 image whose .text is smaller than the
reserve, so the check is meaningful.
"""
import importlib.util
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("mk", os.path.join(HERE, "make-x86-fixture-rust.py"))
mk = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mk)

CORE = r"C:\npbuild\artifacts\test-only-core-2.3.4\CoreRegression.exe"
WORK = r"C:\npbuild\tests\_reg"
small_in = os.path.join(WORK, "small_exec_input.exe")
small_out = os.path.join(WORK, "small_exec_output.exe")

os.makedirs(WORK, exist_ok=True)

# Build the small-section variant (no filler -> .text below the reserve).
mk.SRC = os.path.join(HERE, "rust32-small", "h32.rs")
mk.build(small_in)

if os.path.exists(small_out):
    os.remove(small_out)

r = subprocess.run([CORE, small_in, "-o", small_out], capture_output=True,
                   text=True, encoding="utf-8", errors="replace")
print("\npacker output:")
print(r.stdout[-700:])
print(f"packer rc={r.returncode}")

if "No packable code found" not in r.stdout:
    print("RESULT: the packer did not report that nothing could be packed")
    sys.exit(1)

if not os.path.exists(small_out):
    print("RESULT: no output produced")
    sys.exit(1)

run = subprocess.run([small_out], capture_output=True, timeout=30)
print(f"\npacked run: rc={run.returncode} stdout={run.stdout!r}")
ok = run.returncode == 0 and b"sudfiona" in run.stdout
print("RESULT: " + ("OK - the output is a working image" if ok else "BROKEN"))
sys.exit(0 if ok else 1)
