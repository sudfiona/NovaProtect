"""Build tests/test_target.exe with the commercial VMProtect SDK.

The original fixture calls the commercial VMProtect SDK (VMProtectBeginUltra
and friends), so it carries *real* VMProtect markers.  The regression suite
relies on that distinction: the planner must not expose VMProtect SDK calls
as NovaProtect marker objects.

The SDK is vendored under third_party/vmprotect (see
tools/resolve-vmprotect-sdk.ps1).  Without it the suite falls back to the
marker-free stand-in in tools/test_target_novaprotect.c.
"""
import os
import shutil
import subprocess
import sys

ROOT = r"C:\npbuild"
TESTS = os.path.join(ROOT, "tests")
VMP = os.path.join(ROOT, "third_party", "vmprotect")
MINGW = r"C:\mingw\mingw64\bin"

HEADER = os.path.join(VMP, "VMProtectSDK.h")
LIB_DIR = os.path.join(VMP, "Lib", "Windows", "MinGW")
DLL = os.path.join(VMP, "Lib", "Windows", "VMProtectSDK64.dll")


def have_sdk():
    return (os.path.exists(HEADER)
            and os.path.exists(os.path.join(LIB_DIR, "VMProtectSDK64.a"))
            and os.path.exists(DLL))


def build():
    if not have_sdk():
        print("VMProtect SDK not vendored; keeping the marker-free stand-in")
        return False

    env = dict(os.environ)
    env["PATH"] = MINGW + os.pathsep + env.get("PATH", "")

    out = os.path.join(TESTS, "test_target.exe")
    cmd = [
        os.path.join(MINGW, "gcc.exe"), "-O2", "-o", out,
        os.path.join(TESTS, "test_target.c"),
        "-I", VMP,
        "-L", LIB_DIR,
        "-l:VMProtectSDK64.a",
    ]
    print(" ".join(cmd))
    r = subprocess.run(cmd, env=env, capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    if r.returncode != 0:
        print(r.stdout[-1500:])
        print(r.stderr[-1500:])
        raise SystemExit("gcc failed")

    # The fixture imports VMProtectSDK64.dll, so it has to sit next to it.
    shutil.copy(DLL, TESTS)
    print(f"wrote {out} ({os.path.getsize(out)} bytes)")

    run = subprocess.run([out], capture_output=True, timeout=60, cwd=TESTS)
    print(f"run: rc={run.returncode}")
    print(run.stdout.decode("utf-8", "replace").strip())
    if run.returncode != 0 or b"Hash: 0x6DD33F53" not in run.stdout:
        raise SystemExit("fixture did not produce the expected output")
    return True


if __name__ == "__main__":
    build()
