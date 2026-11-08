"""Build before/after installers with distinct AppIds so each run starts on the
first wizard page (Inno remembers an installed AppId and skips straight to the
finish page otherwise).
"""
import os
import re
import subprocess

WORK = r"C:\npbuild\artifacts\isl-ab"
os.makedirs(WORK, exist_ok=True)
ISCC = r"C:\Inno Setup 7\ISCC.exe"

ISL_BACKUP = r"C:\npbuild\artifacts\isl-test\ChineseSimplified.isl.bak"
def _np_repo_file(relative):
    """Resolve a path inside the NovaProtect repo from either layout.

    The research harness runs from protector-research/ next to the repo in the
    maintainer's workspace, and from research/ inside the published tree.
    """
    from pathlib import Path
    here = Path(__file__).resolve()
    for base in (here.parents[2], here.parents[2] / 'NovaProtect', here.parents[3]):
        candidate = base / relative
        if candidate.is_file():
            return str(candidate)
    return str(here.parents[2] / relative)
MERGED_ISL = _np_repo_file('installer/ChineseSimplified.isl')
ISS = """[Setup]
AppId={{AB-AB-AB-{tag}}}
AppName=NovaProtect {tag}
AppVersion=2.3.3
DefaultDirName={{localappdata}}\\Programs\\NovaProtectAb{tag}
OutputDir=.
OutputBaseFilename=ab-{tag}
WizardStyle=modern
PrivilegesRequired=lowest

[Languages]
Name: "chinese"; MessagesFile: "ChineseSimplified.isl"

[Files]
Source: "C:\\npbuild\\installer\\version.iss"; DestDir: "{{app}}"; Flags: ignoreversion
"""


def build(tag, isl_path):
    work = os.path.join(WORK, tag)
    os.makedirs(work, exist_ok=True)
    open(os.path.join(work, "ChineseSimplified.isl"), "wb").write(open(isl_path, "rb").read())
    iss_path = os.path.join(work, "ab.iss")
    open(iss_path, "w", encoding="utf-8").write(ISS.replace("{tag}", tag))
    r = subprocess.run([ISCC, iss_path], capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    exe = os.path.join(work, f"ab-{tag}.exe")
    print(f"[{tag}] rc={r.returncode} exists={os.path.exists(exe)}")
    if r.returncode != 0:
        print(r.stdout[-1500:])
    return exe if os.path.exists(exe) else None


before = build("before", ISL_BACKUP)
after = build("after", MERGED_ISL)
print()
print("BEFORE_EXE=" + (before or ""))
print("AFTER_EXE=" + (after or ""))
