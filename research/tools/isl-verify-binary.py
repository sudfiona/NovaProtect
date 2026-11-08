"""Verify the Chinese wizard messages actually reach the installer.

Inno Setup stores the localized message table inside the compiled setup
(everything after the "Inno Setup Setup Data" marker).  The table is stored
as UTF-16LE for Unicode language files, so we can look the strings up
directly in the compiled bytes.
"""
import os
import re
import subprocess
import sys

WORK = r"C:\npbuild\artifacts\isl-verify"
os.makedirs(WORK, exist_ok=True)

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
ISCC = r"C:\Inno Setup 7\ISCC.exe"

ISS = """[Setup]
AppId={{VERIFY-VERIFY-VERIFY}
AppName=NovaProtect
AppVersion=2.3.3
DefaultDirName={localappdata}\\Programs\\NovaProtect
OutputDir=.
OutputBaseFilename=verify-{tag}
WizardStyle=modern
PrivilegesRequired=lowest

[Languages]
Name: "chinese"; MessagesFile: "ChineseSimplified.isl"

[Files]
Source: "C:\\npbuild\\installer\\version.iss"; DestDir: "{app}"; Flags: ignoreversion
"""


def build(tag, isl_path):
    work = os.path.join(WORK, tag)
    os.makedirs(work, exist_ok=True)
    data = open(isl_path, "rb").read()
    open(os.path.join(work, "ChineseSimplified.isl"), "wb").write(data)
    iss_path = os.path.join(work, "verify.iss")
    open(iss_path, "w", encoding="utf-8").write(ISS.replace("{tag}", tag))
    r = subprocess.run([ISCC, iss_path], capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    ok = r.returncode == 0
    exe = os.path.join(work, f"verify-{tag}.exe")
    print(f"[{tag}] compile rc={r.returncode} exe={os.path.exists(exe)}")
    if not ok:
        print(r.stdout[-1200:])
    return exe if ok else None


CHECKS = [
    "准备安装",
    "安装程序准备就绪",
    "点击“安装”继续此安装程序",
    "用户信息：",
    "目标位置：",
    "安装类型：",
    "已选择组件：",
    "开始菜单文件夹：",
    "附加任务：",
]
ENGLISH_LEAKS = [
    "Ready to Install",
    "Destination location:",
    "Selected components:",
    "Start Menu folder:",
    "Additional tasks:",
    "Click Install to continue with the installation.",
]


def probe(exe, tag):
    data = open(exe, "rb").read()
    print(f"\n=== {tag} ({len(data)} bytes) ===")
    print("-- Chinese strings present --")
    for c in CHECKS:
        u16 = c.encode("utf-16-le")
        u8 = c.encode("utf-8")
        print(f"  {c!r:34} utf16={u16 in data} utf8={u8 in data}")
    print("-- English leaks still present --")
    for c in ENGLISH_LEAKS:
        u16 = c.encode("utf-16-le")
        u8 = c.encode("utf-8")
        print(f"  {c!r:52} utf16={u16 in data} utf8={u8 in data}")


old_exe = build("before", ISL_BACKUP)
new_exe = build("after", MERGED_ISL)

if old_exe:
    probe(old_exe, "BEFORE (shipped isl)")
if new_exe:
    probe(new_exe, "AFTER (merged official translation)")
