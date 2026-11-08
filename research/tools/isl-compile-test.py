import os, subprocess, sys

base = r"C:\npbuild\artifacts\isl-test"
os.makedirs(base, exist_ok=True)
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
isl_src = _np_repo_file('installer/ChineseSimplified.isl')
# Copy the ISL exactly as shipped.
data = open(isl_src, "rb").read()
open(os.path.join(base, "ChineseSimplified.isl"), "wb").write(data)

iss = """[Setup]
AppId={{TEST-TEST-TEST}
AppName=NovaProtect
AppVersion=2.3.3
DefaultDirName={localappdata}\\Programs\\NovaProtect
OutputDir=.
OutputBaseFilename=isl-test
WizardStyle=modern

[Languages]
Name: "chinese"; MessagesFile: "ChineseSimplified.isl"

[Files]
Source: "C:\\npbuild\\installer\\version.iss"; DestDir: "{app}"; Flags: ignoreversion
"""
iss_path = os.path.join(base, "test.iss")
open(iss_path, "w", encoding="utf-8").write(iss)

r = subprocess.run([r"C:\Inno Setup 7\ISCC.exe", iss_path], capture_output=True, text=True, encoding="utf-8", errors="replace")
print("rc =", r.returncode)
print(r.stdout[-2500:])
if r.stderr:
    print("STDERR:", r.stderr[-1500:])
