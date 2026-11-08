import subprocess, sys, re, os

exe = r"C:\npbuild\artifacts\isl-test\isl-test.exe"
# innounp may not be present; fall back to scanning the installer binary for
# the UTF-16LE message strings that Inno embeds for the wizard pages.
data = open(exe, "rb").read()
print("installer bytes:", len(data))

# Inno stores localized messages as UTF-16LE strings in the setup data.
targets = [
    "Ready to Install",
    "安装程序已准备好安装",
    "Destination location:",
    "Selected components:",
    "User information:",
    "Setup type:",
    "Start Menu folder:",
    "Additional tasks:",
    "Click Install to continue",
    "WizardReady",
]

for t in targets:
    u16 = t.encode("utf-16-le")
    print(f"{t!r:45} utf16le found = {u16 in data}   utf8 found = {t.encode('utf-8') in data}")

print()
print("=== which codepage did ISCC use ===")
for cp in (936, 1200, 65001):
    probe = "准备安装".encode(f"cp{cp}", errors="ignore") if cp != 1200 else "准备安装".encode("utf-16-le")
    print(f"cp{cp}: {probe in data}")
