# -*- coding: utf-8 -*-
"""Security + bug audit for NovaProtect website + UI leftovers."""
from pathlib import Path
import re

ROOT = Path(r"D:\工作区\NovaProtect\NovaProtect-main")

print("=== 1. JS sinks (innerHTML/eval/document.write) ===")
for p in (ROOT / "website").rglob("*"):
    if p.suffix.lower() not in {".php", ".js", ".html"}:
        continue
    if "vendor" in p.parts:
        continue
    t = p.read_text(encoding="utf-8", errors="replace")
    for i, line in enumerate(t.splitlines(), 1):
        if re.search(r"innerHTML|eval\(|document\.write|new Function", line):
            print(f"{p.name}:{i}: {line.strip()[:160]}")

print("\n=== 2. PHP raw variable output (not np_e/htmlspecialchars) ===")
for p in (ROOT / "website").rglob("*.php"):
    if "vendor" in p.parts:
        continue
    t = p.read_text(encoding="utf-8", errors="replace")
    for i, line in enumerate(t.splitlines(), 1):
        if re.search(r"<\?=\s*\$", line) and "np_e(" not in line and "htmlspecialchars(" not in line:
            # allow known safe literals
            if "prerelease" in line or "pill-" in line or "预发布" in line or "正式版" in line:
                continue
            if "$icon" in line or "$macro" in line or "$desc" in line:
                print(f"REVIEW {p.name}:{i}: {line.strip()[:160]}")
                continue
            print(f"UNESCAPED {p.name}:{i}: {line.strip()[:160]}")

print("\n=== 3. include/require of variable ===")
for p in (ROOT / "website").rglob("*.php"):
    if "vendor" in p.parts:
        continue
    t = p.read_text(encoding="utf-8", errors="replace")
    for i, line in enumerate(t.splitlines(), 1):
        if re.search(r"(include|require)(_once)?\s*\(?\s*\$", line):
            print(f"{p.name}:{i}: {line.strip()}")

print("\n=== 4. command injection patterns ===")
for p in (ROOT / "website").rglob("*.php"):
    if "vendor" in p.parts:
        continue
    t = p.read_text(encoding="utf-8", errors="replace")
    for i, line in enumerate(t.splitlines(), 1):
        if re.search(r"\b(exec|system|passthru|shell_exec|popen|proc_open)\s*\(", line):
            print(f"{p.name}:{i}: {line.strip()}")

print("\n=== 5. UI remaining x:Double / corrupt ===")
for p in (ROOT / "ui").rglob("*.xaml"):
    if "obj" in str(p) or "bin" in str(p):
        continue
    t = p.read_text(encoding="utf-8", errors="replace")
    if "x:Double" in t:
        print("x:Double in", p.name)
    if re.search(r'[\u4e00-\u9fff]{0,2}淇濅|閫夋|璁剧', t):
        print("mojibake in", p.name)

print("\n=== 6. required resources present ===")
theme = (ROOT / "ui/Styles/Theme.xaml").read_text(encoding="utf-8-sig")
need = [
    "NovaThemeChipStyle",
    "NovaAccentGradientBrush",
    "NovaGlassCardHoverBorderBrush",
    "NovaCardCornerRadius",
    "NovaButtonCornerRadius",
    "CardCornerRadius",
    "ButtonCornerRadius",
    "AccentActionButtonStyle",
    "RoundedButtonStyle",
    "PageTitleStyle",
    "SubtleTextStyle",
    "PillSoftStyle",
]
for k in need:
    print(f"  {k}: {'OK' if k in theme else 'MISSING'}")

print("\n=== 7. page x:Name vs code-behind (SettingsPage) ===")
xaml = (ROOT / "ui/Pages/SettingsPage.xaml").read_text(encoding="utf-8-sig")
cs = (ROOT / "ui/Pages/SettingsPage.xaml.cs").read_text(encoding="utf-8-sig")
names = re.findall(r'x:Name="([^"]+)"', xaml)
for n in names:
    if n not in cs:
        print("  unused in cs:", n)
handlers = re.findall(r'Click="([^"]+)"|SelectionChanged="([^"]+)"|Toggled="([^"]+)"|Loaded="([^"]+)"', xaml)
for h in handlers:
    name = next(x for x in h if x)
    if name not in cs:
        print("  missing handler:", name)
print("  SettingsPage names:", names)
