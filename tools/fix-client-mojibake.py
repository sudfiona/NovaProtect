# -*- coding: utf-8 -*-
"""Find and fix mojibake Chinese strings in UI C# / XAML."""
from pathlib import Path
import re

UI = Path(r"D:\工作区\NovaProtect\NovaProtect-main\ui")
# mojibake patterns typical of GBK/UTF-8 mix
bad_re = re.compile(r"[鏃閿鎴鍔涓锛鍚痆]+")

fixed = 0
for p in list(UI.rglob("*.cs")) + list(UI.rglob("*.xaml")):
    if "obj" in p.parts or "bin" in p.parts:
        continue
    raw = p.read_bytes()
    try:
        t = raw.decode("utf-8")
    except UnicodeDecodeError:
        t = raw.decode("utf-8", errors="replace")
    if not bad_re.search(t):
        continue
    print("MOJIBAKE", p.relative_to(UI))
    for i, line in enumerate(t.splitlines(), 1):
        if bad_re.search(line):
            print(f"  {i}: {line.strip()[:140]}")

# specifically fix known SettingsPage line
sp = UI / "Pages" / "SettingsPage.xaml.cs"
t = sp.read_text(encoding="utf-8-sig")
# replace broken message strings
t2 = re.sub(
    r'UpdateStatusBar\.Message = "[^"]*[鏃閿鎴][^"]*"\s*\+\s*path;',
    'UpdateStatusBar.Message = "无法打开目录：" + path;',
    t,
)
if t2 == t:
    # try line-based
    lines = t.splitlines(True)
    out = []
    for ln in lines:
        if "UpdateStatusBar.Message" in ln and bad_re.search(ln):
            indent = ln[: len(ln) - len(ln.lstrip())]
            out.append(indent + 'UpdateStatusBar.Message = "无法打开目录：" + path;\n')
            fixed += 1
        else:
            out.append(ln)
    t2 = "".join(out)
else:
    fixed += 1

if t2 != t:
    sp.write_bytes(b"\xef\xbb\xbf" + t2.encode("utf-8"))
    print("SettingsPage fixed")
else:
    print("SettingsPage no change needed or pattern differ")

# rescan
print("--- rescan ---")
for p in list(UI.rglob("*.cs")) + list(UI.rglob("*.xaml")):
    if "obj" in p.parts or "bin" in p.parts:
        continue
    t = p.read_text(encoding="utf-8", errors="replace")
    if bad_re.search(t):
        print("STILL BAD", p.relative_to(UI))
