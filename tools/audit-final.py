# -*- coding: utf-8 -*-
"""Final audit: command injection, XSS, auth, secrets, race, null refs."""
from pathlib import Path
import re

ROOT = Path(r"D:\工作区\NovaProtect\NovaProtect-main")

def scan(pattern, roots, label, exclude=("obj", "bin", "vendor", "node_modules")):
    print(f"\n=== {label} ===")
    rx = re.compile(pattern)
    hits = 0
    for base in roots:
        for p in Path(base).rglob("*"):
            if p.suffix.lower() not in {".cs", ".php", ".js", ".xaml", ".py"}:
                continue
            if any(x in p.parts for x in exclude):
                continue
            try:
                t = p.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            for i, line in enumerate(t.splitlines(), 1):
                if rx.search(line):
                    print(f"{p.relative_to(ROOT)}:{i}: {line.strip()[:150]}")
                    hits += 1
    if not hits:
        print("  (none)")

scan(r'ArgumentList\.Add\([^)]*\$|Arguments\s*=\s*\$"|"explorer\.exe"',
     [ROOT / "ui"], "UI process args")
scan(r'(eval|assert)\s*\(|shell_exec|passthru|proc_open|popen\s*\(',
     [ROOT / "website" / "lib", ROOT / "website" / "public"], "PHP dangerous funcs")
scan(r'innerHTML\s*=|outerHTML\s*=|document\.write|eval\(',
     [ROOT / "website"], "JS XSS sinks")
scan(r'password\s*=\s*["\'][^"\']+["\']|api[_-]?key\s*=\s*["\'][^"\']+["\']',
     [ROOT / "ui", ROOT / "website" / "lib", ROOT / "website" / "public"], "hardcoded secrets")
scan(r'SQL|SELECT .*FROM|INSERT INTO|DELETE FROM',
     [ROOT / "website"], "SQL")
scan(r'\bmd5\(|\bsha1\(|Random\(\)|new Random',
     [ROOT / "ui", ROOT / "website" / "lib"], "weak crypto/rng")
scan(r'catch\s*\{\s*\}|catch\s*\(\s*\w+\s*\w*\)\s*\{\s*\}',
     [ROOT / "ui"], "empty catch (review)")

print("\n=== np_e() required on request-bound vars ===")
for p in (ROOT / "website").rglob("*.php"):
    if "vendor" in p.parts:
        continue
    t = p.read_text(encoding="utf-8", errors="replace")
    if re.search(r"\$_(GET|POST|REQUEST|COOKIE)\[", t):
        print("uses superglobal:", p.relative_to(ROOT))

print("\n=== layout.js theme whitelist ===")
lay = (ROOT / "website/lib/layout.php").read_text(encoding="utf-8-sig")
if "!== 'glass' && name !== 'pop' && name !== 'lab'" in lay:
    print("  whitelist OK")
else:
    print("  MISSING whitelist")
if "innerHTML" in lay:
    print("  WARN innerHTML present")
else:
    print("  no innerHTML")

print("\n=== NovaTheme input validation ===")
nt = (ROOT / "ui/Services/NovaTheme.cs").read_text(encoding="utf-8-sig")
print("  Normalize:", "Normalize" in nt)
print("  IsHex:", "IsHex" in nt)
print("  null root guard:", "ArgumentNullException" in nt)
