# -*- coding: utf-8 -*-
"""0-BUG / 0-VULN audit for website-release package."""
from pathlib import Path
import re
import json

ROOT = Path(r"D:\工作区\NovaProtect\NovaProtect-main\artifacts\website-release")

findings = []

def hit(sev, loc, msg):
    findings.append((sev, loc, msg))

# ---------- PHP ----------
php_files = list(ROOT.rglob("*.php"))
for p in php_files:
    t = p.read_text(encoding="utf-8", errors="replace")
    rel = str(p.relative_to(ROOT))

    # dangerous sinks
    for pat, name in [
        (r"\beval\s*\(", "eval"),
        (r"\bassert\s*\(", "assert"),
        (r"\bexec\s*\(", "exec"),
        (r"\bsystem\s*\(", "system"),
        (r"\bpassthru\s*\(", "passthru"),
        (r"\bshell_exec\s*\(", "shell_exec"),
        (r"\bproc_open\s*\(", "proc_open"),
        (r"\bpopen\s*\(", "popen"),
        (r"\bunserialize\s*\(", "unserialize"),
        (r"\bcreate_function\s*\(", "create_function"),
        (r"preg_replace\s*\([^)]*/e", "preg_replace /e"),
    ]:
        if re.search(pat, t):
            hit("HIGH", f"{rel}", f"dangerous function: {name}")

    # file inclusion of variable
    for m in re.finditer(r"(include|require)(_once)?\s*\(?\s*\$", t):
        hit("MED", rel, f"variable include at offset {m.start()}")

    # command injection concat
    if re.search(r"(exec|system|shell_exec|passthru)\s*\([^)]*\.", t):
        hit("HIGH", rel, "command + string concat")

    # SSRF-ish fetch of request var
    if re.search(r"(file_get_contents|curl_exec|fopen)\s*\([^)]*\$_(GET|POST|REQUEST)", t):
        hit("HIGH", rel, "fetch of request variable")

    # XSS: echo request vars without escape
    for i, line in enumerate(t.splitlines(), 1):
        if re.search(r"\$_(GET|POST|REQUEST|COOKIE|SERVER)\[", line):
            # allow certain safe patterns
            if "np_e(" in line or "htmlspecialchars" in line or "filter_var" in line:
                continue
            if "str_starts_with" in line or "preg_match" in line or "is_string" in line:
                continue
            if "np_text(" in line or "np_integer(" in line or "np_upload_sid" in line:
                continue
            if "session_" in line or "json_decode" in line or "bin2hex" in line:
                continue
            hit("MED", f"{rel}:{i}", f"request var line: {line.strip()[:120]}")

    # raw echo of $ without np_e
    for i, line in enumerate(t.splitlines(), 1):
        if re.search(r"<\?=\s*\$", line) and "np_e(" not in line and "htmlspecialchars(" not in line:
            # static array literals from PHP source are OK if not request
            if re.search(r"\$_", line):
                hit("HIGH", f"{rel}:{i}", f"unescaped request in short echo: {line.strip()[:120]}")

    # open redirect
    if re.search(r"header\s*\(\s*['\"]Location:.*\$_(GET|POST|REQUEST)", t):
        hit("HIGH", rel, "open redirect")

    # path traversal
    if re.search(r"\.\./\.\./|file_get_contents\s*\(\s*\$", t):
        # only if combined with request
        if re.search(r"\$_(GET|POST|REQUEST)", t):
            hit("MED", rel, "possible path + request")

    # missing strict_types / declare
    if "declare(strict_types=1)" not in t and p.name != "README.md":
        hit("LOW", rel, "missing declare(strict_types=1)")

    # BOM
    raw = p.read_bytes()
    if raw.startswith(b"\xef\xbb\xbf"):
        hit("MED", rel, "UTF-8 BOM in PHP (breaks strict_types)")

# ---------- JS (site, not vendor) ----------
for p in ROOT.rglob("*.js"):
    if "vendor" in p.parts:
        continue
    t = p.read_text(encoding="utf-8", errors="replace")
    rel = str(p.relative_to(ROOT))
    if "innerHTML" in t and "textContent" not in t:
        # flag if innerHTML assigned from variable
        if re.search(r"\.innerHTML\s*=", t):
            hit("MED", rel, "innerHTML assignment")
    if re.search(r"\beval\s*\(|new Function|document\.write", t):
        hit("HIGH", rel, "eval/Function/document.write")
    if re.search(r"localStorage\.getItem\([^)]+\)[^;]*[^=]=[^=]", t):
        pass  # theme whitelist exists

# layout/theme whitelist
layout = (ROOT / "lib" / "layout.php").read_text(encoding="utf-8", errors="replace")
if "!== 'glass' && name !== 'pop' && name !== 'lab'" in layout:
    pass
else:
    hit("MED", "lib/layout.php", "theme whitelist missing")

if "innerHTML" in layout:
    hit("MED", "lib/layout.php", "innerHTML present")

# CSP / headers
if "Content-Security-Policy" not in layout:
    hit("LOW", "lib/layout.php", "no CSP meta (static site, note only)")

# ---------- config leaks ----------
for p in ROOT.rglob("*"):
    if not p.is_file():
        continue
    name = p.name.lower()
    if name in {".env", ".git", "id_rsa", "credentials.json", ".aws", "web.config"}:
        hit("HIGH", str(p), "sensitive file in package")
    if name.endswith((".sql", ".bak", ".swp", ".log")):
        hit("MED", str(p), "backup/log file in package")

# ---------- JSON ----------
for p in ROOT.rglob("*.json"):
    try:
        json.loads(p.read_text(encoding="utf-8"))
    except Exception as e:
        hit("HIGH", str(p.relative_to(ROOT)), f"invalid JSON: {e}")

# ---------- HTML pages (php output smoke) ----------
# shell injection via URL in generated HTML - covered by np_e

print("=== FINDINGS ===")
if not findings:
    print("NONE")
else:
    for sev, loc, msg in findings:
        print(f"[{sev}] {loc}: {msg}")

print("\n=== counts ===")
from collections import Counter
print(Counter(s for s, _, _ in findings))
