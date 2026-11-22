# -*- coding: utf-8 -*-
"""Add CSP + security headers to layout.php (source tree)."""
from pathlib import Path

p = Path(r"D:\工作区\NovaProtect\NovaProtect-main\website\lib\layout.php")
t = p.read_text(encoding="utf-8")

CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "form-action 'self'; "
    "frame-ancestors 'none'"
)

if "X-Content-Type-Options" not in t:
    old = "function np_layout(string $title, string $active, string $main, string $description): void\n{"
    new = (
        "function np_layout(string $title, string $active, string $main, string $description): void\n"
        "{\n"
        "    if (!headers_sent()) {\n"
        "        header('X-Content-Type-Options: nosniff');\n"
        "        header('X-Frame-Options: DENY');\n"
        "        header('Referrer-Policy: strict-origin-when-cross-origin');\n"
        "        header('Permissions-Policy: camera=(), microphone=(), geolocation=()');\n"
        f"        header(\"Content-Security-Policy: {CSP}\");\n"
        "    }\n"
    )
    if old in t:
        t = t.replace(old, new, 1)
        print("headers added to np_layout")
    else:
        print("WARN np_layout signature not found")
else:
    print("headers already present")

if "http-equiv=\"Content-Security-Policy\"" not in t and 'http-equiv="Content-Security-Policy"' not in t:
    t = t.replace(
        '<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">',
        '<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">\n'
        f'<meta http-equiv="Content-Security-Policy" content="{CSP}">',
        1,
    )
    print("CSP meta added")

p.write_bytes(t.encode("utf-8"))
print("done")
