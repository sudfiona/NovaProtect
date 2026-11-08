#!/usr/bin/env python3
"""Find files that contain non-ASCII bytes but are NOT valid UTF-8.

Such files are the classic source of mojibake: a tool reads them with the
system ANSI codepage (GBK on zh-CN) or the writer emitted GBK, and the
rendered result is a patch of unreadable characters.

Also reports files that ARE valid UTF-8 but lack a BOM while containing
non-ASCII (PowerShell 5.1 reads those as GBK -> double-encoded Chinese).
"""
import os
import sys

ROOTS = sys.argv[1:] or [os.getcwd()]

SKIP_DIRS = {
    ".git", "node_modules", "bin", "obj", ".vs", "packages",
    "artifacts", "__pycache__", "x64", "x86", "Debug", "Release",
    "publish", "dist", "build", ".vscode", ".idea",
}
SKIP_EXT = {
    ".exe", ".dll", ".pdb", ".ico", ".png", ".jpg", ".jpeg", ".gif",
    ".zip", ".7z", ".rar", ".apk", ".so", ".a", ".lib", ".obj", ".pyc",
    ".woff", ".woff2", ".ttf", ".mp3", ".mp4", ".bin", ".dat", ".db",
    ".msi", ".cab", ".pdf", ".docx", ".xlsx", ".pptx",
}

VALID_UTF8_BOM = b"\xef\xbb\xbf"


def has_non_ascii(data: bytes) -> bool:
    return any(b > 0x7F for b in data)


def main() -> int:
    bad_utf8 = []
    bomless_utf8 = []
    scanned = 0

    for root in ROOTS:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for name in filenames:
                ext = os.path.splitext(name)[1].lower()
                if ext in SKIP_EXT:
                    continue
                path = os.path.join(dirpath, name)
                try:
                    if os.path.getsize(path) > 8 * 1024 * 1024:
                        continue
                    with open(path, "rb") as fh:
                        data = fh.read()
                except OSError:
                    continue
                if not has_non_ascii(data):
                    continue
                scanned += 1
                body = data[len(VALID_UTF8_BOM):] if data.startswith(VALID_UTF8_BOM) else data
                try:
                    body.decode("utf-8")
                    valid = True
                except UnicodeDecodeError:
                    valid = False
                rel = os.path.relpath(path, root)
                if not valid:
                    bad_utf8.append(rel)
                elif not data.startswith(VALID_UTF8_BOM):
                    bomless_utf8.append(rel)

    print(f"scanned files containing non-ASCII: {scanned}")
    print(f"\n=== NOT valid UTF-8 (mojibake source): {len(bad_utf8)} ===")
    for rel in bad_utf8:
        print("  BAD   ", rel)
    print(f"\n=== valid UTF-8 but NO BOM (PS5.1 reads as GBK): {len(bomless_utf8)} ===")
    for rel in bomless_utf8:
        print("  NOBOM ", rel)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
