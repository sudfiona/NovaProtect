#!/usr/bin/env python3
"""Audit Chinese-bearing script files for the BOM requirement.

PowerShell 5.1 reads a BOM-less UTF-8 .ps1 using the system ANSI codepage
(GBK on zh-CN), which turns every Chinese literal into mojibake. Inno
Setup's ISCC has the same expectation for .iss files with non-ASCII text.

The project's own memory log records this trap being hit repeatedly, so the
check is automated here.
"""
import os
import sys

BOM = b'\xef\xbb\xbf'
EXTS = {'.ps1', '.iss', '.psm1'}
SKIP_DIRS = {'.git', 'node_modules', 'obj', 'bin', 'artifacts', '__pycache__'}


def main(roots):
    bad = []
    ok = []
    for root in roots:
        for dp, dn, fn in os.walk(root):
            dn[:] = [d for d in dn if d not in SKIP_DIRS]
            for f in fn:
                if os.path.splitext(f)[1].lower() not in EXTS:
                    continue
                p = os.path.join(dp, f)
                try:
                    d = open(p, 'rb').read()
                except OSError:
                    continue
                if not any(b > 0x7F for b in d):
                    continue
                (ok if d[:3] == BOM else bad).append(p)
    print(f"Chinese-bearing scripts WITH BOM    : {len(ok)}")
    for p in sorted(ok):
        print('   OK   ', p)
    print(f"Chinese-bearing scripts WITHOUT BOM : {len(bad)}   <-- mojibake risk")
    for p in sorted(bad):
        print('   BAD  ', p)
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:] or [os.getcwd()]))
