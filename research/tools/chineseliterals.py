#!/usr/bin/env python3
"""Find Chinese string literals in the native engine sources.

The engine's stdout is read by the client with StandardOutputEncoding =
UTF8. If the engine emitted Chinese that had been written in a different
encoding (for example because the source file was read as the system ANSI
code page), the client would render mojibake in the log box.

This scans src/ and runtime/ for Chinese inside C/C++ string literals,
ignoring comments, and reports the file plus the line.
"""
import glob
import os
import re
import sys

ROOT = sys.argv[1] if len(sys.argv) > 1 else '.'
LITERAL = re.compile(r'"((?:[^"\\]|\\.)*)"')
CHINESE = re.compile(r'[一-鿿]')


def strip_comments(src: str) -> str:
    src = re.sub(r'/\*.*?\*/', '', src, flags=re.S)
    src = re.sub(r'//[^\n]*', '', src)
    return src


def main():
    files = []
    for sub in ('src', 'runtime', 'include'):
        files += glob.glob(os.path.join(ROOT, sub, '*.cpp'))
        files += glob.glob(os.path.join(ROOT, sub, '*.c'))
        files += glob.glob(os.path.join(ROOT, sub, '*.h'))
    total = 0
    for f in sorted(files):
        raw = open(f, 'rb').read()
        try:
            src = raw.decode('utf-8')
            enc = 'utf-8'
        except UnicodeDecodeError:
            src = raw.decode('gbk', errors='replace')
            enc = 'GBK/INVALID-UTF8'
        if enc != 'utf-8':
            print(f'!! {f} is not valid UTF-8')
        body = strip_comments(src)
        hits = []
        for i, line in enumerate(body.splitlines(), 1):
            for m in LITERAL.finditer(line):
                lit = m.group(1)
                if CHINESE.search(lit):
                    hits.append((i, lit))
        if hits:
            print(f'--- {os.path.relpath(f, ROOT)}: {len(hits)} Chinese literal(s)')
            for i, lit in hits[:8]:
                print(f'     {i}: {lit[:88]}')
            total += len(hits)
    print(f'TOTAL Chinese string literals in native sources: {total}')


if __name__ == '__main__':
    main()
