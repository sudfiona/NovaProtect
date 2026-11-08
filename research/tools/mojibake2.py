#!/usr/bin/env python3
"""Precise detector for mis-decoded Chinese text.

A string of legitimate Chinese that was decoded with the wrong code page
produces characters outside the CJK Unified Ideographs block (it spills into
CJK punctuation, Hangul, or fullwidth forms) or produces a run that cannot
be re-encoded to the original bytes.

The reliable test is a round trip: take the text, encode it with GBK, and
see whether the resulting bytes are valid UTF-8 that decodes to something
different. Real Chinese text is valid GBK and does not survive that. Mis-
decoded text does.

This finds actual mojibake rather than guessing at a character list.
"""
import os
import re
import sys

EXTS = {'.xaml', '.cs', '.json', '.md', '.js', '.php', '.html', '.css',
        '.txt', '.iss', '.isl', '.ps1', '.yml', '.yaml', '.xml', '.rc',
        '.h', '.c', '.cpp', '.py', '.sh', '.csv', '.ini', '.cfg', '.resx'}
SKIP_DIRS = {'.git', 'node_modules', 'obj', 'bin', '__pycache__', '.vs',
             'packages', 'dist', 'build', 'artifacts', 'output'}
CJK = re.compile(r'[㐀-䶿一-鿿豈-﫿]')


def looks_like_mojibake(text):
    """True when a run of CJK-looking text cannot be real Chinese."""
    runs = [m.group(0) for m in CJK.finditer(text)]
    if not runs:
        return None
    for run in runs:
        if len(run) < 4:
            continue
        try:
            raw = run.encode('gbk')
        except UnicodeEncodeError:
            # Characters GBK cannot represent at all: real Chinese text is
            # always GBK-encodable, so this is a strong mojibake signal.
            return run
        try:
            decoded = raw.decode('utf-8')
        except UnicodeDecodeError:
            continue
        if decoded != run:
            return run
    return None


def main(roots):
    hits = 0
    for root in roots:
        for dp, dn, fn in os.walk(root):
            dn[:] = [d for d in dn if d not in SKIP_DIRS]
            for f in fn:
                if os.path.splitext(f)[1].lower() not in EXTS:
                    continue
                p = os.path.join(dp, f)
                try:
                    if os.path.getsize(p) > 16 * 1024 * 1024:
                        continue
                    raw = open(p, 'rb').read()
                except OSError:
                    continue
                try:
                    text = raw.decode('utf-8')
                except UnicodeDecodeError:
                    print(f'  NOT-UTF8 {p}')
                    hits += 1
                    continue
                bad = looks_like_mojibake(text)
                if bad:
                    hits += 1
                    i = text.find(bad)
                    lo = max(0, i - 40)
                    hi = min(len(text), i + len(bad) + 40)
                    print(f'=== {p}')
                    print(f'    ...{text[lo:hi]!r}...')
    print(f'\nfiles with real mojibake: {hits}')


if __name__ == '__main__':
    main(sys.argv[1:] or [os.getcwd()])
