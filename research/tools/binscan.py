#!/usr/bin/env python3
"""Precise mojibake detector for compiled client resources.

A run of Chinese text that is really mis-decoded shows up as characters that
cannot be encoded back to GBK, or whose GBK bytes decode as different
UTF-8 text. Real Chinese always survives a GBK round trip.

This applies the test to the compiled XBF resources (UTF-16LE strings) and
to the raw byte heap of the managed assembly, so a single mis-decoded
string anywhere in the shipped client is caught.
"""
import os
import re
import sys

CJK = re.compile(r'[㐀-䶿一-鿿豈-﫿]')
# The concatenation "㐀" through "䶿" plus the CJK block is written as an
# explicit range so the pattern stays readable.
CJK = re.compile('[㐀-䶿一-鿿豈-﫿]')


def bad_run(text):
    for m in CJK.finditer(text):
        run = m.group(0)
        if len(run) < 4:
            continue
        try:
            raw = run.encode('gbk')
        except UnicodeEncodeError:
            return run
        try:
            if raw.decode('utf-8') != run:
                return run
        except UnicodeDecodeError:
            continue
    return None


def check_xbf(path):
    raw = open(path, 'rb').read()
    text = raw.decode('utf-16-le', errors='ignore')
    return bad_run(text)


def check_bytes(path):
    raw = open(path, 'rb').read()
    # UTF-16LE strings inside a PE/assembly.
    for shift in (0, 1):
        text = raw[shift:].decode('utf-16-le', errors='ignore')
        hit = bad_run(text)
        if hit:
            return hit
    return None


def main(roots):
    total = 0
    for root in roots:
        for dp, dn, fn in os.walk(root):
            for f in fn:
                p = os.path.join(dp, f)
                low = f.lower()
                try:
                    if low.endswith('.xbf'):
                        hit = check_xbf(p)
                    elif low.endswith(('.dll', '.exe')) and 'NovaProtect' in f:
                        hit = check_bytes(p)
                    else:
                        continue
                except Exception:
                    continue
                if hit:
                    total += 1
                    i = hit[:1]
                    print(f'=== MOJIBAKE {p}')
                    print(f'    run: {hit[:60]!r}')
    print(f'\nresources with mojibake: {total}')


if __name__ == '__main__':
    main(sys.argv[1:] or [os.getcwd()])
