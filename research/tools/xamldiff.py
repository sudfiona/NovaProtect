#!/usr/bin/env python3
"""Compare the Chinese strings in a XAML source with the compiled XBF.

If the XAML compiler ever reads a BOM-less UTF-8 .xaml with the system ANSI
code page, every Chinese literal in the compiled resource is double-encoded.
The compiled resource therefore contains characters that are NOT in the
source, and the source characters are missing.

This reports the exact differences for each page so the mojibake is pinned to
a specific resource rather than guessed at.
"""
import os
import re
import sys

CJK = re.compile(r'[㐀-䶿一-鿿豈-﫿　-〿＀-￯]')
# Characters that only show up when UTF-8 Chinese is decoded as GBK.
GARBLE = set('鍒涘缓妗岄潰蹇鎹锋柟寮鍗歌浇鍛戒护琛閫鍒璇疯鍔鍚姣鍒绘暟鎹㹧鍙傛暟')


def runs(text):
    """Every maximal run of CJK/CJK-punctuation characters."""
    return [m.group(0) for m in CJK.finditer(text)]


def main(root):
    ui = os.path.join(root, 'ui')
    binroot = os.path.join(ui, 'bin', 'x64', 'Release',
                           'net10.0-windows10.0.19041.0', 'win-x64')
    srcs = []
    for dp, dn, fn in os.walk(ui):
        if 'obj' in dp.split(os.sep) or 'bin' in dp.split(os.sep):
            continue
        for f in fn:
            if f.endswith('.xaml'):
                srcs.append(os.path.join(dp, f))

    total_bad = 0
    for src in sorted(srcs):
        rel = os.path.relpath(src, ui)
        xbf = os.path.join(binroot, rel[:-5] + '.xbf')
        if not os.path.exists(xbf):
            print(f'  {rel}: no compiled xbf (skipped)')
            continue
        raw = open(xbf, 'rb').read()
        compiled = raw.decode('utf-16-le', errors='ignore')
        source = open(src, 'rb').read().decode('utf-8', errors='replace')
        src_runs = set(runs(source))
        cmp_runs = set(runs(compiled))
        missing = src_runs - cmp_runs
        garbled = {c for c in compiled if c in GARBLE}
        if missing or garbled:
            total_bad += 1
            print(f'  MOJIBAKE {rel}: {len(missing)} source strings missing, '
                  f'{len(garbled)} garbled chars')
            for m in list(missing)[:5]:
                print(f'      missing: {m!r}')
            if garbled:
                sample = ''.join(sorted(garbled))[:40]
                print(f'      garbled chars: {sample!r}')
                for m in re.findall(r'.{0,12}[' + ''.join(sorted(garbled)) + r'].{0,12}', compiled)[:3]:
                    print(f'      context: {m!r}')
        else:
            print(f'  ok  {rel}: {len(src_runs)} chinese strings, all present')
    print(f'\npages with mojibake: {total_bad}')


if __name__ == '__main__':
    main(sys.argv[1])
