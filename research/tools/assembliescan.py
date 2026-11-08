#!/usr/bin/env python3
"""Scan a compiled .NET assembly for double-encoded Chinese.

The C# compiler reads a source file without a byte-order mark as UTF-8 when
it can, so a valid UTF-8 source is safe. But when a source file is *not*
valid UTF-8, or when a string was written to the assembly as GBK bytes, the
literal ends up in the binary as GBK and the UI renders it as mojibake.

This walks the assembly's UTF-16 string heap and the raw byte heap looking
for byte runs that only decode as Chinese when read as GBK, which is the
signature of a double-encoded string.
"""
import re
import sys

# A run of bytes that decodes to Chinese under GBK but not under UTF-8.
GBK_RUN = re.compile(rb'(?:[\xb0-\xf7][\xa1-\xfe]){2,}')
UTF8_RUN = re.compile(rb'(?:[\xe4-\xe9][\x80-\xbf]{2}){1,}')


def report(path):
    data = open(path, 'rb').read()
    print(f'=== {path}  ({len(data)} bytes)')

    # 1. UTF-16 strings (the .NET metadata / #US heap).
    u16 = data.decode('utf-16-le', errors='ignore')
    garbled = re.findall(r'[一-鿿]{2,}', u16)
    # A string made of characters that only appear in GBK-misread UTF-8.
    sus = [s for s in garbled if any(c in s for c in '鍒涘缓妗岄潰蹇鎹锋柟寮鍗歌浇鍛戒护琛閫鍒璇疯鍔鍚姣鍒绘暟鎹㹧')]
    print(f'  utf-16 strings with CJK: {len(garbled)}')
    if sus:
        print(f'  SUSPECT double-encoded utf-16 strings: {len(sus)}')
        for s in sus[:10]:
            print(f'      {s!r}')

    # 2. Raw byte runs: GBK-encoded Chinese in a #Blob / literal heap.
    gbk_runs = GBK_RUN.findall(data)
    decoded = []
    for run in gbk_runs:
        try:
            text = run.decode('gbk')
        except UnicodeDecodeError:
            continue
        if not re.search(r'[一-鿿]', text):
            continue
        # Would these same bytes have been valid UTF-8 Chinese? If yes they
        # are genuine GBK text, if no they are the misread-UTF-8 signature.
        try:
            run.decode('utf-8')
            continue
        except UnicodeDecodeError:
            pass
        decoded.append(text)
    print(f'  raw GBK-only Chinese runs: {len(decoded)}')
    for t in decoded[:10]:
        print(f'      {t!r}')


for p in sys.argv[1:]:
    report(p)
    print()
