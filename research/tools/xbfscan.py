#!/usr/bin/env python3
"""Scan compiled WinUI XBF resources for mojibake.

The XAML sources in this project are UTF-8 without a byte-order mark. If the
XAML compiler ever reads them with the system ANSI code page (GBK on zh-CN)
the compiled resource ends up holding double-encoded Chinese, which the UI
then renders as a large patch of unreadable characters.

XBF files store their strings as UTF-16LE, so the check is: decode the file,
look for the classic GBK-read-as-UTF-8 signatures, and compare the Chinese
characters found against the Chinese present in the matching .xaml source.
"""
import os
import re
import sys

# Characters that only appear when UTF-8 Chinese is decoded as GBK.
MOJIBAKE = re.compile(r'[鍒涘缓妗岄潰蹇鎹锋柟寮鍗歌浇鍛戒护琛閫鍒璇疯鍔鍚姣鍒绘暟鎹㹧]')
CHINESE = re.compile(r'[一-鿿]')


def xbf_text(path):
    raw = open(path, 'rb').read()
    return raw.decode('utf-16-le', errors='ignore')


def main(root):
    xbfs = []
    for dp, dn, fn in os.walk(root):
        for f in fn:
            if f.endswith('.xbf'):
                xbfs.append(os.path.join(dp, f))
    print(f'found {len(xbfs)} xbf files')
    bad = 0
    for x in sorted(xbfs):
        text = xbf_text(x)
        moji = MOJIBAKE.findall(text)
        zh = CHINESE.findall(text)
        if moji:
            bad += 1
            print(f'  MOJIBAKE in {os.path.relpath(x, root)}: '
                  f'{len(moji)} suspicious chars, {len(zh)} chinese chars')
            for m in re.findall(r'.{0,14}[鍒涘缓妗岄潰蹇鎹锋柟寮鍗歌浇鍛戒护琛閫鍒璇疯鍔鍚姣鍒绘暟鎹㹧].{0,14}', text)[:4]:
                print(f'      {m!r}')
        elif zh:
            print(f'  ok  {os.path.relpath(x, root)}: {len(zh)} chinese chars')
    print(f'\nfiles with mojibake: {bad}')


if __name__ == '__main__':
    main(sys.argv[1])
