#!/usr/bin/env python3
"""Find text that is already mojibake inside source files.

When UTF-8 Chinese is read as GBK (or the reverse) the result is a
recognisable set of characters: 鍒涘缓妗岄潰蹇, 鍗歌浇鍛戒护琛, 閫鍒璇疯鍔�,
鍚姣鍒绘暟鎹 and so on. A block of that inside a .xaml, .cs or .json file is
exactly the "big patch of garbled text" a user sees on screen, because the
compiler and the renderer both pass it through unchanged.

This searches every text file in the tree for those signatures, in both the
UTF-8 and the GBK byte encodings, and shows the surrounding context.
"""
import os
import re
import sys

# Characters that essentially only occur in mis-decoded Chinese.
SIGNATURE = set(
    '鍒涘缓妗岄潰蹇鎹锋柟寮鍗歌浇鍛戒护琛閫鍒璇疯鍔鍚姣鍒绘暟鎹㹧'
    '鐎鏂囧瓧鍦ㄦ欢鎿嶄綔鍑绘暟鎹よ繘绋嬪簲鐢ㄧ▼'
)

EXTS = {'.xaml', '.cs', '.json', '.md', '.js', '.php', '.html', '.css',
        '.txt', '.iss', '.isl', '.ps1', '.yml', '.yaml', '.xml', '.resx',
        '.rc', '.h', '.c', '.cpp', '.py', '.sh', '.csv', '.ini', '.cfg'}
SKIP_DIRS = {'.git', 'node_modules', 'obj', 'bin', '__pycache__', '.vs',
             'packages', 'dist', 'build'}


def main(roots):
    hits = 0
    for root in roots:
        for dp, dn, fn in os.walk(root):
            dn[:] = [d for d in dn if d not in SKIP_DIRS]
            for f in fn:
                ext = os.path.splitext(f)[1].lower()
                if ext not in EXTS:
                    continue
                p = os.path.join(dp, f)
                try:
                    if os.path.getsize(p) > 16 * 1024 * 1024:
                        continue
                    raw = open(p, 'rb').read()
                except OSError:
                    continue
                for enc in ('utf-8', 'gbk'):
                    try:
                        text = raw.decode(enc)
                    except UnicodeDecodeError:
                        continue
                    bad = [i for i, c in enumerate(text) if c in SIGNATURE]
                    if len(bad) < 3:
                        continue
                    hits += 1
                    print(f'=== {p}  (decoded as {enc}, {len(bad)} signature chars)')
                    shown = 0
                    for i in bad:
                        lo = max(0, i - 30)
                        hi = min(len(text), i + 30)
                        snippet = text[lo:hi].replace('\n', ' ')
                        print(f'      ...{snippet}...')
                        shown += 1
                        if shown >= 4:
                            break
                    break
    print(f'\nfiles containing mojibake signatures: {hits}')


if __name__ == '__main__':
    main(sys.argv[1:] or [os.getcwd()])
