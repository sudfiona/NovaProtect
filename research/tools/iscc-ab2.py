#!/usr/bin/env python3
"""Rigorous A/B: does ISCC mis-decode a BOM-less UTF-8 .iss?

Inno Setup 6 can read script files as UTF-8, but a script without a byte
order mark may be treated as the system ANSI code page (GBK on zh-CN).
When that happens every Chinese literal in the script is double-encoded and
the garbage lands on the wizard's Ready to Install page - the page that
lists the selected tasks and files.

This builds the same installer twice (UTF-8 with BOM, UTF-8 without BOM) and
diffs the two executables. Chinese that survives the round trip is reported
in whichever encoding it actually ended up as.
"""
import os
import subprocess
import sys

ISS = """#define MyComments "版本说明文字"

[Setup]
AppId={{TEST-AB-ENC2}
AppName=编码测试
AppVersion=1.0
DefaultDirName={localappdata}\\EncTest2
OutputBaseFilename=EncTest2
Compression=lzma2
VersionInfoDescription={#MyComments}

[Files]
Source: "payload.txt"; DestDir: "{app}"; Flags: ignoreversion

[Tasks]
Name: "desktopicon"; Description: "创建桌面快捷方式"; GroupDescription: "其他任务:"
Name: "extra"; Description: "额外任务项"; Flags: unchecked
"""

PAYLOAD = "payload\n"


def build(iscc, workdir, with_bom):
    os.makedirs(workdir, exist_ok=True)
    with open(os.path.join(workdir, 'payload.txt'), 'w', encoding='utf-8') as fh:
        fh.write(PAYLOAD)
    path = os.path.join(workdir, 'test.iss')
    data = ISS.encode('utf-8')
    if with_bom:
        data = b'\xef\xbb\xbf' + data
    with open(path, 'wb') as fh:
        fh.write(data)
    proc = subprocess.run([iscc, path], capture_output=True, text=True,
                          encoding='utf-8', errors='replace')
    # ISCC honours OutputBaseFilename plus the script's OutputDir, which
    # defaults to the script's own directory.
    candidates = [
        os.path.join(workdir, 'EncTest2.exe'),
        os.path.join(workdir, 'Output', 'EncTest2.exe'),
    ]
    exe = next((c for c in candidates if os.path.exists(c)), None)
    if not exe:
        print('  build failed:', proc.stdout[-800:], proc.stderr[-800:])
        return None
    return exe


def scan(exe):
    """Look for each Chinese literal in every plausible stored encoding."""
    d = open(exe, 'rb').read()
    u16 = d.decode('utf-16-le', errors='ignore')
    literals = ['编码测试', '创建桌面快捷方式', '其他任务', '额外任务项', '版本说明文字']
    out = {}
    for lit in literals:
        out[lit] = {
            'utf16-raw': lit in u16,
            'utf8-raw': lit.encode('utf-8') in d,
            'gbk-raw': lit.encode('gbk', errors='replace') in d,
        }
    return d, out


def main():
    iscc, base = sys.argv[1], sys.argv[2]
    builds = {}
    for with_bom in (False, True):
        tag = 'with-BOM' if with_bom else 'no-BOM'
        work = os.path.join(base, tag)
        exe = build(iscc, work, with_bom)
        if exe:
            builds[tag] = exe

    for tag, exe in builds.items():
        d, res = scan(exe)
        print(f'=== {tag}  ({len(d)} bytes)')
        for lit, enc in res.items():
            flags = ' '.join(f'{k}={v}' for k, v in enc.items() if v)
            print(f'   {lit:22s} {flags or "NOT FOUND (compressed)"}')

    if len(builds) == 2:
        a = open(builds['no-BOM'], 'rb').read()
        b = open(builds['with-BOM'], 'rb').read()
        print(f'\nno-BOM size={len(a)}  with-BOM size={len(b)}  identical={a == b}')
        if a != b:
            diff = sum(1 for x, y in zip(a, b) if x != y)
            print(f'   differing bytes: {diff}')


if __name__ == '__main__':
    main()
