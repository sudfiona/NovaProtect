"""Isolation test for the Inno Setup encoding question.

Inno Setup 6 treats a script file with no byte-order mark as being in the
system ANSI code page (GBK on zh-CN). A .iss file that is UTF-8 without a
BOM and contains Chinese therefore gets its Chinese double-encoded, and the
garbage shows up on the wizard Ready to Install page - the page that lists
the selected install tasks.

This script builds the same tiny installer twice, once with a UTF-8 BOM and
once without, then reports which encoding the Chinese ended up as inside the
produced setup executable.

Usage:  iscc-ab.py <ISCC.exe> <workdir>
"""
import os
import subprocess
import sys

ISS = """[Setup]
AppId={{TEST-AB-ENC}
AppName=编码测试
AppVersion=1.0
DefaultDirName={localappdata}\\EncTest
OutputDir=.
OutputBaseFilename=EncTest
Compression=lzma2

[Files]
Source: "payload.txt"; DestDir: "{app}"; Flags: ignoreversion

[Tasks]
Name: "desktopicon"; Description: "创建桌面快捷方式"; GroupDescription: "其他任务:"
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
    out = os.path.join(workdir, 'out')
    os.makedirs(out, exist_ok=True)
    proc = subprocess.run(
        [iscc, f'/DOutputDir={out}', path],
        capture_output=True, text=True, encoding='utf-8', errors='replace')
    exe = os.path.join(out, 'EncTest.exe')
    if not os.path.exists(exe):
        print(f'  build FAILED (rc={proc.returncode})')
        print(proc.stdout[-1500:])
        print(proc.stderr[-1500:])
        return None
    return exe


def probe(exe):
    d = open(exe, 'rb').read()
    u16 = d.decode('utf-16-le', errors='ignore')
    results = {}
    for label, text in (('raw-utf8', '编码测试'), ('garbled', '缂栫爜')):
        results[f'utf16:{label}'] = text in u16
        results[f'bytes:{label}'] = text.encode('utf-8') in d
    return results


def main():
    iscc, base = sys.argv[1], sys.argv[2]
    for with_bom in (False, True):
        tag = 'with-BOM' if with_bom else 'no-BOM'
        work = os.path.join(base, tag)
        exe = build(iscc, work, with_bom)
        if not exe:
            continue
        print(f'--- {tag} ---')
        for k, v in probe(exe).items():
            print(f'   {k:22s} {v}')


if __name__ == '__main__':
    main()
