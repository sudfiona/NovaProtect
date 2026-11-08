"""End-to-end check for the 'add all functions then pack' crash.

Before the fix the client passed one -func argument per selected function.
Selecting every feasible function of a large image produced a command line
of tens of thousands of characters, which exceeds the Windows limit of
32767 characters. CreateProcess then failed with Win32Exception(206) and the
UI reported a failed protection run.

This script drives the real client through the whole flow on a target with
many functions and checks the outcome.
"""
import os
import re
import sys
import time

RUNNER = r'C:\npbuild\tools\probe-e2e-ui.ps1'
TARGET = r'C:\npbuild\ui\bin\x64\Release\net10.0-windows10.0.19041.0\win-x64\NovaProtect.Engine.exe'
OUT = r'C:\npbuild\artifacts\ui-crash-verify'


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else TARGET
    cmd = (
        'powershell -NoProfile -ExecutionPolicy Bypass -File "%s" '
        '-Target "%s" -OutputDirectory "%s"' % (RUNNER, target, OUT)
    )
    print('running:', cmd)
    rc = os.system(cmd)
    print('exit code:', rc)

    log = os.path.join(OUT, 'protect.log')
    if not os.path.exists(log):
        print('FAIL: no protect.log produced')
        return 1
    text = open(log, encoding='utf-8', errors='replace').read()
    print('\n--- protect.log ---')
    print(text[-2500:])

    bad = []
    if '文件名或扩展名太长' in text or 'too long' in text.lower():
        bad.append('command-line overflow (Win32Exception 206)')
    if '保护失败' in text:
        bad.append('protection reported failure')
    if not os.path.exists(os.path.join(OUT, 'result.txt')):
        bad.append('no result dump')

    print('\n=== verdict ===')
    if bad:
        for b in bad:
            print('  FAIL:', b)
        return 1
    print('  PASS: protection ran with every function selected')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
