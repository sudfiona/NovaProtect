#!/usr/bin/env python3
"""Reproduce the MSBuild console corruption exactly.

MSBuild emits its localized messages as UTF-8. When a console reads them
with the system ANSI code page (GBK on zh-CN) every Chinese message turns
into unreadable text. This reproduces the transformation so the mechanism is
demonstrated rather than asserted.
"""
GOOD = (
    '正在确定要还原的项目。'
    '已还原 C:\\npbuild\\ui\\NovaProtect.UI.csproj (用时 1.97 秒)。'
)

print('correct UTF-8 text:')
print('   ', GOOD)
print()
print('same UTF-8 bytes decoded as GBK (what the console showed):')
print('   ', GOOD.encode('utf-8').decode('gbk', errors='replace'))
print()

# The inverse: what a GBK-encoded console would show for UTF-8 input.
print('for comparison, GBK bytes decoded as UTF-8:')
try:
    print('   ', GOOD.encode('gbk').decode('utf-8'))
except UnicodeDecodeError as exc:
    print('    (not decodable:', exc.reason, ')')
