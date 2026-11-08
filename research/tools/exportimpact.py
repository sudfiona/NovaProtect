#!/usr/bin/env python3
"""Show what the C# FunctionScanner shows for exported functions.

The UI column "Name" is what the user reads. For an image with an export
table the scanner should show real symbol names (GetProcAddress-style),
but the current ReadExports mis-maps them:

  * AddressOfNameOrdinals stores the EAT index directly, yet the scanner
    computes `index = ordinalTableValue - ordinalBase`. When Base is 1 the
    names shift by one slot (every name belongs to the wrong function);
    when Base is large (user32.dll uses 1502) every index goes negative and
    ALL names are dropped, so exported functions are reported as
    "not exported" and show up as anonymous sub_XXXXXXXX.

This script renders both mappings side by side for a given image so the
difference is visible rather than inferred.
"""
import struct
import sys


def u16(b, o):
    return struct.unpack_from('<H', b, o)[0]


def u32(b, o):
    return struct.unpack_from('<I', b, o)[0]


def analyze(path, limit=12):
    d = open(path, 'rb').read()
    pe = u32(d, 0x3c)
    nsec = u16(d, pe + 6)
    optsz = u16(d, pe + 20)
    opt = pe + 24
    magic = u16(d, opt)
    dd = opt + (112 if magic == 0x20b else 96)
    exp_rva = u32(d, dd)
    print(f'=== {path}')
    if not exp_rva:
        print('  no export directory')
        return
    sec = pe + 24 + optsz
    secs = []
    for i in range(nsec):
        row = d[sec + i * 40:sec + i * 40 + 40]
        secs.append((u32(row, 12), u32(row, 8), u32(row, 16), u32(row, 20)))

    def at(rva):
        for va, vsz, rsz, roff in secs:
            if va <= rva < va + max(vsz, rsz):
                return roff + (rva - va)
        return None

    def cstr(rva):
        off = at(rva)
        if off is None or off >= len(d):
            return ''
        end = d.find(b'\0', off)
        return '' if end < 0 else d[off:end].decode('latin1')

    off = at(exp_rva)
    base = u32(d, off + 16)
    nfuncs = u32(d, off + 20)
    nnames = u32(d, off + 24)
    eat_rva = u32(d, off + 28)
    names_rva = u32(d, off + 32)
    ord_rva = u32(d, off + 36)
    print(f'  Base={base}  NumberOfFunctions={nfuncs}  NumberOfNames={nnames}')

    correct, csharp = {}, {}
    dropped = 0
    for i in range(nnames):
        nrva = u32(d, at(names_rva) + i * 4)
        sym = cstr(nrva)
        if not sym:
            continue
        eat_index = u16(d, at(ord_rva) + i * 2)
        # correct: the ordinal table already holds the EAT index
        if eat_index < nfuncs:
            frva = u32(d, at(eat_rva) + eat_index * 4)
            if frva:
                correct.setdefault(frva, sym)
        # current C#: subtracts Base from the EAT index
        index = eat_index - base
        if index < 0 or index >= nfuncs:
            dropped += 1
            continue
        frva = u32(d, at(eat_rva) + index * 4)
        if frva:
            csharp.setdefault(frva, sym)

    print(f'  correct mapping resolves {len(correct)} names')
    print(f'  current C#  resolves {len(csharp)} names  (dropped by negative index: {dropped})')
    same = sum(1 for r in set(correct) & set(csharp) if correct[r] == csharp[r])
    wrong = len(set(correct) & set(csharp)) - same
    print(f'  overlapping RVAs: {len(set(correct) & set(csharp))}  '
          f'correct name={same}  WRONG name={wrong}')
    print('  first rows as the UI would show them:')
    for frva in sorted(correct)[:limit]:
        print(f'    0x{frva:08X}  correct={correct[frva]:<40s} csharp={csharp.get(frva, "(dropped)")}')


for p in sys.argv[1:]:
    analyze(p)
    print()
