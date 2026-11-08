#!/usr/bin/env python3
"""Mirror the C# FunctionScanner.ReadExports logic step by step.

Purpose: find exactly where the C# scanner diverges from a correct PE
export-directory walk, so the fix is provable rather than guessed.

C# logic under test (ui/Services/FunctionScanner.cs):
    ordinalBase   = u32(dir, 16)
    numberOfNames = u32(dir, 24)
    addressTableRva = u32(dir, 28)
    nameTableRva    = u32(dir, 32)
    ordinalTableRva = u32(dir, 36)
    ...
    index = ordinal - ordinalBase          # <-- suspect
    if index < 0 or index >= addressCount: continue
    functionRva = u32(addressRows, index*4)

Correct semantics:
    AddressOfNameOrdinals[i] holds the EAT index directly.
    The user-visible ordinal is EAT_index + Base.
"""
import struct
import sys


def u16(b, o):
    return struct.unpack_from('<H', b, o)[0]


def u32(b, o):
    return struct.unpack_from('<I', b, o)[0]


class PE:
    def __init__(self, path):
        self.d = d = open(path, 'rb').read()
        pe = u32(d, 0x3c)
        nsec = u16(d, pe + 6)
        optsz = u16(d, pe + 20)
        opt = pe + 24
        magic = u16(d, opt)
        dd = opt + (112 if magic == 0x20b else 96)
        self.exp_rva = u32(d, dd)
        self.exp_size = u32(d, dd + 4)
        sec = pe + 24 + optsz
        self.sections = []
        for i in range(nsec):
            row = d[sec + i * 40:sec + i * 40 + 40]
            self.sections.append({
                'va': u32(row, 12), 'vsz': u32(row, 8),
                'rsz': u32(row, 16), 'roff': u32(row, 20),
                'name': row[:8].split(b'\0')[0].decode('latin1'),
                'chars': u32(row, 36),
            })

    def find(self, rva):
        for s in self.sections:
            size = max(s['vsz'], s['rsz'])
            if size and s['va'] <= rva < s['va'] + size:
                return s
        return None

    def at(self, rva):
        s = self.find(rva)
        if not s:
            return None
        return s['roff'] + (rva - s['va'])

    def cstr(self, rva):
        off = self.at(rva)
        if off is None or off >= len(self.d):
            return ''
        end = self.d.find(b'\0', off)
        if end < 0:
            return ''
        return self.d[off:end].decode('latin1')


def report(path):
    pe = PE(path)
    print(f"=== {path}")
    if pe.exp_rva == 0:
        print("  no export directory")
        return

    off = pe.at(pe.exp_rva)
    if off is None:
        print("  export dir RVA not mapped")
        return
    d = pe.d

    base = u32(d, off + 16)
    nfuncs = u32(d, off + 20)
    nnames = u32(d, off + 24)
    eat_rva = u32(d, off + 28)
    names_rva = u32(d, off + 32)
    ord_rva = u32(d, off + 36)
    dir_name = pe.cstr(u32(d, off + 12))
    print(f"  dir='{dir_name}' base={base} nFuncs={nfuncs} nNames={nnames}")
    print(f"  eat=0x{eat_rva:X} names=0x{names_rva:X} ord=0x{ord_rva:X}")

    # --- correct mapping: ordinal table holds EAT indices -------------
    correct = {}
    for i in range(nnames):
        nrva = u32(d, pe.at(names_rva) + i * 4)
        sym = pe.cstr(nrva)
        eat_index = u16(d, pe.at(ord_rva) + i * 2)
        if eat_index >= nfuncs:
            continue
        frva = u32(d, pe.at(eat_rva) + eat_index * 4)
        if frva:
            correct.setdefault(frva, sym)

    # --- C# mapping: index = ordinal - base ---------------------------
    cs = {}
    dropped_index_lt0 = 0
    dropped_oob = 0
    dropped_empty_sym = 0
    for i in range(nnames):
        nrva = u32(d, pe.at(names_rva) + i * 4)
        sym = pe.cstr(nrva)
        if not sym:
            dropped_empty_sym += 1
            continue
        ordinal = u16(d, pe.at(ord_rva) + i * 2)
        index = ordinal - base
        if index < 0:
            dropped_index_lt0 += 1
            continue
        if index >= nfuncs:
            dropped_oob += 1
            continue
        frva = u32(d, pe.at(eat_rva) + index * 4)
        if frva:
            cs.setdefault(frva, sym)

    print(f"  CORRECT names resolved = {len(correct)}")
    print(f"  C#      names resolved = {len(cs)}")
    print(f"    dropped: ordinal-base<0={dropped_index_lt0} "
          f"oob={dropped_oob} emptySym={dropped_empty_sym}")
    if correct:
        sample = sorted(correct.items())[:4]
        for frva, sym in sample:
            print(f"    correct 0x{frva:X} -> {sym}")
    if cs:
        sample = sorted(cs.items())[:4]
        for frva, sym in sample:
            print(f"    csharp  0x{frva:X} -> {sym}")
    # how many correct names actually land on a .pdata-style function start
    if correct and cs:
        overlap = len(set(correct) & set(cs))
        print(f"    RVA overlap correct-vs-csharp = {overlap} / {len(correct)}")
        wrong = [(r, correct[r], cs[r]) for r in set(correct) & set(cs) if correct[r] != cs[r]]
        print(f"    same RVA but WRONG name = {len(wrong)}")
        for r, want, got in sorted(wrong)[:4]:
            print(f"      0x{r:X} should be '{want}' but got '{got}'")


for p in sys.argv[1:]:
    report(p)
    print()
