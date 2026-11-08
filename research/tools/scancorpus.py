#!/usr/bin/env python3
"""Corpus check for two FunctionScanner.ReadExports/ScanPdata defects.

Defect A (ScanPdata): the C# scanner reads the exception directory from the
    *section* start (section.RawOffset) and derives the record count from
    section.RawSize. The exception directory has its own RVA and size in
    data directory #3. When they differ from the section's, the C# scanner
    parses the wrong bytes -> garbage / duplicated function entries.
    This script reports how often that happens across a corpus.

Defect B (ReadExports): the C# scanner computes the EAT index as
    `ordinalTableValue - ordinalBase`, but AddressOfNameOrdinals stores the
    EAT index directly. This script reports names resolved by the correct
    rule vs the C# rule.
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
        self.exc_rva = u32(d, dd + 3 * 8)
        self.exc_size = u32(d, dd + 3 * 8 + 4)
        sec = pe + 24 + optsz
        self.sections = []
        for i in range(nsec):
            row = d[sec + i * 40:sec + i * 40 + 40]
            self.sections.append({
                'name': row[:8].split(b'\0')[0].decode('latin1'),
                'vsz': u32(row, 8), 'va': u32(row, 12),
                'rsz': u32(row, 16), 'roff': u32(row, 20),
            })

    def find(self, rva):
        for s in self.sections:
            size = max(s['vsz'], s['rsz'])
            if size and s['va'] <= rva < s['va'] + size:
                return s
        return None

    def at(self, rva):
        s = self.find(rva)
        return None if not s else s['roff'] + (rva - s['va'])

    def cstr(self, rva):
        off = self.at(rva)
        if off is None or off >= len(self.d):
            return ''
        end = self.d.find(b'\0', off)
        return '' if end < 0 else self.d[off:end].decode('latin1')


def check(path):
    try:
        pe = PE(path)
    except Exception:
        return None
    if pe.exc_rva == 0:
        return None

    host = pe.find(pe.exc_rva)
    if host is None:
        return None
    delta = pe.exc_rva - host['va']
    true_entries = pe.exc_size // 12
    cs_entries = host['rsz'] // 12

    # how many "functions" does each interpretation yield?
    def decode(start_off, count):
        seen = set()
        d = pe.d
        for i in range(count):
            o = start_off + i * 12
            if o + 12 > len(d):
                break
            b = u32(d, o)
            e = u32(d, o + 4)
            if e <= b:
                continue
            seen.add(b)
        return seen

    true_set = decode(pe.at(pe.exc_rva), true_entries)
    cs_set = decode(host['roff'], cs_entries)

    # export names
    correct_names = cs_names = 0
    if pe.exp_rva:
        off = pe.at(pe.exp_rva)
        if off is not None:
            d = pe.d
            base = u32(d, off + 16)
            nfuncs = u32(d, off + 20)
            nnames = u32(d, off + 24)
            eat_rva = u32(d, off + 28)
            names_rva = u32(d, off + 32)
            ord_rva = u32(d, off + 36)
            if nnames and nnames < 70000:
                for i in range(nnames):
                    nrva = u32(d, pe.at(names_rva) + i * 4)
                    sym = pe.cstr(nrva)
                    if not sym:
                        continue
                    eidx = u16(d, pe.at(ord_rva) + i * 2)
                    if eidx < nfuncs:
                        frva = u32(d, pe.at(eat_rva) + eidx * 4)
                        if frva:
                            correct_names += 1
                    cidx = eidx - base
                    if 0 <= cidx < nfuncs:
                        frva = u32(d, pe.at(eat_rva) + cidx * 4)
                        if frva:
                            cs_names += 1

    return {
        'path': path,
        'delta': delta,
        'true_entries': true_entries,
        'cs_entries': cs_entries,
        'true_set': true_set,
        'cs_set': cs_set,
        'correct_names': correct_names,
        'cs_names': cs_names,
    }


def main(paths):
    n = 0
    offset_bad = []
    count_bad = []
    set_diff = []
    export_bad = []
    for p in paths:
        r = check(p)
        if r is None:
            continue
        n += 1
        if r['delta'] != 0:
            offset_bad.append(r)
        if r['true_entries'] != r['cs_entries']:
            count_bad.append(r)
        if r['true_set'] != r['cs_set']:
            set_diff.append(r)
        if r['correct_names'] != r['cs_names']:
            export_bad.append(r)

    print(f"analysed {n} PE images with an exception directory\n")
    print(f"A) exception dir not at section start : {len(offset_bad)}")
    for r in offset_bad[:8]:
        print(f"     delta=0x{r['delta']:X}  {r['path'][-70:]}")
    print(f"B) record count mismatch (RawSize vs excSize): {len(count_bad)}")
    for r in count_bad[:8]:
        print(f"     true={r['true_entries']} cs={r['cs_entries']}  {r['path'][-70:]}")
    print(f"C) decoded function sets differ        : {len(set_diff)}")
    for r in set_diff[:8]:
        print(f"     true={len(r['true_set'])} cs={len(r['cs_set'])}  {r['path'][-70:]}")
    print(f"D) export name resolution differs      : {len(export_bad)}")
    for r in export_bad[:8]:
        print(f"     correct={r['correct_names']} cs={r['cs_names']}  {r['path'][-70:]}")


if __name__ == '__main__':
    main(sys.argv[1:])
