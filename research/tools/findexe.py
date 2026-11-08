#!/usr/bin/env python3
"""Find EXE files on the system that have a populated export directory.

The function scanner's export-name path only activates for images with an
export table, so a UI reproduction of "all functions look the same" needs a
target that actually has exports.
"""
import os
import struct
import sys


def u16(b, o):
    return struct.unpack_from('<H', b, o)[0]


def u32(b, o):
    return struct.unpack_from('<I', b, o)[0]


def probe(path):
    try:
        d = open(path, 'rb').read()
    except OSError:
        return None
    if len(d) < 0x200 or d[:2] != b'MZ':
        return None
    try:
        pe = u32(d, 0x3c)
        if d[pe:pe + 4] != b'PE\0\0':
            return None
        nsec = u16(d, pe + 6)
        optsz = u16(d, pe + 20)
        opt = pe + 24
        magic = u16(d, opt)
        dd = opt + (112 if magic == 0x20b else 96)
        exp_rva = u32(d, dd)
        if not exp_rva:
            return None
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

        off = at(exp_rva)
        if off is None:
            return None
        base = u32(d, off + 16)
        nn = u32(d, off + 24)
        return (nn, base, path)
    except Exception:
        return None


def main(roots, exts=('.exe',)):
    out = []
    for root in roots:
        for dp, dn, fn in os.walk(root):
            for f in fn:
                if not f.lower().endswith(exts):
                    continue
                p = os.path.join(dp, f)
                try:
                    if os.path.getsize(p) > 60 * 1024 * 1024:
                        continue
                except OSError:
                    continue
                r = probe(p)
                if r and r[0] > 0:
                    out.append(r)
    out.sort(reverse=True)
    for nn, base, p in out[:25]:
        print(f'names={nn:5d} base={base:6d}  {p}')
    print(f'total with exports: {len(out)}')


if __name__ == '__main__':
    main(sys.argv[1:])
