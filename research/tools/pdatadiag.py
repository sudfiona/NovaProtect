#!/usr/bin/env python3
"""Check where the C# scanner reads .pdata from versus where the exception
directory actually lives.

C# logic (ui/Services/FunctionScanner.cs, ScanPdata):
    table = FindSection(sections, exceptionDirRva);
    entries = table.RawSize / 12;
    stream.Position = table.RawOffset;      <-- section start, not exceptionDirRva
    buffer = new byte[table.RawSize];       <-- whole section

Two questions:
  1. Is the exception directory RVA equal to its section's VirtualAddress?
     If not, the C# scanner reads from the wrong file offset entirely.
  2. Is the section RawSize equal to the exception directory size?
     If not, `entries` over/under-counts RUNTIME_FUNCTION records.
"""
import struct
import sys


def u16(b, o):
    return struct.unpack_from('<H', b, o)[0]


def u32(b, o):
    return struct.unpack_from('<I', b, o)[0]


def analyze(path):
    d = open(path, 'rb').read()
    pe = u32(d, 0x3c)
    nsec = u16(d, pe + 6)
    optsz = u16(d, pe + 20)
    opt = pe + 24
    magic = u16(d, opt)
    dd = opt + (112 if magic == 0x20b else 96)
    exc_rva = u32(d, dd + 3 * 8)
    exc_size = u32(d, dd + 3 * 8 + 4)
    sec = pe + 24 + optsz
    sections = []
    for i in range(nsec):
        row = d[sec + i * 40:sec + i * 40 + 40]
        sections.append({
            'name': row[:8].split(b'\0')[0].decode('latin1'),
            'vsz': u32(row, 8), 'va': u32(row, 12),
            'rsz': u32(row, 16), 'roff': u32(row, 20),
            'chars': u32(row, 36),
        })

    print(f"=== {path}")
    if exc_rva == 0:
        print("  no exception directory (x86 or stripped)")
        print()
        return

    print(f"  exceptionDir rva=0x{exc_rva:X} size={exc_size} "
          f"({exc_size // 12} RUNTIME_FUNCTION records)")
    host = None
    for s in sections:
        size = max(s['vsz'], s['rsz'])
        if size and s['va'] <= exc_rva < s['va'] + size:
            host = s
            break
    if host is None:
        print("  exception dir not mapped to any section")
        print()
        return

    delta = exc_rva - host['va']
    print(f"  host section '{host['name']}' va=0x{host['va']:X} "
          f"roff=0x{host['roff']:X} rsz={host['rsz']} vsz={host['vsz']}")
    print(f"  delta (exc_rva - section_va) = 0x{delta:X}  "
          f"{'OK (starts at section head)' if delta == 0 else '*** C# READS FROM WRONG OFFSET ***'}")

    cs_entries = host['rsz'] // 12
    true_entries = exc_size // 12
    print(f"  C# entries = RawSize/12 = {cs_entries}   "
          f"true entries = excSize/12 = {true_entries}   "
          f"{'OK' if cs_entries == true_entries else '*** COUNT MISMATCH ***'}")

    # Decode using the C# start (section head) vs the true start.
    def decode(start_off, count, label):
        seen, prev, dup = set(), 0, 0
        for i in range(count):
            o = start_off + i * 12
            if o + 12 > len(d):
                break
            b = u32(d, o)
            e = u32(d, o + 4)
            if e <= b:
                continue
            if b in seen:
                dup += 1
            seen.add(b)
        print(f"  {label}: valid={len(seen)} duplicateBegin={dup}")
        return seen

    true_off = host['roff'] + delta
    a = decode(true_off, true_entries, "true start (exc_rva)")
    b = decode(host['roff'], cs_entries, "C# start (section head)")
    if a != b:
        print("  *** the two decodes DISAGREE -> C# scans the wrong bytes ***")
    print()


for p in sys.argv[1:]:
    analyze(p)
