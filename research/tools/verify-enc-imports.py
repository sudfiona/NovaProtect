"""Locate the NPM1 metadata container inside a packed image and verify that
the import blob is really encrypted (and that the stub-side keystream
reproduces the plaintext).
"""
import struct
import sys


def sections(d):
    pe = struct.unpack_from("<I", d, 0x3C)[0]
    nsec = struct.unpack_from("<H", d, pe + 6)[0]
    optsize = struct.unpack_from("<H", d, pe + 20)[0]
    opt = pe + 24
    magic = struct.unpack_from("<H", d, opt)[0]
    dd = opt + (112 if magic == 0x20B else 96)
    sec = opt + optsize
    out = []
    for i in range(nsec):
        o = sec + i * 40
        name = d[o:o + 8].rstrip(b"\0").decode("ascii", "replace")
        vsize, vaddr, rsize, raw = struct.unpack_from("<IIII", d, o + 8)
        out.append((name, vaddr, vsize, raw, rsize))
    return out, dd


def to_off(rva, secs):
    for name, vaddr, vsize, raw, rsize in secs:
        if vaddr <= rva < vaddr + max(vsize, rsize):
            return raw + (rva - vaddr)
    return None


def rol32(v, n):
    n &= 31
    return v if n == 0 else ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF


def keystream_byte(seed, i):
    return ((rol32(seed, i & 0x1F) + (i & 0xFF)) & 0xFF)


def main(path):
    d = open(path, "rb").read()
    secs, _ = sections(d)
    print("sections:")
    for s in secs:
        print("  ", s)

    # The metadata container is stored in .np_meta; find it by content.
    found = None
    for name, vaddr, vsize, raw, rsize in secs:
        if name.startswith(".np"):
            blob = d[raw:raw + rsize]
            i = blob.find(b"NPM1")
            while i >= 0:
                ver, cnt, flags = struct.unpack_from("<III", blob, i + 4)
                if ver == 1 and 0 < cnt < 64:
                    found = (name, blob, i, cnt)
                    break
                i = blob.find(b"NPM1", i + 1)
            if found:
                break

    if not found:
        print("NPM1 container not found")
        return 1

    name, blob, base, cnt = found
    print(f"\nNPM1 in {name} at +0x{base:X}, {cnt} entries")
    entries = []
    for k in range(cnt):
        t, h, off, size = struct.unpack_from("<IIII", blob, base + 16 + k * 16)
        entries.append((t, h, off, size))
        print(f"  entry[{k}] type={t} hash=0x{h:08X} off={off} size={size}")

    payload_start = base + 16 + cnt * 16
    for t, h, off, size in entries:
        if t != 6:
            continue
        pay = blob[payload_start + off: payload_start + off + size]
        seed, plen = struct.unpack_from("<II", pay, 0)
        print(f"\n  import blob: seed=0x{seed:08X} plain_len={plen} stored={len(pay)}")
        if len(pay) < 8:
            print("  blob too small")
            continue
        cipher = pay[8:8 + plen]
        plain = bytes(c ^ keystream_byte(seed, i) for i, c in enumerate(cipher))
        print(f"  decrypted head: {plain[:48]!r}")
        # The first field must be the DLL count.
        dc = struct.unpack_from("<I", plain, 0)[0]
        print(f"  dll_count = {dc}")
        if dc == 0 or dc > 512:
            print("  *** DECRYPTION MISMATCH ***")
            return 1
        off2 = 4
        for i in range(min(dc, 5)):
            nlen = struct.unpack_from("<I", plain, off2)[0]
            off2 += 4
            nm = plain[off2:off2 + nlen - 1]
            print(f"    dll[{i}] = {nm!r}")
            off2 += nlen
            fcount = struct.unpack_from("<I", plain, off2)[0]
            off2 += 4
            for j in range(min(fcount, 3)):
                kind = plain[off2]
                ordv = struct.unpack_from("<H", plain, off2 + 1)[0]
                rva = struct.unpack_from("<I", plain, off2 + 3)[0]
                off2 += 7
                if kind == 0:
                    flen = struct.unpack_from("<I", plain, off2)[0]
                    off2 += 4
                    fn = plain[off2:off2 + flen - 1]
                    off2 += flen
                    print(f"      fn = {fn!r}")
                else:
                    print(f"      ordinal {ordv}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
