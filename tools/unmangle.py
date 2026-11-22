"""Full pipeline: undo the PowerShell GBK mangling, then repair dropped bytes
so the result is valid UTF-8 again.

Step 1 builds the inverse byte table of the GBK code page and turns the
mangled text back into the byte stream it came from. Where the original
decoder dropped a byte (replacing it with '?') the stream is left with a gap.
Step 2 fills each gap by trying every single-byte insertion that makes the
stream valid UTF-8 again.
"""
import sys


def build_inverse():
    inv = {}
    for b in range(0x80):
        inv[chr(b)] = bytes([b])
    inv['€'] = b'\x80'                 # cp936 single-byte 0x80
    for lead in range(0x81, 0xFF):
        for trail in range(0x00, 0x100):
            pair = bytes([lead, trail])
            for codec in ('cp936', 'gb18030'):
                try:
                    s = pair.decode(codec)
                except Exception:
                    continue
                if len(s) == 1:
                    inv.setdefault(s, pair)
                    break
    return inv


def find_first_bad(data: bytes):
    i, n = 0, len(data)
    while i < n:
        b = data[i]
        if b < 0x80:
            i += 1
            continue
        if 0xC2 <= b <= 0xDF:
            need = 1
        elif 0xE0 <= b <= 0xEF:
            need = 2
        elif 0xF0 <= b <= 0xF4:
            need = 3
        else:
            return i
        if i + need >= n:
            return i
        try:
            data[i:i + 1 + need].decode('utf-8')
        except UnicodeDecodeError:
            return i
        i += 1 + need
    return None


def repair(data: bytes) -> bytes:
    for _ in range(20000):
        bad = find_first_bad(data)
        if bad is None:
            return data
        # Accept an insertion when the neighbourhood decodes cleanly. Checking
        # the whole rest of the stream would fail on every candidate because
        # later gaps are still open - the window has to be local.
        fixed = None
        for cand in range(0x20, 0x100):
            head = data[:bad] + bytes([cand])
            tail = data[bad:bad + 8]
            try:
                (head[-4:] + tail).decode('utf-8')
            except UnicodeDecodeError:
                continue
            # also require the inserted byte to continue the previous char
            try:
                head.decode('utf-8')
            except UnicodeDecodeError:
                continue
            fixed = head + data[bad:]
            break
        data = fixed if fixed is not None else data[:bad] + data[bad + 1:]
    return data


def main():
    src, dst = sys.argv[1], sys.argv[2]
    raw = open(src, 'rb').read()
    bom = raw.startswith(b'\xef\xbb\xbf')
    t = raw.decode('utf-8')
    if bom:
        t = t[1:]
    inv = build_inverse()
    out = bytearray()
    gaps = 0
    for ch in t:
        b = inv.get(ch)
        if b is None:
            out += b'\xef\xbf\xbd'
            gaps += 1
        else:
            out += b
    print(f'step1: {len(t)} chars -> {len(out)} bytes, {gaps} unmappable')
    fixed = repair(bytes(out))
    try:
        text = fixed.decode('utf-8')
        status = 'ok'
    except UnicodeDecodeError as e:
        status = f'partial ({e})'
        text = fixed.decode('utf-8', errors='replace')
    print('step2:', status, 'len', len(text))
    open(dst, 'wb').write((('\ufeff' if bom else '') + text).encode('utf-8'))
    print(repr(text[:200]))


if __name__ == '__main__':
    main()
