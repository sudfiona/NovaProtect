"""Standalone reference implementation of the PE export directory.

Used to cross-check the C# FunctionScanner.ReadExports field offsets.
Layout of IMAGE_EXPORT_DIRECTORY:
    0  Characteristics
    4  TimeDateStamp
    8  MajorVersion / MinorVersion
   12  Name RVA
   16  Base (ordinal base)
   20  NumberOfFunctions
   24  NumberOfNames
   28  AddressOfFunctions (EAT) RVA
   32  AddressOfNames (name pointer table) RVA
   36  AddressOfNameOrdinals (ordinal table) RVA
"""
import struct
import sys


def u16(b, o):
    return struct.unpack_from('<H', b, o)[0]


def u32(b, o):
    return struct.unpack_from('<I', b, o)[0]


class PE:
    def __init__(self, path):
        self.d = open(path, 'rb').read()
        d = self.d
        pe = u32(d, 0x3c)
        nsec = u16(d, pe + 6)
        optsz = u16(d, pe + 20)
        opt = pe + 24
        magic = u16(d, opt)
        dd = opt + (112 if magic == 0x20b else 96)
        self.exp_rva = u32(d, dd)
        sec = pe + 24 + optsz
        self.sections = []
        for i in range(nsec):
            row = d[sec + i * 40:sec + i * 40 + 40]
            self.sections.append((u32(row, 12), u32(row, 8), u32(row, 16), u32(row, 20)))

    def find(self, rva):
        for va, vsz, rsz, roff in self.sections:
            if va <= rva < va + max(vsz, rsz):
                return va, roff
        return None

    def at(self, rva):
        f = self.find(rva)
        if not f:
            return None
        va, roff = f
        return roff + (rva - va)

    def cstr(self, rva):
        off = self.at(rva)
        if off is None or off >= len(self.d):
            return ''
        end = self.d.index(b'\x00', off)
        return self.d[off:end].decode('latin1')

    def exports(self):
        off = self.at(self.exp_rva)
        if off is None:
            return {}
        b = self.d
        base = u32(b, off + 16)
        nfuncs = u32(b, off + 20)
        nnames = u32(b, off + 24)
        eat_rva = u32(b, off + 28)
        names_rva = u32(b, off + 32)
        ords_rva = u32(b, off + 36)

        eat_off = self.at(eat_rva)
        names_off = self.at(names_rva)
        ords_off = self.at(ords_rva)
        if eat_off is None or names_off is None or ords_off is None:
            return {}

        result = {}
        for i in range(nnames):
            name_rva = u32(b, names_off + i * 4)
            symbol = self.cstr(name_rva)
            if not symbol:
                continue
            # AddressOfNameOrdinals holds the INDEX INTO THE EAT, not an ordinal.
            eat_index = u16(b, ords_off + i * 2)
            if eat_index >= nfuncs:
                continue
            func_rva = u32(b, eat_off + eat_index * 4)
            if func_rva:
                result[func_rva] = symbol
        return result


if __name__ == '__main__':
    for path in sys.argv[1:]:
        pe = PE(path)
        ex = pe.exports()
        print(f'=== {path}')
        print(f'  export dir rva=0x{pe.exp_rva:X}  names resolved={len(ex)}')
        for rva, name in list(ex.items())[:12]:
            print(f'    0x{rva:X} -> {name}')
