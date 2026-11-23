import struct, sys

def u16(b,o): return struct.unpack_from('<H',b,o)[0]
def u32(b,o): return struct.unpack_from('<I',b,o)[0]

def load(path):
    b=open(path,'rb').read()
    pe=u32(b,0x3c); nsec=u16(b,pe+6); optsz=u16(b,pe+20); opt=pe+24
    magic=u16(b,opt)
    ddoff=opt+(112 if magic==0x20b else 96)
    dirs=[(u32(b,ddoff+i*8),u32(b,ddoff+i*8+4)) for i in range(16)]
    secoff=opt+optsz; secs=[]
    for i in range(nsec):
        s=secoff+i*40
        secs.append((b[s:s+8].rstrip(b'\0').decode('latin1'),u32(b,s+8),u32(b,s+12),u32(b,s+16),u32(b,s+20)))
    def r2o(rva):
        for n,vs,va,rs,rp in secs:
            if va<=rva<va+max(vs,rs): return rp+(rva-va)
        return None
    return b,dirs,secs,r2o

def manifest(path):
    b,dirs,secs,r2o=load(path)
    rva,size=dirs[2]
    if not rva: return None,'no rsrc dir'
    base=r2o(rva)
    if base is None: return None,'rsrc rva unmapped'
    out=[]
    def walk_dir(off, level, ids):
        if off<0 or off+16>len(b)-base: return
        nn=u16(b,base+off+12); ni=u16(b,base+off+14)
        for i in range(nn+ni):
            e=base+off+16+i*8
            if e+8>len(b): return
            nm=u32(b,e); od=u32(b,e+4)
            ident=nm & 0x7fffffff if nm & 0x80000000 else nm & 0xffff
            if od & 0x80000000:
                walk_dir(od & 0x7fffffff, level+1, ids+[ident])
            else:
                de=base+od
                if de+16>len(b): return
                drva=u32(b,de); dsz=u32(b,de+4); do=r2o(drva)
                out.append((tuple(ids),drva,dsz,do))
                if level < 2:
                    walk_dir(od, level+1, ids+[ident]) if False else None
    # typed walk: level0 entry = type, level1 = name, level2 = lang
    def walk(off, level, ids):
        nn=u16(b,base+off+12); ni=u16(b,base+off+14)
        for i in range(nn+ni):
            e=base+off+16+i*8
            nm=u32(b,e); od=u32(b,e+4)
            ident=nm & 0x7fffffff if nm & 0x80000000 else nm & 0xffff
            if od & 0x80000000:
                walk(od & 0x7fffffff, level+1, ids+[ident])
            else:
                de=base+od
                drva=u32(b,de); dsz=u32(b,de+4); do=r2o(drva)
                out.append((tuple(ids+[ident]), level, drva, dsz, do))
    walk(0,0,[])
    entries=[]
    for ids,level,drva,dsz,do in out:
        entries.append((ids,drva,dsz,do))
    mans=[e for e in entries if len(e[0])>=2 and e[0][0]==24]
    if not mans: return None,f'no RT_MANIFEST entries (levels={[e[0] for e in entries][:6]})'
    ids,drva,dsz,do=mans[-1]
    if do is None: return None,'manifest data rva unmapped'
    return b[do:do+dsz], f'ids={ids} rva=0x{drva:X} size=0x{dsz:X}'

def main():
    paths=sys.argv[1:]
    payloads={}
    for p in paths:
        data,note=manifest(p)
        print(f'-- {p}\n   {note}')
        if data is None: continue
        payloads[p]=data
        print(f'   len={len(data)} head={data[:60]!r}')
        print(f'   tail={data[-80:]!r}')
        try:
            txt=data.decode('utf-8')
            print(f'   well-formed-ish: starts={txt.lstrip()[:9]!r} ends={txt.rstrip()[-12:]!r}')
        except Exception as ex:
            print(f'   DECODE ERROR {ex}')
        print()
    if len(payloads)>1:
        base=paths[0]
        for p in paths[1:]:
            if base in payloads and p in payloads:
                a=payloads[base]; c=payloads[p]
                print(f'compare {base} vs {p}: equal={a==c} lenA={len(a)} lenB={len(c)}')
                if a!=c:
                    for i,(x,y) in enumerate(zip(a,c)):
                        if x!=y:
                            print(f'  first diff at {i}: {a[max(0,i-20):i+20]!r} vs {c[max(0,i-20):i+20]!r}')
                            break
main()
