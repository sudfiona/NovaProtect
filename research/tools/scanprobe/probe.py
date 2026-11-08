import struct, sys, collections

def u16(b,o): return struct.unpack_from('<H',b,o)[0]
def u32(b,o): return struct.unpack_from('<I',b,o)[0]

def scan(path):
    d=open(path,'rb').read()
    pe=u32(d,0x3c)
    assert d[pe:pe+4]==b'PE\0\0'
    nsec=u16(d,pe+6)
    optsz=u16(d,pe+20)
    opt=pe+24
    magic=u16(d,opt)
    dd = opt + (112 if magic==0x20b else 96)
    exc_rva=u32(d,dd+3*8)
    sec=pe+24+optsz
    sections=[]
    for i in range(nsec):
        row=d[sec+i*40:sec+i*40+40]
        name=row[:8].rstrip(b'\0').decode('latin1')
        vsz=u32(row,8); va=u32(row,12); rsz=u32(row,16); roff=u32(row,20)
        chars=u32(row,36)
        sections.append((name,va,vsz,roff,rsz,chars))
    def find(rva):
        for s in sections:
            size=max(s[2],s[4])
            if size==0: continue
            if s[1]<=rva<s[1]+size: return s
        return None
    pdata=find(exc_rva)
    if not pdata: return None,None
    name,va,vsz,roff,rsz,chars=pdata
    n=rsz//12
    print(f"  .pdata section {name} rawsize={rsz} entries={n}")
    funcs=[]
    for i in range(n):
        o=roff+i*12
        b=u32(d,o); e=u32(d,o+4)
        if e<=b: continue
        s=find(b)
        if not s or not (s[5]&0x20000000): continue
        funcs.append((b,e,s[0]))
    return funcs,sections

for path in sys.argv[1:]:
    print("=== ", path)
    try:
        funcs,secs=scan(path)
    except Exception as ex:
        print("  ERR",ex); continue
    if funcs is None:
        print("  no pdata"); continue
    print("  functions:",len(funcs))
    for f in funcs[:6]:
        print(f"   rva=0x{f[0]:X} end=0x{f[1]:X} size={f[1]-f[0]} sec={f[2]}")
    # 关键: 检查 RVA 是否重复
    c=collections.Counter(f[0] for f in funcs)
    dup=[k for k,v in c.items() if v>1]
    print("  重复 RVA 数:",len(dup))
    # 检查 name 是否都一样
    names=set()
    for b,e,s in funcs: names.add(f"sub_{b:08X}")
    print("  唯一 name 数:",len(names))
    # 检查 size 分布
    sizes=collections.Counter(e-b for b,e,s in funcs)
    print("  size 分布 top5:",sizes.most_common(5))
    print("  相同 size 占比: %.1f%%" % (100*max(sizes.values())/max(len(funcs),1)))
