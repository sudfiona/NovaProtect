"""Cross-check: every wire opcode the translator can emit must have a handler
registered in the freestanding runtime, and vice versa. A gap here is a silent
no-op at run time - exactly the class of defect the XMM index bug was."""
import re
import sys

def read(p):
    return open(p, encoding='utf-8').read()

isa = read('include/vm_isa.h')
engine = read('src/vm_engine.cpp')
prot = read('runtime/prot64.c')

# 1. all defined wire opcodes
defined = set(re.findall(r'^\s*WIRE_([A-Z0-9_]+)\s*=\s*0x', isa, re.M))
# 2. opcodes the translator emits
emitted = set(re.findall(r'emit\(\s*WIRE_([A-Z0-9_]+)', engine))
# 3. handlers registered in the runtime
registered = set(re.findall(r'np_handlers\[\s*VMO_([A-Z0-9_]+)\s*\]', prot))

missing_handler = sorted(emitted - registered)
unused = sorted(registered - emitted)
never_emitted = sorted(defined - emitted)

print(f'defined={len(defined)} emitted={len(emitted)} registered={len(registered)}')
print('*** EMITTED BUT NO HANDLER (silent no-op):', missing_handler or 'none')
print('registered but never emitted:', unused or 'none')
print('defined but never emitted:', never_emitted or 'none')

# 4. every handler function referenced must exist
funcs = set(re.findall(r'static void (np_h_[a-z0-9_]+)\(', prot))
refs = set(re.findall(r'np_handlers\[[^\]]+\]\s*=\s*(np_h_[a-z0-9_]+)', prot))
print('handler funcs defined but not registered:', sorted(funcs - refs) or 'none')
print('registered but not defined:', sorted(refs - funcs) or 'none')

# 5. XMM operand guard sanity: no handler may treat an operand as an xmm index
#    without going through NP_XIDX
raw = re.findall(r's->x\[\s*(\w+)\s*\*\s*16', prot)
print('xmm array indices used:', sorted(set(raw)))
