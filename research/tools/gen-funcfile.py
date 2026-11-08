"""Generate a -funcfile rule list from a PE's exception directory.

This mirrors what the client sends when the user picks "add all functions":
one rule per scanned function, several hundred to several thousand of them.
"""
import importlib.util
import sys
import os

_here = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("pe_symbols", os.path.join(_here, "pe-symbols.py"))
pe_symbols = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pe_symbols)
parse = pe_symbols.parse

path = sys.argv[1]
out = sys.argv[2]
mode = sys.argv[3] if len(sys.argv) > 3 else "virtualization"
vm = sys.argv[4] if len(sys.argv) > 4 else "5"
mut = sys.argv[5] if len(sys.argv) > 5 else "0"

b, base, sections, exports, pdata = parse(path)
if not pdata:
    print("no .pdata entries", file=sys.stderr)
    sys.exit(1)

lines = []
for begin, end in pdata:
    if end <= begin:
        continue
    lines.append(f"{begin:X}-{end:X}-{mode}-{vm}-{mut}-0")

with open(out, "w", encoding="ascii", newline="\n") as f:
    f.write("\n".join(lines) + "\n")

print(f"wrote {len(lines)} rules -> {out}")
