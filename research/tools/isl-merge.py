"""Merge the official Inno Setup Simplified-Chinese translation into the
project's installer/ChineseSimplified.isl.

The shipped ISL was hand-edited from the *English* Default.isl, so 254 of its
281 Messages entries were still English.  The wizard's "Ready to Install"
page (the page the user calls 准备就绪) therefore rendered as a large block
of English / mixed-language text.

Strategy: take the official translation as the base (it is complete and
maintained by Inno Setup), then re-apply any project-specific Chinese
overrides on top of it.
"""
import os
import re
import sys

OFFICIAL = r"C:\Inno Setup 7\Languages\ChineseSimplified.isl"
def _np_repo_file(relative):
    """Resolve a path inside the NovaProtect repo from either layout.

    The research harness runs from protector-research/ next to the repo in the
    maintainer's workspace, and from research/ inside the published tree.
    """
    from pathlib import Path
    here = Path(__file__).resolve()
    for base in (here.parents[2], here.parents[2] / 'NovaProtect', here.parents[3]):
        candidate = base / relative
        if candidate.is_file():
            return str(candidate)
    return str(here.parents[2] / relative)
SHIPPED = _np_repo_file('installer/ChineseSimplified.isl')
def parse(path):
    """Return (entries, order, raw_lines) preserving file order."""
    raw = open(path, "rb").read()
    has_bom = raw[:3] == b"\xef\xbb\xbf"
    text = raw.decode("utf-8-sig")
    entries = {}
    order = []
    sec = None
    for line in text.splitlines():
        m = re.match(r"^\[(.+)\]", line)
        if m:
            sec = m.group(1).strip()
            continue
        if "=" not in line or line.strip().startswith(";"):
            continue
        k, v = line.split("=", 1)
        key = (sec, k.strip())
        if key not in entries:
            order.append(key)
        entries[key] = v.strip()
    return entries, order, has_bom


def is_chinese(value):
    return bool(re.search(r"[\u4e00-\u9fff]", value or ""))


off, off_order, off_bom = parse(OFFICIAL)
ship, ship_order, ship_bom = parse(SHIPPED)

# Project-specific overrides: entries where the shipped file has Chinese that
# the official file does not (or where the project deliberately rewrote the
# value).  These win over the official text.
overrides = {}
for key, value in ship.items():
    if key[0] not in ("Messages", "CustomMessages"):
        continue
    official_value = off.get(key)
    if is_chinese(value) and not is_chinese(official_value or ""):
        overrides[key] = value

print(f"official entries: {len(off)}")
print(f"shipped entries : {len(ship)}")
print(f"project overrides kept: {len(overrides)}")
for key in sorted(overrides):
    print(f"  {key[0]}/{key[1]} = {overrides[key][:80]}")

merged = dict(off)
merged.update(overrides)

# Write the merged file using the official file's layout so comments and
# section ordering stay intact, substituting values from the merge map.
raw = open(OFFICIAL, "rb").read()
official_text = raw.decode("utf-8-sig")
out_lines = []
sec = None
for line in official_text.splitlines():
    m = re.match(r"^\[(.+)\]", line)
    if m:
        sec = m.group(1).strip()
        out_lines.append(line)
        continue
    if "=" not in line or line.strip().startswith(";"):
        out_lines.append(line)
        continue
    k, v = line.split("=", 1)
    key = (sec, k.strip())
    if key in merged:
        out_lines.append(f"{k.strip()}={merged[key]}")
    else:
        out_lines.append(line)

# Keep any project-only sections/entries that the official file lacks.
extra = [k for k in ship if k not in off]
if extra:
    print(f"project-only entries: {len(extra)} -> appended")
    out_lines.append("")
    out_lines.append("; ==== project-specific additions ====")
    for key in extra:
        out_lines.append(f"{key[1]}={ship[key]}")

body = "\r\n".join(out_lines) + "\r\n"
data = b"\xef\xbb\xbf" + body.encode("utf-8")
open(SHIPPED, "wb").write(data)
print(f"written: {SHIPPED} ({len(data)} bytes)")

# Verify
new_entries, new_order, new_bom = parse(SHIPPED)
eng = sum(1 for (s, k), v in new_entries.items()
          if s == "Messages" and not is_chinese(v) and re.search(r"[A-Za-z]", v))
zh = sum(1 for (s, k), v in new_entries.items()
         if s == "Messages" and is_chinese(v))
print(f"after merge -> Messages Chinese={zh} English={eng}")
