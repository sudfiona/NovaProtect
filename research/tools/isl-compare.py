import re

official = r"C:\Inno Setup 7\Languages\ChineseSimplified.isl"
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
shipped = _np_repo_file('installer/ChineseSimplified.isl')
def parse(path):
    out = {}
    sec = None
    with open(path, "rb") as f:
        raw = f.read()
    has_bom = raw[:3] == b"\xef\xbb\xbf"
    text = raw.decode("utf-8-sig")
    for line in text.splitlines():
        m = re.match(r"^\[(.+)\]", line)
        if m:
            sec = m.group(1).strip()
            continue
        if "=" not in line or line.strip().startswith(";"):
            continue
        k, v = line.split("=", 1)
        out[(sec, k.strip())] = v.strip()
    return out, has_bom


o, ob = parse(official)
s, sb = parse(shipped)

print(f"official: {len(o)} entries, BOM={ob}")
print(f"shipped : {len(s)} entries, BOM={sb}")
print()

# The "Ready to Install" wizard page is what the user sees as 准备就绪.
ready_keys = [k for k in o if k[0] == "Messages" and (
    k[1].startswith("Ready") or k[1] in ("WizardReady",))]
print("=== 'Ready to Install' page messages ===")
for sec, k in sorted(ready_keys, key=lambda x: x[1]):
    ov = o.get((sec, k), "<absent>")
    sv = s.get((sec, k), "<absent>")
    flag = "SAME" if ov == sv else "DIFF"
    print(f"[{flag}] {k}")
    print(f"    official: {ov}")
    print(f"    shipped : {sv}")

print()
# How many Messages entries are still English in the shipped file?
import unicodedata

eng = 0
zh = 0
missing = 0
for (sec, k), ov in o.items():
    if sec != "Messages":
        continue
    sv = s.get((sec, k))
    if sv is None:
        missing += 1
        continue
    if re.search(r"[\u4e00-\u9fff]", sv):
        zh += 1
    else:
        eng += 1
print(f"shipped Messages entries: Chinese={zh}  English-or-other={eng}  missing={missing}")
print()
print("=== official file: sample of the Ready page in Chinese ===")
for k in ("WizardReady", "ReadyLabel1", "ReadyLabel2a", "ReadyMemoUserInfo", "ReadyMemoDir", "ReadyMemoType", "ReadyMemoComponents", "ReadyMemoGroup", "ReadyMemoTasks"):
    print(f"  {k} = {o.get(('Messages', k), '<absent>')}")
