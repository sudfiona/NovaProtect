# -*- coding: utf-8 -*-
from pathlib import Path

p = Path(r"D:\工作区\NovaProtect\NovaProtect-main\website\lib\layout.php")
t = p.read_text(encoding="utf-8")

needle = "<script>\n/* Set theme before first paint"
if "js/vendor/motion.js" not in t:
    if needle in t:
        t = t.replace(
            needle,
            '<script src="/js/vendor/motion.js"></script>\n<script>\n/* Set theme before first paint',
            1,
        )
        print("inserted motion src")
    else:
        print("needle missing, trying alt")
        t = t.replace(
            "<script>",
            '<script src="/js/vendor/motion.js"></script>\n<script>',
            1,
        )
        print("inserted at first script")
else:
    print("already present")

t = t.replace(" ?> 路 NovaProtect", " ?> · NovaProtect")
p.write_bytes(t.encode("utf-8"))
print("has motion", "js/vendor/motion.js" in t)
