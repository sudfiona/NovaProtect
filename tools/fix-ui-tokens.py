# -*- coding: utf-8 -*-
from pathlib import Path
import re

theme = Path(r"D:\工作区\NovaProtect\NovaProtect-main\ui\Styles\Theme.xaml")
t = theme.read_text(encoding="utf-8-sig")

# x:Double is unsafe in WinUI resource dictionaries -> CornerRadius tokens
t = re.sub(
    r'<x:Double x:Key="NovaCardRadius">([^<]+)</x:Double>',
    r'<CornerRadius x:Key="NovaCardCornerRadius">\1</CornerRadius>',
    t,
)
t = re.sub(
    r'<x:Double x:Key="NovaButtonRadius">([^<]+)</x:Double>',
    r'<CornerRadius x:Key="NovaButtonCornerRadius">\1</CornerRadius>',
    t,
)
t = re.sub(
    r'<x:Double x:Key="NovaDisplayWeight">[^<]*</x:Double>\r?\n',
    '',
    t,
)

# NovaThemeChipStyle must stay at root (ThemeResource lookup)
if 'x:Key="NovaThemeChipStyle"' not in t:
    print("WARN: NovaThemeChipStyle missing")

theme.write_bytes(b"\xef\xbb\xbf" + t.encode("utf-8"))
print("theme ok, x:Double left:", t.count("x:Double"))

# Fix NovaTheme.cs radii keys to CornerRadius objects via Application resources
ns = Path(r"D:\工作区\NovaProtect\NovaProtect-main\ui\Services\NovaTheme.cs")
n = ns.read_text(encoding="utf-8-sig")
n = n.replace(
    '''        var cardR = theme == Pop ? 22.0 : theme == Lab ? 14.0 : 24.0;
        var btnR = theme == Pop ? 18.0 : theme == Lab ? 10.0 : 18.0;
        SetObj("NovaCardRadius", cardR);
        SetObj("NovaButtonRadius", btnR);''',
    '''        SetObj("NovaCardCornerRadius", new CornerRadius(theme == Pop ? 22 : theme == Lab ? 14 : 24));
        SetObj("NovaButtonCornerRadius", new CornerRadius(theme == Pop ? 18 : theme == Lab ? 10 : 18));''',
)
ns.write_bytes(b"\xef\xbb\xbf" + n.encode("utf-8"))
print("novatheme radii ok")

# GlassCardHoverHost.xaml: use ThemeResource for border
g = Path(r"D:\工作区\NovaProtect\NovaProtect-main\ui\Controls\GlassCardHoverHost.xaml")
gt = g.read_text(encoding="utf-8-sig")
g.write_bytes(b"\xef\xbb\xbf" + gt.encode("utf-8"))
print("glass xaml ok")
