# -*- coding: utf-8 -*-
"""Audit UI theme resources and page wiring for bugs."""
from collections import Counter
from pathlib import Path
import re

ROOT = Path(r"D:\工作区\NovaProtect\NovaProtect-main")

theme = (ROOT / "ui/Styles/Theme.xaml").read_text(encoding="utf-8-sig")
keys = re.findall(r'x:Key="([^"]+)"', theme)
c = Counter(keys)
print("dup x:Key (outside Light/Dark expected):")
for k, n in sorted(c.items(), key=lambda x: -x[1]):
    if n > 1:
        print(f"  {k}: {n}")

print("has NovaThemeChipStyle:", "NovaThemeChipStyle" in keys)
print("has NovaAccentGradientBrush:", "NovaAccentGradientBrush" in keys)
print("x:Double left:", theme.count("x:Double"))

# SettingsPage
sp = (ROOT / "ui/Pages/SettingsPage.xaml.cs").read_text(encoding="utf-8-sig")
print("\nSettingsPage usings:")
for line in sp.splitlines():
    if line.startswith("using "):
        print(" ", line)

# MainWindow
mw = (ROOT / "ui/MainWindow.xaml.cs").read_text(encoding="utf-8-sig")
print("\nMainWindow usings:")
for line in mw.splitlines():
    if line.startswith("using "):
        print(" ", line)

# check every ThemeResource / StaticResource key used in UI exists in Theme.xaml or NovaTheme.cs
used = set()
for p in (ROOT / "ui").rglob("*.xaml"):
    if "obj" in str(p) or "bin" in str(p):
        continue
    t = p.read_text(encoding="utf-8-sig")
    used |= set(re.findall(r'\{(?:ThemeResource|StaticResource)\s+([^}]+)\}', t))

defined = set(keys)
# NovaTheme sets these at runtime
runtime = {
    "NovaGlassCardBrush","NovaGlassCardBorderBrush","NovaPageBgBrush","NovaInkBrush","NovaInk2Brush",
    "NovaAccentBrush","NovaBadgeBrush","NovaBadgeBorderBrush","NovaBadgeSuccessBrush","NovaBadgeSuccessBorderBrush",
    "NovaBadgeMutedBrush","NovaBadgeMutedBorderBrush","NovaConsoleBrush","NovaConsoleTextBrush","NovaConsoleStrokeBrush",
    "NovaGlassInputBrush","NovaGlassInputBorderBrush","NovaTitleDividerBrush","NovaVeilBrush",
    "NovaThemeChipTrackBrush","NovaThemeChipOnBrush","NovaThemeChipOnFgBrush","NovaThemeChipOffFgBrush",
    "ControlFillColorDefaultBrush","ControlFillColorSecondaryBrush","ControlStrokeColorDefaultBrush",
    "CardBackgroundFillColorDefaultBrush","CardStrokeColorDefaultBrush","AccentFillColorDefaultBrush",
    "NovaAccentGradientBrush","NovaGradTextBrush","NovaCardCornerRadius","NovaButtonCornerRadius",
    "NovaGlassCardHoverBorderBrush",
}
missing = sorted(k for k in used if k not in defined and k not in runtime)
print("\npossibly missing resource keys:")
for k in missing:
    print(" ", k)
print("used", len(used), "defined", len(defined))
