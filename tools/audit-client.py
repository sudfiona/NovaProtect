# -*- coding: utf-8 -*-
"""Client 0-BUG / 0-VULN audit (WinUI sources)."""
from pathlib import Path
import re

UI = Path(r"D:\工作区\NovaProtect\NovaProtect-main\ui")
findings = []

def hit(sev, loc, msg):
    findings.append((sev, str(loc), msg))

# --- C# sources ---
for p in UI.rglob("*.cs"):
    if "obj" in p.parts or "bin" in p.parts:
        continue
    t = p.read_text(encoding="utf-8", errors="replace")
    rel = p.relative_to(UI)

    # command injection via string args
    if re.search(r'ProcessStartInfo\s*\(\s*[^)]*\$', t) or re.search(r'Arguments\s*=\s*\$', t):
        hit("HIGH", rel, "ProcessStartInfo string interpolation")
    if re.search(r'Arguments\s*=\s*"', t) and "ArgumentList" not in t:
        hit("MED", rel, "raw Arguments string (check quoting)")

    # Process.Start of user path without validation
    for i, line in enumerate(t.splitlines(), 1):
        if "Process.Start" in line and ("_downloaded" in line or "path" in line.lower() or "Path" in line):
            if "UseShellExecute" in line:
                # check nearby sanitize
                window = "\n".join(t.splitlines()[max(0, i-15):i+2])
                if "GetFullPath" not in window and "Exists" not in window and "IndexOfAny" not in window:
                    hit("MED", f"{rel}:{i}", "Process.Start path without obvious validation")

    # empty catch without comment (review)
    for i, line in enumerate(t.splitlines(), 1):
        if re.search(r"catch\s*\{\s*\}", line) or re.search(r"catch\s*\([^)]*\)\s*\{\s*\}", line):
            hit("LOW", f"{rel}:{i}", "empty catch")

    # null deref risks: .Text = without ?. on named controls after partial init
    # (XAML names are generated - skip)

    # secrets
    if re.search(r'(password|api[_-]?key|secret|token)\s*=\s*"[^"]{8,}"', t, re.I):
        hit("HIGH", rel, "possible hardcoded secret")

    # temp path races: Path.Combine(temp, ...) without unique
    if re.search(r'GetTempPath|TEMP', t) and "GetRandomFileName" not in t and "Guid" not in t:
        hit("LOW", rel, "temp path without uniqueness (review)")

    # SQL
    if re.search(r"SELECT .*FROM|INSERT INTO|DELETE FROM", t, re.I):
        hit("MED", rel, "SQL in client (check parameterization)")

    # crypto weak
    if re.search(r"\bMD5\b|\bSHA1\b|DES\.|RC2\.", t):
        hit("MED", rel, "weak crypto")

# --- XAML ---
for p in UI.rglob("*.xaml"):
    if "obj" in p.parts or "bin" in p.parts:
        continue
    t = p.read_text(encoding="utf-8", errors="replace")
    rel = p.relative_to(UI)
    if "x:Double" in t:
        hit("MED", rel, "x:Double in resources")
    # missing closing tags
    if t.count("<Page") + t.count("<Window") + t.count("<UserControl") + t.count("<ResourceDictionary") > 0:
        if not re.search(r"</(Page|Window|UserControl|ResourceDictionary)>", t):
            hit("HIGH", rel, "missing root close")
    # handlers referenced
    handlers = re.findall(r'(?:Click|Toggled|SelectionChanged|TextChanged|Checked|ValueChanged)="([^"]+)"', t)
    cs = p.with_suffix(p.suffix + ".cs")
    if not cs.exists():
        cs = Path(str(p).replace(".xaml", ".xaml.cs"))
    if cs.exists():
        cst = cs.read_text(encoding="utf-8", errors="replace")
        for h in set(handlers):
            if h not in cst:
                hit("HIGH", f"{rel}", f"missing handler: {h}")

# --- resource keys used vs defined ---
used = set()
for p in UI.rglob("*.xaml"):
    if "obj" in p.parts or "bin" in p.parts:
        continue
    t = p.read_text(encoding="utf-8", errors="replace")
    used |= set(re.findall(r"\{(?:ThemeResource|StaticResource)\s+([^}]+)\}", t))

theme = (UI / "Styles" / "Theme.xaml").read_text(encoding="utf-8-sig")
defined = set(re.findall(r'x:Key="([^"]+)"', theme))

# runtime set by NovaTheme
runtime = {
    "NovaGlassCardBrush","NovaGlassCardBorderBrush","NovaPageBgBrush","NovaInkBrush","NovaInk2Brush",
    "NovaAccentBrush","NovaBadgeBrush","NovaBadgeBorderBrush","NovaBadgeSuccessBrush","NovaBadgeSuccessBorderBrush",
    "NovaBadgeMutedBrush","NovaBadgeMutedBorderBrush","NovaConsoleBrush","NovaConsoleTextBrush","NovaConsoleStrokeBrush",
    "NovaGlassInputBrush","NovaGlassInputBorderBrush","NovaTitleDividerBrush","NovaVeilBrush",
    "NovaThemeChipTrackBrush","NovaThemeChipOnBrush","NovaThemeChipOnFgBrush","NovaThemeChipOffFgBrush",
    "NovaThemeChipOffBgBrush","NovaThemeChipOffBorderBrush",
    "ControlFillColorDefaultBrush","ControlFillColorSecondaryBrush","ControlStrokeColorDefaultBrush",
    "CardBackgroundFillColorDefaultBrush","CardStrokeColorDefaultBrush","AccentFillColorDefaultBrush",
    "NovaAccentGradientBrush","NovaGradTextBrush","NovaCardCornerRadius","NovaButtonCornerRadius",
    "NovaGlassCardHoverBorderBrush",
    # WinUI system
    "TextFillColorPrimaryBrush","TextFillColorSecondaryBrush","TextFillColorTertiaryBrush",
    "AccentTextFillColorPrimaryBrush","DividerStrokeColorDefaultBrush",
    "SystemFillColorSuccessBackgroundBrush","SystemFillColorAttentionBackgroundBrush",
    "SystemFillColorCautionBackgroundBrush","SystemFillColorCriticalBackgroundBrush",
}
missing = sorted(k for k in used if k not in defined and k not in runtime)
if missing:
    hit("HIGH", "resources", f"missing keys: {missing[:20]}")

# NovaTheme parse safety
ns = (UI / "Services" / "NovaTheme.cs").read_text(encoding="utf-8-sig")
if "IsHex" not in ns:
    hit("MED", "NovaTheme.cs", "color parse without hex validation")
if "ArgumentNullException" not in ns and "root is null" not in ns:
    hit("LOW", "NovaTheme.cs", "no null root guard")

print("=== FINDINGS ===")
if not findings:
    print("NONE")
else:
    for sev, loc, msg in findings:
        print(f"[{sev}] {loc}: {msg}")
from collections import Counter
print(Counter(s for s, _, _ in findings))
