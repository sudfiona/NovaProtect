# -*- coding: utf-8 -*-
"""Harden OpenUpdate_Click: only launch .exe under our temp updates tree."""
from pathlib import Path

p = Path(r"D:\工作区\NovaProtect\NovaProtect-main\ui\Pages\SettingsPage.xaml.cs")
t = p.read_text(encoding="utf-8-sig")

old = "            Process.Start(new ProcessStartInfo(_downloadedUpdatePath) { UseShellExecute = true });"
new = """            // Only launch installers we wrote under our private temp tree.
            var updatesRoot = Path.Combine(Path.GetTempPath(), "NovaProtect", "updates");
            var full = Path.GetFullPath(_downloadedUpdatePath);
            if (!full.StartsWith(Path.GetFullPath(updatesRoot), StringComparison.OrdinalIgnoreCase)
                || !full.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            {
                UpdateStatusBar.Severity = InfoBarSeverity.Error;
                UpdateStatusBar.Message = "安装包路径异常，已拒绝启动。";
                return;
            }
            Process.Start(new ProcessStartInfo(full) { UseShellExecute = true });"""

if old in t:
    t = t.replace(old, new, 1)
    p.write_bytes(b"\xef\xbb\xbf" + t.encode("utf-8"))
    print("hardened")
else:
    print("pattern not found")
    for i, line in enumerate(t.splitlines(), 1):
        if "Process.Start" in line:
            print(i, line.strip())
