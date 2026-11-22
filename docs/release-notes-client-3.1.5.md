# NovaProtect 客户端 3.1.5 更新日志

发布类型：客户端（桌面程序）· 版本 `3.1.5` · 2026-11-22

本文是面向使用者的更新说明，可直接作为 GitHub Release 正文使用。实现细节见
`CHANGELOG.md` 的 `## 3.1.5` 一节。

---

## 一句话概括

3.1.5 是纯客户端外观/交互修复：主题切换条不再呈椭圆，打开设置页也不会再把
当前主题强制改成「玻璃」。引擎与打包产物与 3.1.4 相同。

---

## 修复

| 问题 | 根因 | 结果 |
| --- | --- | --- |
| 主题按钮（玻璃/波普/实验室）轨道呈椭圆，不好看 | `ThemeSwitchBar` 外层写死 `CornerRadius="999"` | 改为按主题的圆角矩形 token：玻璃 12 / 波普 4 / 实验室 6，对齐官网 `.theme-switch` |
| 点开「设置」后主题自动变成玻璃特效 | `SettingsPage.xaml` 的 `SelectedIndex="0"` 在 `InitializeComponent()` 时触发 `SelectionChanged` → `NovaTheme.Apply(glass)` 并写入 `ui-theme.txt` | 去掉 XAML 默认选中；构造时用 `_syncingTheme` 只回填选择器、不 Apply；tag 与当前主题一致时 no-op |

## 验证

- WinUI 客户端 Release 构建：0 警告 / 0 错误
- 手动：切到波普或实验室 → 打开设置 → 主题与下拉框保持不变；主题条为圆角矩形

## 安装与升级

```
安装包    NovaProtect-Setup-3.1.5.exe
大小      61605438 字节
SHA-256   b8742f6ff3727714d481fe17326e81a9142badda5b9b9daaef161fb2f6465002

源码包    NovaProtect-3.1.5-source.zip（完整引擎 + 客户端 + 官网，MIT）
大小      460 个文件，约 7.5 MB
          哈希见 Release 资产列表（自包含文档不自引哈希）
```

- 覆盖安装即可升级，设置与项目文件保留
- 安装包未附带 Authenticode 签名，Windows 可能提示未知发布者，请以哈希核对为准
- 客户端更新直接从 GitHub Releases 检查与下载，不经过官网；下载后按摘要逐字节校验

## 已知边界

- 本版不含引擎/虚拟化改动；3.1.4 的覆盖率与已知边界原样有效
- 驱动加载验证边界见 3.1.4 说明
