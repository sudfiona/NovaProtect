# AGENTS.md — 设计决策（供后续 UI 改动遵循）

## 打包与图标 — 2026-11-22

- **客户端安装包只用 Inno Setup**（`installer/novaprotect.iss` + `tools/package-client-release.ps1`）。不要再引入 NSIS/MSIX 等其它安装器。
- **安装后图标以 `ui/Assets/NovaProtect.ico` 为准**，该 ico 必须从品牌主视觉 `ui/Assets/NovaProtect.png` 生成（多尺寸 PNG 帧）。改品牌图后：重生成 ico → `build.ps1 -WinUi` 重嵌 PE 资源 → 再 Inno 打包。
- 校验用 PE `RT_ICON` 哈希与源 ico 比对（`package-client-release.ps1` / `tools/verify-installed.ps1`）；**不要用 `ExtractAssociatedIcon` 判定新旧**——它对 PNG 压缩图标会解码错图。
- 安装器图标：`SetupIconFile` 与 `UninstallDisplayIcon` 均指向上述 ico / 安装后的 `NovaProtect.exe`。

## 主题体系（玻璃 / 波普 / 实验室）— 2026-11-22 重写

三主题以「B 冷雾·热浪·深空色温对撞 × C 时代切片质感」融合重写，取材质/结构精华、
剔除气刷铬、错版阴影、扫描线、全等宽字等噱头。**主题间必须一眼可辨**，差异同时体现在
色温、材质、圆角、字体、描边五个维度：

| 维度 | 玻璃（冷雾液态铬） | 波普（热浪海报） | 实验室（深空终端） |
| --- | --- | --- | --- |
| 色温 | 冰蓝薰衣草（冷雾，静） | 珊瑚/柠檬/品红（热浪，吼） | 黑紫+磷光绿/紫外（深空，肃） |
| 材质 | 半透霜玻璃、全息渐变 | 平涂色块、无渐变 | 暗紫玻璃、霓虹细线 |
| 圆角 | 22/12/10 软 | 2px 直角 | 2px 严格 |
| 字体 | Segoe UI Variable（人文细体） | Bahnschrift（粗黑体） | Cascadia Mono（数据等宽） |
| 描边 | 1px 冰霜渐变 | 2px 黑色描边 | 1px 发丝线 + 强调色辉光 |

### 机制约束（改主题时必须遵守）

- **画刷用原位变更**（`MutateBrushes` 改 Color/GradientStops，不换对象）：`StaticResource`
  引用在解析期抓死对象，换新对象会让 29+ 处冻结引用永不更新。
- **值类型 token**（圆角/字体/描边厚度）靠资源替换 + Apply 末尾的 RequestedTheme
  翻转刷新（ThemeResource 引用必须，Setter 内不得写死数值/字体）。
- 引用方一律 `{ThemeResource ...}`；除非是主题无关常量，禁止在页面 XAML 写死颜色、
  圆角、字体（状态语义色/预览色板除外）。
- 主题名（玻璃/波普/实验室）与官网三主题保持同名同义。
