<div align="center">

# NovaProtect

Windows PE 代码保护工作台，提供项目管理、函数选择、构建记录和版本更新。

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Desktop version](https://img.shields.io/badge/desktop-3.2.7-orange)](VERSION)
[![Website version](https://img.shields.io/badge/website-2.3.0-blue)](website/VERSION)

[官网](https://nova.fbi.plus) · [GitHub Releases](https://github.com/sudfiona/NovaProtect/releases)

</div>

## 下载客户端

在 [GitHub Releases](https://github.com/sudfiona/NovaProtect/releases) 选择所需版本，下载对应的 `NovaProtect-Setup-<版本>.exe`。带 `-beta` 或 `-rc.1` 等后缀的标签表示预发布渠道。桌面客户端使用 WinUI 3 和 .NET 10，官网采用 PHP 8.1+，两者独立编号。

## 3.2.7 更新内容

3.2.7 对客户端界面进行了主题系统优化和多语言支持完善。

- **主题优化**：三套主题（玻璃、波普、实验室）的视觉效果更加一致，圆角、色温、材质等细节按主题正确应用。
- **语言切换**：完整的中英文界面切换支持，页面导航、设置、状态文字等全部国际化，不再出现混杂显示。
- **界面细节**：修复主题切换时的界面还原、导航栏显示、设置页跳转等交互问题，提升用户体验。

[查看完整变更记录](CHANGELOG.md)

## Releases 同步源码

| 文件 | 用途 |
| --- | --- |
| [UpdateClient.cs](ui/Services/UpdateClient.cs) | 桌面端版本检查、更新日志和安装包下载 |
| [releases.php](website/lib/releases.php) | 官网发布标签解析、同步缓存及离线回退 |
| [releases.json](website/public/data/releases.json) | 官网离线版本快照 |

在项目根目录运行同步回归测试。桌面测试使用 .NET 10 SDK，官网测试使用 PHP 8.1+ CLI。

```powershell
dotnet run --project tests/update-client-smoke/NovaProtect.UpdateSmoke.csproj
php tests/releases_parse_test.php
```

官网在线同步需要 PHP 启用 OpenSSL 和 `allow_url_fopen`。需要自定义缓存时间时，可设置 `NP_RELEASES_TTL`，单位为秒。

## 反馈与许可证

- 功能建议或普通问题可在 [GitHub Issues](https://github.com/sudfiona/NovaProtect/issues) 提交，附上版本号与复现步骤。
- 安全问题可经 [GitHub Security Advisories](https://github.com/sudfiona/NovaProtect/security/advisories) 私下报告。
- 项目源码遵循 [MIT 许可证](LICENSE)。第三方组件适用各自的许可条款。
