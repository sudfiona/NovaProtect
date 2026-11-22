# NovaProtect 官网（纯静态 PHP）

站点是**纯静态 PHP 系统**：页面在服务端用 PHP 模板渲染，没有数据库、没有后台、
没有登录入口、不设置 Cookie。UI 为 HyperOS 风格柔光玻璃设计，默认白色主题。

**不显示任何"网站版本"**——页面上出现的每个版本号都是 GitHub Releases 上的客户端版本，
由服务端自动同步（默认 5 分钟缓存，可用环境变量 `NP_RELEASES_TTL` 覆盖；失败回退到
打包时的快照，页面永不空白）。

## 目录

| 路径 | 说明 |
| --- | --- |
| `public/` | 文档根目录（部署时站点根指向这里） |
| `public/index.php` | 首页：Hero、能力总览、五步流程、产品构成 |
| `public/features/` | 功能详解：客户端全部页面、参数与约束（带侧边目录） |
| `public/download/` | 下载：最新版本、SHA-256、直链与近期版本 |
| `public/sdk/` | SDK 文档：宏 API、字节模式、VM 约束、汇编示例 |
| `public/client-updates/` | 更新日志：GitHub Releases 全量列表 |
| `public/privacy/` | 隐私说明 |
| `public/data/releases.json` | 打包时烘焙的版本快照（离线回退数据源） |
| `public/data/cache/` | 运行时 GitHub 同步缓存（需可写） |
| `lib/layout.php` | HTML 骨架（导航 / 页脚 / 转义与工具函数） |
| `lib/releases.php` | GitHub Releases 同步（实时 → 缓存 → 快照） |

## 要求

- PHP 8.1+（宝塔 / php-fpm 默认即可），`json` 扩展
- 实时同步需要 `allow_url_fopen=On` 与 `openssl` 扩展；缺失时自动回退快照，站点仍完整可用
- `public/data/cache/` 可写

## 打包

```powershell
.\tools\package-website-php.ps1          # 语法检查 + 烘焙 GitHub 数据 + 组装
.\tools\package-website-php.ps1 -SkipBake  # 跳过联网烘焙
```

产物：`artifacts/website-release/`（自包含发布目录，内含部署 README）。

只更新版本快照：

```powershell
php tools\website-build\bake-releases.php
# 本地 CLI 若未加载 openssl：
php -d extension_dir=<php>\ext -d extension=php_openssl.dll tools\website-build\bake-releases.php
```

## 部署

把 `artifacts/website-release/public/` 的内容放到网站根目录（或整包上传后将站点根
指向 `public/`）。页面使用目录索引（`/download/` → `download/index.php`），
nginx / 宝塔默认 `index` 指令即可命中，**不需要伪静态规则**。

可选：自定义 404

```nginx
error_page 404 /404.php;
```

## 版本同步

- **运行时**：`lib/releases.php` 每 **5 分钟**最多实时请求一次
  `api.github.com/repos/sudfiona/NovaProtect/releases`，写入 `public/data/cache/`。
  缓存过期后下一次打开页面立刻拉 GitHub；新发版无需等一小时。
  可用环境变量 `NP_RELEASES_TTL`（秒，15–86400）调整，例如 `NP_RELEASES_TTL=60`。
- **HTTP 缓存**：页面响应带 `Cache-Control: no-cache, no-store, must-revalidate`，
  浏览器与 CDN 不应缓存 HTML；若边缘仍缓存了页面，按 `deploy/CDNFLY.md` 清一次全站缓存。
- **打包时**：`tools/website-build/bake-releases.php` 刷新 `data/releases.json` 快照。
- 下载直链取自 Release 附件（`browser_download_url`），SHA-256 取自 GitHub 附件
  `digest` 字段——与桌面客户端更新器同源，页面不另存版本元数据。

## 更新内容

改页面：编辑 `website/public/*.php`（HTML 结构写在 PHP 模板里，动态值一律 `np_e()` 转义），
改样式编辑 `website/public/css/site.css`，然后重新执行打包脚本并同步产物目录。

## 历史说明

- 旧的纯静态 HTML 站与更早的 PHP 后台（发布包上传、管理员口令、离线升级执行器）
  均已移除；`app/` 与 `deploy/` 中的旧后端脚本不再被新站引用。
- `tools/package-website.ps1` / `package-website-upload.ps1` 打包的是旧静态站结构，
  已不适用；新站统一用 `package-website-php.ps1`。
- 客户端更新走 GitHub（`ui/Services/UpdateClient.cs` 直连 `api.github.com` 并按素材
  `digest` 校验），官网不托管二进制。
