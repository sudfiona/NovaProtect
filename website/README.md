# NovaProtect 官网（纯静态 PHP）

站点是**纯静态 PHP 系统**：页面在服务端用 PHP 模板渲染，没有数据库、没有后台、
没有登录入口、不设置 Cookie。UI 为 HyperOS 风格柔光玻璃设计，默认白色主题。

**不显示任何"网站版本"**——页面上出现的每个版本号都是 GitHub Releases 上的客户端版本，
由服务端自动同步（默认 1 分钟复验，可用环境变量 `NP_RELEASES_TTL` 覆盖；失败回退到
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
| `public/data/cache/` | 运行时 GitHub 同步缓存（需可写；**不随包发布**，首次访问自动建立） |
| `lib/layout.php` | HTML 骨架（导航 / 页脚 / 转义与工具函数） |
| `lib/releases.php` | GitHub Releases 同步（实时 → 缓存 → 快照）与 tag 解析 |

## 要求

- PHP 8.1+（宝塔 / php-fpm 默认即可），`json` 扩展
- 实时同步需要 `allow_url_fopen=On` 与 `openssl` 扩展；缺失时自动回退快照，站点仍完整可用
- `public/data/cache/` 可写（存放版本缓存与 ETag；不可写时每次请求都用快照）

## 版本号与 tag 规则（与客户端一致，勿单方面修改）

GitHub 上的 tag 是自由格式的，最新版本实际发布为 `3.2.5-beta`。站点和客户端
（`ui/Services/UpdateClient.cs`）遵循同一套规则：

1. 去掉一个前导 `v` / `V`，丢掉 `+build` 元数据；
2. 在第一个 `-` 处切成「数字核心」和「渠道后缀」；
3. 数字核心必须是 `MAJOR.MINOR.PATCH`，后缀必须匹配 `[0-9A-Za-z][0-9A-Za-z.-]*`；
4. **数字核心**用于排序、比较、安装包文件名与「当前版本」标记；
   **后缀**只用于显示（`v3.2.5-beta`）与「预发布」标记。

所以 `3.2.5`、`v3.2.5`、`3.2.5-beta`、`3.2.5-rc.1`、`3.2.5+build.7` 都会被当作
`3.2.5` 显示与比较；`nightly`、`3.2`、`3.2.5.1`、`3.2.5-`、`release-3.2.5` 会被拒绝。
仅收三段式数字曾导致 `3.2.5-beta` 被整条丢弃：更新日志停在 3.1.6，客户端更新检查
直接报「发布标签不是三段式版本号」，用户收不到新版本。

规则由 `tests/releases_parse_test.php` 固化，打包脚本会先跑它。

## 打包

```powershell
.\tools\package-website-php.ps1          # 语法检查 + 契约测试 + 烘焙 GitHub 数据 + 组装
.\tools\package-website-php.ps1 -SkipBake  # 跳过联网烘焙
```

产物：`artifacts/website-release/`（自包含发布目录，内含部署 README）。
组装时会删除 `public/data/cache/`：那是服务器状态，随包发出去会被部署端当成
「新鲜」缓存，反而盖住一分钟后才发布的版本。

只更新版本快照：

```powershell
php tools\website-build\bake-releases.php
# 本地 CLI 若未加载 openssl：
php -d extension_dir=<php>\ext -d extension=php_openssl.dll tools\website-build\bake-releases.php
```

只跑契约测试：

```powershell
php tests\releases_parse_test.php
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

- **运行时**：`lib/releases.php` 每 **1 分钟**用 `If-None-Match` 复验一次
  `api.github.com/repos/sudfiona/NovaProtect/releases`，写入 `public/data/cache/`。
  Release 未变更时 GitHub 回 **304**（不消耗配额），变更后下一次访问立刻拿到新版本；
  因此 1 分钟的间隔不会打爆未认证的 60 次/小时上限。
  环境变量 `NP_RELEASES_TTL`（秒，15–86400）可调；
  `NP_GITHUB_TOKEN`（只读公共数据即可）把配额提到 5000 次/小时。
- **失败退避**：取不到数据时（离线、限流、缺 openssl）60 秒内不再重试，避免每次
  访问都打一次注定失败的请求；这期间用陈旧缓存或快照。
- **HTTP 缓存**：页面响应带 `Cache-Control: no-cache, no-store, must-revalidate`，
  浏览器与 CDN 不应缓存 HTML；若边缘仍缓存了页面，按 `deploy/CDNFLY.md` 清一次全站缓存。
- **打包时**：`tools/website-build/bake-releases.php` 刷新 `data/releases.json` 快照。
- 下载直链取自 Release 附件（`browser_download_url`），SHA-256 取自 GitHub 附件
  `digest` 字段——与桌面客户端更新器同源，页面不另存版本元数据。

## 更新内容

改页面：编辑 `website/public/*.php`（HTML 结构写在 PHP 模板里，动态值一律 `np_e()` 转义），
改样式编辑 `website/public/css/site.css`，然后重新执行打包脚本并同步产物目录。
页面文案是中文原文即键，改中文时记得同步 `lib/i18n-en.php` 里的键与英文。

## 历史说明

- 旧的纯静态 HTML 站与更早的 PHP 后台（发布包上传、管理员口令、离线升级执行器）
  均已移除；`app/` 与 `deploy/` 中的旧后端脚本不再被新站引用。
- `tools/package-website.ps1` / `package-website-upload.ps1` 打包的是旧静态站结构，
  已不适用；新站统一用 `package-website-php.ps1`。
- 客户端更新走 GitHub（`ui/Services/UpdateClient.cs` 直连 `api.github.com` 并按素材
  `digest` 校验），官网不托管二进制。
