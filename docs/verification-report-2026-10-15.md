# NovaProtect 2.1.3 PHP 官网与客户端交付验证报告

- 日期：2026-10-15（Asia/Shanghai）
- 工作区：`<repo>`
- 目标：清理旧官网生成物、完成 PHP 宝塔安装包、保留可验证的 NovaProtect 2.0.7 Windows 客户端。
- 状态：本地包/脚本/Nginx 配置验证通过；宝塔 Linux、PHP-FPM 和 CDNfly 公网验收待上传后执行。

## 1. 交付文件

| 文件 | 字节 | SHA-256 |
|---|---:|---|
| `artifacts/installer-2.0.7/NovaProtect-Setup-2.0.7.exe` | 92775797 | `D1FD3C3CFA053A1335C295B8380736BEABAE478D897A4D5D00F7123BE742E9D1` |
| `artifacts/NovaProtect-Website-2.1.3-Linux-x64-BaoTa.zip` | 92432487 | `16C1A2ADECD7A5E274BB63ED056D8B9D9506790CEA057EF6147DAA6F760B5169` |

网站包内客户端文件的 SHA-256 与 `website/release.json` 一致。网站版本为 `2.1.3`，客户端安装包版本保持 `2.0.7`，没有重命名或伪造客户端版本。

## 2. PHP 包结构（Observed）

- 入口：`public/index.php`；业务：`app/bootstrap.php`、`app/view.php`。
- 安装向导：`/install`，使用安装脚本生成的 24 小时一次性口令；成功后写入 `installation.json` 并锁定入口。
- API：`/health`、`/api/session`、`/api/auth/login`、`/api/auth/logout`、`/api/account/summary`、登录后客户端下载。
- 存储：生产数据固定在 `/www/server/novaprotect/data`，下载文件在 `/www/server/novaprotect/downloads`，升级不覆盖账户和会话密钥。
- ZIP 只包含 18 个应用/部署/客户端文件；验证脚本确认没有 ASP.NET 源码、DLL、私有账户、密钥、`.env`、`bin/obj` 或旧 service 文件。

## 3. 部署验证（Observed）

已通过：

```text
WEBSITE-ARCHIVE-OK (18 files; all hashes match; PHP-FPM package; no ASP.NET/source/private data; LF scripts)
8 个 BaoTa/Nginx 配置单元测试全部通过
PowerShell 打包/验证脚本解析通过
C# AccountClient smoke 编译通过，28 项离线协议与错误处理检查通过
```

安装脚本行为：

1. 检查 PHP 8.2+、JSON/session/OpenSSL、Python、宝塔 Nginx 和 PHP-FPM socket；
2. 校验 `SHA256SUMS`、`release.json` 和客户端安装包；
3. 备份原 Nginx、发布槽位、安装状态和旧 ASP.NET service；
4. 原子切换 `current` / `previous`，生成 PHP-FPM server block；
5. `nginx -t`、reload、访问 `/health` 与首次 `/install`；
6. 失败时恢复原发布、Nginx 和旧服务状态；不会创建新的 ASP.NET 应用 service。

## 4. 清理结果（Observed）

已删除可重建或已废弃内容：

- 旧 ASP.NET `website/Pages`、`Properties`、`Services`、`wwwroot`、旧 service 和 Python 缓存；
- 根目录 `output/`、旧 UI 诊断日志、空 stdout/stderr；
- 旧客户端图标临时物、PHP 包 staging 目录、测试 `bin/obj`；
- 156 MB 的 VMP 试验二进制、旧 PHP 重构快照和 `_lea_chk.cpp` 调试源文件。
- 旧回归语料中的 200 个生成 PE、复制的 SDK DLL、dump/日志，以及 tools 下编译出的调试探针；保留跨语言样例源代码和轻量 smoke 测试。

保留：`src`、`runtime`、`ui`、`include`、`installer`、`sdk`、`docs`、精简后的 `tests`、`evidence`、正式客户端、最终 VMP 运行库、私有签名材料和当前网站 ZIP。
清理计划副本：`evidence/cleanup-2.1.2/cleanup-plan.json`、`evidence/cleanup-2.1.3/cleanup-plan.json`。

## 5. 尚未在本地完成的部分

当前 Windows 工作区没有 PHP CLI、PHP-FPM、Linux 宝塔或 CDNfly 控制台，因此没有虚构 PHP 运行时成功。对公网 `https://nova.fbi.plus` 的实测显示 CDN 先返回 guard 页面；浏览器通过 guard 后 `/health` 和 `/install` 均落到 Nginx `404 Not Found`，说明服务器当前仍是回滚/旧站点配置，尚未部署本次 PHP 包。证据记录见 `evidence/live-site-2026-10-15.md`。

上传以下新包后在宝塔执行：

```bash
bash install.sh
```

随后浏览器打开 `https://nova.fbi.plus/install`，完成安装向导。验收命令：

```bash
curl -sS -D - -H 'Host: nova.fbi.plus' http://127.0.0.1/health
curl -sk -D - --resolve nova.fbi.plus:443:127.0.0.1 https://nova.fbi.plus/health
```

确认 `Healthy`、网站版本 `2.1.3`，并验证登录、`/api/session`、登录后下载和 CDNfly `no-store`/旁路缓存规则。
