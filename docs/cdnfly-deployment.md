# CDNfly 部署说明

NovaProtect 官网是纯静态站点：只有 HTML、CSS、JS 和一份 JSON，没有 PHP、没有数据库、没有
后台。当前网站版本为 `2.3.0`，发布只生成一个包：
`artifacts/website/2.3.0/NovaProtect-Website-2.3.0-Linux-x64-BaoTa.zip`。

升级不需要单独的增量包：解压新版本包，再以 root 执行 `bash install.sh` 即可，旧槽位保留为
`previous` 供回滚。可先运行 `bash install.sh --check-package` 只读校验包布局与 SHA-256（不需要
root，也不改动系统）。

安装脚本从自身位置解析包根目录，因此可以从任意当前工作目录调用。它放文件、从现有 vhost 继承
listen/TLS/日志指令、原子切换 `current`/`previous`、`nginx -t` 后重载，最后逐页验证返回 200。

## CDNfly 规则

- 源站回源可使用 HTTP，静态文件不区分协议；
- 使用 `website/deploy/cdnfly-edge-policy.json` 作为控制台映射，先创建最高优先级的 `page-html`
  规则，覆盖 `/`、`/download`、`/client-updates`、`/sdk`、`/privacy`、`/404.html`；
- 页面规则关闭 JS/CC/Bot 验证和边缘缓存；CSS、JS、图片与图标走 `site-assets` 规则（挑战关闭、
  缓存遵循源站）；`/data/` 的更新日志走 `release-feed`，缓存遵循源站的短 max-age；
- 未匹配路径必须回源，让源站的 `404.html` 生效，不要让边缘把它改写成验证页；
- 修改规则后清理全站旧缓存，包括 HTML 和人机验证对象；

## 预检

```bash
bash deploy/cdnfly-check.sh https://nova.fbi.plus
```

预检会在边缘侧请求首页、`/download`、`/client-updates`、`/sdk`、`/data/releases.json`、
CSS/JS/图片/图标，以及一个**必须不存在**的路径。判定标准：

- 已存在的页面和资源必须返回 `200`；
- 必须不存在的路径必须返回 `404`（说明边缘没有把它改写）；
- 任何响应返回 `444`、或 body 里出现 `/_guard/auto.js`、`human verification`、
  `javascript challenge`，都视为被边缘拦截，直接失败。

后台相关路径（`/admin`、`/install`、`/api/admin/release/*`、`/health`）已经不是"锁定"而是
**不存在**，因此不再单独探测；它们和任何未知路径一样返回 404。

## 与旧版本的差异

`2.2.x` 的站点是 PHP 应用：需要 PHP 8.4 + PHP-FPM、管理员口令、一次性安装口令、分片上传
接口和离线升级执行器。这些在 `2.3.0` 全部移除，归档在
`artifacts/website-backend-legacy-2.2.31/`，不再参与部署。客户端更新本来就直连 GitHub
Releases，因此移除后台不影响更新链路。
