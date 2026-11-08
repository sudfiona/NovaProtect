# NovaProtect 静态官网部署

站点是纯静态文件：没有 PHP、没有数据库、没有后台、没有登录入口。`public/` 就是文档根目录，
`install.sh` 负责放文件、切槽位、写 Nginx 配置并验证页面能打开。

## 首次安装

```bash
unzip NovaProtect-Website-<version>-Linux-x64-BaoTa-Full.zip -d novaprotect-site
cd novaprotect-site
bash install.sh --check-package     # 只读校验包完整性，不需要 root
sudo bash install.sh                # 正式安装
```

安装过程：

1. 校验 `SHA256SUMS`：清单里每个文件的摘要都要对得上，且包内**每个**文件都要被清单覆盖（漏项即失败）。
   `SHA256SUMS` 自身不在清单里——文件装不下自己的摘要，它由 ZIP 旁边的 `<包名>.zip.sha256` 锚定。
   校验失败时会逐个列出未列入清单的文件名，以及清单里列出但包内不存在的文件名。
2. 备份现有槽位链接与 Nginx 站点配置到 `/www/server/<domain>/backups/<时间戳>/`。
3. 把 `public/` 释放到 `/www/wwwroot/<domain>/releases/<version>-<时间戳>/`。
4. 从**现有** vhost 里继承 `listen`/`ssl_*` 指令，写入静态配置，不自己造证书配置。
   没有检测到 TLS 时只监听 80 并在结束时提示去面板申请证书。
5. 切换 `current` 软链，`nginx -t` 后重载。
6. 跑健康检查：逐页 200、版本号出现在首页、缺失路径必须返回 404。

域名默认 `nova.fbi.plus`，可用 `NOVAPROTECT_DOMAIN=example.com sudo bash install.sh` 覆盖。

## 目录约定

```
/www/wwwroot/<domain>/
  releases/<version>-<stamp>/public/...   # 不可变发布槽位
  current  -> releases/<version>-<stamp>  # 当前生效
  previous -> releases/<version>-<stamp>  # 回滚目标
/www/server/<domain>/
  backups/<stamp>/                        # 上次安装前的槽位链接与 vhost
  diagnostics/                            # 健康检查输出
  deploy.lock                             # 安装/回滚互斥
```

## 更新

静态站没有"一键升级"，也不需要：解压新版本包，再跑一次 `install.sh` 即可。旧槽位保留为
`previous`，随时可回滚。

```bash
unzip NovaProtect-Website-<new-version>-...-Full.zip -d nova-new
cd nova-new && sudo bash install.sh
```

## 回滚

```bash
sudo bash deploy/rollback.sh
```

只恢复槽位链接和 Nginx 配置，然后跑健康检查确认页面能打开。可回滚的槽位必须存在
`public/index.html`（静态发布物的识别标志）。

## 健康检查

```bash
bash deploy/health-check.sh <version> /tmp/np-diag
```

检查项：`/`、`/download`、`/client-updates`、`/sdk`、`/privacy`、`/data/releases.json`、
`/css/site.css`、`/js/site.js`、`/assets/novaprotect.png`、`/favicon.ico` 全部 200；
首页必须出现 `网站版本 <version>`；不存在的路径必须返回 404 而不是目录列表或验证页。

## CDNfly

规则文件 `cdnfly-edge-policy.json`，控制台步骤见 `CDNFLY.md`。站点没有会话，因此边缘规则
只需保证"页面和资源不被挑战页替换、不被错误缓存"。应用规则后清理全站缓存，再跑：

```bash
bash deploy/cdnfly-check.sh https://nova.fbi.plus
```

## 内容更新

页面内容直接改 `public/*.html`。更新日志来自 `public/data/releases.json`：

- 页面里已经烘焙了一份，禁用 JavaScript 也能看；
- `js/site.js` 会 fetch 这个 JSON 并重绘列表，所以只改 JSON 就能刷新更新日志；
- 发布新版本时重新生成这个 JSON（仓库里 `website/tools/fetch-releases.mjs` 从 GitHub Releases 抓）。

## 为什么没有后台

客户端更新走 GitHub Releases（`UpdateClient` 直接请求 `api.github.com`），下载链接指向
GitHub。站点只承担说明页与更新日志，因此任何"上传发布包 / 管理员口令 / 升级执行器"的能力
都不再需要，删掉它们是缩小攻击面，不是功能缺失。
