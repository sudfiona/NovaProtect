# NovaProtect 官网（纯静态）

站点只有 HTML、CSS、JS 和一份 JSON，没有 PHP、没有数据库、没有后台、没有登录入口。
当前网站版本 `2.3.0`。

之前那套 PHP 后台（发布包上传、管理员口令、离线升级执行器、安装向导）已整体移除，归档在
`artifacts/website-backend-legacy-2.2.31/`，不再参与部署。

## 目录

| 路径 | 说明 |
| --- | --- |
| `public/` | 文档根目录。`index` `download` `client-updates` `sdk` `privacy` `404` 六个页面 |
| `public/data/releases.json` | 更新日志数据源，页面烘焙了一份，`js/site.js` 也会读它 |
| `public/js/site.js` | 唯一脚本：从 JSON 重绘更新日志与版本号，失败就保留烘焙内容 |
| `deploy/` | 宝塔部署脚本与 Nginx 片段 |
| `install.sh` | 包入口，转交 `deploy/install.sh` |
| `release.json` | 构建元数据（客户端版本、安装包名、校验值） |
| `github.json` | Releases 仓库名 |

## 打包

站点有两个产物，按部署方式选一个。

### 一、上传就能开（不需要脚本）

```powershell
.\tools\package-website-upload.ps1 -Force
```

产物：`artifacts/website/<version>/NovaProtect-Website-<version>-static-upload.zip`

解压到网站根目录即可，**不需要 nginx 配置、不需要 root、不需要重启服务**。

之所以能零配置，是因为页面被摆成了目录索引：

```
index.html                   /
404.html
download/index.html          /download
client-updates/index.html    /client-updates
privacy/index.html           /privacy
sdk/index.html               /sdk
assets/ css/ js/ data/ favicon.ico
```

导航链接是 `/download` 这种无扩展名路径。直接上传 `download.html` 的话，默认服务器会 404，
必须先配 `try_files $uri.html`。改成 `download/index.html` 后，所有 nginx 与 Apache 默认的
`index` 指令就能命中，一个配置都不用写。

页面内所有引用都是绝对路径（`/css/site.css` 这类），所以整棵树必须放在网站根目录，
不要套一层子目录。

这个包里没有 `install.sh`、`deploy/`、`package.json`、`release.json`、`SHA256SUMS`——
它们是为「用脚本部署 + 校验包」服务的，手动上传的目录没有安装器要向谁交代。

#### 宝塔 / nginx 要不要配伪静态

**不需要。** 目录索引是 nginx 与 Apache 的默认行为，四个带目录的路径都能直接命中：

- nginx：`index` 指令（宝塔 vhost 默认含 `index index.php index.html index.htm`）
- Apache：`DirectoryIndex`

默认行为有一个细节：请求 `/download`（无斜杠）时，服务器会先回 301 到 `/download/`，
再返回里面的 `index.html`。浏览器会自动跟随，页面正常打开，只是地址栏会多一个斜杠。

想让它**不跳 301、直接 200**，在宝塔「网站 → 设置 → 伪静态」里贴：

```nginx
location / {
    try_files $uri $uri/index.html $uri/ =404;
}

error_page 404 /404.html;
```

`try_files` 把 `/download` 内部改写成 `download/index.html`，省掉那次跳转；`error_page`
让 404 走包里自带的页面。两行都是可选的——不配也能正常访问所有页面，只是地址栏带斜杠、
错误页用服务器默认的。

不要写成 `try_files $uri $uri.html $uri/ =404;`——这个包里没有 `download.html`，
那个写法是为脚本部署包准备的。

### 二、脚本部署（槽位切换 + 回滚）

```powershell
.\tools\package-website.ps1 -Force
```

产物：`artifacts/website/<version>/NovaProtect-Website-<version>-Linux-x64-BaoTa.zip`
及其旁挂校验值 `…zip.sha256`。

只有一个包。旧的 Full/Upgrade 双包区分是为 PHP 差分升级服务的，静态站直接重跑安装即可升级，
第二个产物只会多一个需要同步的东西。

打包时会自动校验：清单覆盖全部文件且哈希一致、没有 PHP/可执行文件、脚本是 LF、页面里没有
未替换的占位符和后端链接、页面引用的每个地址在包内都存在。

关于 `SHA256SUMS` 的覆盖范围：它列出包内除自己以外的每一个文件，行数必须正好等于
「条目数 - 1」。文件无法包含自己的摘要，所以 `SHA256SUMS` 自身由 ZIP 旁的 `.sha256` 锚定；
部署前建议先核对这一行：

```bash
sha256sum -c NovaProtect-Website-<version>-Linux-x64-BaoTa.zip.sha256
```

## 部署

**上传版**（`…-static-upload.zip`）：解压后把里面的东西全部丢进网站根目录，比如宝塔的
`/www/wwwroot/<域名>/`。打开域名就能看，不用执行任何脚本。

```bash
unzip NovaProtect-Website-<version>-static-upload.zip -d /www/wwwroot/example.com
```

**脚本版**（`…-Linux-x64-BaoTa.zip`）：

```bash
unzip NovaProtect-Website-<version>-Linux-x64-BaoTa.zip -d novaprotect-site
cd novaprotect-site
bash install.sh --check-package
sudo bash install.sh
```

细节见 `deploy/README.md`。要点：安装脚本不装 PHP、不建服务、不生成口令；它放文件、切
`current`/`previous` 槽位、从现有 vhost 继承 TLS 配置、重载 Nginx，然后逐页验证返回 200。

## 更新内容

**改页面**：直接编辑 `public/*.html`，重新打包部署。HTML 就是源文件，没有模板层。

**改更新日志**：编辑 `public/data/releases.json`（版本、日期、说明、链接），重新打包。
也可以用 `tools/website-build/fetch-releases.mjs` 从 GitHub Releases 重新抓一份：

```powershell
node tools\website-build\fetch-releases.mjs
```

页面里烘焙的内容保证禁用 JS 也能读；`site.js` 只是让 JSON 改动在下次部署后立刻反映出来。

**发新版客户端**：客户端从 GitHub Releases 取版本与摘要，本站只显示"最新发布是哪个"。所以
先在 GitHub 发布，再刷新 `releases.json` 并重新打包，页面上的版本号才会跟着走。

## 为什么没有后台

客户端更新走 GitHub（`ui/Services/UpdateClient.cs` 直接请求 `api.github.com`，并按素材
`digest` 校验下载内容），下载也指向 GitHub。既然站点不再托管二进制、不再分发版本元数据，
后台就没有存在的理由——删掉它去掉的是攻击面和维护量，不是功能。
