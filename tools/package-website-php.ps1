# Packages the PHP static site into artifacts/website-release/.
#
#   .\tools\package-website-php.ps1 [-SkipBake]
#
# Steps: lint every PHP file → bake data/releases.json from GitHub →
# copy public/ + lib/ into a clean release directory with a deploy README.
# The release directory is self-contained: point the web root at its public/.
[CmdletBinding()]
param(
    [switch]$SkipBake
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$website = Join-Path $root 'website'
$target = Join-Path $root 'artifacts\website-release'

function Invoke-Php {
    param([string[]]$PhpArgs)
    $phpExe = (Get-Command php -ErrorAction Stop).Source
    $phpDir = Split-Path -Parent $phpExe
    $extDir = Join-Path $phpDir 'ext'
    $loaded = & $phpExe -r 'echo extension_loaded("openssl") ? "1" : "0";' 2>$null
    $extra = @()
    if ($loaded -ne '1' -and (Test-Path (Join-Path $extDir 'php_openssl.dll'))) {
        $extra = @("-d", "extension_dir=$extDir", "-d", "extension=php_openssl.dll")
    }
    & $phpExe @extra @PhpArgs
    if ($LASTEXITCODE -ne 0) { throw "php failed: $($PhpArgs -join ' ') (exit $LASTEXITCODE)" }
}

Write-Host '[package] lint PHP sources'
$phpFiles = Get-ChildItem -Path (Join-Path $website 'public'), (Join-Path $website 'lib') -Recurse -Filter '*.php' -File
foreach ($file in $phpFiles) {
    Invoke-Php @('-l', $file.FullName) | Out-Null
    Write-Host "  ok  $($file.Name)"
}

if (-not $SkipBake) {
    Write-Host '[package] bake releases.json from GitHub'
    Invoke-Php @(Join-Path $root 'tools\website-build\bake-releases.php')
} else {
    Write-Host '[package] skip bake (-SkipBake)'
}

# The tag contract is what keeps the site and the desktop updater agreeing on a
# GitHub tag like `3.2.5-beta`; a package must not ship if either side would
# drop that release.
Write-Host '[package] releases contract test'
Invoke-Php @(Join-Path $root 'tests\releases_parse_test.php') | Out-Null
Write-Host '  ok  releases_parse_test'

Write-Host "[package] assemble $target"
if (Test-Path $target) { Remove-Item $target -Recurse -Force }
New-Item -ItemType Directory -Path $target -Force | Out-Null
Copy-Item -Path (Join-Path $website 'public') -Destination $target -Recurse
Copy-Item -Path (Join-Path $website 'lib') -Destination $target -Recurse

# The runtime cache is server state, not content: a snapshot taken now would be
# served as "fresh" by the deployment and hide the release published a minute
# later. The first request rebuilds it.
$packagedCache = Join-Path $target 'public\data\cache'
if (Test-Path -LiteralPath $packagedCache) {
    Remove-Item -LiteralPath $packagedCache -Recurse -Force
    Write-Host '[package] dropped the runtime release cache (rebuilt on first request)'
}

$readme = @'
# NovaProtect 官网发布包（PHP 静态站）

PHP 官网无需数据库或账户。页面在服务端渲染，手动切换语言后用 Cookie 记住选择；
客户端版本与更新日志自动同步自 GitHub Releases（服务端一分钟缓存，用 ETag
条件请求复验，未变更时 GitHub 回 304 不占配额；失败时回退到
`public/data/releases.json` 快照）。

## 结构

    public/    Web 文档根目录（把站点根指向这里）
    lib/       布局与 Releases 同步（被 public 下的页面 require，不要对外直接暴露为可下载路径以外的用途）

## 要求

- PHP 8.1+（php-fpm / 宝塔默认即可），`json` 扩展
- 联网同步需要 `allow_url_fopen=On` 与 `openssl` 扩展（缺失时自动回退快照，站点仍可用）
- `public/data/cache/` 可写（存放版本缓存与 ETag；不可写时每次请求回退快照）
- 可选：环境变量 `NP_RELEASES_TTL`（秒，默认 60）调整复验间隔，
  `NP_GITHUB_TOKEN`（只读公共数据即可）把接口配额从 60 次/小时提到 5000 次/小时

## 部署

完整解压发布包，保留 `public/` 与 `lib/` 同级，将站点的文档根目录指向 `public/`。
页面使用目录索引（`/download/` → `download/index.php`），nginx / 宝塔默认
`index` 指令即可命中，**不需要伪静态规则**。

可选：404 走自定义页

    error_page 404 /404.php;

## 版本同步

- 运行时：`lib/releases.php` 每分钟用 `If-None-Match` 复验一次 GitHub API；
  Release 未变更时是 304（不计配额），变更后下次访问即刷新。
- 版本号来自 tag 的数字核心：`3.2.5`、`v3.2.5`、`3.2.5-beta`、`3.2.5-rc.1`
  都按 `3.2.5` 排序与比对，`-beta` 这类后缀只作显示与「预发布」标记。
- 打包时：`tools/website-build/bake-releases.php` 刷新快照，并删除随包的运行时缓存。
- 页面不显示任何"网站版本"；所有版本号均为 GitHub 上的客户端 Release。

## 更新内容

改页面 → 编辑源仓库 `website/public/*.php` 后重新执行
`tools\package-website-php.ps1`，再同步本目录。
'@
Set-Content -Path (Join-Path $target 'README.md') -Value $readme -Encoding UTF8

$count = (Get-ChildItem $target -Recurse -File | Measure-Object).Count
$size = [math]::Round(((Get-ChildItem $target -Recurse -File | Measure-Object Length -Sum).Sum / 1KB), 1)
Write-Host "[package] done: $target ($count files, $size KB)"
