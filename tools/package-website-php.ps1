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

Write-Host "[package] assemble $target"
if (Test-Path $target) { Remove-Item $target -Recurse -Force }
New-Item -ItemType Directory -Path $target -Force | Out-Null
Copy-Item -Path (Join-Path $website 'public') -Destination $target -Recurse
Copy-Item -Path (Join-Path $website 'lib') -Destination $target -Recurse

$readme = @'
# NovaProtect 官网发布包（PHP 静态站）

纯静态 PHP 系统：无数据库、无后台、无账户、无 Cookie。页面在服务端渲染，
客户端版本与更新日志自动同步自 GitHub Releases（1 小时服务端缓存，
失败时回退到 `public/data/releases.json` 快照）。

## 结构

    public/    Web 文档根目录（把站点根指向这里）
    lib/       布局与 Releases 同步（被 public 下的页面 require，不要对外直接暴露为可下载路径以外的用途）

## 要求

- PHP 8.1+（php-fpm / 宝塔默认即可），`json` 扩展
- 联网同步需要 `allow_url_fopen=On` 与 `openssl` 扩展（缺失时自动回退快照，站点仍可用）
- `public/data/cache/` 可写（存放 1 小时版本缓存；不可写时回退快照）

## 部署

把 `public/` 内容放到网站根目录（或整包放置后将站点根指向 `public/`）。
页面使用目录索引（`/download/` → `download/index.php`），nginx / 宝塔默认
`index` 指令即可命中，**不需要伪静态规则**。

可选：404 走自定义页

    error_page 404 /404.php;

## 版本同步

- 运行时：`lib/releases.php` 每小时最多实时请求一次 GitHub API。
- 打包时：`tools/website-build/bake-releases.php` 刷新快照。
- 页面不显示任何"网站版本"；所有版本号均为 GitHub 上的客户端 Release。

## 更新内容

改页面 → 编辑源仓库 `website/public/*.php` 后重新执行
`tools\package-website-php.ps1`，再同步本目录。
'@
Set-Content -Path (Join-Path $target 'README.md') -Value $readme -Encoding UTF8

$count = (Get-ChildItem $target -Recurse -File | Measure-Object).Count
$size = [math]::Round(((Get-ChildItem $target -Recurse -File | Measure-Object Length -Sum).Sum / 1KB), 1)
Write-Host "[package] done: $target ($count files, $size KB)"
