# Builds the "upload and it works" website archive.
#
# The deployment package (package-website.ps1) ships install.sh and expects a
# vhost with `try_files "$uri.html"` so that /download resolves to download.html.
# That is the right thing for slot-based deploys, but it means the site does not
# open if you simply drop the files into a webroot: every navigation link is an
# extension-less path and a default server answers 404.
#
# This script produces the no-configuration variant. Each page becomes a
# directory index:
#
#     index.html                /            -> index.html
#     download/index.html       /download    -> directory index
#     client-updates/index.html /client-updates
#     privacy/index.html        /privacy
#     sdk/index.html            /sdk
#     404.html
#     assets/ css/ js/ data/ favicon.ico
#
# Directory indexes are handled by every nginx and Apache default, so uploading
# the extracted tree into a webroot is enough: no rewrite rule, no script, no
# root, no service restart. All in-page references are absolute paths under the
# document root, so the same tree works at a domain root without edits.
#
# Not included on purpose: install.sh, deploy/, package.json, release.json,
# SHA256SUMS. Those exist to deploy and verify a package; a directory you upload
# by hand has no installer to explain itself to.

param(
    [string]$OutputPath,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = Split-Path -Parent $PSScriptRoot
$public = Join-Path $root 'website\public'
$versionFile = Join-Path $root 'website\VERSION'
$releaseFile = Join-Path $root 'website\release.json'

if (-not (Test-Path -LiteralPath $public)) { throw "Missing site source: $public" }
if (-not (Test-Path -LiteralPath $versionFile)) { throw "Missing $versionFile" }

$version = (Get-Content -LiteralPath $versionFile -Raw).Trim()
if ($version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+$') { throw "Invalid website VERSION: $version" }
if (-not (Test-Path -LiteralPath $releaseFile)) { throw "Missing $releaseFile" }
$release = Get-Content -LiteralPath $releaseFile -Raw | ConvertFrom-Json
if ([string]$release.websiteVersion -ne $version) {
    throw "release.json websiteVersion '$($release.websiteVersion)' does not match VERSION '$version'"
}

if (-not $OutputPath) {
    $OutputPath = Join-Path $root "artifacts\website\$version\NovaProtect-Website-$version-static-upload.zip"
}
$OutputPath = [IO.Path]::GetFullPath($OutputPath)
if ((Test-Path -LiteralPath $OutputPath) -and -not $Force) {
    throw "Output already exists: $OutputPath (pass -Force to overwrite)"
}

# Pages that get a directory-index treatment. index.html and 404.html are copied
# as-is; everything else listed here becomes <name>/index.html.
$pageDirs = @('download', 'client-updates', 'privacy', 'sdk')
$requiredPages = @('index.html', '404.html') + ($pageDirs | ForEach-Object { "$_.html" })
foreach ($page in $requiredPages) {
    $source = Join-Path $public $page
    if (-not (Test-Path -LiteralPath $source)) { throw "Missing page: $page" }
}

$staging = Join-Path ([IO.Path]::GetTempPath()) ('np-upload-' + [guid]::NewGuid().ToString('n'))
New-Item -ItemType Directory -Path $staging -Force | Out-Null

function Copy-FileInto([string]$From, [string]$To) {
    $dir = Split-Path -Parent $To
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    Copy-Item -LiteralPath $From -Destination $To -Force
}

try {
    # Root document and the error page keep their names.
    Copy-FileInto (Join-Path $public 'index.html') (Join-Path $staging 'index.html')
    Copy-FileInto (Join-Path $public '404.html') (Join-Path $staging '404.html')

    # Every other page becomes its own directory index.
    foreach ($name in $pageDirs) {
        Copy-FileInto (Join-Path $public "$name.html") (Join-Path $staging "$name\index.html")
    }

    # Static assets keep their paths: the pages reference them as /css/..., so
    # these must stay rooted at the document root.
    foreach ($assetDir in @('assets', 'css', 'js', 'data')) {
        $from = Join-Path $public $assetDir
        if (-not (Test-Path -LiteralPath $from)) { throw "Missing asset directory: $assetDir" }
        Copy-Item -LiteralPath $from -Destination (Join-Path $staging $assetDir) -Recurse -Force
    }
    Copy-FileInto (Join-Path $public 'favicon.ico') (Join-Path $staging 'favicon.ico')

    # --- verification ------------------------------------------------------
    # A directory whose index the navigation depends on must not be empty, and
    # anything executable or dynamic would defeat the point of a static upload.
    foreach ($name in $pageDirs) {
        $index = Join-Path $staging "$name\index.html"
        if (-not (Test-Path -LiteralPath $index -PathType Leaf)) { throw "Missing directory index: $name/index.html" }
        if ((Get-Item -LiteralPath $index).Length -eq 0) { throw "Empty directory index: $name/index.html" }
    }

    $banned = @('\.php\d?$', '\.phtml$', '\.cgi$', '\.pl$', '\.sh$', '\.exe$', '\.dll$', '\.bat$', '\.ps1$', '\.db$')
    $all = @(Get-ChildItem -LiteralPath $staging -Recurse -File)
    foreach ($file in $all) {
        foreach ($pattern in $banned) {
            if ($file.Name -match $pattern) { throw "Upload package must stay static; found $($file.Name)" }
        }
    }

    # Every absolute reference in the HTML must resolve inside this package, or
    # the uploaded site has a broken link that only shows up on the live host.
    $resolved = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    foreach ($file in $all) {
        $rel = $file.FullName.Substring($staging.Length + 1).Replace('\', '/')
        [void]$resolved.Add('/' + $rel)
    }
    $missing = New-Object System.Collections.Generic.List[string]
    foreach ($file in ($all | Where-Object { $_.Extension -eq '.html' })) {
        $text = [IO.File]::ReadAllText($file.FullName)
        foreach ($m in [regex]::Matches($text, '(?:href|src)="(/[^"#?]*)"')) {
            $path = $m.Groups[1].Value
            if ($path -eq '/') { continue }
            $candidates = @($path, "$path/index.html")
            $ok = $false
            foreach ($candidate in $candidates) {
                if ($resolved.Contains($candidate)) { $ok = $true; break }
            }
            if (-not $ok) {
                $relFile = $file.FullName.Substring($staging.Length + 1).Replace('\', '/')
                $missing.Add("$relFile -> $path")
            }
        }
    }
    if ($missing.Count -gt 0) {
        throw ("Unresolved references in the upload package:`n  " + ($missing -join "`n  "))
    }

    # --- archive -----------------------------------------------------------
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $OutputPath) | Out-Null
    if (Test-Path -LiteralPath $OutputPath) { Remove-Item -LiteralPath $OutputPath -Force }
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem

    # Entries are written by hand so names use '/' separators: CreateFromDirectory
    # on .NET Framework emits backslashes, which some readers treat literally and
    # then unpack the whole tree as one flat filename.
    $archive = [IO.Compression.ZipFile]::Open($OutputPath, [IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach ($file in ($all | Sort-Object FullName)) {
            $entryName = $file.FullName.Substring($staging.Length + 1).Replace('\', '/')
            $entry = $archive.CreateEntry($entryName, [IO.Compression.CompressionLevel]::Optimal)
            $stream = $entry.Open()
            try {
                $bytes = [IO.File]::ReadAllBytes($file.FullName)
                $stream.Write($bytes, 0, $bytes.Length)
            }
            finally { $stream.Dispose() }
        }
    }
    finally { $archive.Dispose() }

    $hash = (Get-FileHash -LiteralPath $OutputPath -Algorithm SHA256).Hash
    $utf8 = [Text.UTF8Encoding]::new($false)
    $sidecar = "$OutputPath.sha256"
    [IO.File]::WriteAllText($sidecar, "$($hash.ToLowerInvariant())  $([IO.Path]::GetFileName($OutputPath))`n", $utf8)

    $count = $all.Count
    Write-Host "WEBSITE-UPLOAD-OK ($count files; directory indexes for /download /client-updates /privacy /sdk; no scripts, no backend; every absolute reference resolves)"
    Write-Host "UPLOAD-INSTRUCTION unzip into the webroot, no nginx/apache rule required"
    Write-Host "WEBSITE-PACKAGE $OutputPath"
    Write-Host "SHA256 $hash"
    Write-Host "SHA256-SIDECAR $sidecar"
    Write-Host "WEBSITE-UPLOAD-READY"
}
finally {
    if (Test-Path -LiteralPath $staging) {
        try { Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction Stop } catch { }
    }
}
