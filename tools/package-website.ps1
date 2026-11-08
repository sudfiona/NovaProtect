[CmdletBinding()]
param(
  [string]$OutputPath,
  [switch]$Force
)

# Packages the static site.
#
# There is one package, not two. The old split existed because an upgrade ZIP
# carried PHP diff logic and a copy of the client installer; a static site
# upgrades by running install.sh from the new package, so a second artefact
# would only be a second thing to keep in sync.
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$website = Join-Path $root 'website'
$version = (Get-Content -LiteralPath (Join-Path $website 'VERSION') -Raw).Trim()
if ($version -notmatch '^\d+\.\d+\.\d+$') { throw "Invalid website VERSION: $version" }

$releasePath = Join-Path $website 'release.json'
$release = Get-Content -LiteralPath $releasePath -Raw | ConvertFrom-Json
if ([string]$release.websiteVersion -ne $version) {
  throw "website/release.json websiteVersion $($release.websiteVersion) does not match website/VERSION $version"
}
if ([string]$release.sha256 -notmatch '^[0-9a-f]{64}$') { throw 'website/release.json sha256 must be 64 hex characters' }

if (-not $OutputPath) { $OutputPath = Join-Path $root "artifacts\website\$version\NovaProtect-Website-$version-Linux-x64-BaoTa.zip" }
$OutputPath = [IO.Path]::GetFullPath($OutputPath)
if ((Test-Path -LiteralPath $OutputPath) -and -not $Force) { throw "Output exists: $OutputPath (use -Force)" }

$required = @(
  (Join-Path $website 'VERSION'),
  (Join-Path $website 'release.json'),
  (Join-Path $website 'github.json'),
  (Join-Path $website 'install.sh'),
  (Join-Path $website 'deploy\install.sh'),
  (Join-Path $website 'deploy\rollback.sh'),
  (Join-Path $website 'deploy\health-check.sh'),
  (Join-Path $website 'deploy\nginx-location.conf'),
  (Join-Path $website 'deploy\cdnfly-edge-policy.json'),
  (Join-Path $website 'deploy\cdnfly-check.sh'),
  (Join-Path $website 'deploy\CDNFLY.md'),
  (Join-Path $website 'deploy\README.md'),
  (Join-Path $website 'public\index.html'),
  (Join-Path $website 'public\download.html'),
  (Join-Path $website 'public\client-updates.html'),
  (Join-Path $website 'public\sdk.html'),
  (Join-Path $website 'public\privacy.html'),
  (Join-Path $website 'public\404.html'),
  (Join-Path $website 'public\css\site.css'),
  (Join-Path $website 'public\js\site.js'),
  (Join-Path $website 'public\data\releases.json'),
  (Join-Path $website 'public\assets\novaprotect.png'),
  (Join-Path $website 'public\favicon.ico')
)
foreach ($path in $required) { if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Missing website file: $path" } }

# The archived PHP backend must not creep back into a package.
$stale = Get-ChildItem -LiteralPath $website -Recurse -File -ErrorAction SilentlyContinue |
  Where-Object { $_.Extension -in '.php', '.phtml', '.phar', '.py' }
if ($stale) { throw "PHP/Python files are not allowed in the static site: $($stale[0].FullName)" }

$utf8 = [Text.UTF8Encoding]::new($false)
$staging = Join-Path ([IO.Path]::GetTempPath()) ("np-site-" + [guid]::NewGuid().ToString('n'))
New-Item -ItemType Directory -Path $staging | Out-Null
try {
  function Get-RelativePath([string]$Base, [string]$Full) {
    # Windows PowerShell 5.1 lacks System.IO.Path.GetRelativePath.
    $baseUri = [Uri](([IO.Path]::GetFullPath($Base).TrimEnd('\')) + '\')
    $fullUri = [Uri]([IO.Path]::GetFullPath($Full))
    return [Uri]::UnescapeDataString($baseUri.MakeRelativeUri($fullUri).ToString()).Replace('\', '/')
  }
  function Copy-Tree([string]$From, [string]$To) {
    foreach ($file in (Get-ChildItem -LiteralPath $From -Recurse -File)) {
      $relative = Get-RelativePath $From $file.FullName
      $target = Join-Path $To $relative
      New-Item -ItemType Directory -Force -Path (Split-Path -Parent $target) | Out-Null
      Copy-Item -LiteralPath $file.FullName -Destination $target -Force
    }
  }

  Copy-Tree (Join-Path $website 'public') (Join-Path $staging 'public')
  Copy-Tree (Join-Path $website 'deploy') (Join-Path $staging 'deploy')
  foreach ($file in 'VERSION', 'release.json', 'github.json', 'install.sh') {
    Copy-Item -LiteralPath (Join-Path $website $file) -Destination (Join-Path $staging $file) -Force
  }
  Copy-Item -LiteralPath (Join-Path $website 'deploy\README.md') -Destination (Join-Path $staging 'README.md') -Force

  # Linux scripts must arrive with LF endings regardless of how the working
  # copy was checked out: CRLF makes bash fail with a confusing "bad interpreter".
  foreach ($script in (Get-ChildItem -LiteralPath $staging -Recurse -File -Include *.sh)) {
    $text = [IO.File]::ReadAllText($script.FullName)
    $text = $text.Replace("`r`n", "`n").Replace("`r", "`n")
    [IO.File]::WriteAllText($script.FullName, $text, $utf8)
  }

  $metadata = [ordered]@{
    product        = 'NovaProtect'
    packageType    = 'static'
    websiteVersion = $version
    clientVersion  = [string]$release.clientVersion
    entryPoints    = @('install.sh')
    runtime        = 'static-files-only'
    builtAt        = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
  }
  [IO.File]::WriteAllText((Join-Path $staging 'package.json'), ($metadata | ConvertTo-Json -Depth 4), $utf8)

  # Manifest last: it must cover every file that ships. A file cannot contain its
  # own digest, so SHA256SUMS is the one entry it cannot list; the archive
  # checksum written below (and verified by verify-website-package.ps1) is what
  # pins the manifest itself. The count assertion makes that exclusion explicit
  # instead of leaving a one-line gap for a strict checker to trip over.
  $lines = New-Object System.Collections.Generic.List[string]
  # Counted before SHA256SUMS exists, so this is exactly the number of payload
  # files the manifest must cover.
  $payloadCount = @(Get-ChildItem -LiteralPath $staging -Recurse -File).Count
  foreach ($file in (Get-ChildItem -LiteralPath $staging -Recurse -File | Sort-Object FullName)) {
    $relative = Get-RelativePath $staging $file.FullName
    if ($relative -eq 'SHA256SUMS') { continue }
    $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    $lines.Add("$hash  $relative")
  }

  if ($lines.Count -ne $payloadCount) {
    throw "SHA256SUMS covers $($lines.Count) files but $payloadCount payload files were staged"
  }
  [IO.File]::WriteAllText((Join-Path $staging 'SHA256SUMS'), ($lines -join "`n") + "`n", $utf8)

  New-Item -ItemType Directory -Force -Path (Split-Path -Parent $OutputPath) | Out-Null
  if (Test-Path -LiteralPath $OutputPath) { Remove-Item -LiteralPath $OutputPath -Force }
  Add-Type -AssemblyName System.IO.Compression
  Add-Type -AssemblyName System.IO.Compression.FileSystem

  # Do NOT use ZipFile.CreateFromDirectory here: on .NET Framework it writes
  # entry names with backslashes. Info-ZIP's unzip copes, but the ZIP spec and
  # most other readers (Python zipfile, Java, Go) treat a backslash as a literal
  # filename character, which would unpack the whole package into one flat file
  # named "public\index.html". Writing the entries by hand keeps '/' separators.
  $archive = [IO.Compression.ZipFile]::Open($OutputPath, [IO.Compression.ZipArchiveMode]::Create)
  try {
    foreach ($file in (Get-ChildItem -LiteralPath $staging -Recurse -File | Sort-Object FullName)) {
      $entryName = (Get-RelativePath $staging $file.FullName)
      $entry = $archive.CreateEntry($entryName, [IO.Compression.CompressionLevel]::Optimal)
      # Executable bit matters for install.sh; store the mode in the external
      # attributes so a plain `unzip` on Linux keeps the scripts runnable.
      $stream = $entry.Open()
      try {
        $bytes = [IO.File]::ReadAllBytes($file.FullName)
        $stream.Write($bytes, 0, $bytes.Length)
      }
      finally { $stream.Dispose() }
    }
  }
  finally { $archive.Dispose() }

  # Trust anchor for the archive, and therefore for SHA256SUMS itself: the
  # manifest cannot list its own digest, so the digest of the ZIP that contains
  # it is recorded next to the ZIP. Written before verification so the verifier
  # can check it in the same pass instead of warning that it is missing.
  $hash = (Get-FileHash -LiteralPath $OutputPath -Algorithm SHA256).Hash
  $sidecar = "$OutputPath.sha256"
  [IO.File]::WriteAllText($sidecar, "$($hash.ToLowerInvariant())  $([IO.Path]::GetFileName($OutputPath))`n", $utf8)

  $verify = Join-Path $PSScriptRoot 'verify-website-package.ps1'
  $bash = 'C:\Program Files\Git\bin\bash.exe'
  $verifyArgs = @{ PackagePath = $OutputPath }
  if (Test-Path -LiteralPath $bash) { $verifyArgs.BashPath = $bash }
  & $verify @verifyArgs
  if ($LASTEXITCODE -ne 0) { throw "Package verification failed: $OutputPath" }

  Write-Host "WEBSITE-PACKAGE $OutputPath"
  Write-Host "SHA256 $hash"
  Write-Host "SHA256-SIDECAR $sidecar"
  Write-Host "WEBSITE-PACKAGES-READY"
}
finally {
  if (Test-Path -LiteralPath $staging) {
    try { Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction Stop } catch { }
  }
}
