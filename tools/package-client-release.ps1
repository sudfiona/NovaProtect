# NovaProtect client release packaging (no VMProtect post-processing).
#
# Flow: version policy -> full build (build.ps1: stubs, protection runtime,
# mutation kernel, managed host, engine, WinUI) -> Inno Setup installer ->
# website release metadata -> client update contract smoke (fixture transport,
# no site involved: the client updates straight from GitHub).
#
# The VMProtect SDK marker calls in the sources stay untouched; when the
# commercial SDK is absent they compile to no-ops (NOVAPROTECT_VMP_STUB), so a
# clean open-source clone builds without any VMProtect component.
[CmdletBinding()]
param(
  [switch]$SkipBuild,          # reuse existing build outputs
  [switch]$SkipE2E,            # skip the client update contract smoke
  [switch]$RunTests            # run tests/regress.ps1 before packaging
)

$ErrorActionPreference = 'Stop'
$tools = $PSScriptRoot
$root = [IO.Path]::GetFullPath((Split-Path -Parent $tools)).TrimEnd('\')
$utf8 = [Text.UTF8Encoding]::new($false)

function Write-Step([string]$message) { Write-Host "==> $message" }

# ---------------------------------------------------------------- version ---
$clientVersion = (Get-Content -Raw -LiteralPath (Join-Path $root 'VERSION')).Trim()
if ($clientVersion -notmatch '^\d+\.\d+\.\d+$') { throw "VERSION must be MAJOR.MINOR.PATCH, got '$clientVersion'" }
$installerName = "NovaProtect-Setup-$clientVersion.exe"
$installerDir = Join-Path $root "artifacts\client-installer\$clientVersion"
$installerPath = Join-Path $installerDir $installerName
Write-Step "NovaProtect client $clientVersion"

& (Join-Path $tools 'version.ps1') -Action Check
if ($LASTEXITCODE -ne 0) { throw 'version policy check failed' }

# ------------------------------------------------------------------ tests ---
if ($RunTests) {
  Write-Step 'running the regression suite before packaging'
  & (Join-Path $root 'tests\regress.ps1')
  if ($LASTEXITCODE -ne 0) { throw 'regression suite failed' }
}

# ------------------------------------------------------------------ build ---
if (-not $SkipBuild) {
  Write-Step 'full build (stub, protection runtime, mutation kernel, managed host, engine, WinUI)'
  & (Join-Path $root 'build.ps1')
  if ($LASTEXITCODE -ne 0) { throw 'full build failed' }
}

$publishDir = Join-Path $root 'ui\bin\x64\Release\net10.0-windows10.0.19041.0\win-x64'
foreach ($required in @(
    (Join-Path $root 'NovaProtect.Engine.exe'),
    (Join-Path $root 'NovaProtect.ManagedHost.exe'),
    (Join-Path $publishDir 'NovaProtect.exe'),
    (Join-Path $publishDir 'NovaProtect.dll'),
    (Join-Path $publishDir 'client-integrity.manifest'),
    (Join-Path $publishDir 'client-integrity.sig')
  )) {
  if (-not (Test-Path -LiteralPath $required -PathType Leaf)) { throw "Missing build output: $required" }
}

# ------------------------------------------------------------- Inno Setup ---
$iscc = $null
# Per-user installs (the winget/unpacked default on this machine) live under
# LOCALAPPDATA, so the Program Files probes alone miss a perfectly good ISCC.
foreach ($candidate in @(
    (Join-Path ${env:ProgramFiles} 'Inno Setup 7\ISCC.exe'),
    (Join-Path ${env:ProgramFiles(x86)} 'Inno Setup 7\ISCC.exe'),
    (Join-Path ${env:ProgramFiles(x86)} 'Inno Setup 6\ISCC.exe'),
    (Join-Path ${env:ProgramFiles} 'Inno Setup 6\ISCC.exe'),
    (Join-Path $env:LOCALAPPDATA 'Programs\Inno Setup 7\ISCC.exe'),
    (Join-Path $env:LOCALAPPDATA 'Programs\Inno Setup 6\ISCC.exe')
  )) {
  if ($candidate -and (Test-Path -LiteralPath $candidate)) { $iscc = $candidate; break }
}
if (-not $iscc) { $command = Get-Command iscc -ErrorAction SilentlyContinue; if ($command) { $iscc = $command.Source } }
if (-not $iscc) { throw 'Inno Setup compiler (ISCC.exe) not found; install Inno Setup 6/7 or add ISCC to PATH.' }

New-Item -ItemType Directory -Force -Path $installerDir | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $root 'output') | Out-Null

$isccLog = Join-Path $root "output\iscc-$clientVersion.log"
Write-Step "compiling installer: $iscc"
$isccOutput = & $iscc "/DOutputDir=$installerDir" (Join-Path $root 'installer\novaprotect.iss') 2>&1
$isccExit = $LASTEXITCODE
[IO.File]::WriteAllText($isccLog, (($isccOutput | Out-String) + "`n"), $utf8)
if ($isccExit -ge 2) { throw "ISCC failed (exit $isccExit); see $iscc`n$($isccOutput | Out-String)" }
if ($isccExit -eq 1) { Write-Warning "ISCC reported warnings; see $isccLog" }
if (-not (Test-Path -LiteralPath $installerPath -PathType Leaf)) { throw "ISCC did not produce $installerPath" }

$installerItem = Get-Item -LiteralPath $installerPath
$installerHash = (Get-FileHash -LiteralPath $installerPath -Algorithm SHA256).Hash.ToLowerInvariant()

# The Inno version resource carries the release notes used by the website
# backend. Inno Setup truncates every version-info string at 60 characters and
# the description prefix is 30 of them, so verify the full expected string is
# embedded (this catches a truncated or stale version.iss).
$versionIss = [IO.File]::ReadAllText((Join-Path $root 'installer\version.iss'), [Text.Encoding]::UTF8)
$versionComments = [regex]::Match($versionIss, '#define MyAppVersionComments "([^"]*)"').Groups[1].Value
if (-not $versionComments) { throw 'installer/version.iss is missing MyAppVersionComments' }
$expectedDescription = "NovaProtect Client Installer - $versionComments"
if ($expectedDescription.Length -gt 60) {
  throw "VersionInfoDescription would be $($expectedDescription.Length) characters; Inno Setup truncates version strings at 60. Shorten MyAppVersionComments in tools/version.ps1."
}
$installerBytes = [IO.File]::ReadAllBytes($installerPath)
$installerText = [Text.Encoding]::Unicode.GetString($installerBytes)
if (-not $installerText.Contains($expectedDescription)) {
  throw "Installer is missing the expected version description '$expectedDescription'; check installer/version.iss."
}
Write-Step "installer ready: $installerName ($([math]::Round($installerItem.Length / 1MB, 1)) MB)"
Write-Host "       sha256 $installerHash"

# --------------------------------------------------------- release.json -----
$releasePath = Join-Path $root 'website\release.json'
$release = Get-Content -Raw -LiteralPath $releasePath | ConvertFrom-Json
if ("$($release.clientVersion)" -ne $clientVersion) {
  throw "website/release.json clientVersion $($release.clientVersion) does not match VERSION $clientVersion; bump the client version first."
}
$release.fileName = $installerName
$release.sha256 = $installerHash
[IO.File]::WriteAllText($releasePath, (($release | ConvertTo-Json -Depth 8) + "`n"), $utf8)

$sumsPath = "$installerPath.sha256"
[IO.File]::WriteAllText($sumsPath, "$installerHash  $installerName`n", $utf8)
Write-Step "website/release.json points at $installerName; checksum written to $([IO.Path]::GetFileName($sumsPath))"

# ------------------------------------------------------------------- E2E ----
# The client updates from GitHub Releases and verifies the asset digest itself,
# so the update contract is exercised against a fixture transport rather than a
# site. This still proves the real UpdateClient code path: API URL, asset
# selection, digest enforcement, redirect host checks and download accounting.
if (-not $SkipE2E) {
  Write-Step 'building the update contract harness'
  & dotnet build (Join-Path $root 'tests\update-client-smoke\NovaProtect.UpdateSmoke.csproj') -c Release --nologo -v:q
  if ($LASTEXITCODE -ne 0) { throw 'update smoke harness build failed' }
  $smokeExe = Join-Path $root 'tests\update-client-smoke\bin\Release\net10.0\NovaProtect.UpdateSmoke.exe'
  if (-not (Test-Path -LiteralPath $smokeExe -PathType Leaf)) { throw "Missing smoke harness: $smokeExe" }

  Write-Step 'running the update contract smoke'
  & $smokeExe
  if ($LASTEXITCODE -ne 0) { throw 'update contract smoke failed' }
  Write-Step 'update contract passed: GitHub API shape, digest enforcement, redirect host pinning, download accounting'
}
# ---------------------------------------------------------------- summary ---
Write-Host ''
Write-Host "CLIENT-RELEASE-OK version=$clientVersion"
Write-Host "  installer : $installerPath"
Write-Host "  size      : $($installerItem.Length) bytes"
Write-Host "  sha256    : $installerHash"
Write-Host "  metadata  : website/release.json (clientVersion $clientVersion)"
Write-Host '  next      : publish the installer as a GitHub Release asset (the site is static and only links there).'
