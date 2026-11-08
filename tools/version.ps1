[CmdletBinding()]
param(
  [ValidateSet('Check', 'Sync', 'Seal', 'Bump')]
  [string]$Action = 'Check',
  [ValidateSet('Patch', 'Minor', 'Major')]
  [string]$Part = 'Patch',
  [string]$SetVersion
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$versionPath = Join-Path $root 'VERSION'
$lockPath = Join-Path $root 'version-lock.json'
$utf8 = [System.Text.UTF8Encoding]::new($false)

function Read-Version {
  if (-not (Test-Path -LiteralPath $versionPath)) { throw "Missing VERSION file: $versionPath" }
  $value = (Get-Content -Raw -LiteralPath $versionPath).Trim()
  if ($value -notmatch '^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$') {
    throw "VERSION must be strict MAJOR.MINOR.PATCH, got '$value'"
  }
  return [version]::Parse("$value.0")
}

function Version-Text([version]$version) {
  return "$($version.Major).$($version.Minor).$($version.Build)"
}

function Write-Utf8([string]$path, [string]$content) {
  $directory = Split-Path -Parent $path
  if ($directory) { [IO.Directory]::CreateDirectory($directory) | Out-Null }
  [IO.File]::WriteAllText($path, $content, $utf8)
}

function Sync-Version([version]$version) {
  $text = Version-Text $version
  $quad = "$text.0"
  $csv = "$($version.Major),$($version.Minor),$($version.Build),0"

  Write-Utf8 (Join-Path $root 'Directory.Build.props') @"
<Project>
  <PropertyGroup>
    <Version>$text</Version>
    <AssemblyVersion>$quad</AssemblyVersion>
    <FileVersion>$quad</FileVersion>
    <InformationalVersion>$text</InformationalVersion>
    <Product>NovaProtect</Product>
    <Company>NovaProtect</Company>
    <Authors>NovaProtect</Authors>
  </PropertyGroup>
</Project>
"@

  Write-Utf8 (Join-Path $root 'src\product_version.h') @"
#pragma once
#define NOVAPROTECT_PRODUCT_NAME "NovaProtect"
#define NOVAPROTECT_PRODUCT_VERSION "$text"
#define NOVAPROTECT_FILE_VERSION $csv
#define NOVAPROTECT_FILE_VERSION_STRING "$quad"
"@

  $packerHeader = Join-Path $root 'include\packer.h'
  if (Test-Path -LiteralPath $packerHeader) {
    $content = Get-Content -Raw -LiteralPath $packerHeader
    $sdkLine = 'constexpr const char* NOVAPROTECT_SDK_VERSION = "' + $text + '";'
    $content = [regex]::Replace($content, 'constexpr const char\* NOVAPROTECT_SDK_VERSION = "[^"]+";', $sdkLine)
    Write-Utf8 $packerHeader $content
  }

  Write-Utf8 (Join-Path $root 'runtime\version.rcinc') @"
#define NOVAPROTECT_FILE_VERSION $csv
#define NOVAPROTECT_PRODUCT_VERSION $csv
#define NOVAPROTECT_FILE_VERSION_STR "$text"
#define NOVAPROTECT_PRODUCT_VERSION_STR "$text"
"@

  # Inno Setup truncates every version-info string at 60 characters, and the
  # installer description prefix below is 30 of them: keep the comment within
  # 30 characters or the website release notes lose their tail.
  Write-Utf8 (Join-Path $root 'installer\version.iss') @"
#define MyAppVersion "$text"
#define MyAppVersionComments "沙箱对抗强化；延时复测默认开启"
"@

  $websiteVersionPath = Join-Path $root 'website\VERSION'
  if (-not (Test-Path -LiteralPath $websiteVersionPath)) { throw "Missing website VERSION file: $websiteVersionPath" }
  $websiteVersion = (Get-Content -Raw -LiteralPath $websiteVersionPath).Trim()
  if ($websiteVersion -notmatch '^\d+\.\d+\.\d+$') { throw "Invalid website VERSION: $websiteVersion" }
  $releasePath = Join-Path $root 'website\release.json'
  if (Test-Path -LiteralPath $releasePath) {
    $release = Get-Content -Raw -LiteralPath $releasePath | ConvertFrom-Json
    # The website release has its own version stream; client version sync must preserve it.
    if ([string]$release.websiteVersion -ne $websiteVersion) { throw "website/release.json version mismatch: $($release.websiteVersion) / $websiteVersion" }
    Write-Utf8 $releasePath (($release | ConvertTo-Json -Depth 8) + "`n")
    $appVersion = [ordered]@{ websiteVersion = $websiteVersion; clientVersion = [string]$release.clientVersion }
    Write-Utf8 (Join-Path $root 'website\app\version.json') (($appVersion | ConvertTo-Json) + "`n")
  }

  $manifest = Join-Path $root 'ui\app.manifest'
  if (Test-Path -LiteralPath $manifest) {
    $content = Get-Content -Raw -LiteralPath $manifest
    $replacement = '${1}' + $quad + '${2}'
    $content = [regex]::Replace($content, '(<assemblyIdentity\s+version=")[^"]+("\s+name="NovaProtect\.UI")', $replacement)
    Write-Utf8 $manifest $content
  }
  Write-Host "[version] synchronized NovaProtect $text"
}

function Get-SourceDigest {
  $roots = @(
    'VERSION', 'build.ps1', 'README.md', 'STATUS.md',
    'src', 'include', 'runtime', 'ui', 'installer', 'sdk',
    'tests\planner-smoke', 'tests\update-client-smoke', 'tests\deploy_config_test.py', 'tests\website_installer_test.py', 'tests\core_test_gate.cpp', 'tests\regress.ps1', 'tools', 'website'
  )
  $derived = @('Directory.Build.props', 'product_version.h', 'version.rcinc', 'version.iss', 'version-lock.json')
  $files = foreach ($relative in $roots) {
    $path = Join-Path $root $relative
    if (-not (Test-Path -LiteralPath $path)) { continue }
    if ((Get-Item -LiteralPath $path).PSIsContainer) {
      # Exclusion must be evaluated on the path RELATIVE to $root: matching
      # the full path would let a checkout that itself lives under a
      # directory named "artifacts" exclude the entire tree.
      Get-ChildItem -LiteralPath $path -Recurse -File | Where-Object {
        $rel = $_.FullName.Substring($root.Length).TrimStart('\')
        $rel -notmatch '^(bin|obj|artifacts|evidence|_reg|App_Data|__pycache__)\\' -and
        $rel -notmatch '\\(bin|obj|artifacts|evidence|_reg|App_Data|__pycache__)\\' -and
        $_.Extension -notin @('.exe', '.dll', '.pdb', '.obj', '.o', '.bin', '.res', '.ldimg', '.png', '.ico') -and
        $derived -notcontains $_.Name
      }
    } else {
      Get-Item -LiteralPath $path
    }
  }

  $rows = foreach ($file in ($files | Sort-Object FullName -Unique)) {
    $relative = $file.FullName.Substring($root.Length).TrimStart('\').Replace('\', '/')
    $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $file.FullName).Hash
    $relative + [char]0 + $hash
  }
  $material = [Text.Encoding]::UTF8.GetBytes(($rows -join [Environment]::NewLine))
  $sha = [Security.Cryptography.SHA256]::Create()
  try { return ([BitConverter]::ToString($sha.ComputeHash($material))).Replace('-', '') }
  finally { $sha.Dispose() }
}

function Check-VersionPolicy([version]$version) {
  $text = Version-Text $version
  $digest = Get-SourceDigest
  if (-not (Test-Path -LiteralPath $lockPath)) {
    Write-Warning 'version-lock.json does not exist yet; seal the verified release with tools/version.ps1 -Action Seal.'
    return
  }

  $lock = Get-Content -Raw -LiteralPath $lockPath | ConvertFrom-Json
  $locked = [version]::Parse("$($lock.Version).0")
  if ($version -lt $locked) { throw "VERSION $text is lower than sealed version $($lock.Version)" }
  if ($version -eq $locked -and $digest -ne $lock.SourceDigest) {
    throw "NovaProtect source changed after $text was sealed. Increment VERSION first: powershell -File tools/version.ps1 -Action Bump -Part Patch"
  }
  Write-Host "[version] policy ok: $text"
}

$version = Read-Version
if ($Action -eq 'Bump') {
  if ($SetVersion) {
    if ($SetVersion -notmatch '^\d+\.\d+\.\d+$') { throw "Invalid -SetVersion '$SetVersion'" }
    $version = [version]::Parse("$SetVersion.0")
  } else {
    $version = switch ($Part) {
      'Major' { [version]::new($version.Major + 1, 0, 0, 0) }
      'Minor' { [version]::new($version.Major, $version.Minor + 1, 0, 0) }
      default { [version]::new($version.Major, $version.Minor, $version.Build + 1, 0) }
    }
  }
  Write-Utf8 $versionPath ((Version-Text $version) + [Environment]::NewLine)
  Sync-Version $version
  Write-Host "[version] bumped to $(Version-Text $version); seal only after complete verification"
  exit 0
}

Sync-Version $version
if ($Action -eq 'Check') { Check-VersionPolicy $version; exit 0 }
if ($Action -eq 'Sync') { exit 0 }
if ($Action -eq 'Seal') {
  $record = [ordered]@{
    Product = 'NovaProtect'
    Version = Version-Text $version
    SourceDigest = Get-SourceDigest
    SealedAt = [DateTimeOffset]::Now.ToString('O')
  }
  Write-Utf8 $lockPath (($record | ConvertTo-Json -Depth 4) + [Environment]::NewLine)
  Write-Host "[version] sealed NovaProtect $($record.Version) source digest $($record.SourceDigest)"
}
