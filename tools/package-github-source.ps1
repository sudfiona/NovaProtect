# NovaProtect GitHub source package.
#
# Produces artifacts/github-source/NovaProtect-<version>-source.zip: the full
# open-source tree. Every part of the product ships here - the VM engine, the
# wire interpreter, the revirtualiser, the crypto layers, the stub assembly, the
# x64 runtime, the tests, the WinUI client, the website and the release tooling.
#
# What is withheld is only what cannot be redistributed or must not be public:
# the commercial VMProtect SDK, signing keys, build outputs and third-party
# analysis artefacts. See $forbidden / $banned below.
#
# The zip is written in place (no staging copy, no deletes): entries are
# streamed straight from the workspace sources.
[CmdletBinding()]
param(
  [string]$OutputDirectory
)

$ErrorActionPreference = 'Stop'
$tools = $PSScriptRoot
$root = [IO.Path]::GetFullPath((Split-Path -Parent $tools)).TrimEnd('\')
$utf8 = [Text.UTF8Encoding]::new($false)

function Write-Step([string]$message) { Write-Host "==> $message" }

$clientVersion = (Get-Content -Raw -LiteralPath (Join-Path $root 'VERSION')).Trim()
if ($clientVersion -notmatch '^\d+\.\d+\.\d+$') { throw "VERSION must be MAJOR.MINOR.PATCH, got '$clientVersion'" }

& (Join-Path $tools 'version.ps1') -Action Check
if ($LASTEXITCODE -ne 0) { throw 'version policy check failed' }

if (-not $OutputDirectory) { $OutputDirectory = Join-Path $root 'artifacts\github-source' }
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
$packageName = "NovaProtect-$clientVersion"
$zipPath = Join-Path $OutputDirectory "$packageName-source.zip"

# ---------------------------------------------------------------------------
# Full open-source release: the engine sources are published too.
#
# This snapshot ships the entire NovaProtect tree - the VM engine, the wire
# interpreter, the revirtualiser, the crypto layers, the stub assembly, the x64
# runtime, the tests and the client. The only things deliberately withheld are
# the commercial VMProtect SDK (not redistributable), signing keys, build
# outputs and third-party analysis artefacts.
# ---------------------------------------------------------------------------
$coreDirs = @()

# Directories never shipped (matched as a path segment at any depth).
$excludeDirs = @(
  '.git', '.vs', '.idea', '.vscode', '.playwright-cli',
  'artifacts', 'output', '_wtest', '_icontest', 'evidence',
  '__pycache__', 'bin', 'obj', 'App_Data',
  # Scratch copies of superseded sources. Publishing them would ship a second,
  # stale version of main.cpp and prot64.c next to the real ones.
  '.work-backup-20261021'
)
# Directories matched by full relative path (repo-specific scratch).
# NOTE: this script is intentionally stored without a BOM, and Windows
# PowerShell 5.1 decodes a BOM-less UTF-8 file as ANSI. A non-ASCII literal here
# would therefore never match and would fail silently - use ASCII wildcards
# (the marketing folder has a CJK name) or match on a stable ASCII marker.
$excludePaths = @(
  # Regression OUTPUT: ~90 packed sample binaries plus a VMProtect runtime DLL.
  # Build products, not content; the driver that produces them ships.
  'tests\_reg',
  # Rendered marketing assets (page rasters + a PDF). The generators ship, the
  # 1.5 MB of page images do not.
  'docs\marketing-build\render',
  # Commercial VMProtect SDK: licensed binaries, never redistributable. A clone
  # builds without it via NOVAPROTECT_VMP_STUB, which build.ps1 selects
  # automatically when the SDK is absent.
  'third_party\vmprotect'
)
# Directories skipped inside external source roots (accumulated evidence trees
# and per-run output would otherwise dominate the archive).
$externalSkipDirs = @('evidence', 'outputs', 'artifacts', '__pycache__', '.git')
# Top-level folders whose names are not ASCII are matched through their file
# extension instead of their path (see Test-ExcludedFile). Marketing copy and
# Office documents are never part of a source snapshot, and neither is an
# analysis artefact: a sandbox capture of a packed sample is evidence about this
# product, not source for it.
$excludeExtensionsAnywhere = @(
  '.docx', '.doc', '.pptx', '.xlsx', '.pdf',
  '.pcap', '.pcapng', '.cap',
  '.exe', '.dll', '.pdb', '.lib', '.a', '.zip', '.7z', '.rar'
)
# Any path segment containing non-ASCII characters is excluded: such folders are
# local marketing material, and depending on their literal name would break on
# this file's BOM-less ANSI decoding.
function Test-HasNonAsciiSegment([string]$relative) {
  foreach ($segment in $relative.Replace('/', '\').Split('\')) {
    foreach ($ch in $segment.ToCharArray()) { if ([int]$ch -gt 127) { return $true } }
  }
  return $false
}
# Reverse-engineering / debugging tooling under tools/ is part of the published
# tree now: it is how the VM internals were inspected in the first place.
$excludeToolFiles = @()
# Design notes and verification reports are published alongside the engine they
# describe. They used to be withheld while the engine was closed.
$excludeDocFiles = @()
# File name patterns never shipped.
$excludeFiles = @(
  'NovaProtect.Engine.exe', 'NovaProtect.ManagedHost.exe',
  'VMProtectSDK64.dll', 'VMProtectSDK64.a', 'VMProtectSDK64.lib',
  'hostname32.obj', 'vm_target.o',
  'tests\VMProtectSDK.h', 'tests\VMProtectSDK32.h',
  'tests\VMProtectSDK64.dll', 'tests\hostname32.exe',
  'tests\test_target.exe', 'tests\vm_target.exe',
  'runtime\_*', 'tests\_*',
  'client-integrity.key.xml',
  '_regress_out.txt', '_regress_icon.txt', '_writetest.txt',
  '*.dbg_bak', '*.check', '*.real', 'stub_blob32_dbg.inc',
  '*.pdb', '*.map', '*.log', '*.vmprotect.log',
  '*.tmp', '*.user', '*.suo', 'Thumbs.db', 'desktop.ini', '.DS_Store',
  '*.vmp', '*.pfx', '*.snk', '*.p12', '*.private.pem', 'id_rsa*', '.env',
  '*.novaprotect-build.json', '*.novaprotect-prebuild.json',
  # The seal records the internal source digest of the released tree; a clone
  # regenerates it with tools/version.ps1 -Action Seal.
  'version-lock.json',
  # Generated intermediates only. C/C++/ASM sources, headers and linker scripts
  # are part of the published engine now, so no source extension is excluded
  # anywhere; binaries are caught by $excludeExtensionsAnywhere.
  '*.o', '*.obj', '*.ldimg'
)
# Generated runtime intermediates (regenerated by build.ps1 -Stub/-Prot/-Mut).
$runtimeGenerated = @('*.o', '*.bin', '*.res', '*.ldimg')

# Files synthesised into the archive instead of being read from the workspace.
# Nothing is regenerated any more: the real sources ship, including the marker
# header that used to be replaced by a no-op stand-in.
$generated = @{}

function Test-ExcludedFile([string]$relative) {
  $normalized = $relative.Replace('/', '\')
  $segments = $normalized.Split('\')
  # Marketing/office documents are never source, wherever they live.
  $ext = [IO.Path]::GetExtension($normalized).ToLowerInvariant()
  if ($excludeExtensionsAnywhere -contains $ext) { return $true }
  if (Test-HasNonAsciiSegment $normalized) { return $true }
  if ($segments.Count -ge 2 -and $segments[0] -eq 'tools' -and $segments.Count -eq 2) {
    if ($excludeToolFiles -contains $segments[-1]) { return $true }
  }
  if ($segments.Count -eq 2 -and $segments[0] -eq 'docs') {
    if ($excludeDocFiles -contains $segments[-1]) { return $true }
  }
  # Only tools/*.ps1 and website/*.sh are allowed to carry the generic code
  # extensions above; everywhere else they belong to the core tree.
  $isTooling = $normalized.StartsWith('tools\') -or $normalized.StartsWith('sdk\')
  $isWebsite = $normalized.StartsWith('website\') -or $normalized.StartsWith('installer\')
  foreach ($pattern in $excludeFiles) {
    # Path-style patterns (containing a separator) match the full relative
    # path; bare patterns match the file name at any depth.
    $pathStyle = $pattern.Contains('\')
    if ($pathStyle) {
      if ($normalized -like $pattern) { return $true }
    } else {
      if ($segments[-1] -like $pattern) { return $true }
    }
  }
  if ($segments.Count -eq 2 -and $segments[0] -eq 'runtime') {
    foreach ($pattern in $runtimeGenerated) {
      if ($segments[-1] -like $pattern) { return $true }
    }
  }
  return $false
}

Write-Step "collecting source files for $packageName"
$collected = New-Object System.Collections.Generic.List[string]
$skipped = 0
$stack = New-Object System.Collections.Stack
$stack.Push('')
while ($stack.Count -gt 0) {
  $relative = $stack.Pop()
  $absolute = if ($relative) { Join-Path $root $relative } else { $root }
  foreach ($entry in [IO.Directory]::GetFileSystemEntries($absolute)) {
    $name = [IO.Path]::GetFileName($entry)
    $child = if ($relative) { "$relative\$name" } else { $name }
    if ([IO.Directory]::Exists($entry)) {
      $segment = $child.Replace('/', '\')
      $isExcludedDir = $false
      foreach ($dir in $excludePaths) {
        if ($segment -eq $dir -or $segment.StartsWith($dir + '\', [StringComparison]::OrdinalIgnoreCase)) { $isExcludedDir = $true; break }
      }
      foreach ($dir in $coreDirs) {
        if ($segment -eq $dir -or $segment.StartsWith($dir + '\', [StringComparison]::OrdinalIgnoreCase)) { $isExcludedDir = $true; break }
      }
      if (-not $isExcludedDir -and ($excludeDirs -notcontains $name)) { $stack.Push($child) }
      else { $skipped++ }
      continue
    }
    if (Test-ExcludedFile $child) { $skipped++; continue }
    $collected.Add($child)
  }
}
# Stand-ins live only in $generated; they are not read from the workspace copy
# (whose real header belongs to the core tree).
foreach ($relative in $generated.Keys) {
  if ($collected -notcontains $relative) { $collected.Add($relative) }
}

# ------------------------------------------------ external source roots ---
# protector-research/ sits next to the repository, not inside it, but it is part
# of how this product was built: the harness that analysed other protectors and
# produced the fixtures the regression suite runs on. It ships under research/.
# Files are read from their real location and written into the archive with a
# remapped prefix, so nothing is copied into the workspace.
$externalRoots = [ordered]@{}
$siblingResearch = Join-Path (Split-Path -Parent $root) 'protector-research'
if (Test-Path -LiteralPath $siblingResearch) { $externalRoots['research'] = $siblingResearch }
$externalFiles = @{}
foreach ($prefix in @($externalRoots.Keys)) {
  $base = [IO.Path]::GetFullPath($externalRoots[$prefix]).TrimEnd('\')
  $pending = New-Object System.Collections.Stack
  $pending.Push('')
  while ($pending.Count -gt 0) {
    $relative = $pending.Pop()
    $absolute = if ($relative) { Join-Path $base $relative } else { $base }
    foreach ($entry in [IO.Directory]::GetFileSystemEntries($absolute)) {
      $name = [IO.Path]::GetFileName($entry)
      $child = if ($relative) { "$relative\$name" } else { $name }
      if ([IO.Directory]::Exists($entry)) {
        $isExcludedDir = $false
        foreach ($dir in $excludeDirs) { if ($name -eq $dir) { $isExcludedDir = $true } }
        foreach ($dir in $externalSkipDirs) { if ($name -eq $dir) { $isExcludedDir = $true } }
        if (-not $isExcludedDir) { $pending.Push($child) }
        continue
      }
      if (Test-ExcludedFile $child) { $skipped++; continue }
      $target = "$prefix\$child"
      $externalFiles[$target] = $entry
      if ($collected -notcontains $target) { $collected.Add($target) }
    }
  }
}

$collected.Sort()

# ------------------------------------------------------------ safety gate ---
# Path fragments that must never appear anywhere in a published archive.
# "vmprotectsdk" is deliberately absent: tools/resolve-vmprotect-sdk.ps1 is a
# build script that has to ship, and the SDK binaries themselves are caught by
# the extension rules plus $forbidden below.
$banned = @('private-signing', 'client-integrity.key.xml', 'id_rsa', '.pfx', '.snk', '.p12', 'id_ed25519')
foreach ($relative in $collected) {
  $lower = $relative.Replace('/', '\').ToLowerInvariant()
  foreach ($token in $banned) {
    if ($lower.Contains($token)) { throw "Refusing to package sensitive path: $relative" }
  }
}

# Full open-source release: the engine must be PROVEN present, not merely
# hoped for. A change to $excludeDirs or Test-ExcludedFile that silently drops
# the VM sources would otherwise publish a client that cannot be rebuilt.
$engineRequired = @(
  'src\vm_engine.cpp', 'src\vm_revirt.cpp', 'src\vm_obfuscate.cpp',
  'src\packer.cpp', 'src\packer_meta.cpp', 'src\mutation.cpp', 'src\disasm.cpp',
  'src\crypto_layers.cpp', 'src\crypto_stream.cpp', 'src\pe_lib.cpp',
  'src\anti_debug.cpp', 'src\evasion.cpp', 'src\evasion_static.cpp',
  'src\evasion_dynamic.cpp', 'src\evasion_kernel.cpp',
  'src\evasion_hypervisor.cpp', 'src\evasion_entropy.cpp',
  'src\evasion_variants.cpp', 'src\mem_loader.cpp', 'src\api_unhook.cpp',
  'src\client_gate.cpp', 'src\white_launcher.cpp', 'src\managed_envelope.cpp',
  'src\junk_emitter.cpp', 'src\main.cpp', 'src\stub_blob.h', 'src\prot_blob.h',
  'include\vm_isa.h', 'include\wire_table.h', 'include\vm_revirt.h',
  'include\pe_types.h', 'include\packer.h', 'include\vmp_markers.h',
  'runtime\prot64.c', 'runtime\prot64.S', 'runtime\stub.S', 'runtime\stub32.S',
  'runtime\mutkern.S', 'runtime\managed_host.cpp', 'runtime\prot64.ld',
  'docs\engine-redesign.md', 'tools\vmdbg.cpp', 'tools\rtinspect.cpp'
)
$missingEngine = @($engineRequired | Where-Object { $collected -notcontains $_ })
if ($missingEngine.Count -gt 0) {
  throw ("Engine sources missing from the package: " + ($missingEngine -join ', '))
}

# Binaries and licensed components must be PROVEN absent: the public snapshot
# may not carry anything that cannot be redistributed.
$forbidden = @(
  'third_party\vmprotect\VMProtectSDK.h',
  'third_party\vmprotect\Lib\Windows\VMProtectSDK64.dll',
  'third_party\vmprotect\Lib\Windows\MinGW\VMProtectSDK64.a',
  'tests\VMProtectSDK64.dll', 'tests\VMProtectSDK.h',
  'client-integrity.key.xml', 'version-lock.json'
)
foreach ($relative in $forbidden) {
  if ($collected -contains $relative) { throw "Non-redistributable file leaked into the public package: $relative" }
}
# A published tree must still contain the integration surface and the site.
foreach ($required in @(
    'VERSION', 'README.md', 'LICENSE', 'build.ps1',
    'sdk\include\novaprotect_sdk.h', 'include\vmp_markers.h',
    'installer\novaprotect.iss', 'ui\NovaProtect.UI.csproj',
    'website\public\index.html', 'tools\package-client-release.ps1'
  )) {
  if ($collected -notcontains $required) { throw "Expected file missing from the package: $required" }
}

$totalBytes = 0L
foreach ($relative in $collected) {
  if ($generated.ContainsKey($relative)) { $totalBytes += $utf8.GetByteCount($generated[$relative]) }
  elseif ($externalFiles.ContainsKey($relative)) { $totalBytes += (Get-Item -LiteralPath $externalFiles[$relative]).Length }
  else { $totalBytes += (Get-Item -LiteralPath (Join-Path $root $relative)).Length }
}
Write-Step "$($collected.Count) files, $([math]::Round($totalBytes / 1MB, 2)) MB ($skipped entries excluded)"

# ------------------------------------------------------------------- zip ----
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$stream = [IO.File]::Open($zipPath, [IO.FileMode]::Create, [IO.FileAccess]::Write)
try {
  $archive = New-Object IO.Compression.ZipArchive($stream, [IO.Compression.ZipArchiveMode]::Create, $true)
  try {
    foreach ($relative in $collected) {
      $entryName = "$packageName/" + $relative.Replace('\', '/')
      if ($generated.ContainsKey($relative)) {
        $entry = $archive.CreateEntry($entryName, [IO.Compression.CompressionLevel]::Optimal)
        $writer = [IO.StreamWriter]::new($entry.Open(), $utf8)
        try { $writer.Write($generated[$relative]) } finally { $writer.Dispose() }
        continue
      }
      $sourcePath = if ($externalFiles.ContainsKey($relative)) { $externalFiles[$relative] }
                    else { Join-Path $root $relative }
      [IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
        $archive, $sourcePath, $entryName, [IO.Compression.CompressionLevel]::Optimal) | Out-Null
    }
  }
  finally { $archive.Dispose() }
}
finally { $stream.Dispose() }

$zipItem = Get-Item -LiteralPath $zipPath
$zipHash = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
[IO.File]::WriteAllText("$zipPath.sha256", "$zipHash  $([IO.Path]::GetFileName($zipPath))`n", $utf8)

Write-Host ''
Write-Host "GITHUB-SOURCE-OK version=$clientVersion"
Write-Host "  package : $zipPath"
Write-Host "  size    : $([math]::Round($zipItem.Length / 1MB, 2)) MB ($($collected.Count) files)"
Write-Host "  sha256  : $zipHash"
Write-Host '  license : MIT (full engine + client + website; VMProtect SDK excluded)'
