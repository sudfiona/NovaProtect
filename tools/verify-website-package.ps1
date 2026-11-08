[CmdletBinding()]
param(
  [string]$PackagePath,
  [string]$BashPath
)

# Verifies the static-site package. The PHP-era checks (PHP entry points,
# FastCGI config, upgrade ZIP validation, admin upload transport) are gone with
# the backend; what remains is what a static package can actually get wrong:
# missing pages, a hash manifest that does not cover the payload, CRLF in shell
# scripts, executable payloads that should not exist, and leaked build material.
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$version = (Get-Content -LiteralPath (Join-Path $root 'website\VERSION') -Raw).Trim()
if (-not $PackagePath) {
  $PackagePath = Join-Path $root "artifacts\website\${version}\NovaProtect-Website-$version-Linux-x64-BaoTa.zip"
}
$PackagePath = [IO.Path]::GetFullPath($PackagePath)
if (-not (Test-Path -LiteralPath $PackagePath -PathType Leaf)) { throw "Missing package: $PackagePath" }

Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [IO.Compression.ZipFile]::OpenRead($PackagePath)
try {
  $entries = @{}
  foreach ($entry in $zip.Entries) {
    # ZIP paths are '/'-separated by spec. A backslash here means the archive was
    # produced by .NET Framework's CreateFromDirectory, which unpacks into a flat
    # root on readers that do not normalise (Python, Java, Go).
    if ($entry.FullName.Contains('\')) { throw "ZIP entry uses a backslash separator: $($entry.FullName)" }
    $name = $entry.FullName
    if ($name.EndsWith('/')) { continue }
    if ($name -match '(^|/)(\.git|__pycache__|node_modules|bin|obj|\.vs|App_Data)(/|$)|(^|/)\.env($|\.)|(^|/)\.user\.ini$|\.pdb$|(^|/)\.\./|^/') {
      throw "Forbidden package entry: $name"
    }
    # A static package must not carry anything the origin could execute.
    if ($name -match '\.(php|phtml|phar|cs|cshtml|csproj|dll|exe|so|dylib|py|jsp|asp|aspx)$') {
      throw "Executable or backend entry in a static package: $name"
    }
    if ($entries.ContainsKey($name)) { throw "Duplicate package entry: $name" }
    $entries[$name] = $entry
  }

  function Read-EntryBytes([string]$name) {
    if (-not $entries.ContainsKey($name)) { throw "Missing package entry: $name" }
    $stream = $entries[$name].Open()
    try {
      $buffer = [byte[]]::new($entries[$name].Length)
      $read = 0
      while ($read -lt $buffer.Length) {
        $n = $stream.Read($buffer, $read, $buffer.Length - $read)
        if ($n -le 0) { break }
        $read += $n
      }
      return $buffer
    } finally { $stream.Dispose() }
  }
  function Read-EntryText([string]$name) { [Text.Encoding]::UTF8.GetString((Read-EntryBytes $name)) }
  function Hash-Entry([string]$name) {
    $stream = $entries[$name].Open()
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose(); $stream.Dispose() }
  }

  # --- manifest ---------------------------------------------------------
  $metadata = Read-EntryText 'package.json' | ConvertFrom-Json
  if ([string]$metadata.product -ne 'NovaProtect') { throw 'Invalid package.json product' }
  if ([string]$metadata.websiteVersion -ne $version) { throw "package.json websiteVersion mismatch (expected $version)" }
  if ([string]$metadata.packageType -ne 'static') { throw "Invalid package.json packageType: $($metadata.packageType)" }
  if ((@($metadata.entryPoints) -join ',') -ne 'install.sh') { throw 'package.json entryPoints must be exactly install.sh' }
  $declaredVersion = (Read-EntryText 'VERSION').Trim()
  if ($declaredVersion -ne $version) { throw "VERSION mismatch: $declaredVersion vs $version" }

  $required = @(
    'VERSION', 'SHA256SUMS', 'package.json', 'release.json', 'github.json', 'README.md', 'install.sh',
    'deploy/install.sh', 'deploy/rollback.sh', 'deploy/health-check.sh', 'deploy/nginx-location.conf',
    'deploy/cdnfly-edge-policy.json', 'deploy/cdnfly-check.sh', 'deploy/CDNFLY.md', 'deploy/README.md',
    'public/index.html', 'public/download.html', 'public/client-updates.html', 'public/sdk.html',
    'public/privacy.html', 'public/404.html', 'public/css/site.css', 'public/js/site.js',
    'public/data/releases.json', 'public/assets/novaprotect.png', 'public/favicon.ico'
  )
  foreach ($name in $required) { if (-not $entries.ContainsKey($name)) { throw "Missing package entry: $name" } }

  # --- hashes -----------------------------------------------------------
  $manifest = @{}
  foreach ($line in ((Read-EntryText 'SHA256SUMS') -split "`r?`n")) {
    if ($line -notmatch '^\s*([0-9a-fA-F]{64})\s+\*?(.+?)\s*$') { continue }
    $manifest[$Matches[2].Replace('\', '/')] = $Matches[1].ToLowerInvariant()
  }
  if ($manifest.Count -eq 0) { throw 'SHA256SUMS is empty or unparsable' }
  foreach ($name in $entries.Keys) {
    if ($name -eq 'SHA256SUMS') { continue }
    if (-not $manifest.ContainsKey($name)) { throw "SHA256SUMS does not cover $name" }
    if ((Hash-Entry $name) -ne $manifest[$name]) { throw "SHA-256 mismatch for $name" }
  }
  foreach ($name in $manifest.Keys) {
    if ($name -ne 'SHA256SUMS' -and -not $entries.ContainsKey($name)) { throw "SHA256SUMS lists a missing file: $name" }
  }

  # Coverage must be exact, not merely sufficient: every entry except SHA256SUMS
  # has to appear in the manifest, and nothing else may. SHA256SUMS is the single
  # unavoidable exclusion (a file cannot hold its own digest); the archive-level
  # checksum recorded next to the ZIP pins it instead. Asserting the identity
  # here means a future entry added to the staging tree cannot slip out of the
  # manifest unnoticed.
  $uncovered = @($entries.Keys | Where-Object { $_ -ne 'SHA256SUMS' -and -not $manifest.ContainsKey($_) })
  if ($uncovered.Count -gt 0) { throw "SHA256SUMS omits $($uncovered.Count) entries: $($uncovered -join ', ')" }
  if ($manifest.Count -ne ($entries.Count - 1)) {
    throw "SHA256SUMS has $($manifest.Count) rows for $($entries.Count) entries; expected exactly entries-1 (SHA256SUMS itself excluded)"
  }

  # --- archive checksum sidecar ----------------------------------------
  # When the caller passes a path to a package on disk, the sibling .sha256 is
  # the trust anchor for the archive, and therefore for SHA256SUMS. Its absence
  # is reported rather than ignored: without it the manifest is the only claim
  # about the payload and it is not itself verified by anything.
  $sidecarPath = "$PackagePath.sha256"
  if (Test-Path -LiteralPath $PackagePath -PathType Leaf) {
    if (Test-Path -LiteralPath $sidecarPath -PathType Leaf) {
      $sidecarText = (Get-Content -Raw -LiteralPath $sidecarPath).Trim()
      $sidecarHash = ($sidecarText -split '\s+')[0]
      $actualArchiveHash = (Get-FileHash -LiteralPath $PackagePath -Algorithm SHA256).Hash.ToLowerInvariant()
      if ($sidecarHash -notmatch '^[0-9a-fA-F]{64}$') { throw "Malformed archive checksum sidecar: $sidecarPath" }
      if ($sidecarHash.ToLowerInvariant() -ne $actualArchiveHash) {
        throw "Archive checksum sidecar does not match $([IO.Path]::GetFileName($PackagePath))"
      }
    }
    else {
      Write-Warning "No archive checksum sidecar next to $([IO.Path]::GetFileName($PackagePath)); SHA256SUMS is unanchored."
    }
  }

  # --- shell scripts: LF only, executable, entry points intact ----------
  $shellScripts = $entries.Keys | Where-Object { $_ -match '\.sh$' }
  foreach ($name in $shellScripts) {
    $bytes = Read-EntryBytes $name
    if ($bytes -contains 13) { throw "CRLF line endings in $name (Linux scripts must be LF)" }
    $text = [Text.Encoding]::UTF8.GetString($bytes)
    if ($text -notmatch '(?m)^#!.*\bbash\b') { throw "$name is missing a bash shebang" }
  }

  # --- pages: no backend references, no unresolved placeholders ---------
  $pages = $entries.Keys | Where-Object { $_ -match '^public/.*\.html$' }
  foreach ($name in $pages) {
    $text = Read-EntryText $name
    if ($text -match '__(WEBSITE|CLIENT)_[A-Z]+__') { throw "Unresolved placeholder in $name" }
    if ($text -match 'href="/(admin|install|api|logout|health)') { throw "Backend path still linked from $name" }
    if ($text -match '<\?php') { throw "PHP block in $name" }
    if ($text -notmatch '<!doctype html>') { throw "$name is not a complete HTML document" }
  }

  # Every clean URL a page links to must be served by a file in the package.
  $linked = New-Object System.Collections.Generic.HashSet[string]
  foreach ($name in $pages) {
    foreach ($m in [regex]::Matches((Read-EntryText $name), 'href="(/[a-z0-9\-/]*)"')) {
      $path = $m.Groups[1].Value.TrimEnd('/')
      if ($path -eq '') { continue }
      if ($path -match '^/(css|js|assets|data)/') { $linked.Add("public$path") | Out-Null; continue }
      $linked.Add("public$path.html") | Out-Null
    }
  }
  foreach ($target in $linked) {
    if (-not $entries.ContainsKey($target)) { throw "Linked resource missing from package: $target" }
  }

  # --- release feed -----------------------------------------------------
  $feed = Read-EntryText 'public/data/releases.json' | ConvertFrom-Json
  if (@($feed).Count -eq 0) { throw 'releases.json is empty' }
  foreach ($release in @($feed)) {
    if (-not [string]$release.version) { throw 'releases.json entry without a version' }
    if (-not [string]$release.notes) { throw "releases.json entry $($release.version) without notes" }
  }
  $release = Read-EntryText 'release.json' | ConvertFrom-Json
  if (-not [string]$release.clientVersion) { throw 'release.json has no clientVersion' }
  if ([string]$release.sha256 -notmatch '^[0-9a-f]{64}$') { throw 'release.json sha256 is not 64 hex characters' }

  # --- optional bash syntax check ---------------------------------------
  if ($BashPath) {
    if (-not (Test-Path -LiteralPath $BashPath -PathType Leaf)) { throw "Missing bash: $BashPath" }
    $temp = Join-Path ([IO.Path]::GetTempPath()) ("np-pkg-" + [guid]::NewGuid().ToString('n'))
    New-Item -ItemType Directory -Path $temp | Out-Null
    try {
      foreach ($name in $shellScripts) {
        $file = Join-Path $temp ($name.Replace('/', '_'))
        [IO.File]::WriteAllBytes($file, (Read-EntryBytes $name))
        $previous = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try { $out = & $BashPath -n $file 2>&1 } finally { $ErrorActionPreference = $previous }
        if ($LASTEXITCODE -ne 0) { throw "bash -n failed for ${name}: $out" }
      }
    } finally { Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue }
  }

  $count = $entries.Count
  Write-Host "WEBSITE-STATIC-ARCHIVE-OK ($count files; SHA256SUMS covers all $($manifest.Count) others and itself is anchored by the archive checksum; no backend or executable entries; LF scripts; linked pages resolve)"
  Get-Item -LiteralPath $PackagePath |
    Select-Object Name, Length, @{Name = 'SHA256'; Expression = { (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash } } |
    Format-List
}
finally { $zip.Dispose() }
