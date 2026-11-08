# Independent audit of the published source archive.
#
# The packaging script asserts its own exclusions, but a release that ships a
# signing key or a commercial SDK is not recoverable once it is on GitHub, so the
# archive is re-opened here and checked against a list that does not come from
# the packager.
param(
    [Parameter(Mandatory = $true)][string]$ZipPath
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression.FileSystem

$zip = [IO.Compression.ZipFile]::OpenRead($ZipPath)
try {
    $entries = $zip.Entries | ForEach-Object { $_.FullName }
} finally {
    $zip.Dispose()
}

Write-Host "archive : $ZipPath"
Write-Host "entries : $($entries.Count)"
Write-Host ''

$failures = 0
function Fail([string]$message) {
    Write-Host "  FAIL  $message"
    $script:failures++
}
function Pass([string]$message) { Write-Host "  ok    $message" }

# --- 1. secrets -------------------------------------------------------------
$secretPatterns = @(
    '*.pem', '*.pfx', '*.p12', '*.snk', '*.key', '*.jks', '*.keystore',
    '*id_rsa*', '*id_ed25519*', '.env', '*private*', '*secret*'
)
$secretHits = $entries | Where-Object {
    $leaf = ($_ -split '/')[-1]
    $hit = $false
    foreach ($p in $secretPatterns) { if ($leaf -like $p) { $hit = $true } }
    $hit
}
if ($secretHits) { $secretHits | ForEach-Object { Fail "possible secret: $_" } }
else { Pass 'no key / secret / env files' }

# A private key body would be caught even under an innocent filename.
$zip = [IO.Compression.ZipFile]::OpenRead($ZipPath)
try {
    foreach ($entry in $zip.Entries) {
        if ($entry.Length -gt 512KB) { continue }
        $reader = [IO.StreamReader]::new($entry.Open())
        try { $text = $reader.ReadToEnd() } finally { $reader.Dispose() }
        if ($text -match 'BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY') {
            Fail "private key body inside $($entry.FullName)"
        }
        if ($text -match 'MIIE[A-Za-z0-9+/]{200,}') {
            Fail "PEM-looking base64 blob inside $($entry.FullName)"
        }
    }
} finally { $zip.Dispose() }
Pass 'no private key material in file bodies'

# --- 2. commercial SDK ------------------------------------------------------
# Only binaries and headers matter. A script whose name mentions the SDK (for
# example one that locates it on the maintainer's machine) is not the SDK.
$sdkHits = $entries | Where-Object {
    ($_ -match 'vmprotect' -or $_ -match 'VMProtectSDK') -and
    ($_ -match '\.(dll|a|lib|h|hpp|so|dylib)$')
}
if ($sdkHits) { $sdkHits | ForEach-Object { Fail "commercial SDK present: $_" } }
else { Pass 'no VMProtect SDK binaries or headers' }

# --- 3. engine sources ------------------------------------------------------
# The engine is open source now, so the archive must CONTAIN it. A snapshot that
# silently loses src/ or runtime/ would publish a client nobody can rebuild.
$engineRequired = @(
    'src/vm_engine.cpp', 'src/vm_revirt.cpp', 'src/vm_obfuscate.cpp',
    'src/packer.cpp', 'src/mutation.cpp', 'src/disasm.cpp',
    'src/crypto_layers.cpp', 'src/main.cpp',
    'include/vm_isa.h', 'include/wire_table.h', 'include/vm_revirt.h',
    'include/pe_types.h', 'include/packer.h', 'include/vmp_markers.h',
    'runtime/prot64.c', 'runtime/prot64.S', 'runtime/stub.S', 'runtime/stub32.S',
    'runtime/mutkern.S', 'runtime/managed_host.cpp'
)
$engineMissing = @($engineRequired | Where-Object {
    $needle = "*/$_"
    -not ($entries | Where-Object { $_ -like $needle })
})
if ($engineMissing) {
    $engineMissing | ForEach-Object { Fail "engine source missing from archive: $_" }
} else {
    Pass "engine sources present ($($engineRequired.Count) checked)"
}

# Superseded scratch copies must not travel with the real sources.
$backupHits = $entries | Where-Object { $_ -match '/\.work-backup' }
if ($backupHits) { $backupHits | ForEach-Object { Fail "stale backup copy: $_" } }
else { Pass 'no .work-backup scratch directories' }

# --- 4. build outputs and local junk ---------------------------------------
$junkHits = $entries | Where-Object {
    $_ -match '/bin/' -or $_ -match '/obj/' -or
    $_ -match '\.pdb$' -or $_ -match '\.pcap$' -or
    $_ -match '\.pdf$' -or $_ -match '\.docx$' -or
    $_ -match '\.exe$' -or $_ -match '\.dll$' -or
    $_ -match 'novaprotect-build\.json$' -or $_ -match 'novaprotect-prebuild\.json$'
}
if ($junkHits) { $junkHits | ForEach-Object { Fail "build output / local artifact: $_" } }
else { Pass 'no build outputs, binaries, samples or office documents' }

# --- 5. the things a published repo must have ------------------------------
$required = @(
    'LICENSE', 'README.md', 'VERSION', 'build.ps1', '.gitignore',
    'ui/NovaProtect.UI.csproj',
    'website/public/index.html',
    'website/public/css/site.css',
    'website/public/js/site.js',
    'sdk/include/novaprotect_sdk.h',
    'installer/novaprotect.iss'
)
foreach ($r in $required) {
    $found = $entries | Where-Object { $_ -like "*/$r" }
    if ($found) { Pass "present: $r" } else { Fail "missing: $r" }
}

# --- 6. licence text -------------------------------------------------------
$zip = [IO.Compression.ZipFile]::OpenRead($ZipPath)
try {
    $lic = $zip.Entries | Where-Object { $_.FullName -like '*/LICENSE' } | Select-Object -First 1
    if ($lic) {
        $reader = [IO.StreamReader]::new($lic.Open())
        try { $text = $reader.ReadToEnd() } finally { $reader.Dispose() }
        if ($text -match 'MIT License') { Pass 'LICENSE is MIT' } else { Fail 'LICENSE is not MIT' }
        if ($text -match 'All rights reserved') { Fail 'LICENSE still says All rights reserved' }
        else { Pass 'no all-rights-reserved language' }
    } else { Fail 'no LICENSE in archive' }
} finally { $zip.Dispose() }

# --- 7. internal absolute paths -------------------------------------------
# A public repo must not carry the maintainer's machine layout: a real user
# profile path leaks a person and a project directory, and it silently breaks for
# everyone else.
#
# Toolchain search paths are NOT a leak: a build script legitimately lists
# C:\mingw\mingw64\bin or D:\Microsoft Visual Studio as candidates, the same way
# a Linux script lists /usr/local/bin. Only a concrete user profile counts.
$pathPatterns = @(
    # a user profile with a real name, not a placeholder
    'C:\\Users\\(?!\$|<|%|USER|user|Public\\)[A-Za-z0-9._-]{2,}\\\S',
    'C:\\Documents and Settings\\[A-Za-z0-9._-]{2,}\\\S'
)
$pathHits = @()
$zip = [IO.Compression.ZipFile]::OpenRead($ZipPath)
try {
    foreach ($entry in $zip.Entries) {
        if ($entry.Length -gt 2MB) { continue }
        if ($entry.FullName -match '\.(png|ico|jpg|jpeg|gif|zip|7z)$') { continue }
        # This audit file necessarily contains the patterns themselves.
        if ($entry.FullName -like '*/tools/audit-github-source.ps1') { continue }
        $reader = [IO.StreamReader]::new($entry.Open())
        try { $text = $reader.ReadToEnd() } finally { $reader.Dispose() }
        if ($text -match $pathPatterns[0]) { $pathHits += "$($entry.FullName) <- user profile path" }
        if ($text -match $pathPatterns[1]) { $pathHits += "$($entry.FullName) <- legacy profile path" }
    }
} finally { $zip.Dispose() }
if ($pathHits) { $pathHits | Sort-Object -Unique | ForEach-Object { Fail "internal path: $_" } }
else { Pass 'no maintainer user-profile paths' }

Write-Host ''
if ($failures -gt 0) {
    Write-Host "SOURCE-AUDIT-FAIL ($failures problems)"
    exit 1
}
Write-Host 'SOURCE-AUDIT-OK'
exit 0
