# NovaProtect build script (PowerShell, UTF-8 no BOM; VERSION is authoritative)
param(
  [switch]$Stub,     # rebuild stub blobs from .S
  [switch]$Prot,     # rebuild protection runtime blob (runtime/prot64.c)
  [switch]$Mut,      # rebuild mutation kernel template (runtime/mutkern.S)
  [switch]$ManagedHost, # build the CLR-safe encrypted EXE host
  [switch]$Cli,      # build internal NovaProtect.Engine.exe (not a CLI API)
  [switch]$WinUi,    # build the C# WinUI 3 client
  [switch]$All
)
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$env:Path = 'C:\mingw\mingw64\bin;' + $env:Path
& (Join-Path $root 'tools\version.ps1') -Action Check
if ($LASTEXITCODE -ne 0) { throw 'version policy check failed' }
if ($All) { $Stub = $true; $Prot = $true; $Mut = $true; $ManagedHost = $true; $Cli = $true; $WinUi = $true }
if (-not ($Stub -or $Prot -or $Mut -or $ManagedHost -or $Cli -or $WinUi)) { $Stub = $true; $Prot = $true; $Mut = $true; $ManagedHost = $true; $Cli = $true; $WinUi = $true }

$utf8 = [System.Text.UTF8Encoding]::new($false)
# The commercial VMProtect SDK is optional. When it is installed next to the
# workspace the build links the real import library; on an open-source clone
# without the SDK the marker calls compile to no-ops (NOVAPROTECT_VMP_STUB)
# and no VMProtectSDK64.dll is required at runtime.
# Resolve the commercial VMProtect SDK. Priority:
#   1. project-vendored third_party\vmprotect (checked in with the release)
#   2. sibling "VMProtect Professional" install
#   3. common absolute install paths
# On success the real import library is linked and VMProtectSDK64.dll is
# copied next to the protected binaries. Otherwise the same call sites compile
# to no-ops via NOVAPROTECT_VMP_STUB (open-source clones).
$vmpResolve = & (Join-Path $root 'tools\resolve-vmprotect-sdk.ps1') 2>$null | Out-String
$vmpSdkLibrary = ''
$vmpSdkRuntime = ''
if ($vmpResolve -match 'NOVAPROTECT_VMP_LIB=(.+)') { $vmpSdkLibrary = $Matches[1].Trim() }
if ($vmpResolve -match 'NOVAPROTECT_VMP_DLL=(.+)') { $vmpSdkRuntime = $Matches[1].Trim() }
$vmpDefine = ''
$vmpLink = @()
if ($vmpSdkLibrary -ne '' -and (Test-Path -LiteralPath $vmpSdkLibrary)) {
  # Hand the linker a workspace-relative path. The checkout lives under
  # non-ASCII directory names, and an absolute path gets re-encoded through the
  # OEM code page when the compiler child process receives it, which makes ld
  # report "cannot find <mojibake>.a" for a file that is plainly there.
  $vmpRel = $vmpSdkLibrary
  if ($vmpRel.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) {
    $vmpRel = '.' + $vmpRel.Substring($root.Length)
  }
  $vmpLink = @($vmpRel)
  Write-Host "[vmp] linking VMProtect SDK import library: $vmpRel"
} else {
  $vmpDefine = '-DNOVAPROTECT_VMP_STUB'
  Write-Host '[vmp] VMProtect SDK not found; building with no-op SDK markers (NOVAPROTECT_VMP_STUB)'
}
if ($Cli -or $WinUi) { & (Join-Path $root 'tools\client-integrity.ps1') -Action Prepare }

function Build-Stub {
  Push-Location $root
  Write-Host '[stub] assembling x64...'
  & as.exe runtime\stub.S -o runtime\stub.o
  if ($LASTEXITCODE -ne 0) { throw 'as x64 failed' }
  & objcopy.exe -O binary --only-section=.text runtime\stub.o runtime\stub.bin
  if ($LASTEXITCODE -ne 0) { throw 'objcopy x64 failed' }
  Write-Host '[stub] assembling x86...'
  & as.exe --32 runtime\stub32.S -o runtime\stub32.o
  if ($LASTEXITCODE -ne 0) { throw 'as x86 failed' }
  & objcopy.exe -O binary --only-section=.text runtime\stub32.o runtime\stub32.bin
  if ($LASTEXITCODE -ne 0) { throw 'objcopy x86 failed' }

  $b64 = [IO.File]::ReadAllBytes("$root\runtime\stub.bin")
  $b32 = [IO.File]::ReadAllBytes("$root\runtime\stub32.bin")
  $sb = New-Object System.Text.StringBuilder
  [void]$sb.AppendLine('#pragma once')
  [void]$sb.AppendLine('#include <cstdint>')
  [void]$sb.AppendLine('')
  [void]$sb.AppendLine('// Auto-generated unpacker stub blobs. Do not edit by hand.')
  [void]$sb.AppendLine('// Regenerate with: powershell -File build.ps1 -Stub')
  [void]$sb.AppendLine('')
  $sb.AppendLine("inline constexpr uint8_t kUnpackerStub[] = {") | Out-Null
  for ($i = 0; $i -lt $b64.Length; $i += 16) {
    $line = '    '
    for ($j = 0; $j -lt 16 -and ($i + $j) -lt $b64.Length; $j++) {
      $line += ('0x{0:x2}, ' -f $b64[$i + $j])
    }
    $sb.AppendLine($line.TrimEnd()) | Out-Null
  }
  $sb.AppendLine('};') | Out-Null
  $sb.AppendLine("inline constexpr uint32_t kUnpackerStubSize = $($b64.Length);") | Out-Null
  $sb.AppendLine('') | Out-Null
  $sb.AppendLine('inline constexpr uint8_t kUnpackerStub32[] = {') | Out-Null
  for ($i = 0; $i -lt $b32.Length; $i += 16) {
    $line = '    '
    for ($j = 0; $j -lt 16 -and ($i + $j) -lt $b32.Length; $j++) {
      $line += ('0x{0:x2}, ' -f $b32[$i + $j])
    }
    $sb.AppendLine($line.TrimEnd()) | Out-Null
  }
  $sb.AppendLine('};') | Out-Null
  $sb.AppendLine("inline constexpr uint32_t kUnpackerStub32Size = $($b32.Length);") | Out-Null
  [IO.File]::WriteAllText("$root\src\stub_blob.h", $sb.ToString(), $utf8)
  Write-Host "[stub] x64=$($b64.Length) x86=$($b32.Length) -> src\stub_blob.h"
  Pop-Location
}

function Build-Prot {
  Push-Location $root
  Write-Host '[prot] compiling x64 protection runtime...'
  & gcc.exe -c -o runtime\prot64_entry.o runtime\prot64_entry.S
  if ($LASTEXITCODE -ne 0) { throw 'gcc prot64_entry failed' }
  & gcc.exe -c -O2 -ffreestanding -fno-stack-protector -fno-asynchronous-unwind-tables -fno-unwind-tables -fno-ident -fPIC -mno-red-zone -fno-tree-vectorize -Wall -Wextra -o runtime\prot64.o runtime\prot64.c
  if ($LASTEXITCODE -ne 0) { throw 'gcc prot64 failed' }
  & ld.exe -m i386pep -T runtime\prot64.ld --section-alignment 16 --file-alignment 16 -o runtime\prot64.ldimg runtime\prot64_entry.o runtime\prot64.o
  if ($LASTEXITCODE -ne 0) { throw 'ld prot64 failed' }
  & objcopy.exe -O binary -j .np_text -j .np_rdat -j .np_data runtime\prot64.ldimg runtime\prot64.bin
  if ($LASTEXITCODE -ne 0) { throw 'objcopy prot64 failed' }

  # Section sizes and VMAs from the link image. objcopy -O binary lays the
  # sections out at their relative VMAs and keeps the alignment gaps, so a
  # section's offset inside prot64.bin is (VMA - link base) - NOT the sum of
  # the preceding section sizes.
  $bssSize = 0
  $bssVma = 0
  $secVma = @{ '.np_text' = 0; '.np_rdat' = 0; '.np_data' = 0 }
  $secSize = @{ '.np_text' = 0; '.np_rdat' = 0; '.np_data' = 0 }
  $hdr = & objdump.exe -h runtime\prot64.ldimg 2>$null | Out-String
  foreach ($ln in $hdr -split "`r?`n") {
    if ($ln -match '^\s*\d+\s+(\.np_\w+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)') {
      $nm = $Matches[1]
      if ($secSize.ContainsKey($nm)) {
        $secSize[$nm] = [Convert]::ToUInt32($Matches[2], 16)
        $secVma[$nm]  = [Convert]::ToUInt64($Matches[3], 16)
      }
      if ($nm -eq '.np_bss') {
        $bssSize = [Convert]::ToUInt32($Matches[2], 16)
        $bssVma  = [Convert]::ToUInt64($Matches[3], 16)
      }
    }
  }

  # Link-time base from the linker script (must stay the single source).
  $linkBase = 0
  foreach ($ln in ([IO.File]::ReadAllLines("$root\runtime\prot64.ld"))) {
    if ($ln -match '^\s*\.\s*=\s*0x([0-9a-fA-F]+)\s*;') { $linkBase = [Convert]::ToUInt64($Matches[1], 16); break }
  }
  if ($linkBase -eq 0) { throw 'could not parse link base from runtime\prot64.ld' }

  $pb = [IO.File]::ReadAllBytes("$root\runtime\prot64.bin")
  if ($pb.Length -eq 0) { throw 'prot64 blob is empty' }

  # Layout invariants the packer and the runtime's PC-relative references
  # both depend on. A failure here means the linker script was changed in a
  # way that desynchronises the extracted blob from the VMA space.
  if ($secVma['.np_text'] -ne $linkBase) { throw 'np_text does not start at the link base' }
  foreach ($nm in @('.np_text', '.np_rdat', '.np_data')) {
    $o = $secVma[$nm] - $linkBase
    if ($o + $secSize[$nm] -gt $pb.Length) {
      throw ("$nm (VMA 0x$($secVma[$nm].ToString('x'))) extends past prot64.bin ($($pb.Length) bytes)")
    }
  }
  if ($bssVma -ne 0 -and ($bssVma - $linkBase) -ne $pb.Length) {
    throw ("np_bss VMA 0x$($bssVma.ToString('x')) is not directly behind prot64.bin (blob $($pb.Length) bytes) - the packer deploys the zeroed statics window there")
  }

  # Tripwire: the blob is deployed at an arbitrary load base with no reloc
  # table, so every reference must be PC-relative. An 8-byte value inside the
  # data sections that points back into the link-time image means someone
  # reintroduced a pointer table (const char* array / struct with pointer
  # members) - it would dangle at run time. Fail the build instead.
  $extent = [uint64]$pb.Length + [uint64]$bssSize
  $bad = @()
  foreach ($nm in @('.np_rdat', '.np_data')) {
    $o = $secVma[$nm] - $linkBase
    $s = $secSize[$nm]
    if ($s -lt 8) { continue }
    for ($i = 0; $i + 8 -le $s; $i++) {
      $v = [BitConverter]::ToUInt64($pb, $o + $i)
      if ($v -ge $linkBase -and $v -lt ($linkBase + $extent)) {
        $bad += ("$nm+0x{0:x} -> 0x{1:x}" -f $i, $v)
      }
    }
  }
  if ($bad.Count -gt 0) {
    throw ("prot64 blob contains $($bad.Count) absolute link-time pointer(s) in .np_rdat/.np_data: " + ($bad -join '; ') + ". Pointer tables dangle once the packer deploys the blob at a load base != 0x$($linkBase.ToString('x')). Use fixed-width char matrices (see kTemplates/kTags) so references stay RIP-relative.")
  }

  $sb = New-Object System.Text.StringBuilder
  [void]$sb.AppendLine('#pragma once')
  [void]$sb.AppendLine('#include <cstdint>')
  [void]$sb.AppendLine('')
  [void]$sb.AppendLine('// Auto-generated x64 protection runtime blob (runtime/prot64.c).')
  [void]$sb.AppendLine('// Blob offset 0 is the entry trampoline (np_blob_entry -> np_prot_start).')
  [void]$sb.AppendLine('// Regenerate with: powershell -File build.ps1 -Prot')
  [void]$sb.AppendLine('')
  $sb.AppendLine('inline constexpr uint8_t kProtBlob64[] = {') | Out-Null
  for ($i = 0; $i -lt $pb.Length; $i += 16) {
    $line = '    '
    for ($j = 0; $j -lt 16 -and ($i + $j) -lt $pb.Length; $j++) {
      $line += ('0x{0:x2}, ' -f $pb[$i + $j])
    }
    $sb.AppendLine($line.TrimEnd()) | Out-Null
  }
  $sb.AppendLine('};') | Out-Null
  $sb.AppendLine("inline constexpr uint32_t kProtBlob64Size = $($pb.Length);") | Out-Null
  $sb.AppendLine("inline constexpr uint32_t kProtBlob64BssSize = $bssSize;") | Out-Null
  $sb.AppendLine("inline constexpr uint64_t kProtBlob64LinkBase = 0x$($linkBase.ToString('x'));") | Out-Null
  # An absent section has size 0 - emit 0/0 instead of a wrapped offset.
  $rdOff = if ($secSize['.np_rdat']) { $secVma['.np_rdat'] - $linkBase } else { 0 }
  $dtOff = if ($secSize['.np_data'])  { $secVma['.np_data']  - $linkBase } else { 0 }
  $sb.AppendLine("inline constexpr uint32_t kProtBlob64RdataOff = $rdOff;") | Out-Null
  $sb.AppendLine("inline constexpr uint32_t kProtBlob64RdataSize = $($secSize['.np_rdat']);") | Out-Null
  $sb.AppendLine("inline constexpr uint32_t kProtBlob64DataOff = $dtOff;") | Out-Null
  $sb.AppendLine("inline constexpr uint32_t kProtBlob64DataSize = $($secSize['.np_data']);") | Out-Null
  [IO.File]::WriteAllText("$root\src\prot_blob.h", $sb.ToString(), $utf8)
  Write-Host "[prot] $($pb.Length) bytes (+$bssSize bss, rdata @$rdOff+$($secSize['.np_rdat'])) -> src\prot_blob.h"
  Pop-Location
}
function Build-Mut {
  Push-Location $root
  Write-Host '[mut] assembling x64 mutation kernel template...'
  & as.exe runtime\mutkern.S -o runtime\mutkern.o
  if ($LASTEXITCODE -ne 0) { throw 'as mutkern failed' }
  & objcopy.exe -O binary --only-section=.text runtime\mutkern.o runtime\mutkern.bin
  if ($LASTEXITCODE -ne 0) { throw 'objcopy mutkern failed' }

  $mb = [IO.File]::ReadAllBytes("$root\runtime\mutkern.bin")
  if ($mb.Length -eq 0) { throw 'mutkern blob is empty' }
  $sb = New-Object System.Text.StringBuilder
  [void]$sb.AppendLine('#pragma once')
  [void]$sb.AppendLine('#include <cstdint>')
  [void]$sb.AppendLine('')
  [void]$sb.AppendLine('// Auto-generated x64 mutation kernel template (runtime/mutkern.S).')
  [void]$sb.AppendLine('// The packer patches four 8-byte constants before emitting the kernel:')
  [void]$sb.AppendLine('//   +2 basis  +28 prime  +47 seed  +64 prime2')
  [void]$sb.AppendLine('// ABI: rcx = buffer, rdx = length -> rax = 64-bit hash.')
  [void]$sb.AppendLine('')
  $sb.AppendLine('inline constexpr uint8_t kMutationKernel64[] = {') | Out-Null
  for ($i = 0; $i -lt $mb.Length; $i += 16) {
    $line = '    '
    for ($j = 0; $j -lt 16 -and ($i + $j) -lt $mb.Length; $j++) {
      $line += ('0x{0:x2}, ' -f $mb[$i + $j])
    }
    $sb.AppendLine($line.TrimEnd()) | Out-Null
  }
  $sb.AppendLine('};') | Out-Null
  $sb.AppendLine("inline constexpr uint32_t kMutationKernel64Size = $($mb.Length);") | Out-Null
  $sb.AppendLine('') | Out-Null
  $sb.AppendLine('constexpr uint32_t kMutKernBasisOff  = 2;') | Out-Null
  $sb.AppendLine('constexpr uint32_t kMutKernPrimeOff  = 28;') | Out-Null
  $sb.AppendLine('constexpr uint32_t kMutKernSeedOff   = 47;') | Out-Null
  $sb.AppendLine('constexpr uint32_t kMutKernPrime2Off = 64;') | Out-Null
  [IO.File]::WriteAllText("$root\src\mutkern_blob.h", $sb.ToString(), $utf8)
  Write-Host "[mut] $($mb.Length) bytes -> src\mutkern_blob.h"
  Pop-Location
}
function Build-Cli {
  Push-Location $root
  Write-Host '[core] compiling NovaProtect.Engine.exe...'
  & windres.exe runtime\novaprotect_cli.rc -O coff -o runtime\novaprotect_cli.res
  if ($LASTEXITCODE -ne 0) { throw 'cli resource build failed' }
  $vmpArgs = @(); if ($vmpDefine -ne "") { $vmpArgs += $vmpDefine }
  & g++.exe -std=c++17 -O2 -municode @vmpArgs -o NovaProtect.Engine.exe src\main.cpp src\client_gate.cpp src\managed_envelope.cpp src\pe_lib.cpp src\packer.cpp src\packer_meta.cpp src\mutation.cpp src\disasm.cpp src\anti_debug.cpp src\vm_engine.cpp src\vm_obfuscate.cpp src\vm_revirt.cpp src\crypto_layers.cpp src\crypto_stream.cpp src\evasion.cpp src\evasion_static.cpp src\evasion_dynamic.cpp src\evasion_entropy.cpp src\evasion_variants.cpp src\evasion_hypervisor.cpp src\evasion_kernel.cpp src\junk_emitter.cpp src\api_unhook.cpp src\mem_loader.cpp src\white_launcher.cpp runtime\novaprotect_cli.res @vmpLink -Iinclude -Isrc -static -static-libgcc -static-libstdc++ -lbcrypt
  if ($LASTEXITCODE -ne 0) { throw 'cli build failed' }
  Write-Host '[cli] ok'
  # The engine links the commercial VMProtect SDK, so its runtime DLL has to
  # sit next to the binary - otherwise the engine fails to start with
  # STATUS_DLL_NOT_FOUND before it can do any work.
  if ($vmpSdkRuntime -and (Test-Path -LiteralPath $vmpSdkRuntime)) {
    Copy-Item -LiteralPath $vmpSdkRuntime -Destination (Join-Path $root 'VMProtectSDK64.dll') -Force
  }
  Pop-Location
}

function Build-ManagedHost {
  Push-Location $root
  Write-Host '[managed-host] compiling NovaProtect.ManagedHost.exe...'
  & windres.exe runtime\managed_host.rc -O coff -o runtime\managed_host.res
  if ($LASTEXITCODE -ne 0) { throw 'managed host resource build failed' }
  $vmpArgs = @(); if ($vmpDefine -ne "") { $vmpArgs += $vmpDefine }
  & g++.exe -std=c++17 -O2 -municode @vmpArgs -o NovaProtect.ManagedHost.exe runtime\managed_host.cpp runtime\managed_host.res @vmpLink -static -static-libgcc -static-libstdc++
  if ($LASTEXITCODE -ne 0) { throw 'managed host build failed' }
  Write-Host '[managed-host] ok'
  # Same as the engine: the SDK runtime belongs next to the binary.
  if ($vmpSdkRuntime -and (Test-Path -LiteralPath $vmpSdkRuntime)) {
    Copy-Item -LiteralPath $vmpSdkRuntime -Destination (Join-Path $root 'VMProtectSDK64.dll') -Force
  }
  Pop-Location
}

function Build-WinUi {
  Push-Location $root
  $project = Join-Path $root 'ui\NovaProtect.UI.csproj'
  if (-not (Test-Path $project)) {
    Pop-Location
    throw 'WinUI project not found: ui\NovaProtect.UI.csproj'
  }

  $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
  $msbuild = $null
  if (Test-Path $vswhere) {
    $vsCandidates = @(& $vswhere -products Microsoft.VisualStudio.Product.Community -requires Microsoft.Component.MSBuild -property installationPath)
    $vsCandidates += @(& $vswhere -products Microsoft.VisualStudio.Product.Professional,Microsoft.VisualStudio.Product.Enterprise -requires Microsoft.Component.MSBuild -property installationPath)
    foreach ($vs in $vsCandidates) {
      if ([string]::IsNullOrWhiteSpace($vs)) { continue }
      $candidate = Join-Path $vs 'MSBuild\Current\Bin\MSBuild.exe'
      $sdkResolver = Join-Path $vs 'MSBuild\Current\Bin\SdkResolvers\Microsoft.DotNet.MSBuildSdkResolver\Microsoft.DotNet.MSBuildSdkResolver.dll'
      if ((Test-Path $candidate) -and (Test-Path $sdkResolver)) { $msbuild = $candidate; break }
    }
  }

  Write-Host '[winui] building NovaProtect.UI...'
  if ($msbuild) {
    Write-Host "[winui] using MSBuild: $msbuild"
    & $msbuild $project /restore /t:Build /p:Configuration=Release /p:Platform=x64 /v:minimal /nologo
  } else {
    Write-Host '[winui] using dotnet msbuild'
    & dotnet msbuild $project /restore /t:Build /p:Configuration=Release /p:Platform=x64 /v:minimal /nologo
  }
  if ($LASTEXITCODE -ne 0) { Pop-Location; throw 'WinUI build failed' }
  Write-Host '[winui] ok'
  # $vmpSdkRuntime is empty when the commercial SDK is absent; Test-Path throws
  # on an empty LiteralPath under ErrorActionPreference=Stop and would abort
  # the whole build after every artifact was already produced.
  if ($vmpSdkRuntime -and (Test-Path -LiteralPath $vmpSdkRuntime)) {
    Copy-Item -LiteralPath $vmpSdkRuntime -Destination (Join-Path $root 'ui\bin\x64\Release\net10.0-windows10.0.19041.0\win-x64\VMProtectSDK64.dll') -Force
  }
  & (Join-Path $root 'tools\client-integrity.ps1') -Action Sign -Directory (Join-Path $root 'ui\bin\x64\Release\net10.0-windows10.0.19041.0\win-x64')
  Pop-Location
}

if ($Stub) { Build-Stub }
if ($Prot) { Build-Prot }
if ($Mut)  { Build-Mut }
if ($ManagedHost) { Build-ManagedHost }
if ($Cli)  { Build-Cli }
if ($WinUi) { Build-WinUi }
Write-Host 'build complete'







