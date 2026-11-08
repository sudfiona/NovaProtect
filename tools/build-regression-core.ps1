[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$version=(Get-Content -LiteralPath (Join-Path $root 'VERSION') -Raw).Trim()
$output=Join-Path $root "artifacts\test-only-core-$version"
New-Item -ItemType Directory -Force -Path $output|Out-Null
$gcc='C:\mingw\mingw64\bin\g++.exe'
Push-Location $root
try{
  # Relative output path: the checkout lives under non-ASCII directory names and
  # an absolute path is re-encoded through the OEM code page on the way to the
  # child compiler, so ld reports "cannot open output file <mojibake>".
  $relOutput = "artifacts\test-only-core-$version"
  # Source list must mirror build.ps1's engine link line, otherwise the
  # regression core silently tests an older product surface: it kept missing the
  # whole evasion subsystem for a release.
  & $gcc -std=c++17 -O2 -municode -o "$relOutput\CoreRegression.exe" src\main.cpp tests\core_test_gate.cpp src\managed_envelope.cpp src\pe_lib.cpp src\packer.cpp src\packer_meta.cpp src\mutation.cpp src\disasm.cpp src\anti_debug.cpp src\vm_engine.cpp src\vm_obfuscate.cpp src\vm_revirt.cpp src\crypto_layers.cpp src\crypto_stream.cpp src\evasion.cpp src\evasion_entropy.cpp src\evasion_variants.cpp src\evasion_hypervisor.cpp src\evasion_kernel.cpp src\evasion_static.cpp src\evasion_dynamic.cpp src\junk_emitter.cpp src\api_unhook.cpp src\mem_loader.cpp src\white_launcher.cpp -Iinclude -Isrc -static -static-libgcc -static-libstdc++ -lbcrypt
  if($LASTEXITCODE){throw 'Test-only core build failed'}
}finally{Pop-Location}
Write-Host "TEST-ONLY-CORE $output\CoreRegression.exe (not part of installer/website)"
