# Driver-emitter check: the emitted ring-0 source must build for real.
#
# Two stages, in order of strength:
#   1. parse check  -- MinGW's C front end against tools/wdkshim (a stand-in for
#                      ntddk.h). Catches malformed C without needing a WDK.
#   2. real build   -- cl.exe /kernel with the installed WDK headers and
#                      ntoskrnl.lib, linked into a .sys. Catches everything the
#                      parse check cannot: wrong kernel types, missing kernels
#                      exports, linker problems.
#
# Stage 2 runs only when a WDK is detected, and says so when it is skipped. Even
# when it runs, the result is an unsigned test image: this script does not sign,
# install or load the driver.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    $gcc = 'C:\mingw\mingw64\bin\gcc.exe'
    $version = (Get-Content -LiteralPath 'VERSION' -Raw).Trim()
    $core = "artifacts\test-only-core-$version\CoreRegression.exe"
    if (-not (Test-Path $core)) { throw "build artifacts\test-only-core-$version\CoreRegression.exe first" }
    if (-not (Test-Path 'tools\wdkshim\ntddk.h')) { throw 'tools\wdkshim\ntddk.h missing' }

    $out = 'artifacts\driver-emit'
    New-Item -ItemType Directory -Force -Path $out | Out-Null

    $cases = @(
        @{ name = 'balanced';  args = @('-kernel-driver-out', "$out\np_hv_driver.c");  scrub = $false },
        @{ name = 'paranoid';  args = @('-evasion', 'paranoid', '-kernel-driver-out', "$out\np_hv_driver_paranoid.c"); scrub = $true }
    )

    $checks = 0
    $failures = 0
    foreach ($case in $cases) {
        $file = $case.args[-1]
        & $core @($case.args) 2>&1 | Out-Null
        if (-not (Test-Path $file)) { throw "emitter produced no file for $($case.name)" }

        $checks++
        Write-Host "  ok   $($case.name): source emitted ($((Get-Item $file).Length) bytes)"

        $text = Get-Content -LiteralPath $file -Raw
        $checks++
        if ($text -match 'DriverEntry' -and $text -match 'IOCTL_NP_HV_QUERY' -and $text -match '__readmsr') {
            Write-Host "  ok   $($case.name): carries DriverEntry, the IOCTL and an MSR read"
        } else {
            $failures++; Write-Host "  FAIL $($case.name): required ring-0 entry points missing"
        }

        $checks++
        $hasScrub = ($text -match 'np_scrub_module_list')
        if ($hasScrub -eq $case.scrub) {
            Write-Host "  ok   $($case.name): module-list scrubbing $(if ($case.scrub) { 'present' } else { 'absent' }) as configured"
        } else {
            $failures++; Write-Host "  FAIL $($case.name): scrubbing does not match the profile"
        }

        # Stage 1: parse. Compiled exactly as emitted; the shim only supplies
        # ntddk.h, nothing is rewritten.
        $checks++
        $compile = & $gcc -std=gnu11 -fsyntax-only -Itools\wdkshim $file 2>&1 | Out-String
        if ($LASTEXITCODE -eq 0) {
            Write-Host "  ok   $($case.name): parses as C (MinGW front end, wdk shim for ntddk.h)"
        } else {
            $failures++; Write-Host "  FAIL $($case.name): does not parse`n$compile"
        }
    }

    Write-Host "DRIVER-EMIT-OK ($checks checks, parse level)"

    # Stage 2: the real thing, when a WDK is installed.
    $wdkScript = 'tools\build-driver-wdk.ps1'
    $wdkPresent = Test-Path 'C:\Windows Kits\10\Include' -PathType Container
    if ($wdkPresent) {
        Write-Host ''
        Write-Host '== WDK detected: building the driver for real =='
        & $wdkScript 2>&1 | ForEach-Object { Write-Host "  $_" }
        if ($LASTEXITCODE -ne 0) { throw 'WDK driver build failed' }
    } else {
        Write-Host ''
        Write-Host 'No WDK under C:\Windows Kits\10: the real build was skipped, so the'
        Write-Host 'driver has NOT been proven to compile with cl.exe /kernel or to link.'
    }

    if ($failures) { throw "$failures driver-emit check(s) failed" }
}
finally { Pop-Location }
