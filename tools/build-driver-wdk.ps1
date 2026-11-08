# Build the emitted driver with the real WDK and MSVC.
#
# Unlike tools/test-driver-emit.ps1 (a parse check against a stand-in ntddk.h),
# this compiles and LINKS the source the emitter produces into a .sys using the
# installed WDK. That turns "the emitted C is well-formed" into "the WDK accepts
# it and the linker produces a kernel image".
#
# Scope note, stated so nobody over-reads the result: the output is an unsigned
# test binary. This script does not sign it, install it, load it, or run it in a
# VM. Loading an unsigned driver needs test-signing mode and a reboot.
[CmdletBinding()]
param(
    [string] $KitRoot = 'C:\Windows Kits\10',
    [string] $VsRoot  = 'D:\Microsoft Visual Studio\18\Community'
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    $version = (Get-Content -LiteralPath 'VERSION' -Raw).Trim()
    $core = "artifacts\test-only-core-$version\CoreRegression.exe"
    if (-not (Test-Path $core)) { throw "run tools\build-regression-core.ps1 first (need $core)" }

    # --- locate the WDK / MSVC pieces --------------------------------
    $incRoot = Join-Path $KitRoot 'Include'
    $kitVersion = Get-ChildItem $incRoot -Directory |
        Where-Object { $_.Name -match '^10\.0\.\d+\.0$' -and (Test-Path (Join-Path $_.FullName 'km\ntddk.h')) } |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $kitVersion) { throw "no WDK km headers under $incRoot" }
    $kitVer = $kitVersion.Name

    $kmInc  = Join-Path $incRoot "$kitVer\km"
    $shared = Join-Path $incRoot "$kitVer\shared"
    $ucrt   = Join-Path $incRoot "$kitVer\ucrt"
    $wdfInc = Join-Path $incRoot 'wdf\kmdf'
    $kmLib  = Join-Path $KitRoot "Lib\$kitVer\km\x64"

    $msvc = Get-ChildItem (Join-Path $VsRoot 'VC\Tools\MSVC') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    $cl    = Join-Path $msvc.FullName 'bin\Hostx64\x64\cl.exe'
    $link  = Join-Path $msvc.FullName 'bin\Hostx64\x64\link.exe'
    $msvcInc = Join-Path $msvc.FullName 'include'
    $msvcLib = Join-Path $msvc.FullName 'lib\x64'
    foreach ($tool in @($cl, $link)) { if (-not (Test-Path $tool)) { throw "missing $tool" } }
    foreach ($dir in @($kmInc, $kmLib, $msvcInc, $msvcLib)) {
        if (-not (Test-Path $dir)) { throw "missing $dir" }
    }

    Write-Host "WDK   : $kitVer"
    Write-Host "MSVC  : $($msvc.Name)"
    Write-Host "cl    : $cl"

    # --- emit the driver sources ------------------------------------
    $out = 'artifacts\driver-build'
    New-Item -ItemType Directory -Force -Path $out | Out-Null
    $cases = @(
        @{ name = 'plain';    args = @('-kernel-driver-out', "$out\np_hv_plain.c") },
        @{ name = 'paranoid'; args = @('-evasion', 'paranoid', '-kernel-driver-out', "$out\np_hv_paranoid.c") }
    )
    foreach ($case in $cases) {
        & $core @($case.args) 2>&1 | Out-Null
        if (-not (Test-Path $case.args[-1])) { throw "emitter produced nothing for $($case.name)" }
    }

    # The emitter writes a complete translation unit. WDK kernel builds normally
    # add -D_AMD64_, the KMDF version defines and the buffer-overflow fast-fail
    # stub library; all of that is supplied here.
    $defines = @(
        '/D_AMD64_', '/DAMD64', '/D_WIN64', '/DWIN32', '/D_WIN32',
        '/DNT', '/D_KERNEL', '/DKERNEL', '/DPOOL_NX_OPTIN=1',
        '/D_WIN32_WINNT=0x0A00', '/DNTDDI_VERSION=0x0A000000',
        '/DUNICODE', '/D_UNICODE'
    )
    $includes = @("/I$kmInc", "/I$shared", "/I$ucrt", "/I$msvcInc")
    if (Test-Path $wdfInc) { $includes += "/I$wdfInc" }

    $compileFlags = @(
        '/nologo', '/c', '/kernel', '/GS-', '/GR-', '/Gz', '/Zl',
        '/W4', '/WX-', '/Od', '/Z7', '/Gy', '/guard:cf-',
        '/D_CRT_SECURE_NO_WARNINGS'
    )

    $checks = 0
    $failures = 0
    $built = @()

    foreach ($case in $cases) {
        $src = $case.args[-1]
        $obj = [IO.Path]::ChangeExtension($src + '.obj', $null)
        $obj = "$src.obj"
        Write-Host "`n== $($case.name) =="

        $checks++
        $compile = & $cl @compileFlags @defines @includes "/Fo$obj" $src 2>&1 | Out-String
        if ($LASTEXITCODE -eq 0) {
            Write-Host "  ok   compiles with the WDK kernel switches (/kernel, /GS-)"
        } else {
            $failures++; Write-Host "  FAIL compile`n$compile"; continue
        }

        # Warnings matter: a kernel build that warns is a kernel build that is
        # one API change away from broken. Report the count, do not hide it.
        $warnings = ([regex]::Matches($compile, 'warning C\d+')).Count
        $checks++
        if ($warnings -le 2) {
            Write-Host "  ok   warning count is $warnings (<= 2)"
        } else {
            $failures++; Write-Host "  FAIL $warnings warnings`n$compile"
        }

        $checks++
        $sys = "$out\np_hv_$($case.name).sys"
        # "/OUT:$sys" has to be one token: passing '/OUT:' and the path as two
        # arguments makes the linker read the path as an input file and fail
        # with LNK1146.
        $linkArgs = @(
            '/nologo', '/DRIVER', '/SUBSYSTEM:NATIVE', '/ENTRY:DriverEntry',
            '/NODEFAULTLIB', "/OUT:$sys", '/MACHINE:X64', '/OPT:REF', '/DYNAMICBASE',
            $obj,
            "$kmLib\ntoskrnl.lib", "$kmLib\hal.lib",
            "$kmLib\BufferOverflowFastFailK.lib", "$kmLib\wdm.lib"
        )
        $linkOut = & $link @linkArgs 2>&1 | Out-String
        if ($LASTEXITCODE -eq 0 -and (Test-Path $sys)) {
            Write-Host "  ok   links to a native kernel image ($((Get-Item $sys).Length) bytes)"
        } else {
            $failures++; Write-Host "  FAIL link`n$linkOut"; continue
        }

        # The PE must actually be a driver: native subsystem, a real entry point,
        # and the device name the emitter writes (a UTF-16 string literal -- an
        # ASCII scan would miss it, and DriverEntry is not a symbol in the image
        # table after linking, so its name is the wrong thing to look for).
        $checks++
        $bytes = [IO.File]::ReadAllBytes((Resolve-Path $sys))
        $peOff = [BitConverter]::ToInt32($bytes, 0x3C)
        $subsystem = [BitConverter]::ToUInt16($bytes, $peOff + 0x5C)
        if ($subsystem -eq 1) {
            Write-Host "  ok   PE subsystem is NATIVE (1), i.e. a kernel-mode image"
        } else {
            $failures++; Write-Host "  FAIL PE subsystem is $subsystem, expected 1"
        }

        $checks++
        $entryRva = [BitConverter]::ToUInt32($bytes, $peOff + 0x28)
        if ($entryRva -ne 0) {
            Write-Host ("  ok   AddressOfEntryPoint is set (0x{0:X})" -f $entryRva)
        } else {
            $failures++; Write-Host "  FAIL AddressOfEntryPoint is zero"
        }

        $checks++
        $ascii = [Text.Encoding]::ASCII.GetString($bytes)
        $wide  = [Text.Encoding]::Unicode.GetString($bytes)
        if ($wide.Contains('NpHvProbe') -or $ascii.Contains('NpHvProbe')) {
            Write-Host "  ok   image carries the NpHvProbe device name"
        } else {
            $failures++; Write-Host "  FAIL image is missing the NpHvProbe device name"
        }

        $built += [pscustomobject]@{ case = $case.name; sys = $sys; bytes = (Get-Item $sys).Length; warnings = $warnings }
    }

    Write-Host ''
    $built | Format-Table -AutoSize | Out-String | Write-Host
    Write-Host "DRIVER-BUILD-OK ($checks checks) -- compiled and linked; NOT signed, NOT loaded"
    if ($failures) { throw "$failures driver build check(s) failed" }
    $global:LASTEXITCODE = 0
}
finally { Pop-Location }
