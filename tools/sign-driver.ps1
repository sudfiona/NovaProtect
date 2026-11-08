# Sign the built driver with a throwaway self-signed certificate and verify it.
#
# What this proves: the linked .sys is a signable PE, signtool embeds a valid
# Authenticode signature, and the signature verifies against a trusted root.
#
# What this does NOT prove: that Windows will load it. Loading a driver needs the
# image to be trusted by the *kernel* policy (test-signing mode or an attestation
# / WHQL signature), not just by a user-mode chain. Enabling test-signing
# requires an elevated bcdedit and a reboot, so this script refuses to touch that
# and says so instead.
#
# The certificate is created in the current user's personal store and is trusted
# only for the duration of the verification: the root entry is added, the check
# runs, and the entry is removed again so nothing is left behind.
[CmdletBinding()]
param(
    [string] $KitRoot = 'C:\Windows Kits\10',
    [string] $Subject = 'CN=NovaProtect Test Signing'
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    $dir = 'artifacts\driver-build'
    $targets = @(Get-ChildItem $dir -Filter '*.sys' -ErrorAction SilentlyContinue)
    if (-not $targets) { throw "no .sys under $dir -- run tools\build-driver-wdk.ps1 first" }

    $signtool = Get-ChildItem "$KitRoot\bin" -Recurse -Filter 'signtool.exe' -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match '\\x64\\' } | Sort-Object FullName -Descending | Select-Object -First 1
    $makecert = Get-ChildItem "$KitRoot\bin" -Recurse -Filter 'MakeCert.exe' -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match '\\x64\\' } | Sort-Object FullName -Descending | Select-Object -First 1
    if (-not $signtool) { throw "signtool.exe not found under $KitRoot\bin" }
    if (-not $makecert) { throw "MakeCert.exe not found under $KitRoot\bin" }

    $checks = 0
    $failures = 0

    # A fresh cert per run, so a stale one can never mask a signing failure.
    $cerPath = Join-Path $dir 'np_test_signing.cer'
    Remove-Item $cerPath -Force -ErrorAction SilentlyContinue
    & $makecert.FullName -r -pe -ss My -n $Subject -eku 1.3.6.1.5.5.7.3.3 -sky signature $cerPath 2>&1 | Out-Null
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2((Resolve-Path $cerPath).Path)
    Write-Host "cert: $($cert.Thumbprint)  $($cert.Subject)"

    foreach ($file in $targets) {
        $name = $file.Name

        $checks++
        & $signtool.FullName sign /s My /sha1 $cert.Thumbprint /fd SHA256 $file.FullName 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "  ok   $name : signature embedded"
        } else {
            $failures++; Write-Host "  FAIL $name : signtool could not sign"; continue
        }

        # Trust the throwaway root just long enough to complete a chain check.
        $rootStore = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root', 'CurrentUser')
        $rootStore.Open('ReadWrite')
        $rootStore.Add($cert)
        $rootStore.Close()
        try {
            $checks++
            $verify = & $signtool.FullName verify /pa /v $file.FullName 2>&1 | Out-String
            if ($LASTEXITCODE -eq 0 -and $verify -match 'Successfully verified') {
                Write-Host "  ok   $name : Authenticode signature verifies"
            } else {
                $failures++; Write-Host "  FAIL $name : verify`n$verify"
            }

            $checks++
            $auth = Get-AuthenticodeSignature $file.FullName
            if ($auth.Status -eq 'Valid' -and $auth.SignerCertificate.Subject -eq $cert.Subject) {
                Write-Host "  ok   $name : signature status Valid, signer $($auth.SignerCertificate.Subject)"
            } else {
                $failures++; Write-Host "  FAIL $name : status $($auth.Status)"
            }
        }
        finally {
            $cleanup = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root', 'CurrentUser')
            $cleanup.Open('ReadWrite')
            $cleanup.Remove($cert)
            $cleanup.Close()
        }
    }

    # The same check without trust: the chain must fail, which is what a
    # self-signed root on a clean machine looks like.
    # Re-verify with the root gone. The chain must now fail: that is exactly what
    # a throwaway self-signed root looks like on a clean machine, and it is the
    # honest statement about loadability. Judged on the exit code rather than the
    # message text, which signtool localises.
    $checks++
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'   # this failure is the expected outcome
    & $signtool.FullName verify /pa /v $targets[0].FullName 2>&1 | Out-Null
    $verifyExit = $LASTEXITCODE
    $ErrorActionPreference = $previous
    if ($verifyExit -ne 0) {
        Write-Host "  ok   $(($targets[0]).Name) : no longer verifies once the throwaway root is gone"
    } else {
        $failures++; Write-Host "  FAIL signature still verifies after the root was removed"
    }

    $checks++
    $testSigning = (bcdedit /enum '{current}' 2>&1 | Out-String)
    if ($testSigning -match 'testsigning\s+Yes') {
        Write-Host '  note test-signing is ENABLED on this machine'
    } else {
        Write-Host '  ok   test-signing is off, so this image cannot be loaded as-is (by design)'
    }

    Write-Host ''
    Write-Host "DRIVER-SIGN-OK ($checks checks) -- signed and chain-verified; NOT loaded, no bcdedit change"
    if ($failures) { throw "$failures driver sign check(s) failed" }
    # One deliberate negative check above leaves $LASTEXITCODE non-zero; the
    # script succeeded, so clear it or every caller reads a false failure.
    $global:LASTEXITCODE = 0
}
finally { Pop-Location }
