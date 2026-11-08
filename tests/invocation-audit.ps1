# Reference implementation of the client-invocation handshake, kept as
# documentation of the protocol between the client and the protection core.
#
# IT CANNOT SUCCEED FROM THIS SCRIPT, BY DESIGN. The core's gate (src/client_gate.cpp)
# requires the pipe's server process to be the core's own parent AND for that
# parent's image to be <core dir>\NovaProtect.exe, alive, and covered by the signed
# manifest. A standalone PowerShell host fails at the "server-pid" stage and the
# core exits. Use tests\ui-automation.ps1 instead: it drives the real buttons in
# the real window, which is the only context where the gate is satisfied.
#
# The handshake below is still accurate and useful when reading or re-implementing
# the client side (ui/Services/ClientInvocation.cs):
#   1. host creates a random named pipe with CurrentUserOnly
#   2. host sets NOVAPROTECT_INVOCATION_PIPE in the child's environment
#   3. child connects and writes a 40-byte challenge starting with "NPGATE01"
#   4. host verifies the connecting process id and echoes the challenge back
#   5. child proceeds and prints its audit result
param(
    [Parameter(Mandatory = $true)][string]$Engine,
    [Parameter(Mandatory = $true)][string[]]$EngineArgs
)

$ErrorActionPreference = 'Stop'

# Windows PowerShell 5.1 sits on .NET Framework: neither the static GetBytes(int)
# nor Convert.ToHexString exists there, so use the instance RNG and hand-format.
$rng = [Security.Cryptography.RandomNumberGenerator]::Create()
try {
    $entropy = [byte[]]::new(16)
    $rng.GetBytes($entropy)
} finally {
    $rng.Dispose()
}
$name = 'novaprotect-' + (($entropy | ForEach-Object { $_.ToString('x2') }) -join '')

$pipe = [IO.Pipes.NamedPipeServerStream]::new(
    $name,
    [IO.Pipes.PipeDirection]::InOut,
    1,
    [IO.Pipes.PipeTransmissionMode]::Byte,
    [IO.Pipes.PipeOptions]::Asynchronous -bor [IO.Pipes.PipeOptions]::CurrentUserOnly,
    4096,
    4096)

$psi = [Diagnostics.ProcessStartInfo]::new($Engine)
# ProcessStartInfo.ArgumentList is a .NET Core API; on .NET Framework the
# argument vector has to be handed over as one pre-quoted string.
$psi.Arguments = (($EngineArgs | ForEach-Object { '"' + $_ + '"' }) -join ' ')
$psi.UseShellExecute = $false
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.CreateNoWindow = $true
$psi.StandardOutputEncoding = [Text.Encoding]::UTF8
$psi.StandardErrorEncoding = [Text.Encoding]::UTF8
$psi.EnvironmentVariables['NOVAPROTECT_INVOCATION_PIPE'] = $name

$result = 'unknown'
try {
    $process = [Diagnostics.Process]::Start($psi)
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()

    # The engine connects within milliseconds when the gate is satisfied; a long
    # block here means the pipe name never reached it.
    $wait = $pipe.BeginWaitForConnection($null, $null)
    if (-not $wait.AsyncWaitHandle.WaitOne(10000)) {
        "  HANDSHAKE FAILED: engine never connected"
        return
    }
    $pipe.EndWaitForConnection($wait)

    $challenge = [byte[]]::new(40)
    $read = 0
    while ($read -lt 40) {
        $n = $pipe.Read($challenge, $read, 40 - $read)
        if ($n -le 0) { break }
        $read += $n
    }
    if ($read -ne 40) {
        "  HANDSHAKE FAILED: short challenge ($read bytes)"
        return
    }
    $magic = [Text.Encoding]::ASCII.GetString($challenge, 0, 8)
    if ($magic -ne 'NPGATE01') {
        "  HANDSHAKE FAILED: bad magic '$magic'"
        return
    }

    $pipe.Write($challenge, 0, 40)
    $pipe.Flush()

    if (-not $process.WaitForExit(90000)) {
        "  HANDSHAKE OK but engine still running after 90s"
        return
    }

    $result = "handshake OK, exit=$($process.ExitCode)"
    "  $result"
    foreach ($line in ($stdout.Result -split "`r?`n")) {
        if ($line.Trim()) { "  | $line" }
    }
    foreach ($line in ($stderr.Result -split "`r?`n")) {
        if ($line.Trim()) { "  ! $line" }
    }
}
finally {
    $pipe.Dispose()
}
