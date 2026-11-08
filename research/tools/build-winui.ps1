# Build the WinUI client and capture the compiler output to a file.
# The build script swallows the MSBuild diagnostics, so this wrapper writes
# them out where they can be read.
$root = 'C:\npbuild'
$msbuild = 'D:\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe'
$log = Join-Path $root 'output\winui-build.log'
$project = Join-Path $root 'ui\NovaProtect.UI.csproj'

Push-Location (Join-Path $root 'ui')
& $msbuild $project /restore /t:Build /p:Configuration=Release /p:Platform=x64 /v:normal /nologo *>&1 |
    Out-File -FilePath $log -Encoding utf8
$code = $LASTEXITCODE
Pop-Location

Write-Host "msbuild exit: $code"
Write-Host "log: $log"
exit $code
