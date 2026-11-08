# Drive the NovaProtect window far enough to produce one packed sample.
#
# The engine's invocation gate only opens for a child of the real client process,
# so this drives the real controls instead of calling the engine directly.
param(
    [Parameter(Mandatory = $true)][int]$TargetProcessId,
    [Parameter(Mandatory = $true)][string]$InputFile,
    [Parameter(Mandatory = $true)][string]$OutputFile,
    [int]$RunSeconds = 180
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes

$AE = [System.Windows.Automation.AutomationElement]
$scope = [System.Windows.Automation.TreeScope]

$window = $AE::RootElement.FindFirst(
    $scope::Children,
    [System.Windows.Automation.PropertyCondition]::new($AE::ProcessIdProperty, $TargetProcessId))
if (-not $window) { throw "no top-level window for pid $TargetProcessId" }

function Find-All-AutomationId([string]$id) {
    return $window.FindAll(
        $scope::Descendants,
        [System.Windows.Automation.PropertyCondition]::new($AE::AutomationIdProperty, $id))
}

function Set-EditByIndex([int]$index, [string]$value) {
    $edits = $window.FindAll(
        $scope::Descendants,
        [System.Windows.Automation.PropertyCondition]::new($AE::ControlTypeProperty, [System.Windows.Automation.ControlType]::Edit))
    if ($edits.Count -le $index) { throw "only $($edits.Count) edit fields, wanted index $index" }
    $pattern = $edits[$index].GetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern)
    $pattern.SetValue($value)
    Write-Host "  edit[$index] = $value"
}

Write-Host '[driver] setting paths'
Set-EditByIndex 0 $InputFile
Set-EditByIndex 1 $OutputFile

$start = $window.FindAll(
    $scope::Descendants,
    [System.Windows.Automation.PropertyCondition]::new($AE::NameProperty, '开始保护'))
if ($start.Count -eq 0) { throw 'no 开始保护 element' }

# WinUI puts the label in a TextBlock and the clickable surface on an ancestor,
# so walk up until something actually exposes InvokePattern.
$invokable = $null
foreach ($candidate in $start) {
    $node = $candidate
    for ($depth = 0; $depth -lt 6 -and $node; $depth++) {
        $pattern = $null
        if ($node.TryGetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern, [ref]$pattern)) {
            $invokable = $node
            break
        }
        $node = [System.Windows.Automation.TreeWalker]::ControlViewWalker.GetParent($node)
    }
    if ($invokable) { break }
}
if (-not $invokable) { throw 'no invokable ancestor for 开始保护' }

$invoke = $invokable.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern)
$invoke.Invoke()
Write-Host '[driver] invoked 开始保护'

$deadline = (Get-Date).AddSeconds($RunSeconds)
while ((Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 3
    if (Test-Path $OutputFile) {
        $size = (Get-Item $OutputFile).Length
        if ($size -gt 0) {
            Write-Host "[driver] output present: $size bytes"
            Start-Sleep -Seconds 4
            if ((Get-Item $OutputFile).Length -eq $size) {
                Write-Host '[driver] size stable, done'
                break
            }
        }
    }
}

if (-not (Test-Path $OutputFile)) { throw 'output never appeared' }
Write-Host "[driver] final: $((Get-Item $OutputFile).Length) bytes"
