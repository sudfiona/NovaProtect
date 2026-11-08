# Drive the running NovaProtect window through UI Automation.
#
# The client's engine gate requires the invocation pipe's server process to be
# the engine's own parent and to be named NovaProtect.exe, so a standalone
# script can never exercise the audit commands. Invoking the real buttons inside
# the real window is the only honest way to verify them.
#
# Usage:
#   ui-automation.ps1 -Pid <pid> -List
#   ui-automation.ps1 -Pid <pid> -Select "对抗与规避"
#   ui-automation.ps1 -Pid <pid> -Invoke "审计本机 hypervisor"
#   ui-automation.ps1 -Pid <pid> -Read "AuditBox"
param(
    [Parameter(Mandatory = $true)][Alias("Pid")][int]$TargetProcessId,
    [switch]$List,
    [string]$Select,
    [string]$Invoke,
    [string]$Expand,
    [string]$Read,
    [int]$WaitSeconds = 0
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes

$AE = [System.Windows.Automation.AutomationElement]
$scope = [System.Windows.Automation.TreeScope]

$root = $AE::RootElement
$pidCondition = [System.Windows.Automation.PropertyCondition]::new($AE::ProcessIdProperty, $TargetProcessId)
$window = $root.FindFirst($scope::Children, $pidCondition)
if (-not $window) { throw "no top-level window for pid $TargetProcessId" }

function Find-All([string]$name) {
    $cond = [System.Windows.Automation.PropertyCondition]::new($AE::NameProperty, $name)
    return $window.FindAll($scope::Descendants, $cond)
}

if ($List) {
    $all = $window.FindAll($scope::Descendants, [System.Windows.Automation.Condition]::TrueCondition)
    foreach ($el in $all) {
        $name = $el.Current.Name
        if (-not $name) { continue }
        $type = $el.Current.ControlType.ProgrammaticName -replace 'ControlType\.', ''
        "  {0,-14} {1}" -f $type, $name
    }
    return
}

if ($Select) {
    $hits = Find-All $Select
    $item = $hits | Where-Object {
        $_.GetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern)
    } | Select-Object -First 1
    if (-not $item) { throw "no selectable item named '$Select'" }
    $pattern = $item.GetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern)
    $pattern.Select()
    "  selected: $Select"
    Start-Sleep -Milliseconds 1200
}

if ($Invoke) {
    # Buttons on these pages wrap their caption in a TextBlock, so the accessible
    # name can sit on the child. Walk up to the nearest ancestor that invokes.
    $invokePattern = [System.Windows.Automation.InvokePattern]::Pattern
    $walker = [System.Windows.Automation.TreeWalker]::ControlViewWalker
    $button = $null
    foreach ($hit in (Find-All $Invoke)) {
        $cursor = $hit
        for ($depth = 0; $depth -lt 6 -and $cursor; $depth++) {
            $supported = $null
            if ($cursor.TryGetCurrentPattern($invokePattern, [ref]$supported)) { $button = $cursor; break }
            $cursor = $walker.GetParent($cursor)
        }
        if ($button) { break }
    }
    if (-not $button) { throw "no invokable element named '$Invoke'" }
    $button.GetCurrentPattern($invokePattern).Invoke()
    "  invoked: $Invoke"
    if ($WaitSeconds -gt 0) { Start-Sleep -Seconds $WaitSeconds }
}

if ($Expand) {
    # Expander / ComboBox expose ExpandCollapsePattern, not Invoke.
    $collapsePattern = [System.Windows.Automation.ExpandCollapsePattern]::Pattern
    $walker = [System.Windows.Automation.TreeWalker]::ControlViewWalker
    $target = $null
    foreach ($hit in (Find-All $Expand)) {
        $cursor = $hit
        for ($depth = 0; $depth -lt 6 -and $cursor; $depth++) {
            $supported = $null
            if ($cursor.TryGetCurrentPattern($collapsePattern, [ref]$supported)) { $target = $cursor; break }
            $cursor = $walker.GetParent($cursor)
        }
        if ($target) { break }
    }
    if (-not $target) { throw "no expandable element named '$Expand'" }
    $pattern = $target.GetCurrentPattern($collapsePattern)
    $pattern.Expand()
    "  expanded: $Expand (state=$($pattern.Current.ExpandCollapseState))"
    Start-Sleep -Milliseconds 900
}

if ($Read) {
    # x:Name in XAML surfaces as AutomationId, not as the accessible Name, so look
    # there first and fall back to Name for controls that set both.
    $edit = $null
    $byId = [System.Windows.Automation.PropertyCondition]::new($AE::AutomationIdProperty, $Read)
    $edit = $window.FindFirst($scope::Descendants, $byId)
    if (-not $edit) {
        $edit = Find-All $Read | Where-Object {
            $_.TryGetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern, [ref]$null)
        } | Select-Object -First 1
    }
    if (-not $edit) { throw "no element with AutomationId or Name '$Read'" }
    # TextBlock exposes its text as the accessible Name; only editable controls
    # carry a ValuePattern.
    if (-not $edit.TryGetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern, [ref]$null)) {
        $value = $edit.Current.Name
    } else {
        $value = $edit.GetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern).Current.Value
    }
    "  --- $Read ---"
    foreach ($line in ($value -split "`r?`n")) { if ($line.Trim()) { "  | $line" } }
}
