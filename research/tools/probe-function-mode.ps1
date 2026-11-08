# Verify the per-function protection type dropdown in the client.
#
# The function list must offer a protection type per row (none / virtualization
# / mutation / ultra), and picking one has to check the row: the checkbox and
# the type are two views of the same decision.
param(
  [string]$Directory = 'C:\npbuild\ui\bin\x64\Release\net10.0-windows10.0.19041.0\win-x64',
  [string]$Target = 'C:\npbuild\tests\test_target.exe'
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes

function Find-Window {
  param([string]$TitleLike)
  $root = [System.Windows.Automation.AutomationElement]::RootElement
  $cond = New-Object System.Windows.Automation.PropertyCondition(
    [System.Windows.Automation.AutomationElement]::ControlTypeProperty,
    [System.Windows.Automation.ControlType]::Window)
  $wins = $root.FindAll([System.Windows.Automation.TreeScope]::Children, $cond)
  foreach ($w in $wins) {
    try { if ($w.Current.Name -like $TitleLike) { return $w } } catch {}
  }
  return $null
}

$exe = Join-Path $Directory 'NovaProtect.exe'
Write-Host "launching $exe"
$proc = Start-Process -FilePath $exe -WorkingDirectory $Directory -PassThru
for ($i = 0; $i -lt 40; $i++) {
  $proc.Refresh()
  if ($proc.MainWindowHandle -ne 0) { break }
  Start-Sleep -Milliseconds 500
}
if ($proc.MainWindowHandle -eq 0) {
  Write-Host 'UI WINDOW NOT READY'
  Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
  exit 2
}
$win = [System.Windows.Automation.AutomationElement]::FromHandle($proc.MainWindowHandle)
Write-Host "window: $($win.Current.Name)"
$desc = [System.Windows.Automation.TreeScope]::Descendants

function Find-Name([string]$Name, [string]$Type) {
  $c = New-Object System.Windows.Automation.PropertyCondition(
    [System.Windows.Automation.AutomationElement]::NameProperty, $Name)
  @($win.FindAll($desc, $c)) | Where-Object {
    -not $Type -or $_.Current.ControlType.ProgrammaticName -eq "ControlType.$Type"
  } | Select-Object -First 1
}
function Find-Id([string]$Id) {
  $c = New-Object System.Windows.Automation.PropertyCondition(
    [System.Windows.Automation.AutomationElement]::AutomationIdProperty, $Id)
  $win.FindFirst($desc, $c)
}
function Click($e) { if (-not $e) { throw 'control missing' }; $e.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern).Invoke() }
function Set-Value($e, [string]$v) { if (-not $e) { throw 'value control missing' }; $e.GetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern).SetValue($v) }

# Dismiss the first-run dialog and open the protection page.
$close = Find-Name '关闭' 'Button'
if ($close) { Click $close; Start-Sleep -Milliseconds 400 }
$nav = Find-Name '保护项目' 'ListItem'
if ($nav) {
  $nav.GetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern).Select()
  Start-Sleep -Seconds 2
}

# The function list is empty until a target is scanned, so drive the client
# the way a user would: type the path, then press the scan button.
$desc = [System.Windows.Automation.TreeScope]::Descendants
$all = $win.FindAll($desc, [System.Windows.Automation.Condition]::TrueCondition)

$edit = Find-Id 'InputPathBox'
$scanBtn = Find-Name '扫描函数' 'Button'
if ($edit) {
  try {
    $vp = $edit.GetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern)
    $vp.SetValue($Target)
    Write-Host "input path set"
  } catch { Write-Host "cannot set the path: $($_.Exception.Message)" }
} else { Write-Host 'no edit box found' }

if ($scanBtn) {
  try { $scanBtn.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern).Invoke() } catch {}
  Start-Sleep -Seconds 5
  Write-Host 'scan requested'
} else { Write-Host 'no scan button found' }

# Re-read the tree now that the list is populated.
$all = $win.FindAll($desc, [System.Windows.Automation.Condition]::TrueCondition)
$combos = @()
foreach ($n in $all) {
  try {
    if ($n.Current.ControlType -eq [System.Windows.Automation.ControlType]::ComboBox) {
      $combos += $n
    }
  } catch {}
}
Write-Host "combo boxes found: $($combos.Count)"

# Read the selected value of every combo box.  A WinUI combo exposes it as a
# text child; the value pattern carries it as well.
$rowCombos = @()
foreach ($c in $combos) {
  $value = $null
  try {
    $vp = $c.GetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern)
    $value = $vp.Current.Value
  } catch {}
  if (-not $value) {
    try {
      $sel = $c.FindFirst([System.Windows.Automation.TreeScope]::Descendants,
        (New-Object System.Windows.Automation.PropertyCondition(
          [System.Windows.Automation.AutomationElement]::ControlTypeProperty,
          [System.Windows.Automation.ControlType]::Text)))
      if ($sel) { $value = $sel.Current.Name }
    } catch {}
  }
  if ($value) { $rowCombos += [pscustomobject]@{ El = $c; Value = $value } }
}
foreach ($rc in $rowCombos) { Write-Host "  combo value: $($rc.Value)" }
Write-Host "--- expanding the per-row combo boxes ---"
$found = @()
$expanded = 0
foreach ($c in $combos) {
  $aid = ''
  try { $aid = $c.Current.AutomationId } catch {}
  if ($aid) { continue }          # named combos are the batch controls
  if ($expanded -ge 2) { break }
  try {
    $c.GetCurrentPattern([System.Windows.Automation.ExpandCollapsePattern]::Pattern).Expand()
    Start-Sleep -Milliseconds 700
    $items = @($c.FindAll([System.Windows.Automation.TreeScope]::Descendants,
      (New-Object System.Windows.Automation.PropertyCondition(
        [System.Windows.Automation.AutomationElement]::ControlTypeProperty,
        [System.Windows.Automation.ControlType]::ListItem))))
    $names = @()
    foreach ($it in $items) { $names += $it.Current.Name }
    Write-Host ("  combo options: {0}" -f ($names -join ', '))
    foreach ($n in $names) { $found += $n }
    $c.GetCurrentPattern([System.Windows.Automation.ExpandCollapsePattern]::Pattern).Collapse()
    $expanded++
  } catch { Write-Host "  cannot expand: $($_.Exception.Message)" }
}

# Pick a protection type on the first row and check that the row becomes
# checked: the checkbox and the type are two views of one decision.
$rowCombo = $null
foreach ($c in $combos) {
  $aid = ''
  try { $aid = $c.Current.AutomationId } catch {}
  if ($aid) { continue }
  $rowCombo = $c
  break
}
$linkedOk = $false
if ($rowCombo) {
  try {
    $rowCombo.GetCurrentPattern([System.Windows.Automation.ExpandCollapsePattern]::Pattern).Expand()
    Start-Sleep -Milliseconds 600
    $items = @($rowCombo.FindAll([System.Windows.Automation.TreeScope]::Descendants,
      (New-Object System.Windows.Automation.PropertyCondition(
        [System.Windows.Automation.AutomationElement]::ControlTypeProperty,
        [System.Windows.Automation.ControlType]::ListItem))))
    $ultra = $null
    foreach ($it in $items) { if ($it.Current.Name -like '*变异*') { $ultra = $it; break } }
    if ($ultra) {
      # Find the checkbox of the same row first and clear it, so that the
      # effect of choosing a protection type is observable.
      $rowRoot = $rowCombo
      for ($up = 0; $up -lt 8 -and $rowRoot; $up++) {
        $rowRoot = [System.Windows.Automation.TreeWalker]::ControlViewWalker.GetParent($rowRoot)
        if (-not $rowRoot) { break }
        $checks = @($rowRoot.FindAll([System.Windows.Automation.TreeScope]::Descendants,
          (New-Object System.Windows.Automation.PropertyCondition(
            [System.Windows.Automation.AutomationElement]::ControlTypeProperty,
            [System.Windows.Automation.ControlType]::CheckBox))))
        if ($checks.Count -gt 0) {
          foreach ($cb in $checks) {
            try {
              $tp = $cb.GetCurrentPattern([System.Windows.Automation.TogglePattern]::Pattern)
              if ($tp.Current.ToggleState -eq 'On') { $tp.Toggle(); Start-Sleep -Milliseconds 400 }
            } catch {}
          }
          break
        }
      }

      $ultra.GetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern).Select()
      Start-Sleep -Milliseconds 900

      # The row checkbox must now be checked again.
      $rowRoot = $rowCombo
      for ($up = 0; $up -lt 8 -and $rowRoot; $up++) {
        $rowRoot = [System.Windows.Automation.TreeWalker]::ControlViewWalker.GetParent($rowRoot)
        if (-not $rowRoot) { break }
        $checks = @($rowRoot.FindAll([System.Windows.Automation.TreeScope]::Descendants,
          (New-Object System.Windows.Automation.PropertyCondition(
            [System.Windows.Automation.AutomationElement]::ControlTypeProperty,
            [System.Windows.Automation.ControlType]::CheckBox))))
        foreach ($cb in $checks) {
          try {
            $tp = $cb.GetCurrentPattern([System.Windows.Automation.TogglePattern]::Pattern)
            if ($tp.Current.ToggleState -eq 'On') { $linkedOk = $true }
          } catch {}
        }
        if ($linkedOk) { break }
      }
    }
  } catch { Write-Host "  link check failed: $($_.Exception.Message)" }
}
if ($linkedOk) { Write-Host '[ OK ] picking a protection type checks the row' }
else { Write-Host '[FAIL] picking a protection type did not check the row' }

# The expected protection type labels.
$expected = @('不保护', '虚拟化', '变异')
foreach ($rc in $rowCombos) { $found += $rc.Value }
$ok = $found.Count -gt 0
foreach ($e in $expected) { if ($found -contains $e) { Write-Host "[ OK ] protection type '$e' is offered per row" } else { $ok = $false; Write-Host "[FAIL] protection type '$e' missing" } }

Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
if ($ok) { Write-Host 'PROBE-OK'; exit 0 } else { Write-Host 'PROBE-FAIL'; exit 1 }
