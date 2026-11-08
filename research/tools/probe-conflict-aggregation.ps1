# Verify the client no longer shows a wall of identical conflict lines.
#
# Scenario: the user checks the scanned functions and turns on "require the
# global activation binding" for them.  Every checked function then asks for an
# activation lock while no binding is configured, which used to produce one
# conflict line per function.  The conflicts have to be aggregated into a
# single line, and the static architecture matrix must be gone.
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
  foreach ($w in $root.FindAll([System.Windows.Automation.TreeScope]::Children, $cond)) {
    try { if ($w.Current.Name -like $TitleLike) { return $w } } catch {}
  }
  return $null
}

$proc = Start-Process -FilePath (Join-Path $Directory 'NovaProtect.exe') -WorkingDirectory $Directory -PassThru
for ($i = 0; $i -lt 40; $i++) {
  $proc.Refresh()
  if ($proc.MainWindowHandle -ne 0) { break }
  Start-Sleep -Milliseconds 500
}
if ($proc.MainWindowHandle -eq 0) { Write-Host 'UI WINDOW NOT READY'; Stop-Process -Id $proc.Id -Force; exit 2 }

$win = [System.Windows.Automation.AutomationElement]::FromHandle($proc.MainWindowHandle)
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

$close = Find-Name '关闭' 'Button'
if ($close) { Click $close; Start-Sleep -Milliseconds 400 }
$nav = Find-Name '保护项目' 'ListItem'
if ($nav) { $nav.GetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern).Select(); Start-Sleep -Seconds 2 }

Set-Value (Find-Id 'InputPathBox') $Target
Start-Sleep -Seconds 3
Click (Find-Name '扫描函数' 'Button')
Start-Sleep -Seconds 8
Click (Find-Name '添加所有函数' 'Button')
Start-Sleep -Milliseconds 1200

# Turn on "require the global activation binding" for the checked functions.
$toggle = Find-Name '勾选函数要求启用全局激活绑定' $null
if (-not $toggle) {
  $toggle = Find-Id 'FunctionBatchActivationSwitch'
}
if ($toggle) {
  try {
    $tp = $toggle.GetCurrentPattern([System.Windows.Automation.TogglePattern]::Pattern)
    if ($tp.Current.ToggleState -ne 'On') { $tp.Toggle(); Start-Sleep -Milliseconds 800 }
    Write-Host 'activation lock requested for the checked functions'
  } catch { Write-Host "cannot toggle: $($_.Exception.Message)" }
} else {
  Write-Host 'activation toggle not found'
}

# The switch only takes effect once it is applied to the checked rows.
Click (Find-Name '应用到勾选函数' 'Button')
Start-Sleep -Milliseconds 1500

# Press start: the conflict dialog is what the user complained about.
Click (Find-Id 'StartButton')
Start-Sleep -Seconds 5

$all = $win.FindAll($desc, [System.Windows.Automation.Condition]::TrueCondition)
$texts = @()
foreach ($n in $all) {
  try {
    if ($n.Current.ControlType -eq [System.Windows.Automation.ControlType]::Text) {
      $texts += $n.Current.Name
    }
  } catch {}
}

# The same summary is shown in the dialog and in the log box, so the check is
# per text block: inside one block the conflict must appear only once.
$blocks = @()
foreach ($t in $texts) {
  if ($t -like '*请求激活锁定*') { $blocks += $t }
}
$worst = 0
$sample = ''
foreach ($b in $blocks) {
  $count = ([regex]::Matches($b, '请求激活锁定')).Count
  if ($count -gt $worst) { $worst = $count }
  if (-not $sample) { $sample = $b }
}

Write-Host "--- text blocks mentioning the activation lock: $($blocks.Count), max repeats in one block: $worst ---"
if ($sample) {
  foreach ($part in ($sample -split '。')) {
    if ($part -like '*激活锁定*') { Write-Host "  $part。" }
  }
}

# The static architecture matrix must be gone from the page.
$matrixLeft = @($texts | Where-Object { $_ -like '*完整架构能力矩阵*' }).Count
if ($matrixLeft -eq 0) { Write-Host '[ OK ] the architecture matrix is no longer shown' }
else { Write-Host '[FAIL] the architecture matrix is still on the page' }

Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue

if ($blocks.Count -eq 0) {
  Write-Host '[FAIL] the activation conflict did not appear at all'
  exit 1
}
if ($worst -gt 1) {
  Write-Host "[FAIL] the activation conflict is still repeated $worst times in one block"
  exit 1
}
if ($sample -notmatch '\d+ 项') {
  Write-Host "[FAIL] the aggregated line does not say how many rules are affected: $sample"
  exit 1
}
if ($matrixLeft -ne 0) {
  Write-Host '[FAIL] the architecture matrix is still on the page'
  exit 1
}

Write-Host '[ OK ] the activation conflict is a single aggregated line'
Write-Host 'PROBE-OK'
exit 0
