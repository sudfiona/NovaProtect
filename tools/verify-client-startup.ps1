[CmdletBinding()]
param([Parameter(Mandatory)][string]$Directory,[int]$TimeoutSeconds=20)
$ErrorActionPreference='Stop'
$Directory=[IO.Path]::GetFullPath($Directory)
Add-Type -AssemblyName UIAutomationClient,UIAutomationTypes
$scope=[System.Windows.Automation.TreeScope]::Descendants
$process=$null
try{
  $process=Start-Process -FilePath (Join-Path $Directory 'NovaProtect.exe') -WorkingDirectory $Directory -PassThru
  $deadline=[DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
  $ready=$false
  while([DateTime]::UtcNow -lt $deadline){
    $process.Refresh()
    if($process.HasExited){throw ('Startup exit 0x{0:X8}' -f $process.ExitCode)}
    if($process.MainWindowHandle -ne 0 -and $process.MainWindowTitle -eq 'NovaProtect' -and $process.Responding){$ready=$true;break}
    Start-Sleep -Milliseconds 150
  }
  if(-not $ready){throw 'No responsive NovaProtect window'}
  $window=[System.Windows.Automation.AutomationElement]::FromHandle($process.MainWindowHandle)
  function Find-Id([string]$id){$window.FindFirst($scope,(New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::AutomationIdProperty,$id)))}
  $condition=New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::NameProperty,'检查工具')
  $nav=$null
  # The nav is a radio-button group in current builds (ListItem in older ones);
  # SelectionItemPattern works on both, so accept either type.
  while([DateTime]::UtcNow -lt $deadline){
    $nav=@($window.FindAll($scope,$condition))|Where-Object {$_.Current.ControlType -eq [System.Windows.Automation.ControlType]::RadioButton -or $_.Current.ControlType -eq [System.Windows.Automation.ControlType]::ListItem}|Select-Object -First 1
    if($nav){break}; Start-Sleep -Milliseconds 100
  }
  if(-not $nav){throw 'Nav item did not render'}
  $nav.GetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern).Select()
  $button=$null
  # The machine-ID action's label moved ("本机激活 ID" -> "本机 ID") and the
  # button's own UIA name is empty when its content is an icon+text panel, so
  # match on the inner label text and accept either wording.
  $walker=[System.Windows.Automation.TreeWalker]::ControlViewWalker
  while([DateTime]::UtcNow -lt $deadline){
    foreach($label in @('本机 ID','本机激活 ID')){
      $lc=New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::NameProperty,$label)
      foreach($b in @($window.FindAll($scope,$lc))){
        $node=$b
        while($node -and $node.Current.ControlType -ne [System.Windows.Automation.ControlType]::Button){
          $node=$walker.GetParent($node)
        }
        if($node){$button=$node;break}
      }
      if($button){break}
    }
    if($button){break}; Start-Sleep -Milliseconds 100
  }
  if(-not $button){throw 'Inspect page did not render'}
  $button.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern).Invoke()
  while([DateTime]::UtcNow -lt $deadline){
    $result=Find-Id 'ResultBox'
    if($result){
      $value=$result.GetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern).Current.Value
      if($value -match '^[0-9A-Fa-f]{16}$'){Write-Host 'CLIENT-STARTUP-OK (window + UI-authorized engine)';exit 0}
      if($value -and $value -ne '正在读取…'){throw "Engine call: $value"}
    }
    $process.Refresh();if($process.HasExited){throw 'UI exited during core invocation'}
    Start-Sleep -Milliseconds 100
  }
  throw 'Core invocation timed out'
}catch{Write-Host $_.Exception.Message;exit 1}
finally{if($process){try{if(-not $process.HasExited){Stop-Process -Id $process.Id; $null=$process.WaitForExit(5000)}}catch{}}}
