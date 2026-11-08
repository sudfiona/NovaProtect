[CmdletBinding()]
param(
  [string]$Installer = 'C:\npbuild\artifacts\isl-verify\after\verify-after.exe',
  [string]$OutputDirectory = 'C:\npbuild\artifacts\isl-verify'
)
$ErrorActionPreference='Stop'
Add-Type -AssemblyName UIAutomationClient,UIAutomationTypes
Add-Type -AssemblyName System.Drawing

function Shot([IntPtr]$h,[string]$name){
  Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class WinRect2 {
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left, Top, Right, Bottom; }
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
}
'@ -ErrorAction SilentlyContinue
  $r=New-Object WinRect2+RECT
  [void][WinRect2]::GetWindowRect($h,[ref]$r)
  $w=$r.Right-$r.Left; $ht=$r.Bottom-$r.Top
  if($w -le 0 -or $ht -le 0){return}
  $bmp=New-Object System.Drawing.Bitmap($w,$ht)
  $g=[System.Drawing.Graphics]::FromImage($bmp)
  $g.CopyFromScreen($r.Left,$r.Top,0,0,$bmp.Size)
  $path=Join-Path $OutputDirectory $name
  $bmp.Save($path,[System.Drawing.Imaging.ImageFormat]::Png)
  $g.Dispose();$bmp.Dispose()
  Write-Host "  shot $name"
}

Write-Host "launching $Installer"
$proc=Start-Process -FilePath $Installer -WorkingDirectory (Split-Path -Parent $Installer) -PassThru
Start-Sleep -Seconds 8

$root=[System.Windows.Automation.AutomationElement]::RootElement
$scope=[System.Windows.Automation.TreeScope]::Children
$wins=$root.FindAll($scope,[System.Windows.Automation.Condition]::TrueCondition)
Write-Host "top-level automation elements: $($wins.Count)"
# Match the window that belongs to the installer we just started, so leftovers
# from earlier runs cannot be mistaken for it.
$expected=[IO.Path]::GetFileNameWithoutExtension($Installer)
Write-Host "expecting a window of '$expected'"
$target=$null
$procId=$proc.Id
foreach($w in $wins){
  try{
    $n=$w.Current.Name; $c=$w.Current.ClassName; $ownerPid=$w.Current.ProcessId
    Write-Host "  win pid=$ownerPid class=$c name=$n"
    if($ownerPid -eq $procId -and $c -eq 'TWizardForm' -and -not $target){ $target=$w }
  }catch{}
}
if(-not $target){
  # The setup loader spawns a child process that owns the wizard form.
  foreach($w in $wins){
    try{
      $n=$w.Current.Name; $c=$w.Current.ClassName; $ownerPid=$w.Current.ProcessId
      if($c -eq 'TWizardForm' -and $n -match 'NovaProtect' -and -not $target){ $target=$w }
    }catch{}
  }
}
if(-not $target){
  Write-Host 'INSTALLER WINDOW NOT FOUND VIA UIA'
  try{Stop-Process -Id $proc.Id}catch{}
  exit 2
}
Write-Host "found: $($target.Current.Name)"

$hwnd=[IntPtr]$target.Current.NativeWindowHandle
try{ $target.SetFocus() }catch{}

$desc=[System.Windows.Automation.TreeScope]::Descendants
for($page=0;$page -lt 6;$page++){
  Write-Host "--- page $page ---"
  # Grab every element's Name (Inno renders its labels as owner-drawn static
  # controls, but the accessibility tree still exposes the strings).
  $nodes=$target.FindAll($desc,[System.Windows.Automation.Condition]::TrueCondition)
  $lines=foreach($n in $nodes){ try{ $n.Current.Name }catch{ $null } }
  ($lines | Where-Object { $_ -and $_.Trim() } | Select-Object -Unique) | ForEach-Object { Write-Host "    $_" }

  # Advance the wizard. Inno draws its buttons itself, so InvokePattern does
  # nothing useful - send the accelerator key (Enter) to the form instead.
  $clicked=$false
  foreach($n in $target.FindAll($desc,[System.Windows.Automation.Condition]::TrueCondition)){
    try{
      $nm=$n.Current.Name
      if($nm -match '^(下一步|安装|完成|Next|Install|Finish)'){
        try{ $n.SetFocus() }catch{}
        $p=$null
        if($n.TryGetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern,[ref]$p)){
          $p.Invoke(); $clicked=$true; Write-Host "  invoked '$nm'"; break
        }
      }
    }catch{}
  }
  if(-not $clicked){
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class KeySend {
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern void keybd_event(byte v, byte s, uint f, IntPtr e);
  public static void Enter(IntPtr h){ SetForegroundWindow(h); System.Threading.Thread.Sleep(150);
    keybd_event(0x0D,0,0,IntPtr.Zero); keybd_event(0x0D,0,2,IntPtr.Zero); }
}
'@ -ErrorAction SilentlyContinue
    [KeySend]::Enter($hwnd)
    Write-Host '  sent ENTER'
  }
  Start-Sleep -Seconds 2
}
Write-Host 'DONE'
try{Stop-Process -Id $proc.Id}catch{}
