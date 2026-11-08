[CmdletBinding()]
param(
  [string]$Installer = 'C:\npbuild\artifacts\isl-test\isl-test.exe',
  [string]$OutputDirectory = 'C:\npbuild\artifacts\isl-test'
)
$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Drawing
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class WinIsl {
  public delegate bool EnumProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr l);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern IntPtr GetDlgItem(IntPtr h, int id);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint msg, IntPtr wp, StringBuilder lp);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint msg, IntPtr wp, IntPtr lp);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h, uint msg, IntPtr wp, IntPtr lp);
  [DllImport("user32.dll")] public static extern IntPtr GetParent(IntPtr h);
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left, Top, Right, Bottom; }
}
'@

function Get-Windows {
  $list=New-Object System.Collections.ArrayList
  $cb=[WinIsl+EnumProc]{ param($h,$l)
    if([WinIsl]::IsWindowVisible($h)){
      $sb=New-Object System.Text.StringBuilder 512
      [void][WinIsl]::GetWindowTextW($h,$sb,512)
      $cn=New-Object System.Text.StringBuilder 256
      [void][WinIsl]::GetClassNameW($h,$cn,256)
      [void]$list.Add([pscustomobject]@{Handle=$h;Title=$sb.ToString();Class=$cn.ToString()})
    }
    return $true
  }
  [void][WinIsl]::EnumWindows($cb,[IntPtr]::Zero)
  return $list
}
function Shot([IntPtr]$h,[string]$name){
  $r=New-Object WinIsl+RECT
  [void][WinIsl]::GetWindowRect($h,[ref]$r)
  $w=$r.Right-$r.Left; $ht=$r.Bottom-$r.Top
  if($w -le 0){return}
  $bmp=New-Object System.Drawing.Bitmap($w,$ht)
  $g=[System.Drawing.Graphics]::FromImage($bmp)
  $g.CopyFromScreen($r.Left,$r.Top,0,0,$bmp.Size)
  $path=Join-Path $OutputDirectory $name
  $bmp.Save($path,[System.Drawing.Imaging.ImageFormat]::Png)
  $g.Dispose();$bmp.Dispose()
  Write-Host "  shot $name"
}
# Read the text of every child control so we can see the rendered strings.
function Dump-Children([IntPtr]$h,[string]$name){
  $lines=New-Object System.Collections.ArrayList
  $walk=[WinIsl+EnumProc]{ param($c,$l)
    $sb=New-Object System.Text.StringBuilder 2048
    [void][WinIsl]::SendMessageW($c,0x000D,[IntPtr]2048,$sb)   # WM_GETTEXT
    $t=$sb.ToString()
    if($t){ [void]$lines.Add($t) }
    return $true
  }
  # enumerate children of the window
  $enumChild=[WinIsl+EnumProc]{ param($c,$l) return $true }
  [void]$lines.Add("---- child texts ----")
  return $lines
}

Write-Host "launching $Installer"
$proc=Start-Process -FilePath $Installer -WorkingDirectory (Split-Path -Parent $Installer) -PassThru
Start-Sleep -Seconds 6

$wins=Get-Windows
$wins|ForEach-Object{ Write-Host ("  win [{0}] class={1} title={2}" -f $_.Handle,$_.Class,$_.Title) }
$target=$wins|Where-Object{ $_.Title -match 'NovaProtect|安装|Setup' -and $_.Class -eq '#32770' }|Select-Object -First 1
if(-not $target){ Write-Host 'NO INSTALLER DIALOG'; try{Stop-Process -Id $proc.Id}catch{}; exit 2 }
$h=$target.Handle
[void][WinIsl]::SetForegroundWindow($h)
Start-Sleep -Milliseconds 800
Shot $h 'wizard-step0.png'

# Walk the wizard forward with the Next button (ID 1) until we reach the
# "Ready to Install" page (its title is the app name + "安装向导"/Setup Wizard).
for($step=1;$step -le 6;$step++){
  $next=[WinIsl]::GetDlgItem($h,1)   # IDOK / Next
  if(-not $next){ Write-Host "  no next button at step $step"; break }
  [void][WinIsl]::PostMessageW($next,0x00F5,[IntPtr]::Zero,[IntPtr]::Zero)  # BM_CLICK
  Start-Sleep -Seconds 2
  $wins=Get-Windows
  $cur=$wins|Where-Object{ $_.Handle -eq $h }|Select-Object -First 1
  Write-Host ("  step {0}: title={1}" -f $step,$cur.Title)
  Shot $h ("wizard-step{0}.png" -f $step)
}
Write-Host 'DONE'
try{Stop-Process -Id $proc.Id}catch{}
