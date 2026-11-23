[CmdletBinding()]
param([string]$InstallDirectory)
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$version=(Get-Content -LiteralPath (Join-Path $root 'VERSION') -Raw).Trim()
if (-not $InstallDirectory) { $InstallDirectory=Join-Path $env:TEMP ('NovaProtectInstall'+$version.Replace('.','')) }
$ui=Join-Path $InstallDirectory 'NovaProtect.exe'
$cli=Join-Path $InstallDirectory 'NovaProtect.Engine.exe'
foreach($file in @($ui,$cli,(Join-Path $InstallDirectory 'Assets\NovaProtect.ico'))) {
  if(-not(Test-Path -LiteralPath $file -PathType Leaf)){throw "Missing installed file: $file"}
}
$output=Join-Path $root 'output'
$rejected=Start-Process -FilePath $cli -ArgumentList '-machineid' -PassThru -WindowStyle Hidden
if(-not $rejected.WaitForExit(10000)){Stop-Process -Id $rejected.Id;throw 'Installed direct core call did not fail closed'}
if($rejected.ExitCode -eq 0){throw 'Installed direct core call was accepted'}
& (Join-Path $PSScriptRoot 'verify-client-startup.ps1') -Directory $InstallDirectory
if($LASTEXITCODE){throw 'Installed genuine UI/core invocation failed'}
$process=Start-Process -FilePath $ui -WorkingDirectory $InstallDirectory -PassThru -WindowStyle Hidden
$ready=$false
for($i=0;$i -lt 40;$i++){
  Start-Sleep -Milliseconds 250
  $process.Refresh()
  if($process.HasExited){throw "Installed UI exited: $($process.ExitCode)"}
  if($process.MainWindowHandle -ne 0 -and $process.MainWindowTitle -eq 'NovaProtect' -and $process.Responding){$ready=$true;break}
}
if(-not $ready){throw 'No responsive NovaProtect top-level window'}
# Icon check: hash-compare PE RT_ICON blobs against the source .ico.
# ExtractAssociatedIcon mis-decodes PNG-compressed icons and can report a stale
# or wrong bitmap even when the PE resource is correct.
$py = $env:MIMO_PYTHON
if (-not $py) { $py = 'python' }
$iconPy = Join-Path $PSScriptRoot 'check_pe_icons.py'
$sourceIco = Join-Path $root 'ui\Assets\NovaProtect.ico'
if (-not (Test-Path -LiteralPath $sourceIco -PathType Leaf)) { throw "Missing source icon: $sourceIco" }
$hashCheck = & $py -c @"
import struct, hashlib, sys
from pathlib import Path

def ico_shas(path):
    data = Path(path).read_bytes()
    n = struct.unpack_from('<H', data, 4)[0]
    out = set()
    for i in range(n):
        w,h,c,r,p,bpp,size,off = struct.unpack_from('<BBBBHHII', data, 6+i*16)
        out.add(hashlib.sha256(data[off:off+size]).hexdigest())
    return out

def pe_shas(path):
    data = Path(path).read_bytes()
    e = struct.unpack_from('<I', data, 0x3C)[0]
    machine, nsec, _t, _s, _n, optsz, _c = struct.unpack_from('<HHIIIHH', data, e+4)
    opt = e+24
    magic = struct.unpack_from('<H', data, opt)[0]
    dir_off = opt + (112 if magic==0x20B else 96)
    rsrc_rva, _ = struct.unpack_from('<II', data, dir_off+16)
    secs=[]
    sec_off=opt+optsz
    for i in range(nsec):
        _n,vsize,vaddr,rsize,raddr = struct.unpack_from('<8sIIII', data, sec_off+i*40)
        secs.append((vaddr, max(vsize,rsize), raddr, rsize))
    sec=next(s for s in secs if s[0]<=rsrc_rva<s[0]+s[1])
    vaddr,span,raddr,rsize=sec
    base=data[raddr+(rsrc_rva-vaddr):raddr+(rsrc_rva-vaddr)+rsize]
    def dir_at(off):
        *_, nn, ni = struct.unpack_from('<IIHHHH', base, off)
        return off+16, nn, ni
    out=set()
    root, rn, ri = dir_at(0)
    for i in range(rn+ri):
        name, target = struct.unpack_from('<II', base, root+i*8)
        if name & 0x80000000 or not target & 0x80000000 or name != 3: continue
        sub, sn, si = dir_at(target & 0x7FFFFFFF)
        for j in range(sn+si):
            ename, etarget = struct.unpack_from('<II', base, sub+j*8)
            if not etarget & 0x80000000: continue
            langs, ln, li = dir_at(etarget & 0x7FFFFFFF)
            for k in range(ln+li):
                _ln, ltarget = struct.unpack_from('<II', base, langs+k*8)
                if ltarget & 0x80000000: continue
                doff, dsize, _, _ = struct.unpack_from('<IIII', base, ltarget)
                foff=None
                for va, span, raw, rsz in secs:
                    if va <= doff < va+span:
                        foff = raw+(doff-va); break
                blob = data[foff:foff+dsize] if foff is not None else base[doff:doff+dsize]
                out.add(hashlib.sha256(blob).hexdigest())
    return out

src=ico_shas(sys.argv[1]); pe=pe_shas(sys.argv[2])
if not pe:
    print('NO_PE_ICONS'); sys.exit(2)
if not pe <= src:
    print('PE_HAS_FOREIGN'); sys.exit(3)
if not src <= pe:
    print('PE_MISSING_SOURCE'); sys.exit(4)
print('ICON_HASH_MATCH')
"@ $sourceIco $ui
if ($LASTEXITCODE -ne 0 -or "$hashCheck" -notmatch 'ICON_HASH_MATCH') {
  throw "Installed PE icon does not match ui\Assets\NovaProtect.ico (latest brand asset). Output: $hashCheck"
}
# Still dump a preview via the 256px source frame for the report.
Add-Type -AssemblyName System.Drawing
$icoBytes=[IO.File]::ReadAllBytes($sourceIco)
$count=[BitConverter]::ToUInt16($icoBytes,4)
$bestOff=0;$bestSize=0
for($i=0;$i -lt $count;$i++){
  $e=6+$i*16
  $size=[BitConverter]::ToUInt32($icoBytes,$e+8)
  $off=[BitConverter]::ToUInt32($icoBytes,$e+12)
  if($size -gt $bestSize){$bestSize=$size;$bestOff=$off}
}
$ms=[IO.MemoryStream]::new($icoBytes,$bestOff,$bestSize)
$png=[Drawing.Image]::FromStream($ms)
try{$png.Save((Join-Path $output "installed-icon-$version.png"),[Drawing.Imaging.ImageFormat]::Png)}
finally{$png.Dispose();$ms.Dispose()}
$shortcut=Join-Path ([Environment]::GetFolderPath('Programs')) 'NovaProtect\NovaProtect.lnk'
if(-not(Test-Path -LiteralPath $shortcut)){throw 'NovaProtect Start Menu link missing'}
$shell=New-Object -ComObject WScript.Shell
$target=$shell.CreateShortcut($shortcut).TargetPath
if($target -ne $ui){throw "Unexpected shortcut target: $target"}
$legacyLink=Join-Path ([Environment]::GetFolderPath('Programs')) 'NovaPack\NovaProtect.lnk'
if(Test-Path -LiteralPath $legacyLink){throw 'Legacy NovaPack group link still exists'}
$debug=@(Get-ChildItem -LiteralPath $InstallDirectory -Recurse -File | Where-Object { $_.Extension -in @('.pdb','.map','.vmp') -or $_.Name -like '*.vmprotect.log' })
if($debug.Count){throw 'Debug or VMP configuration files leaked into installation'}
$record=[ordered]@{
  Version=$version;Directory=$InstallDirectory;ProcessId=$process.Id;Title=$process.MainWindowTitle;
  WindowHandle=$process.MainWindowHandle.ToInt64();Responding=$process.Responding;
  FileVersion=(Get-Item -LiteralPath $ui).VersionInfo.FileVersion;DirectCoreRejected=$true;CoreViaUI=$true;
  IconExtracted=$true;StartMenuLink=$shortcut;DebugFilesExcluded=$true;
  UiSha256=(Get-FileHash -LiteralPath $ui -Algorithm SHA256).Hash;
  DllSha256=(Get-FileHash -LiteralPath (Join-Path $InstallDirectory 'NovaProtect.dll') -Algorithm SHA256).Hash;
  CliSha256=(Get-FileHash -LiteralPath $cli -Algorithm SHA256).Hash
}
$record | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $output "installed-verification-$version.json") -Encoding UTF8
$record | ConvertTo-Json
Write-Host 'INSTALLED-VERIFY-OK (verified UI is left running)'
