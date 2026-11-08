[Setup]
AppId={{TEST-AB-ENC}
AppName=编码测试
AppVersion=1.0
DefaultDirName={localappdata}\EncTest
OutputDir=.
OutputBaseFilename=EncTest
Compression=lzma2

[Files]
Source: "payload.txt"; DestDir: "{app}"; Flags: ignoreversion

[Tasks]
Name: "desktopicon"; Description: "创建桌面快捷方式"; GroupDescription: "其他任务:"
