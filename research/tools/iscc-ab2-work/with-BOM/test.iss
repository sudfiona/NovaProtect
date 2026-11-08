#define MyComments "版本说明文字"

[Setup]
AppId={{TEST-AB-ENC2}
AppName=编码测试
AppVersion=1.0
DefaultDirName={localappdata}\EncTest2
OutputBaseFilename=EncTest2
Compression=lzma2
VersionInfoDescription={#MyComments}

[Files]
Source: "payload.txt"; DestDir: "{app}"; Flags: ignoreversion

[Tasks]
Name: "desktopicon"; Description: "创建桌面快捷方式"; GroupDescription: "其他任务:"
Name: "extra"; Description: "额外任务项"; Flags: unchecked
