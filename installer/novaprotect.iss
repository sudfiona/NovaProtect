; NovaProtect full offline installer
#include "version.iss"
#define MyAppName "NovaProtect"
#define MyAppPublisher "NovaProtect"
#define MyAppExeName "NovaProtect.exe"
#ifndef SourceDir
  #define SourceDir "..\ui\bin\x64\Release\net10.0-windows10.0.19041.0\win-x64"
#endif
#ifndef OutputDir
  #define OutputDir "."
#endif

[Setup]
AppId={{D8D5F0A9-0AA7-4D31-9EF0-9B350A7D3C6B}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL=https://nova.fbi.plus
AppSupportURL=https://nova.fbi.plus/
AppUpdatesURL=https://github.com/sudfiona/NovaProtect/releases/latest
DefaultDirName={localappdata}\Programs\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
UsePreviousGroup=no
PrivilegesRequired=lowest
OutputDir={#OutputDir}
OutputBaseFilename=NovaProtect-Setup-{#MyAppVersion}
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
UninstallDisplayIcon={app}\{#MyAppExeName}
SetupIconFile=..\ui\Assets\NovaProtect.ico
SetupLogging=yes
CloseApplications=yes
RestartApplications=no
VersionInfoVersion={#MyAppVersion}.0
VersionInfoCompany={#MyAppPublisher}
VersionInfoDescription=NovaProtect Client Installer - {#MyAppVersionComments}
VersionInfoProductName={#MyAppName}
VersionInfoProductVersion={#MyAppVersion}

[Languages]
Name: "chinese"; MessagesFile: "ChineseSimplified.isl"

[Tasks]
Name: "desktopicon"; Description: "创建桌面快捷方式"; GroupDescription: "其他任务:"; Flags: unchecked

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Excludes: "*.pdb,*.map,*.vmp,*.vmprotect.log,README*,readme*,readme.*,NovaProtect.exe.WebView2\*"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\sdk\*"; DestDir: "{app}\sdk"; Excludes: "README*,readme*,readme.*"; Flags: ignoreversion recursesubdirs createallsubdirs skipifsourcedoesntexist

[Icons]
Name: "{group}\NovaProtect"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\卸载 NovaProtect"; Filename: "{uninstallexe}"
Name: "{autodesktop}\NovaProtect"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[InstallDelete]
Type: files; Name: "{app}\novaprotect.exe"
Type: files; Name: "{app}\NovaProtect.UI.exe"
Type: files; Name: "{app}\NovaProtect.UI.dll"
Type: files; Name: "{app}\NovaProtect.UI.deps.json"
Type: files; Name: "{app}\NovaProtect.UI.runtimeconfig.json"
Type: files; Name: "{userprograms}\NovaProtect\NovaProtect 命令行.lnk"
; Remove only this product's known legacy links; never recursively delete a group.
Type: files; Name: "{userprograms}\NovaPack\NovaPack.lnk"
Type: files; Name: "{userprograms}\NovaPack\NovaPack 命令行.lnk"
Type: files; Name: "{userprograms}\NovaPack\卸载 NovaPack.lnk"
Type: files; Name: "{userprograms}\NovaPack\NovaProtect.lnk"
Type: files; Name: "{userprograms}\NovaPack\NovaProtect 命令行.lnk"
Type: files; Name: "{userprograms}\NovaPack\卸载 NovaProtect.lnk"
Type: dirifempty; Name: "{userprograms}\NovaPack"

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "启动 NovaProtect"; Flags: nowait postinstall skipifsilent
