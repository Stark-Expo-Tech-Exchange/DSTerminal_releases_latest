; DSTerminal Installer Script using Inno Setup

[Setup]
AppName=DSTerminal
AppVersion=v2.1.0
AppPublisher=Stark Expo Tech Exchange
AppPublisherURL=https://starkexpotechexchange-mw.com
DefaultDirName={pf}\DSTerminal
DefaultGroupName=DSTerminal
LicenseFile=license.txt
OutputDir=.
OutputBaseFilename=DSTerminal_Installer
Compression=lzma
SolidCompression=yes
DisableWelcomePage=no
WizardStyle=modern
SetupIconFile=icon.ico
DisableProgramGroupPage=yes
AllowNoIcons=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
Source: "dist\dsterminal.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\DSTerminal"; Filename: "{app}\dsterminal.exe"
Name: "{group}\Uninstall DSTerminal"; Filename: "{uninstallexe}"
Name: "{userdesktop}\DSTerminal"; Filename: "{app}\dsterminal.exe"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional icons:"; Flags: checkedonce

[Run]
Filename: "{app}\dsterminal.exe"; Description: "Launch DSTerminal"; Flags: nowait postinstall skipifsilent
