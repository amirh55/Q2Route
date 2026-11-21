; Q2Route installer. Build with: scripts\package.ps1 -Setup  (passes /DAppVersion=x.y.z)
#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif

[Setup]
; Never change this AppId: it is how Setup recognises an earlier install.
AppId={{3BE0A35A-7768-4215-B05F-784B652698AF}
AppName=Q2Route
AppVersion={#AppVersion}
AppPublisher=Q2Route
DefaultDirName={autopf}\Q2Route
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
CloseApplications=yes
RestartApplications=no
UninstallDisplayIcon={app}\q2route.exe
OutputDir=..\dist
OutputBaseFilename=Q2Route-Setup-{#AppVersion}
SolidCompression=yes
WizardStyle=modern

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; Flags: unchecked

[Files]
; Source: the staged folder built by scripts\package.ps1 -Setup
Source: "..\dist\setup-stage\q2route.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\dist\setup-stage\q2route-service.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\dist\setup-stage\WinDivert.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\dist\setup-stage\WinDivert64.sys"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\dist\setup-stage\WinDivert-LICENSE.txt"; DestDir: "{app}"; Flags: ignoreversion
; Copy of the new service exe so PrepareToInstall can remove an old service before files are replaced.
Source: "..\dist\setup-stage\q2route-service.exe"; DestDir: "{tmp}"; Flags: dontcopy

[Icons]
Name: "{autoprograms}\Q2Route"; Filename: "{app}\q2route.exe"
Name: "{autodesktop}\Q2Route"; Filename: "{app}\q2route.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\q2route.exe"; Description: "Launch Q2Route"; Flags: nowait postinstall skipifsilent runasoriginaluser; Check: not SilentNoLaunch
Filename: "{app}\q2route.exe"; Flags: nowait runasoriginaluser; Check: SilentLaunch

[UninstallRun]
Filename: "{sys}\taskkill.exe"; Parameters: "/IM q2route.exe /F"; Flags: runhidden; RunOnceId: "KillUi"
Filename: "{app}\q2route-service.exe"; Parameters: "uninstall"; Flags: runhidden; RunOnceId: "RemoveService"

[Code]
function HasSwitch(const Name: String): Boolean;
var
  I: Integer;
begin
  Result := False;
  for I := 1 to ParamCount do
    if CompareText(ParamStr(I), '/' + Name) = 0 then Result := True;
end;

function SilentNoLaunch: Boolean;
begin
  Result := WizardSilent and HasSwitch('NOLAUNCH');
end;

{ Silent installs (e.g. the in-app updater) relaunch the UI unless /NOLAUNCH is given. }
function SilentLaunch: Boolean;
begin
  Result := WizardSilent and (not HasSwitch('NOLAUNCH'));
end;

function ProcessRunning(const Exe: String): Boolean;
var
  Code: Integer;
begin
  { find returns 0 when the image name is listed }
  Result := Exec(ExpandConstant('{cmd}'),
    '/C tasklist /FI "IMAGENAME eq ' + Exe + '" | find /I "' + Exe + '"',
    '', SW_HIDE, ewWaitUntilTerminated, Code) and (Code = 0);
end;

function ServiceExists: Boolean;
var
  Code: Integer;
begin
  Result := Exec(ExpandConstant('{sys}\sc.exe'), 'query Q2Route', '', SW_HIDE,
    ewWaitUntilTerminated, Code) and (Code = 0);
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  Code: Integer;
  Tmp: String;
begin
  Result := '';
  if ProcessRunning('Proxifier.exe') then begin
    Result := 'Proxifier is running. Exit it fully (tray icon too), then run Setup again.';
    Exit;
  end;
  { Close the UI. CloseApplications usually did it already; this is the fallback. }
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/IM q2route.exe /F', '', SW_HIDE,
    ewWaitUntilTerminated, Code);
  if ServiceExists then begin
    { The new exe works by service name, wherever the old copy lives. }
    ExtractTemporaryFile('q2route-service.exe');
    Tmp := ExpandConstant('{tmp}\q2route-service.exe');
    if not Exec(Tmp, 'uninstall', '', SW_HIDE, ewWaitUntilTerminated, Code) or (Code <> 0) then begin
      Result := 'Could not remove the existing Q2Route service (exit code ' + IntToStr(Code) + ').';
      Exit;
    end;
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  Code: Integer;
  OutFile, Output: AnsiString;
  Cmd: String;
begin
  if CurStep <> ssPostInstall then Exit;
  OutFile := ExpandConstant('{tmp}\service-install.txt');
  Cmd := '/C ""' + ExpandConstant('{app}\q2route-service.exe') + '" install > "' + OutFile + '" 2>&1"';
  if not Exec(ExpandConstant('{cmd}'), Cmd, '', SW_HIDE, ewWaitUntilTerminated, Code) or (Code <> 0) then begin
    LoadStringFromFile(OutFile, Output);
    SuppressibleMsgBox('Q2Route service install failed (exit code ' + IntToStr(Code) + '):'#13#10#13#10 +
      String(Output), mbError, MB_OK, IDOK);
    Abort;
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep <> usPostUninstall then Exit;
  if UninstallSilent then Exit;
  if MsgBox('Also delete Q2Route''s settings, rules and logs?', mbConfirmation,
       MB_YESNO or MB_DEFBUTTON2) = IDYES then begin
    DelTree(ExpandConstant('{commonappdata}\Q2Route'), True, True, True);
    DelTree(ExpandConstant('{userappdata}\Q2Route'), True, True, True);
  end;
end;
