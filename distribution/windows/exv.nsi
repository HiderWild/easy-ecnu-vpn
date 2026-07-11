Unicode true
ManifestDPIAware true
RequestExecutionLevel user

!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "nsDialogs.nsh"

!ifndef APP_VERSION
  !error "APP_VERSION define is required"
!endif

!ifndef SOURCE_DIR
  !error "SOURCE_DIR define is required"
!endif

!ifndef OUTPUT_FILE
  !error "OUTPUT_FILE define is required"
!endif

!ifndef UNINSTALL_MANIFEST
  !error "UNINSTALL_MANIFEST define is required"
!endif

!ifndef DEFAULT_INSTALL_DIR
  !define DEFAULT_INSTALL_DIR "$LOCALAPPDATA\Programs\EXV"
!endif

!define APP_NAME "EXV"
!define COMPANY_NAME "EXV"
!define UNINSTALL_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\EXV"
!define MUI_ICON "..\..\assets\icons\icon.ico"
!define MUI_UNICON "..\..\assets\icons\icon.ico"
!define MUI_ABORTWARNING
!define SERVICE_NAME "exv-helper"

Name "${APP_NAME}"
Caption "${APP_NAME} 安装向导"
OutFile "${OUTPUT_FILE}"
InstallDir "${DEFAULT_INSTALL_DIR}"
InstallDirRegKey HKCU "Software\EXV" "InstallDir"
Icon "..\..\assets\icons\icon.ico"
UninstallIcon "..\..\assets\icons\icon.ico"
BrandingText "${APP_NAME}"

Var HadHelperService
Var HelperServiceStillInstalled
Var FinishCreateDesktopShortcut
Var FinishLaunchApp
Var FinishCreateDesktopShortcutCheckbox
Var FinishLaunchAppCheckbox
Var UninstallClearUserData
Var UninstallClearUserDataCheckbox

Function un.onInit
  StrCpy $UninstallClearUserData ${BST_UNCHECKED}
FunctionEnd

Function DetectHelperServiceBeforeInstall
  StrCpy $HadHelperService 0
  nsExec::ExecToStack `sc.exe query ${SERVICE_NAME}`
  Pop $0
  Pop $1
  StrCmp $0 0 0 +2
    StrCpy $HadHelperService 1
FunctionEnd

Function WriteHelperServiceMaintenanceScript
  InitPluginsDir
  FileOpen $0 "$PLUGINSDIR\exv-helper-service-maintenance.ps1" w
  FileWrite $0 "$$ErrorActionPreference = 'SilentlyContinue'$\r$\n"
  FileWrite $0 "Stop-Service -Name '${SERVICE_NAME}' -Force$\r$\n"
  FileWrite $0 "Stop-Process -Name exv-helper -Force$\r$\n"
  FileWrite $0 "sc.exe delete ${SERVICE_NAME} | Out-Null$\r$\n"
  FileClose $0
FunctionEnd

Function RunElevatedHelperServiceCleanup
  Call WriteHelperServiceMaintenanceScript
  nsExec::ExecToLog `powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath powershell.exe -Verb RunAs -Wait -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File \"$PLUGINSDIR\exv-helper-service-maintenance.ps1\"'"`
FunctionEnd

Function WaitForHelperServiceRemoval
  StrCpy $HelperServiceStillInstalled 1
  StrCpy $0 0
  loop:
    nsExec::ExecToStack `sc.exe query ${SERVICE_NAME}`
    Pop $1
    Pop $2
    StrCmp $1 0 still_installed removed
  removed:
    StrCpy $HelperServiceStillInstalled 0
    Goto done
  still_installed:
    IntCmp $0 20 done wait done
  wait:
    IntOp $0 $0 + 1
    Sleep 500
    Goto loop
  done:
FunctionEnd

Function RunHelperServicePreInstallMaintenance
  StrCmp $HadHelperService 1 0 done
  IfFileExists "$INSTDIR\bin\exv.exe" 0 fallback
    nsExec::ExecToLog `"$INSTDIR\bin\exv.exe" desktop-rpc service.uninstall "{}"`
    Call WaitForHelperServiceRemoval
    StrCmp $HelperServiceStillInstalled 0 done
  fallback:
    Call RunElevatedHelperServiceCleanup
    Call WaitForHelperServiceRemoval
  done:
FunctionEnd

Function RunHelperServicePostInstallRepair
  StrCmp $HadHelperService 1 0 done
  IfFileExists "$INSTDIR\bin\exv.exe" 0 done
    nsExec::ExecToLog `"$INSTDIR\bin\exv.exe" desktop-rpc service.install "{}"`
  done:
FunctionEnd

Function WriteHelperProcessCleanupScript
  InitPluginsDir
  FileOpen $0 "$PLUGINSDIR\exv-helper-process-cleanup.ps1" w
  FileWrite $0 "$$ErrorActionPreference = 'SilentlyContinue'$\r$\n"
  FileWrite $0 "$$deadline = (Get-Date).AddSeconds(15)$\r$\n"
  FileWrite $0 "$$remaining = @()$\r$\n"
  FileWrite $0 "do {$\r$\n"
  FileWrite $0 "  Stop-Process -Name exv-helper -Force -ErrorAction SilentlyContinue$\r$\n"
  FileWrite $0 "  Start-Sleep -Milliseconds 300$\r$\n"
  FileWrite $0 "  $$remaining = @(Get-Process -Name exv-helper -ErrorAction SilentlyContinue)$\r$\n"
  FileWrite $0 "} while ($$remaining.Count -gt 0 -and (Get-Date) -lt $$deadline)$\r$\n"
  FileWrite $0 "if ($$remaining.Count -gt 0) { exit 1 }$\r$\n"
  FileWrite $0 "exit 0$\r$\n"
  FileClose $0
FunctionEnd

Function RunHelperProcessCleanup
  Call WriteHelperProcessCleanupScript
  nsExec::ExecToStack `powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$PLUGINSDIR\exv-helper-process-cleanup.ps1"`
  Pop $0
  Pop $1
  StrCmp $0 0 done
    nsExec::ExecToLog `powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath powershell.exe -Verb RunAs -Wait -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File \"$PLUGINSDIR\exv-helper-process-cleanup.ps1\"'"`
  done:
  nsExec::ExecToLog `taskkill.exe /IM exv-helper.exe /T /F`
  Pop $0
FunctionEnd

Function ExtractLegacyCompatibilityCleanupScript
  InitPluginsDir
  File /oname=$PLUGINSDIR\clear-windows-legacy-state.ps1 "${SOURCE_DIR}\support\clear-windows-legacy-state.ps1"
FunctionEnd

Function RunLegacyCompatibilityCleanup
  Call ExtractLegacyCompatibilityCleanupScript
  nsExec::ExecToStack `powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$PLUGINSDIR\clear-windows-legacy-state.ps1" -CurrentInstallDir "$INSTDIR"`
  Pop $0
  Pop $1
  StrCmp $0 0 done
    nsExec::ExecToLog `powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath powershell.exe -Verb RunAs -Wait -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File \"$PLUGINSDIR\clear-windows-legacy-state.ps1\" -CurrentInstallDir \"$INSTDIR\"'"`
    Pop $0
  done:
FunctionEnd

Function WriteAppProcessCleanupScript
  InitPluginsDir
  FileOpen $0 "$PLUGINSDIR\exv-app-process-cleanup.ps1" w
  FileWrite $0 "$$ErrorActionPreference = 'SilentlyContinue'$\r$\n"
  FileWrite $0 "$$shutdownSent = $$false$\r$\n"
  FileWrite $0 "$$pipe = $$null$\r$\n"
  FileWrite $0 "$$writer = $$null$\r$\n"
  FileWrite $0 "$$reader = $$null$\r$\n"
  FileWrite $0 "try {$\r$\n"
  FileWrite $0 "  $$pipe = [System.IO.Pipes.NamedPipeClientStream]::new('.', 'exv-core-ipc-v1', [System.IO.Pipes.PipeDirection]::InOut)$\r$\n"
  FileWrite $0 "  $$pipe.Connect(500)$\r$\n"
  FileWrite $0 "  $$writer = [System.IO.StreamWriter]::new($$pipe)$\r$\n"
  FileWrite $0 "  $$writer.AutoFlush = $$true$\r$\n"
  FileWrite $0 "  $$reader = [System.IO.StreamReader]::new($$pipe)$\r$\n"
  FileWrite $0 "  $$writer.WriteLine('{$\"id$\":990001,$\"action$\":$\"core.shutdown$\",$\"payload$\":{}}')$\r$\n"
  FileWrite $0 "  $$null = $$reader.ReadLine()$\r$\n"
  FileWrite $0 "  $$shutdownSent = $$true$\r$\n"
  FileWrite $0 "} catch {} finally {$\r$\n"
  FileWrite $0 "  if ($$writer) { $$writer.Dispose() }$\r$\n"
  FileWrite $0 "  if ($$reader) { $$reader.Dispose() }$\r$\n"
  FileWrite $0 "  if ($$pipe) { $$pipe.Dispose() }$\r$\n"
  FileWrite $0 "}$\r$\n"
  FileWrite $0 "if ($$shutdownSent) { Start-Sleep -Milliseconds 1200 } else { Start-Sleep -Milliseconds 300 }$\r$\n"
  FileWrite $0 "Stop-Process -Name exv-ui -Force -ErrorAction SilentlyContinue$\r$\n"
  FileWrite $0 "Stop-Process -Name exv -Force -ErrorAction SilentlyContinue$\r$\n"
  FileWrite $0 "Start-Sleep -Milliseconds 300$\r$\n"
  FileWrite $0 "$$remaining = @(Get-Process -Name exv-ui,exv -ErrorAction SilentlyContinue)$\r$\n"
  FileWrite $0 "if ($$remaining.Count -gt 0) { exit 1 }$\r$\n"
  FileWrite $0 "exit 0$\r$\n"
  FileClose $0
FunctionEnd

Function RunAppProcessCleanup
  Call WriteAppProcessCleanupScript
  nsExec::ExecToStack `powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$PLUGINSDIR\exv-app-process-cleanup.ps1"`
  Pop $0
  Pop $1
  StrCmp $0 0 done
    nsExec::ExecToLog `powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath powershell.exe -Verb RunAs -Wait -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File \"$PLUGINSDIR\exv-app-process-cleanup.ps1\"'"`
  done:
FunctionEnd

Function StopRunningAppProcesses
  Call RunAppProcessCleanup
  nsExec::ExecToLog `taskkill.exe /IM exv-ui.exe /T /F`
  Pop $0
  nsExec::ExecToLog `taskkill.exe /IM exv.exe /T /F`
  Pop $0
FunctionEnd

Function un.DetectHelperServiceBeforeInstall
  StrCpy $HadHelperService 0
  nsExec::ExecToStack `sc.exe query ${SERVICE_NAME}`
  Pop $0
  Pop $1
  StrCmp $0 0 0 +2
    StrCpy $HadHelperService 1
FunctionEnd

Function un.WriteHelperServiceMaintenanceScript
  InitPluginsDir
  FileOpen $0 "$PLUGINSDIR\exv-helper-service-maintenance.ps1" w
  FileWrite $0 "$$ErrorActionPreference = 'SilentlyContinue'$\r$\n"
  FileWrite $0 "Stop-Service -Name '${SERVICE_NAME}' -Force$\r$\n"
  FileWrite $0 "Stop-Process -Name exv-helper -Force$\r$\n"
  FileWrite $0 "sc.exe delete ${SERVICE_NAME} | Out-Null$\r$\n"
  FileClose $0
FunctionEnd

Function un.RunElevatedHelperServiceCleanup
  Call un.WriteHelperServiceMaintenanceScript
  nsExec::ExecToLog `powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath powershell.exe -Verb RunAs -Wait -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File \"$PLUGINSDIR\exv-helper-service-maintenance.ps1\"'"`
FunctionEnd

Function un.WaitForHelperServiceRemoval
  StrCpy $HelperServiceStillInstalled 1
  StrCpy $0 0
  loop:
    nsExec::ExecToStack `sc.exe query ${SERVICE_NAME}`
    Pop $1
    Pop $2
    StrCmp $1 0 still_installed removed
  removed:
    StrCpy $HelperServiceStillInstalled 0
    Goto done
  still_installed:
    IntCmp $0 20 done wait done
  wait:
    IntOp $0 $0 + 1
    Sleep 500
    Goto loop
  done:
FunctionEnd

Function un.WriteHelperProcessCleanupScript
  InitPluginsDir
  FileOpen $0 "$PLUGINSDIR\exv-helper-process-cleanup.ps1" w
  FileWrite $0 "$$ErrorActionPreference = 'SilentlyContinue'$\r$\n"
  FileWrite $0 "$$deadline = (Get-Date).AddSeconds(15)$\r$\n"
  FileWrite $0 "$$remaining = @()$\r$\n"
  FileWrite $0 "do {$\r$\n"
  FileWrite $0 "  Stop-Process -Name exv-helper -Force -ErrorAction SilentlyContinue$\r$\n"
  FileWrite $0 "  Start-Sleep -Milliseconds 300$\r$\n"
  FileWrite $0 "  $$remaining = @(Get-Process -Name exv-helper -ErrorAction SilentlyContinue)$\r$\n"
  FileWrite $0 "} while ($$remaining.Count -gt 0 -and (Get-Date) -lt $$deadline)$\r$\n"
  FileWrite $0 "if ($$remaining.Count -gt 0) { exit 1 }$\r$\n"
  FileWrite $0 "exit 0$\r$\n"
  FileClose $0
FunctionEnd

Function un.RunHelperProcessCleanup
  Call un.WriteHelperProcessCleanupScript
  nsExec::ExecToStack `powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$PLUGINSDIR\exv-helper-process-cleanup.ps1"`
  Pop $0
  Pop $1
  StrCmp $0 0 done
    nsExec::ExecToLog `powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath powershell.exe -Verb RunAs -Wait -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File \"$PLUGINSDIR\exv-helper-process-cleanup.ps1\"'"`
  done:
  nsExec::ExecToLog `taskkill.exe /IM exv-helper.exe /T /F`
  Pop $0
FunctionEnd

Function un.RunLegacyCompatibilityCleanup
  IfFileExists "$INSTDIR\support\clear-windows-legacy-state.ps1" 0 done
    nsExec::ExecToStack `powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$INSTDIR\support\clear-windows-legacy-state.ps1" -CurrentInstallDir "$INSTDIR"`
    Pop $0
    Pop $1
    StrCmp $0 0 done
      nsExec::ExecToLog `powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath powershell.exe -Verb RunAs -Wait -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File \"$INSTDIR\support\clear-windows-legacy-state.ps1\" -CurrentInstallDir \"$INSTDIR\"'"`
      Pop $0
  done:
FunctionEnd

Function un.WriteAppProcessCleanupScript
  InitPluginsDir
  FileOpen $0 "$PLUGINSDIR\exv-app-process-cleanup.ps1" w
  FileWrite $0 "$$ErrorActionPreference = 'SilentlyContinue'$\r$\n"
  FileWrite $0 "$$shutdownSent = $$false$\r$\n"
  FileWrite $0 "$$pipe = $$null$\r$\n"
  FileWrite $0 "$$writer = $$null$\r$\n"
  FileWrite $0 "$$reader = $$null$\r$\n"
  FileWrite $0 "try {$\r$\n"
  FileWrite $0 "  $$pipe = [System.IO.Pipes.NamedPipeClientStream]::new('.', 'exv-core-ipc-v1', [System.IO.Pipes.PipeDirection]::InOut)$\r$\n"
  FileWrite $0 "  $$pipe.Connect(500)$\r$\n"
  FileWrite $0 "  $$writer = [System.IO.StreamWriter]::new($$pipe)$\r$\n"
  FileWrite $0 "  $$writer.AutoFlush = $$true$\r$\n"
  FileWrite $0 "  $$reader = [System.IO.StreamReader]::new($$pipe)$\r$\n"
  FileWrite $0 "  $$writer.WriteLine('{$\"id$\":990001,$\"action$\":$\"core.shutdown$\",$\"payload$\":{}}')$\r$\n"
  FileWrite $0 "  $$null = $$reader.ReadLine()$\r$\n"
  FileWrite $0 "  $$shutdownSent = $$true$\r$\n"
  FileWrite $0 "} catch {} finally {$\r$\n"
  FileWrite $0 "  if ($$writer) { $$writer.Dispose() }$\r$\n"
  FileWrite $0 "  if ($$reader) { $$reader.Dispose() }$\r$\n"
  FileWrite $0 "  if ($$pipe) { $$pipe.Dispose() }$\r$\n"
  FileWrite $0 "}$\r$\n"
  FileWrite $0 "if ($$shutdownSent) { Start-Sleep -Milliseconds 1200 } else { Start-Sleep -Milliseconds 300 }$\r$\n"
  FileWrite $0 "Stop-Process -Name exv-ui -Force -ErrorAction SilentlyContinue$\r$\n"
  FileWrite $0 "Stop-Process -Name exv -Force -ErrorAction SilentlyContinue$\r$\n"
  FileWrite $0 "Start-Sleep -Milliseconds 300$\r$\n"
  FileWrite $0 "$$remaining = @(Get-Process -Name exv-ui,exv -ErrorAction SilentlyContinue)$\r$\n"
  FileWrite $0 "if ($$remaining.Count -gt 0) { exit 1 }$\r$\n"
  FileWrite $0 "exit 0$\r$\n"
  FileClose $0
FunctionEnd

Function un.RunAppProcessCleanup
  Call un.WriteAppProcessCleanupScript
  nsExec::ExecToStack `powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$PLUGINSDIR\exv-app-process-cleanup.ps1"`
  Pop $0
  Pop $1
  StrCmp $0 0 done
    nsExec::ExecToLog `powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath powershell.exe -Verb RunAs -Wait -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File \"$PLUGINSDIR\exv-app-process-cleanup.ps1\"'"`
  done:
FunctionEnd

Function un.StopRunningAppProcesses
  Call un.RunAppProcessCleanup
  nsExec::ExecToLog `taskkill.exe /IM exv-ui.exe /T /F`
  Pop $0
  nsExec::ExecToLog `taskkill.exe /IM exv.exe /T /F`
  Pop $0
FunctionEnd

Function un.RunHelperServiceUninstallMaintenance
  Call un.DetectHelperServiceBeforeInstall
  StrCmp $HadHelperService 1 0 done
  IfFileExists "$INSTDIR\bin\exv.exe" 0 fallback
    nsExec::ExecToLog `"$INSTDIR\bin\exv.exe" desktop-rpc service.uninstall "{}"`
    Call un.WaitForHelperServiceRemoval
    StrCmp $HelperServiceStillInstalled 0 done
  fallback:
    Call un.RunElevatedHelperServiceCleanup
    Call un.WaitForHelperServiceRemoval
  done:
FunctionEnd

Function un.RemoveStableHelperPayload
  RMDir /r "$INSTDIR\exv-ui.exe.WebView2"
  Delete "$LOCALAPPDATA\EXV\Helper\exv-helper.exe"
  RMDir "$LOCALAPPDATA\EXV\Helper"
FunctionEnd

Function un.RunUserDataCleanup
  StrCmp $UninstallClearUserData ${BST_CHECKED} 0 done
  IfFileExists "$INSTDIR\support\clear-local-user-config.ps1" 0 done
    nsExec::ExecToLog `powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$INSTDIR\support\clear-local-user-config.ps1" -Force -IncludeCredentialManager`
  done:
FunctionEnd

Function FinishOptionsPage
  !insertmacro MUI_HEADER_TEXT "安装完成" "EXV 已安装到此电脑。"
  nsDialogs::Create 1018
  Pop $0
  ${If} $0 == error
    Abort
  ${EndIf}
  ${NSD_CreateLabel} 0 0 100% 26u "安装程序已完成。你可以现在创建桌面快捷方式并立即打开 EXV。"
  Pop $0
  ${NSD_CreateCheckbox} 0 42u 100% 12u "创建桌面快捷方式"
  Pop $FinishCreateDesktopShortcutCheckbox
  ${NSD_SetState} $FinishCreateDesktopShortcutCheckbox ${BST_CHECKED}
  ${NSD_CreateCheckbox} 0 62u 100% 12u "立即打开 EXV"
  Pop $FinishLaunchAppCheckbox
  ${NSD_SetState} $FinishLaunchAppCheckbox ${BST_CHECKED}
  nsDialogs::Show
FunctionEnd

Function FinishOptionsLeave
  ${NSD_GetState} $FinishCreateDesktopShortcutCheckbox $FinishCreateDesktopShortcut
  ${NSD_GetState} $FinishLaunchAppCheckbox $FinishLaunchApp
  ${If} $FinishCreateDesktopShortcut == ${BST_CHECKED}
    CreateShortCut "$DESKTOP\EXV.lnk" "$INSTDIR\exv-ui.exe" "" "$INSTDIR\exv-ui.exe"
  ${EndIf}
  ${If} $FinishLaunchApp == ${BST_CHECKED}
    SetOutPath "$INSTDIR"
    ExecShell "open" "$INSTDIR\exv-ui.exe" "" SW_SHOWNORMAL
  ${EndIf}
FunctionEnd

Function un.UninstallOptionsPage
  !insertmacro MUI_HEADER_TEXT "卸载选项" "选择是否同时清除当前用户数据。"
  nsDialogs::Create 1018
  Pop $0
  ${If} $0 == error
    Abort
  ${EndIf}
  ${NSD_CreateLabel} 0 0 100% 26u "卸载程序会移除 EXV 应用文件。勾选下面的选项后，还会清除当前用户的配置、日志、WebView2 数据和本地凭据。"
  Pop $0
  ${NSD_CreateCheckbox} 0 42u 100% 12u "清除用户数据"
  Pop $UninstallClearUserDataCheckbox
  ${NSD_SetState} $UninstallClearUserDataCheckbox ${BST_UNCHECKED}
  nsDialogs::Show
FunctionEnd

Function un.UninstallOptionsLeave
  ${NSD_GetState} $UninstallClearUserDataCheckbox $UninstallClearUserData
FunctionEnd

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
Page custom FinishOptionsPage FinishOptionsLeave
!insertmacro MUI_UNPAGE_CONFIRM
UninstPage custom un.UninstallOptionsPage un.UninstallOptionsLeave
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "SimpChinese"

Section "Install"
  SetShellVarContext current
  Call StopRunningAppProcesses
  Call DetectHelperServiceBeforeInstall
  Call RunHelperServicePreInstallMaintenance
  Call RunHelperProcessCleanup
  Call RunLegacyCompatibilityCleanup
  SetOutPath "$INSTDIR\support"
  File "${SOURCE_DIR}\support\clear-local-user-config.ps1"
  File "${SOURCE_DIR}\support\clear-windows-legacy-state.ps1"
  SetOutPath "$INSTDIR"
  WriteUninstaller "$INSTDIR\Uninstall.exe"
  File /r "${SOURCE_DIR}\*.*"

  WriteRegStr HKCU "Software\EXV" "InstallDir" "$INSTDIR"
  WriteRegStr HKCU "${UNINSTALL_KEY}" "DisplayName" "${APP_NAME}"
  WriteRegStr HKCU "${UNINSTALL_KEY}" "DisplayVersion" "${APP_VERSION}"
  WriteRegStr HKCU "${UNINSTALL_KEY}" "Publisher" "${COMPANY_NAME}"
  WriteRegStr HKCU "${UNINSTALL_KEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKCU "${UNINSTALL_KEY}" "DisplayIcon" "$INSTDIR\exv-ui.exe"
  WriteRegStr HKCU "${UNINSTALL_KEY}" "UninstallString" '"$INSTDIR\Uninstall.exe"'
  WriteRegStr HKCU "${UNINSTALL_KEY}" "QuietUninstallString" '"$INSTDIR\Uninstall.exe" /S'
  WriteRegDWORD HKCU "${UNINSTALL_KEY}" "NoModify" 1
  WriteRegDWORD HKCU "${UNINSTALL_KEY}" "NoRepair" 1

  CreateDirectory "$SMPROGRAMS\EXV"
  CreateShortCut "$SMPROGRAMS\EXV\EXV.lnk" "$INSTDIR\exv-ui.exe" "" "$INSTDIR\exv-ui.exe"
  CreateShortCut "$SMPROGRAMS\EXV\Uninstall EXV.lnk" "$INSTDIR\Uninstall.exe" "" "$INSTDIR\Uninstall.exe"

  Call RunHelperServicePostInstallRepair
SectionEnd

Section "Uninstall"
  SetShellVarContext current
  Call un.StopRunningAppProcesses
  Call un.RunHelperServiceUninstallMaintenance
  Call un.RunHelperProcessCleanup
  Call un.RunLegacyCompatibilityCleanup
  Call un.RemoveStableHelperPayload
  Call un.RunUserDataCleanup
  RMDir "$LOCALAPPDATA\EXV"
  Delete "$DESKTOP\EXV.lnk"
  Delete "$SMPROGRAMS\EXV\EXV.lnk"
  Delete "$SMPROGRAMS\EXV\Uninstall EXV.lnk"
  RMDir "$SMPROGRAMS\EXV"

  DeleteRegKey HKCU "${UNINSTALL_KEY}"
  DeleteRegValue HKCU "Software\EXV" "InstallDir"
  DeleteRegKey /ifempty HKCU "Software\EXV"

  !include "${UNINSTALL_MANIFEST}"
SectionEnd
