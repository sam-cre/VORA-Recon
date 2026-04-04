!include "MUI2.nsh"
!include "nsDialogs.nsh"
!include "LogicLib.nsh"

; ═══════════════════════════════════════
; BASIC INFO
; ═══════════════════════════════════════
Name "Vora Recon"
OutFile "VoraRecon-Setup.exe"
InstallDir "$PROGRAMFILES64\VoraRecon"
InstallDirRegKey HKLM "Software\VoraRecon" "Install_Dir"
RequestExecutionLevel admin

; ═══════════════════════════════════════
; MODERN UI SETTINGS
; ═══════════════════════════════════════
!define MUI_ABORTWARNING
!define MUI_ICON "${NSISDIR}\Contrib\Graphics\Icons\modern-install.ico"
!define MUI_UNICON "${NSISDIR}\Contrib\Graphics\Icons\modern-uninstall.ico"
!define MUI_WELCOMEPAGE_TITLE "Welcome to Vora Recon Setup"
!define MUI_WELCOMEPAGE_TEXT "Vora Recon is a terminal-native network monitoring tool.$\r$\n$\r$\nThis installer will:$\r$\n  - Install Vora Recon on your system$\r$\n  - Check for Npcap (required for packet capture)$\r$\n  - Create a desktop shortcut$\r$\n$\r$\nClick Next to continue."

; Pages
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
Page custom NpcapPage NpcapPageLeave
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"

; ═══════════════════════════════════════
; NPCAP CHECK PAGE
; ═══════════════════════════════════════
Var NpcapCheckbox
Var InstallNpcap

Function NpcapPage
    ; Check if Npcap is already installed
    ReadRegStr $0 HKLM "SOFTWARE\Npcap" ""
    ${If} $0 != ""
        ; Already installed, skip this page
        Abort
    ${EndIf}

    nsDialogs::Create 1018
    Pop $0

    ${NSD_CreateLabel} 0 0 100% 40u "Npcap is required for Vora Recon to capture network packets.$\r$\nIt was not detected on your system."
    Pop $0

    ${NSD_CreateCheckbox} 0 50u 100% 12u "Download and install Npcap automatically (recommended)"
    Pop $NpcapCheckbox
    ${NSD_SetState} $NpcapCheckbox ${BST_CHECKED}

    nsDialogs::Show
FunctionEnd

Function NpcapPageLeave
    ${NSD_GetState} $NpcapCheckbox $InstallNpcap
FunctionEnd

; ═══════════════════════════════════════
; INSTALLER SECTION
; ═══════════════════════════════════════
Section "Vora Recon" SecMain

    SetOutPath "$INSTDIR"

    ; Copy the main executable
    File "target\release\vora-recon.exe"

    ; Install Npcap if checkbox was checked
    ${If} $InstallNpcap == ${BST_CHECKED}
        DetailPrint "Downloading Npcap..."
        NSISdl::download "https://npcap.com/dist/npcap-1.79.exe" "$TEMP\npcap-installer.exe"
        Pop $0
        ${If} $0 == "success"
            DetailPrint "Installing Npcap..."
            ExecWait '"$TEMP\npcap-installer.exe" /winpcap_mode=yes /S' $0
            ${If} $0 != 0
                MessageBox MB_OK|MB_ICONEXCLAMATION "Npcap installation failed. Please install it manually from https://npcap.com"
            ${Else}
                DetailPrint "Npcap installed successfully."
            ${EndIf}
        ${Else}
            MessageBox MB_OK|MB_ICONEXCLAMATION "Could not download Npcap. Please install it manually from https://npcap.com"
        ${EndIf}
    ${EndIf}

    ; Create launch.vbs
    FileOpen $0 "$INSTDIR\launch.vbs" w
    FileWrite $0 'Set UAC = CreateObject("Shell.Application")$\r$\n'
    FileWrite $0 'UAC.ShellExecute "wt.exe", "-d """ & CreateObject("Scripting.FileSystemObject").GetParentFolderName(WScript.ScriptFullName) & """ """ & CreateObject("Scripting.FileSystemObject").GetParentFolderName(WScript.ScriptFullName) & "\vora-recon.exe""", "", "runas", 1$\r$\n'
    FileClose $0

    ; Create desktop shortcut
    CreateShortcut "$DESKTOP\Vora Recon.lnk" "$WINDIR\System32\wscript.exe" '"$INSTDIR\launch.vbs"' "$INSTDIR\vora-recon.exe"

    ; Create start menu entry
    CreateDirectory "$SMPROGRAMS\VoraRecon"
    CreateShortcut "$SMPROGRAMS\VoraRecon\Vora Recon.lnk" "$WINDIR\System32\wscript.exe" '"$INSTDIR\launch.vbs"' "$INSTDIR\vora-recon.exe"
    CreateShortcut "$SMPROGRAMS\VoraRecon\Uninstall.lnk" "$INSTDIR\Uninstall.exe"

    ; Write registry keys for uninstaller
    WriteRegStr HKLM "Software\VoraRecon" "Install_Dir" "$INSTDIR"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\VoraRecon" "DisplayName" "Vora Recon"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\VoraRecon" "UninstallString" '"$INSTDIR\Uninstall.exe"'
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\VoraRecon" "DisplayVersion" "0.4.0"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\VoraRecon" "Publisher" "Kael Riven"
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\VoraRecon" "NoModify" 1
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\VoraRecon" "NoRepair" 1

    ; Write uninstaller
    WriteUninstaller "$INSTDIR\Uninstall.exe"

SectionEnd

; ═══════════════════════════════════════
; UNINSTALLER
; ═══════════════════════════════════════
Section "Uninstall"

    Delete "$INSTDIR\vora-recon.exe"
    Delete "$INSTDIR\launch.vbs"
    Delete "$INSTDIR\Uninstall.exe"
    RMDir "$INSTDIR"

    Delete "$DESKTOP\Vora Recon.lnk"
    Delete "$SMPROGRAMS\VoraRecon\Vora Recon.lnk"
    Delete "$SMPROGRAMS\VoraRecon\Uninstall.lnk"
    RMDir "$SMPROGRAMS\VoraRecon"

    DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\VoraRecon"
    DeleteRegKey HKLM "Software\VoraRecon"

SectionEnd
