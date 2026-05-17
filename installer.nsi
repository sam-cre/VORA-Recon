!include "MUI2.nsh"
!include "nsDialogs.nsh"
!include "LogicLib.nsh"

; ═══════════════════════════════════════
; BASIC INFO
; ═══════════════════════════════════════
Name "VORA-Recon"
OutFile "VORA-Recon-Setup.exe"
InstallDir "$PROGRAMFILES64\VoraRecon"
InstallDirRegKey HKLM "Software\VoraRecon" "Install_Dir"
RequestExecutionLevel admin

; ═══════════════════════════════════════
; MODERN UI SETTINGS
; ═══════════════════════════════════════
!define MUI_ABORTWARNING
!define MUI_ICON "assets\logo.ico"
!define MUI_UNICON "assets\logo.ico"
!define MUI_WELCOMEPAGE_TITLE "Welcome to VORA-Recon Setup"
!define MUI_WELCOMEPAGE_TEXT "VORA-Recon is a terminal-native network monitoring tool.$\r$\n$\r$\nThis installer will:$\r$\n  - Install VORA-Recon on your system$\r$\n  - Check for Npcap (required for packet capture)$\r$\n$\r$\nClick Next to continue."

; Pages
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "EULA.txt"
!insertmacro MUI_PAGE_DIRECTORY
Page custom NpcapPage NpcapPageLeave
!insertmacro MUI_PAGE_INSTFILES
!define MUI_FINISHPAGE_SHOWREADME ""
!define MUI_FINISHPAGE_SHOWREADME_TEXT "Create Desktop Shortcut"
!define MUI_FINISHPAGE_SHOWREADME_FUNCTION CreateDesktopShortcut
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

    ${NSD_CreateLabel} 0 0 100% 40u "Npcap is required for VORA-Recon to capture network packets.$\r$\nIt was not detected on your system."
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
Section "VORA-Recon" SecMain
    
    ; Ensure processes are closed before installing
    DetailPrint "Closing running instances..."
    nsExec::Exec 'taskkill /F /IM vora-recon.exe /T'
    nsExec::Exec 'taskkill /F /IM launcher.exe /T'
    Sleep 500

    SetOutPath "$INSTDIR"

    ; Copy the main executables
    File "target\release\vora-recon.exe"
    File "target\release\launcher.exe"

    ; Copy Optimization scripts
    File "Optimize-Vora.ps1"
    File "VoraPerformance.reg"

    ; Copy Assets (icon, etc.)
    SetOutPath "$INSTDIR\assets"
    File "assets\logo.ico"
    File "assets\logo.png"

    SetOutPath "$INSTDIR"

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

    ; Automatically apply performance optimizations
    DetailPrint "Applying performance optimizations..."
    ExecWait 'regedit.exe /s "$INSTDIR\VoraPerformance.reg"'

    ; Cleanup any old shortcut variants
    Delete "$DESKTOP\Vora Recon.lnk"
    Delete "$DESKTOP\VORA-RECON.lnk"
    Delete "$DESKTOP\VORA-Recon.lnk"

    ; Create start menu entry
    CreateDirectory "$SMPROGRAMS\VoraRecon"
    CreateShortcut "$SMPROGRAMS\VoraRecon\VORA-Recon.lnk" "$INSTDIR\launcher.exe" "" "$INSTDIR\assets\logo.ico"
    CreateShortcut "$SMPROGRAMS\VoraRecon\Uninstall.lnk" "$INSTDIR\Uninstall.exe"

    ; Write registry keys for uninstaller
    WriteRegStr HKLM "Software\VoraRecon" "Install_Dir" "$INSTDIR"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\VoraRecon" "DisplayName" "VORA-Recon"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\VoraRecon" "UninstallString" '"$INSTDIR\Uninstall.exe"'
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\VoraRecon" "DisplayVersion" "0.4.0"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\VoraRecon" "Publisher" "Sam Rogers"
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
    Delete "$INSTDIR\launcher.exe"
    Delete "$INSTDIR\Uninstall.exe"
    Delete "$INSTDIR\assets\logo.ico"
    Delete "$INSTDIR\assets\logo.png"
    RMDir "$INSTDIR\assets"
    RMDir "$INSTDIR"

    Delete "$DESKTOP\VORA-RECON.lnk"
    Delete "$DESKTOP\VORA-Recon.lnk"
    Delete "$DESKTOP\Vora Recon.lnk"
    Delete "$SMPROGRAMS\VoraRecon\VORA-RECON.lnk"
    Delete "$SMPROGRAMS\VoraRecon\VORA-Recon.lnk"
    Delete "$SMPROGRAMS\VoraRecon\Vora Recon.lnk"
    Delete "$SMPROGRAMS\VoraRecon\Uninstall.lnk"
    RMDir "$SMPROGRAMS\VoraRecon"

    DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\VoraRecon"
    DeleteRegKey HKLM "Software\VoraRecon"

SectionEnd

Function CreateDesktopShortcut
    Delete "$DESKTOP\VORA-Recon.lnk"
    Delete "$DESKTOP\VORA-RECON.lnk"
    Delete "$DESKTOP\Vora Recon.lnk"
    CreateShortcut "$DESKTOP\VORA-Recon.lnk" "$INSTDIR\launcher.exe" "" "$INSTDIR\assets\logo.ico"
FunctionEnd
