# --- VORA-Recon Optimization & Setup Script ---
# This script finds the Npcap SDK (Packet.lib) and configures your environment.

$ErrorActionPreference = "Continue"
Write-Host "--- Finding Network Libraries (Npcap SDK) ---" -ForegroundColor Cyan

# Common search paths for Npcap SDK
$searchPaths = @(
    "$HOME\Downloads\Npcap-SDK\Lib\x64",
    "$HOME\Documents\Npcap-SDK\Lib\x64",
    "C:\Npcap-SDK\Lib\x64",
    "C:\Npcap\Lib\x64",
    "$PSScriptRoot\lib\x64"
)

$foundPath = $null
foreach ($path in $searchPaths) {
    if (Test-Path "$path\Packet.lib") {
        $foundPath = $path
        break
    }
}

if ($null -eq $foundPath) {
    Write-Host "Warning: Packet.lib not found in standard locations." -ForegroundColor Yellow
    Write-Host "Please download the Npcap SDK from https://npcap.com/#download and place the Lib folder here."
    $manualPath = Read-Host "Or, enter the path to the Npcap SDK Lib\x64 folder manually"
    if (Test-Path "$manualPath\Packet.lib") {
        $foundPath = $manualPath
    } elseif (Test-Path "$manualPath\Lib\x64\Packet.lib") {
        $foundPath = "$manualPath\Lib\x64"
    } elseif (Test-Path "$manualPath\x64\Packet.lib") {
        $foundPath = "$manualPath\x64"
    }
}

if ($foundPath) {
    Write-Host "Success! Found Packet.lib at: $foundPath" -ForegroundColor Green
    
    # Set LIB environment variable for the current session and the user
    $env:LIB += ";$foundPath"
    [Environment]::SetEnvironmentVariable("LIB", $env:LIB + ";$foundPath", "User")
    Write-Host "Environment configured. LIB path updated." -ForegroundColor Cyan

    Write-Host "--- Attempting Optimized Release Build ---" -ForegroundColor Cyan
    cargo build --release
    
    if ($?) {
        Write-Host "Build Succeeded! You can find vora-recon.exe in target\release\" -ForegroundColor Green

        # --- Shortcut Creation ---
        $createShortcut = Read-Host "`nWould you like to create a Desktop Shortcut for VORA-Recon? (y/n)"
        if ($createShortcut -eq 'y' -or $createShortcut -eq 'Y') {
            try {
                $wshell = New-Object -ComObject WScript.Shell
                $desktop = [System.Environment]::GetFolderPath('Desktop')
                $shortcut = $wshell.CreateShortcut("$desktop\Vora Recon.lnk")
                $targetPath = "$PSScriptRoot\target\release\launcher.exe"
                $shortcut.TargetPath = $targetPath
                $shortcut.WorkingDirectory = "$PSScriptRoot\target\release"
                $shortcut.Description = "VORA-Recon Network Sniffer"
                $shortcut.Save()
                Write-Host "Desktop Shortcut Created!" -ForegroundColor Green
            } catch {
                Write-Host "Failed to create shortcut: $_" -ForegroundColor Yellow
            }
        }
    } else {
        Write-Host "Build failed. Ensure you have the Npcap driver installed (https://npcap.com/)." -ForegroundColor Red
    }
} else {
    Write-Host "Error: Could not configure build environment without Packet.lib." -ForegroundColor Red
}

Write-Host "`nPress any key to exit..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
