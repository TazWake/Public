<#
.SYNOPSIS
    Create Windows Explorer context menu for quick DFIR tool access

.DESCRIPTION
    This script creates a right-click context menu in Windows Explorer providing
    quick access to commonly-used DFIR tools from the desktop or folder backgrounds.

    Based on an idea by Mohamed Talaat (LinkedIn post).

.PARAMETER ConfigFile
    Path to JSON configuration file containing tool definitions.
    If not specified, uses default hardcoded tools.

.PARAMETER Remove
    Remove the DFIR context menu instead of creating it

.EXAMPLE
    .\setContextMenu.ps1

    Creates context menu with default tools (edit $apps hashtable first)

.EXAMPLE
    .\setContextMenu.ps1 -ConfigFile "C:\DFIR\tools.json"

    Creates context menu from JSON configuration file

.EXAMPLE
    .\setContextMenu.ps1 -Remove

    Removes the DFIR context menu

.NOTES
    Author: @tazwake
    Purpose: Windows Explorer customization for DFIR workflows

    Based on idea by Mohamed Talaat:
    https://www.linkedin.com/posts/muhammadtalaat_dfir-forensics-windows-activity-7300469718484750337-Vk_J

    JSON Configuration Format:
    {
        "Timeline Explorer": "D:\\DFIR\\TimelineExplorer\\TimelineExplorer.exe",
        "PEStudio": "D:\\DFIR\\pestudio\\pestudio.exe"
    }

    Requires: Administrator privileges (modifies HKLM registry)
#>

[CmdletBinding()]
param(
    [Parameter(HelpMessage="Path to JSON configuration file with tool definitions")]
    [string]$ConfigFile,

    [Parameter(HelpMessage="Remove DFIR context menu")]
    [switch]$Remove
)

# Check for Administrator privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host -ForegroundColor Red "`n[!] ERROR: This script requires Administrator privileges"
    Write-Host -ForegroundColor Yellow "[*] Modifying HKLM registry requires elevation"
    Write-Host -ForegroundColor Yellow "[*] Please run PowerShell as Administrator and try again`n"
    exit 1
}

# Registry path for DFIR tools menu
$dfirPath = "HKLM:\SOFTWARE\Classes\Directory\Background\shell\DFIR"

function Remove-DFIRContextMenu {
    <#
    .SYNOPSIS
        Remove DFIR context menu from Windows Explorer
    #>
    Write-Host -ForegroundColor Cyan "`n========== Removing DFIR Context Menu =========="

    try {
        if (Test-Path -Path $dfirPath) {
            Write-Host -ForegroundColor Yellow "[*] Removing registry keys..."
            Remove-Item -Path $dfirPath -Recurse -Force -ErrorAction Stop
            Write-Host -ForegroundColor Green "[+] DFIR context menu removed successfully"
        } else {
            Write-Host -ForegroundColor Yellow "[!] DFIR context menu not found (already removed)"
        }
    } catch {
        Write-Host -ForegroundColor Red "[!] ERROR removing context menu:"
        Write-Host -ForegroundColor Red "    $($_.Exception.Message)"
        exit 1
    }

    Write-Host -ForegroundColor Cyan "========================================`n"
}

function New-DFIRContextMenu {
    <#
    .SYNOPSIS
        Create DFIR context menu in Windows Explorer
    #>
    param(
        [hashtable]$Tools
    )

    Write-Host -ForegroundColor Cyan "`n========== Creating DFIR Context Menu =========="

    # Validate tools exist
    $validTools = @{}
    $missingTools = @()

    foreach ($tool in $Tools.GetEnumerator()) {
        if (Test-Path -Path $tool.Value -PathType Leaf) {
            $validTools[$tool.Key] = $tool.Value
            Write-Host -ForegroundColor Green "[+] Found: $($tool.Key) at $($tool.Value)"
        } else {
            $missingTools += $tool.Key
            Write-Host -ForegroundColor Yellow "[!] Warning: $($tool.Key) not found at $($tool.Value)"
        }
    }

    if ($validTools.Count -eq 0) {
        Write-Host -ForegroundColor Red "`n[!] ERROR: No valid tools found"
        Write-Host -ForegroundColor Yellow "[*] Please update tool paths in the script or configuration file"
        exit 1
    }

    if ($missingTools.Count -gt 0) {
        Write-Host -ForegroundColor Yellow "`n[!] The following tools were not found and will be skipped:"
        $missingTools | ForEach-Object { Write-Host -ForegroundColor Yellow "    - $_" }
        Write-Host ""
        $response = Read-Host "[?] Continue with valid tools only? (Y/N)"
        if ($response -notmatch "^[Yy]") {
            Write-Host -ForegroundColor Cyan "[*] Operation cancelled"
            exit 0
        }
    }

    try {
        # Create main DFIR menu entry
        Write-Host -ForegroundColor Yellow "`n[*] Creating main context menu entry..."

        if (Test-Path -Path $dfirPath) {
            Write-Host -ForegroundColor Yellow "[*] Removing existing DFIR menu..."
            Remove-Item -Path $dfirPath -Recurse -Force -ErrorAction Stop
        }

        New-Item -Path $dfirPath -Force -ErrorAction Stop | Out-Null
        Set-ItemProperty -Path $dfirPath -Name "MUIVerb" -Value "DFIR Tools" -ErrorAction Stop
        Set-ItemProperty -Path $dfirPath -Name "Icon" -Value "shell32.dll,-27" -ErrorAction Stop
        Set-ItemProperty -Path $dfirPath -Name "SubCommands" -Value "" -ErrorAction Stop

        Write-Host -ForegroundColor Green "[+] Main menu entry created"

        # Create submenu entries for each tool
        Write-Host -ForegroundColor Yellow "[*] Adding tool shortcuts..."

        foreach ($tool in $validTools.GetEnumerator()) {
            $appPath = "`"$($tool.Value)`""  # Ensure proper quoting of the path
            $regPath = "$dfirPath\shell\$($tool.Key)"

            New-Item -Path $regPath -Force -ErrorAction Stop | Out-Null
            Set-ItemProperty -Path $regPath -Name "MUIVerb" -Value $tool.Key -ErrorAction Stop

            $commandPath = "$regPath\command"
            New-Item -Path $commandPath -Force -ErrorAction Stop | Out-Null
            Set-ItemProperty -Path $commandPath -Name "(Default)" -Value $appPath -ErrorAction Stop

            Write-Host -ForegroundColor Gray "    [+] Added: $($tool.Key)"
        }

        Write-Host ""
        Write-Host -ForegroundColor Green "[+] DFIR Tools context menu created successfully!"
        Write-Host -ForegroundColor Cyan "[*] Right-click on desktop or folder background to access DFIR Tools menu"
        Write-Host -ForegroundColor Cyan "[*] Total tools added: $($validTools.Count)"

    } catch {
        Write-Host -ForegroundColor Red "[!] ERROR creating context menu:"
        Write-Host -ForegroundColor Red "    $($_.Exception.Message)"
        exit 1
    }

    Write-Host -ForegroundColor Cyan "========================================`n"
}

# Main script execution

if ($Remove) {
    Remove-DFIRContextMenu
    exit 0
}

# Load tools configuration
if ($ConfigFile) {
    Write-Host -ForegroundColor Gray "[*] Loading configuration from: $ConfigFile"

    if (-not (Test-Path -Path $ConfigFile)) {
        Write-Host -ForegroundColor Red "[!] ERROR: Configuration file not found: $ConfigFile"
        exit 1
    }

    try {
        $configContent = Get-Content -Path $ConfigFile -Raw | ConvertFrom-Json
        $apps = @{}
        $configContent.PSObject.Properties | ForEach-Object {
            $apps[$_.Name] = $_.Value
        }
        Write-Host -ForegroundColor Green "[+] Configuration loaded: $($apps.Count) tool(s)"
    } catch {
        Write-Host -ForegroundColor Red "[!] ERROR parsing configuration file:"
        Write-Host -ForegroundColor Red "    $($_.Exception.Message)"
        exit 1
    }
} else {
    # Default hardcoded tools
    # IMPORTANT: Modify these paths to match your DFIR tool locations
    Write-Host -ForegroundColor Yellow "[!] Using default hardcoded tool paths"
    Write-Host -ForegroundColor Yellow "[!] Edit this script or use -ConfigFile to customize"
    Write-Host ""

    $apps = @{
        "Timeline Explorer"   = "D:\DFIR\TimelineExplorer\TimelineExplorer.exe"
        "PEStudio"            = "D:\DFIR\pestudio\pestudio.exe"
        "Registry Explorer"   = "D:\DFIR\RegistryExplorer\RegistryExplorer.exe"
        "ShellBags Explorer"  = "D:\DFIR\ShellBagsExplorer\ShellBagsExplorer.exe"
        "OllyDBG"             = "D:\DFIR\OllyDBG\OLLYDBG.exe"
    }
}

# Create the context menu
New-DFIRContextMenu -Tools $apps
