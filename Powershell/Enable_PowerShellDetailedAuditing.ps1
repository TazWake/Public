<#
.SYNOPSIS
    Enable comprehensive PowerShell auditing and logging

.DESCRIPTION
    This script enables and configures PowerShell Script Block Logging, Module Logging,
    and Transcription Logging for enhanced security monitoring and incident detection.

    All three logging mechanisms are critical for detecting malicious PowerShell usage
    and should be enabled in production environments.

.PARAMETER TranscriptPath
    Directory where PowerShell transcripts will be stored. Defaults to C:\Transcripts

.PARAMETER Force
    Skip confirmation prompt and enable all logging automatically

.PARAMETER CheckOnly
    Only check current logging status without making changes

.EXAMPLE
    .\Enable_PowerShellDetailedAuditing.ps1

    Checks current status and prompts to enable logging

.EXAMPLE
    .\Enable_PowerShellDetailedAuditing.ps1 -Force

    Immediately enables all logging without prompting

.EXAMPLE
    .\Enable_PowerShellDetailedAuditing.ps1 -TranscriptPath "D:\PSTranscripts"

    Uses custom transcript directory

.EXAMPLE
    .\Enable_PowerShellDetailedAuditing.ps1 -CheckOnly

    Only displays current logging status

.NOTES
    Author: @tazwake
    Purpose: Security hardening and forensic capability enhancement
    Requires: Administrator privileges
    Registry Keys Modified:
        - HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
        - HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
        - HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription
#>

[CmdletBinding()]
param(
    [Parameter(HelpMessage="Directory for PowerShell transcripts")]
    [string]$TranscriptPath = "C:\Transcripts",

    [Parameter(HelpMessage="Enable all logging without confirmation prompt")]
    [switch]$Force,

    [Parameter(HelpMessage="Only check status, don't make changes")]
    [switch]$CheckOnly
)

# Check for Administrator privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host -ForegroundColor Red "`n[!] ERROR: This script requires Administrator privileges"
    Write-Host -ForegroundColor Yellow "[*] Please run PowerShell as Administrator and try again`n"
    exit 1
}

function Check-LoggingStatus {
    <#
    .SYNOPSIS
        Check current PowerShell logging configuration
    #>
    $results = [ordered]@{}

    try {
        # Script Block Logging
        $path = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
        $results["Script Block Logging"] = if ((Test-Path $path) -and ((Get-ItemProperty -Path $path -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue).EnableScriptBlockLogging -eq 1)) {
            "Enabled"
        } else {
            "Disabled"
        }

        # Module Logging
        $path = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
        $results["Module Logging"] = if ((Test-Path $path) -and ((Get-ItemProperty -Path $path -Name EnableModuleLogging -ErrorAction SilentlyContinue).EnableModuleLogging -eq 1)) {
            "Enabled"
        } else {
            "Disabled"
        }

        # Transcription Logging
        $path = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription"
        $transcriptionEnabled = $false
        if (Test-Path $path) {
            $val = (Get-ItemProperty -Path $path -Name EnableTranscripting -ErrorAction SilentlyContinue).EnableTranscripting
            $transcriptionEnabled = ($val -eq 1)
        }
        $results["Transcription Logging"] = if ($transcriptionEnabled) { "Enabled" } else { "Disabled" }

    } catch {
        Write-Host -ForegroundColor Red "[!] ERROR checking logging status: $($_.Exception.Message)"
    }

    return $results
}

function Enable-AllLogging {
    <#
    .SYNOPSIS
        Enable all PowerShell auditing settings
    #>
    param(
        [string]$TranscriptDirectory
    )

    Write-Host "`n[*] Enabling all PowerShell auditing settings..."

    try {
        # Script Block Logging
        Write-Host -ForegroundColor Yellow "[*] Enabling Script Block Logging..."
        $path = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
        if (-not (Test-Path $path)) {
            New-Item -Path $path -Force -ErrorAction Stop | Out-Null
        }
        Set-ItemProperty -Path $path -Name "EnableScriptBlockLogging" -Value 1 -Force -ErrorAction Stop
        Write-Host -ForegroundColor Green "[+] Script Block Logging enabled"

        # Module Logging
        Write-Host -ForegroundColor Yellow "[*] Enabling Module Logging..."
        $path = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
        if (-not (Test-Path $path)) {
            New-Item -Path $path -Force -ErrorAction Stop | Out-Null
        }
        Set-ItemProperty -Path $path -Name "EnableModuleLogging" -Value 1 -Force -ErrorAction Stop

        $moduleNamesPath = "$path\ModuleNames"
        if (-not (Test-Path $moduleNamesPath)) {
            New-Item -Path $moduleNamesPath -Force -ErrorAction Stop | Out-Null
        }
        New-ItemProperty -Path $moduleNamesPath -Name "*" -Value "*" -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
        Write-Host -ForegroundColor Green "[+] Module Logging enabled (all modules)"

        # Transcription Logging
        Write-Host -ForegroundColor Yellow "[*] Enabling Transcription Logging..."
        $path = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription"
        if (-not (Test-Path $path)) {
            New-Item -Path $path -Force -ErrorAction Stop | Out-Null
        }
        Set-ItemProperty -Path $path -Name "EnableTranscripting" -Value 1 -Force -ErrorAction Stop
        Set-ItemProperty -Path $path -Name "IncludeInvocationHeader" -Value 1 -Force -ErrorAction Stop
        Set-ItemProperty -Path $path -Name "EnableInvocationHeader" -Value 1 -Force -ErrorAction Stop
        Set-ItemProperty -Path $path -Name "OutputDirectory" -Value $TranscriptDirectory -Force -ErrorAction Stop

        # Create transcription directory if needed
        if (-not (Test-Path $TranscriptDirectory)) {
            Write-Host -ForegroundColor Yellow "[*] Creating transcript directory: $TranscriptDirectory"
            New-Item -ItemType Directory -Path $TranscriptDirectory -Force -ErrorAction Stop | Out-Null
            Write-Host -ForegroundColor Green "[+] Transcript directory created"
        }

        Write-Host -ForegroundColor Green "[+] Transcription Logging enabled"
        Write-Host -ForegroundColor Cyan "[*] Transcripts will be saved to: $TranscriptDirectory"
        Write-Host ""
        Write-Host -ForegroundColor Green "[+] All logging settings have been enabled successfully"

        return $true

    } catch {
        Write-Host -ForegroundColor Red "[!] ERROR enabling logging: $($_.Exception.Message)"
        Write-Host -ForegroundColor Yellow "[*] Some settings may not have been applied"
        return $false
    }
}

# Main script execution
Write-Host -ForegroundColor Cyan "`n========== PowerShell Auditing Configuration =========="
Write-Host -ForegroundColor Gray "[*] Checking current logging status...`n"

# Check current status
$logStatus = Check-LoggingStatus
Write-Host "PowerShell Logging Status:`n"
$logStatus.GetEnumerator() | ForEach-Object {
    $color = if ($_.Value -eq "Enabled") { "Green" } else { "Yellow" }
    Write-Host -ForegroundColor $color ("- {0}: {1}" -f $_.Key, $_.Value)
}
Write-Host ""

# If CheckOnly flag is set, exit after displaying status
if ($CheckOnly) {
    Write-Host -ForegroundColor Cyan "[*] Check-only mode: No changes made"
    exit 0
}

# Determine if any logging is disabled
$anyDisabled = $logStatus.Values -contains "Disabled"

if (-not $anyDisabled) {
    Write-Host -ForegroundColor Green "[+] All logging features are already enabled"
    Write-Host -ForegroundColor Cyan "[*] No changes needed`n"
    exit 0
}

# Prompt or auto-enable based on Force parameter
if ($Force) {
    Write-Host -ForegroundColor Yellow "[*] Force mode enabled - applying all logging settings..."
    $enableLogging = $true
} else {
    $response = Read-Host "`nWould you like to enable all three logging features? (Y/N)"
    $enableLogging = $response -match "^[Yy]"
}

if ($enableLogging) {
    $success = Enable-AllLogging -TranscriptDirectory $TranscriptPath

    if ($success) {
        Write-Host "`n[*] Re-checking status..."
        $updatedStatus = Check-LoggingStatus
        $updatedStatus.GetEnumerator() | ForEach-Object {
            $color = if ($_.Value -eq "Enabled") { "Green" } else { "Red" }
            Write-Host -ForegroundColor $color ("- {0}: {1}" -f $_.Key, $_.Value)
        }
        Write-Host ""
    }
} else {
    Write-Host -ForegroundColor Yellow "`n[*] No changes were made"
}

Write-Host -ForegroundColor Cyan "========================================`n"
