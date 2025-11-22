<#
.SYNOPSIS
    Triage data collection script for Windows systems

.DESCRIPTION
    This script captures essential triage data from a device and stores the
    resulting files on a removable disk, including memory dumps and filesystem
    artifacts using KAPE and Magnet RAM Capture.

.PARAMETER SkipMemory
    Skip memory capture (useful for systems with large RAM or when time-constrained)

.PARAMETER SkipKAPE
    Skip KAPE artifact collection (useful when only memory is needed)

.EXAMPLE
    .\collectEvidence.ps1

    Runs full collection with memory and KAPE artifacts

.EXAMPLE
    .\collectEvidence.ps1 -SkipMemory

    Collects only KAPE artifacts, skipping memory capture

.NOTES
    Author: @tazwake
    Requirements:
        - Administrator privileges
        - USB or storage location with sufficient space
        - Memory capture: ~5-10% larger than system RAM
        - KAPE VHDX: ~0.5GB minimum
        - Licensed copy of KAPE in .\Kape\ directory
        - Magnet RAM Capture (MRC.exe) in current directory
#>

[CmdletBinding()]
param(
    [Parameter(HelpMessage="Skip memory capture")]
    [switch]$SkipMemory,

    [Parameter(HelpMessage="Skip KAPE artifact collection")]
    [switch]$SkipKAPE
)

# Check for Administrator privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host -ForegroundColor Red "[!] ERROR: This script requires Administrator privileges"
    Write-Host -ForegroundColor Yellow "[*] Please run PowerShell as Administrator and try again"
    exit 1
}

# Display header
Write-Host -ForegroundColor Blue "++++++++++++++++++++++++++"
Write-Host -ForegroundColor DarkCyan "+ Triage Data Collection +"
Write-Host -ForegroundColor DarkCyan "+   Starting Collection  +"
Write-Host -ForegroundColor DarkCyan "+       @tazwake         +"
Write-Host -ForegroundColor Blue "++++++++++++++++++++++++++"
Write-Host ""

# Set up evidence directory
$evidenceRoot = Join-Path -Path "." -ChildPath "Evidence"
$evidencePath = Join-Path -Path $evidenceRoot -ChildPath $env:COMPUTERNAME
$logFile = Join-Path -Path $evidencePath -ChildPath "log.txt"

try {
    Write-Host -ForegroundColor Gray "[*] Creating evidence directory: $evidencePath"
    New-Item -Path $evidencePath -ItemType Directory -Force | Out-Null
    Write-Host -ForegroundColor Green "[+] Evidence directory created"

    # Initialize log file
    Write-Host -ForegroundColor Gray "[*] Artifact collection initiated at $(Get-Date)"
    Set-Content -Path $logFile -Value "Evidence collection started: $((Get-Date).ToString())"
    Add-Content -Path $logFile -Value "Hostname: $env:COMPUTERNAME"
    Add-Content -Path $logFile -Value "Initial folder created: $evidencePath"
} catch {
    Write-Host -ForegroundColor Red "[!] ERROR: Failed to create evidence directory"
    Write-Host -ForegroundColor Red "    $($_.Exception.Message)"
    exit 1
}

Add-Content -Path \Evidence\$env:COMPUTERNAME\log.txt -Value "Memory capture initiated: $((Get-Date).ToString())"
.\MRC.exe /accepteula /go /silent
Start-Sleep -Seconds 3
Write-host -ForegroundColor Yellow "[ ] Launching Magnet RAM Capture to collect a memory image."
Write-host -ForegroundColor Yellow "[!] This may take a long time. "
Wait-Process -Name "MRC"
Write-host -ForergroundColor DarkYellow "[X] Capture complete, logging OS build data. Renaming evidence."
[System.Environment]::OSVersion.Version > .\Evidence\$env:COMPUTERNAME\OS_build_version.txt
Get-ChildItem -Filter 'MagnetRAMCapture*' -Recurse | Rename-Item -NewName {$_.name -replace 'MagnetRAMCapture', $env:COMPUTERNAME }
Move-Item -Path .\*.txt -Destination .\Evidence\$env:COMPUTERNAME\
Move-Item -Path .\*.raw -Destination .\Evidence\$env:COMPUTERNAME\
Get-FileHash -Algorithm MD5 .\Evidence\$env:COMPUTERNAME\*.raw | Out-File .\Evidence\$env:COMPUTERNAME\MemoryCapture_MD5Hashes.txt
Write-host -ForergroundColor Yellow "[ ] Memory capture completed."
Add-Content -Path \Evidence\$env:COMPUTERNAME\log.txt -Value "Memory capture completed: $((Get-Date).ToString())"

Start-Sleep -Seconds 1
Add-Content -Path \Evidence\$env:COMPUTERNAME\log.txt -Value "KAPE triage date collection initiated: $((Get-Date).ToString())"
Write-host -ForegroundColor Green "[ ] Collecting OS Artifacts."
.\Kape\kape.exe --tsource C: --tdest .\Evidence\$env:COMPUTERNAME --target !SANS_Triage --vhdx $env:COMPUTERNAME --zv false
Set-Content -Path \Evidence\$env:COMPUTERNAME\Finished.txt -Value "Evidence collection complete: $((Get-Date).ToString())"
Get-FileHash -Algorithm MD5 .\Evidence\$env:COMPUTERNAME\*.vhdx | Out-File .\Evidence\$env:COMPUTERNAME\KapeOutput_MD5Hashes.txt
Add-Content -Path \Evidence\$env:COMPUTERNAME\log.txt -Value "Collection completed: $((Get-Date).ToString())"
Write-Host -ForegroundColor Green "[ ] Collection completed"
