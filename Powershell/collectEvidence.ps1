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

# Memory Capture Section
if (-not $SkipMemory) {
    Write-Host ""
    Write-Host -ForegroundColor Cyan "========== Memory Capture =========="

    # Validate MRC.exe exists
    $mrcPath = Join-Path -Path "." -ChildPath "MRC.exe"
    if (-not (Test-Path -Path $mrcPath)) {
        Write-Host -ForegroundColor Red "[!] ERROR: MRC.exe not found in current directory"
        Write-Host -ForegroundColor Yellow "[*] Skipping memory capture"
        Add-Content -Path $logFile -Value "Memory capture skipped: MRC.exe not found"
    } else {
        try {
            Add-Content -Path $logFile -Value "Memory capture initiated: $((Get-Date).ToString())"

            Write-Host -ForegroundColor Yellow "[*] Launching Magnet RAM Capture to collect memory image"
            Write-Host -ForegroundColor Yellow "[!] This may take a long time depending on system RAM"

            Start-Process -FilePath $mrcPath -ArgumentList "/accepteula", "/go", "/silent" -NoNewWindow
            Start-Sleep -Seconds 3

            Wait-Process -Name "MRC" -ErrorAction Stop

            Write-Host -ForegroundColor Green "[+] Memory capture process completed"

            # Log OS build information
            $osBuildFile = Join-Path -Path $evidencePath -ChildPath "OS_build_version.txt"
            [System.Environment]::OSVersion.Version | Out-File -FilePath $osBuildFile

            # Rename and move memory capture files
            Write-Host -ForegroundColor Gray "[*] Organizing memory capture files..."
            $memoryFiles = Get-ChildItem -Filter 'MagnetRAMCapture*' -Recurse -ErrorAction SilentlyContinue

            foreach ($file in $memoryFiles) {
                $newName = $file.Name -replace 'MagnetRAMCapture', $env:COMPUTERNAME
                $destPath = Join-Path -Path $evidencePath -ChildPath $newName
                Move-Item -Path $file.FullName -Destination $destPath -Force
            }

            # Move any remaining .txt and .raw files
            Get-ChildItem -Path "." -Filter "*.txt" -File | Where-Object { $_.Name -ne "log.txt" } | Move-Item -Destination $evidencePath -Force -ErrorAction SilentlyContinue
            Get-ChildItem -Path "." -Filter "*.raw" -File | Move-Item -Destination $evidencePath -Force -ErrorAction SilentlyContinue

            # Generate MD5 hashes for memory captures
            $rawFiles = Get-ChildItem -Path $evidencePath -Filter "*.raw"
            if ($rawFiles) {
                $hashFile = Join-Path -Path $evidencePath -ChildPath "MemoryCapture_MD5Hashes.txt"
                Get-FileHash -Algorithm MD5 -Path $rawFiles.FullName | Out-File -FilePath $hashFile
                Write-Host -ForegroundColor Green "[+] MD5 hashes generated for memory captures"
            }

            Write-Host -ForegroundColor Green "[+] Memory capture completed successfully"
            Add-Content -Path $logFile -Value "Memory capture completed: $((Get-Date).ToString())"

        } catch {
            Write-Host -ForegroundColor Red "[!] ERROR during memory capture: $($_.Exception.Message)"
            Add-Content -Path $logFile -Value "Memory capture failed: $($_.Exception.Message)"
        }
    }
} else {
    Write-Host -ForegroundColor Yellow "[*] Memory capture skipped (SkipMemory flag set)"
    Add-Content -Path $logFile -Value "Memory capture skipped by user request"
}

# KAPE Collection Section
if (-not $SkipKAPE) {
    Write-Host ""
    Write-Host -ForegroundColor Cyan "========== KAPE Artifact Collection =========="

    Start-Sleep -Seconds 1

    # Validate KAPE exists
    $kapePath = Join-Path -Path "." -ChildPath "Kape\kape.exe"
    if (-not (Test-Path -Path $kapePath)) {
        Write-Host -ForegroundColor Red "[!] ERROR: KAPE not found at .\Kape\kape.exe"
        Write-Host -ForegroundColor Yellow "[*] Skipping KAPE artifact collection"
        Add-Content -Path $logFile -Value "KAPE collection skipped: kape.exe not found"
    } else {
        try {
            Add-Content -Path $logFile -Value "KAPE triage data collection initiated: $((Get-Date).ToString())"

            Write-Host -ForegroundColor Green "[*] Collecting OS artifacts with KAPE"
            Write-Host -ForegroundColor Gray "[*] Target: !SANS_Triage"
            Write-Host -ForegroundColor Gray "[*] Source: C:\"
            Write-Host -ForegroundColor Gray "[*] Destination: $evidencePath"

            $kapeArgs = @(
                "--tsource", "C:",
                "--tdest", $evidencePath,
                "--target", "!SANS_Triage",
                "--vhdx", $env:COMPUTERNAME,
                "--zv", "false"
            )

            Start-Process -FilePath $kapePath -ArgumentList $kapeArgs -NoNewWindow -Wait

            Write-Host -ForegroundColor Green "[+] KAPE collection completed"

            # Generate MD5 hashes for VHDX files
            $vhdxFiles = Get-ChildItem -Path $evidencePath -Filter "*.vhdx" -ErrorAction SilentlyContinue
            if ($vhdxFiles) {
                $hashFile = Join-Path -Path $evidencePath -ChildPath "KapeOutput_MD5Hashes.txt"
                Get-FileHash -Algorithm MD5 -Path $vhdxFiles.FullName | Out-File -FilePath $hashFile
                Write-Host -ForegroundColor Green "[+] MD5 hashes generated for KAPE output"
            }

            Add-Content -Path $logFile -Value "KAPE collection completed: $((Get-Date).ToString())"

        } catch {
            Write-Host -ForegroundColor Red "[!] ERROR during KAPE collection: $($_.Exception.Message)"
            Add-Content -Path $logFile -Value "KAPE collection failed: $($_.Exception.Message)"
        }
    }
} else {
    Write-Host -ForegroundColor Yellow "[*] KAPE artifact collection skipped (SkipKAPE flag set)"
    Add-Content -Path $logFile -Value "KAPE collection skipped by user request"
}

# Finalize collection
Write-Host ""
Write-Host -ForegroundColor Blue "===================================="
$finishedFile = Join-Path -Path $evidencePath -ChildPath "Finished.txt"
Set-Content -Path $finishedFile -Value "Evidence collection complete: $((Get-Date).ToString())"
Add-Content -Path $logFile -Value "Collection completed: $((Get-Date).ToString())"

Write-Host -ForegroundColor Green "[+] Evidence collection completed successfully"
Write-Host -ForegroundColor Cyan "[*] Evidence location: $evidencePath"
Write-Host -ForegroundColor Blue "===================================="
