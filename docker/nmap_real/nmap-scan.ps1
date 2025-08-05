#!/usr/bin/env pwsh

<#
.SYNOPSIS
    Wrapper script for containerized nmap scanning

.DESCRIPTION
    This PowerShell script provides an easy interface to run nmap scans using
    a Docker container. It handles volume mounting, builds the container if needed,
    and provides convenient parameter passing.

.PARAMETER Target
    The target IP address, hostname, or network range to scan

.PARAMETER Arguments
    Custom nmap arguments to pass to the scanner

.PARAMETER Quick
    Use the quick scan profile (top 1000 ports)

.PARAMETER Build
    Force rebuild of the Docker image

.PARAMETER Help
    Show nmap help and usage information

.EXAMPLE
    .\nmap-scan.ps1 -Target "192.168.1.0/24"
    Runs default comprehensive scan against the local subnet

.EXAMPLE
    .\nmap-scan.ps1 -Arguments "-sS -p 80,443 192.168.1.1"
    Runs custom SYN scan on ports 80 and 443

.EXAMPLE
    .\nmap-scan.ps1 -Target "192.168.1.1" -Quick
    Runs quick scan (top 1000 ports) against single host

.NOTES
    Requires Docker to be installed and running
    Output files are saved to ./output directory
#>

param(
    [Parameter(Position=0, HelpMessage="Target IP, hostname, or network range")]
    [string]$Target,
    
    [Parameter(HelpMessage="Custom nmap arguments")]
    [string]$Arguments,
    
    [Parameter(HelpMessage="Use quick scan profile")]
    [switch]$Quick,
    
    [Parameter(HelpMessage="Force rebuild of Docker image")]
    [switch]$Build,
    
    [Parameter(HelpMessage="Show help information")]
    [switch]$Help
)

# Configuration
$ImageName = "nmap-scanner:latest"
$ContainerName = "nmap-scanner"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$OutputDir = Join-Path $ScriptDir "output"

# Function to write colored output
function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = "White"
    )
    Write-Host $Message -ForegroundColor $Color
}

# Function to check if Docker is available
function Test-DockerAvailable {
    try {
        $null = docker --version 2>$null
        return $true
    }
    catch {
        return $false
    }
}

# Function to check if image exists
function Test-ImageExists {
    param([string]$ImageName)
    
    try {
        $images = docker images --format "{{.Repository}}:{{.Tag}}" | Where-Object { $_ -eq $ImageName }
        return $images.Count -gt 0
    }
    catch {
        return $false
    }
}

# Function to build the Docker image
function Build-NmapImage {
    Write-ColorOutput "Building nmap scanner Docker image..." "Yellow"
    
    try {
        Push-Location $ScriptDir
        docker build -t $ImageName .
        
        if ($LASTEXITCODE -eq 0) {
            Write-ColorOutput "✓ Docker image built successfully" "Green"
            return $true
        }
        else {
            Write-ColorOutput "✗ Failed to build Docker image" "Red"
            return $false
        }
    }
    catch {
        Write-ColorOutput "✗ Error building Docker image: $($_.Exception.Message)" "Red"
        return $false
    }
    finally {
        Pop-Location
    }
}

# Function to create output directory
function Initialize-OutputDirectory {
    if (-not (Test-Path $OutputDir)) {
        try {
            New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
            Write-ColorOutput "✓ Created output directory: $OutputDir" "Green"
        }
        catch {
            Write-ColorOutput "✗ Failed to create output directory: $($_.Exception.Message)" "Red"
            return $false
        }
    }
    return $true
}

# Function to run nmap scan
function Invoke-NmapScan {
    param(
        [string]$ScanTarget,
        [string]$ScanArguments,
        [bool]$UseQuick
    )
    
    if (-not (Initialize-OutputDirectory)) {
        return $false
    }
    
    # Prepare Docker run command
    $DockerArgs = @(
        "run"
        "--rm"
        "--network=host"
        "-v"
        "${OutputDir}:/output"
        "--name"
        "${ContainerName}_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        $ImageName
    )
    
    # Add scan parameters
    if ($UseQuick) {
        Write-ColorOutput "Running quick scan..." "Cyan"
        $DockerArgs += @("-T4", "--top-ports", "1000", "-sV", "--version-light", $ScanTarget)
    }
    elseif (-not [string]::IsNullOrEmpty($ScanArguments)) {
        Write-ColorOutput "Running custom scan with arguments: $ScanArguments" "Cyan"
        $DockerArgs += $ScanArguments.Split(' ')
    }
    elseif (-not [string]::IsNullOrEmpty($ScanTarget)) {
        Write-ColorOutput "Running default comprehensive scan against: $ScanTarget" "Cyan"
        $DockerArgs += $ScanTarget
    }
    else {
        Write-ColorOutput "No target specified, showing help..." "Yellow"
        $DockerArgs += "--help"
    }
    
    # Execute the scan
    Write-ColorOutput "Executing: docker $($DockerArgs -join ' ')" "Gray"
    Write-ColorOutput "Output directory: $OutputDir" "Gray"
    Write-ColorOutput ("-" * 60) "Gray"
    
    try {
        & docker @DockerArgs
        
        if ($LASTEXITCODE -eq 0) {
            Write-ColorOutput ("-" * 60) "Gray"
            Write-ColorOutput "✓ Scan completed successfully" "Green"
            
            # List output files
            $OutputFiles = Get-ChildItem -Path $OutputDir -File | Where-Object { $_.LastWriteTime -gt (Get-Date).AddMinutes(-5) }
            if ($OutputFiles.Count -gt 0) {
                Write-ColorOutput "Output files created:" "Green"
                foreach ($file in $OutputFiles) {
                    Write-ColorOutput "  - $($file.Name)" "White"
                }
            }
            return $true
        }
        else {
            Write-ColorOutput "✗ Scan failed with exit code: $LASTEXITCODE" "Red"
            return $false
        }
    }
    catch {
        Write-ColorOutput "✗ Error running scan: $($_.Exception.Message)" "Red"
        return $false
    }
}

# Function to show usage information
function Show-Usage {
    Write-ColorOutput @"
Nmap Container Scanner - Usage Examples

Basic Usage:
  .\nmap-scan.ps1 -Target "192.168.1.0/24"
  .\nmap-scan.ps1 -Target "192.168.1.1"

Quick Scan:
  .\nmap-scan.ps1 -Target "192.168.1.0/24" -Quick

Custom Arguments:
  .\nmap-scan.ps1 -Arguments "-sS -p 80,443,8080 192.168.1.0/24"
  .\nmap-scan.ps1 -Arguments "--top-ports 100 -sV 10.0.0.0/8"

Build Options:
  .\nmap-scan.ps1 -Build                    # Rebuild Docker image
  .\nmap-scan.ps1 -Help                     # Show this help

Output Location:
  All scan results are saved to: $OutputDir

Default Scan Options:
  -Pn -sC -sV -oA scan_tcp -vvvvvvvvv --reason -T4 -p-

"@ "Yellow"
}

# Main execution
function Main {
    Write-ColorOutput "Nmap Container Scanner" "Cyan"
    Write-ColorOutput "=====================" "Cyan"
    
    # Handle help request
    if ($Help) {
        Show-Usage
        return
    }
    
    # Check Docker availability
    if (-not (Test-DockerAvailable)) {
        Write-ColorOutput "✗ Docker is not available. Please install Docker and ensure it's running." "Red"
        return
    }
    
    # Build image if requested or if it doesn't exist
    if ($Build -or -not (Test-ImageExists -ImageName $ImageName)) {
        if (-not (Build-NmapImage)) {
            Write-ColorOutput "✗ Cannot continue without Docker image" "Red"
            return
        }
    }
    
    # Execute scan
    $success = Invoke-NmapScan -ScanTarget $Target -ScanArguments $Arguments -UseQuick $Quick.IsPresent
    
    if ($success) {
        Write-ColorOutput "`n✓ Scan operation completed" "Green"
    }
    else {
        Write-ColorOutput "`n✗ Scan operation failed" "Red"
        exit 1
    }
}

# Run the main function
Main