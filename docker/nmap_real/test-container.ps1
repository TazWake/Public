#!/usr/bin/env pwsh

<#
.SYNOPSIS
    Test script to verify the nmap container is working correctly

.DESCRIPTION
    This script tests the containerized nmap application to ensure it's working
    after fixing the entrypoint issues.
#>

param(
    [Parameter(HelpMessage="Force rebuild of the Docker image")]
    [switch]$ForceRebuild
)

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ImageName = "nmap-scanner:latest"

function Write-TestResult {
    param(
        [string]$TestName,
        [bool]$Success,
        [string]$Details = ""
    )
    
    if ($Success) {
        Write-Host "✓ $TestName" -ForegroundColor Green
        if ($Details) {
            Write-Host "  $Details" -ForegroundColor Gray
        }
    } else {
        Write-Host "✗ $TestName" -ForegroundColor Red
        if ($Details) {
            Write-Host "  $Details" -ForegroundColor Red
        }
    }
}

function Test-DockerAvailable {
    try {
        $null = docker --version 2>$null
        return $true
    }
    catch {
        return $false
    }
}

function Test-ImageExists {
    try {
        $images = docker images --format "{{.Repository}}:{{.Tag}}" | Where-Object { $_ -eq $ImageName }
        return $images.Count -gt 0
    }
    catch {
        return $false
    }
}

function Build-Image {
    Write-Host "Building Docker image..." -ForegroundColor Yellow
    
    try {
        Push-Location $ScriptDir
        $buildOutput = docker build -t $ImageName . 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            Write-TestResult "Docker image build" $true
            return $true
        } else {
            Write-TestResult "Docker image build" $false "Build failed: $buildOutput"
            return $false
        }
    }
    catch {
        Write-TestResult "Docker image build" $false "Exception: $($_.Exception.Message)"
        return $false
    }
    finally {
        Pop-Location
    }
}

function Test-ContainerHelp {
    try {
        $output = docker run --rm $ImageName --help 2>&1
        
        if ($LASTEXITCODE -eq 0 -and $output -match "Nmap Container Usage") {
            Write-TestResult "Container help command" $true "Help output generated correctly"
            return $true
        } else {
            Write-TestResult "Container help command" $false "Help command failed or wrong output"
            return $false
        }
    }
    catch {
        Write-TestResult "Container help command" $false "Exception: $($_.Exception.Message)"
        return $false
    }
}

function Test-ContainerVersion {
    try {
        $output = docker run --rm $ImageName nmap --version 2>&1
        
        if ($LASTEXITCODE -eq 0 -and $output -match "Nmap version") {
            Write-TestResult "Container nmap version" $true "Nmap is accessible in container"
            return $true
        } else {
            Write-TestResult "Container nmap version" $false "nmap --version failed"
            return $false
        }
    }
    catch {
        Write-TestResult "Container nmap version" $false "Exception: $($_.Exception.Message)"
        return $false
    }
}

function Test-QuickScan {
    try {
        # Create output directory if it doesn't exist
        $OutputDir = Join-Path $ScriptDir "output"
        if (-not (Test-Path $OutputDir)) {
            New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
        }
        
        # Run a quick scan against localhost
        Write-Host "Running quick test scan against 127.0.0.1..." -ForegroundColor Yellow
        $output = docker run --rm -v "${OutputDir}:/output" $ImageName -T4 --top-ports 10 127.0.0.1 2>&1
        
        if ($LASTEXITCODE -eq 0 -and $output -match "Nmap scan report") {
            Write-TestResult "Quick scan test" $true "Scan completed successfully"
            return $true
        } else {
            Write-TestResult "Quick scan test" $false "Scan failed: $output"
            return $false
        }
    }
    catch {
        Write-TestResult "Quick scan test" $false "Exception: $($_.Exception.Message)"
        return $false
    }
}

# Main test execution
Write-Host "Nmap Container Test Suite" -ForegroundColor Cyan
Write-Host "=========================" -ForegroundColor Cyan
Write-Host ""

# Test 1: Docker availability
$dockerAvailable = Test-DockerAvailable
Write-TestResult "Docker availability" $dockerAvailable

if (-not $dockerAvailable) {
    Write-Host "Docker is not available. Please install Docker and try again." -ForegroundColor Red
    exit 1
}

# Test 2: Image exists or build
$imageExists = Test-ImageExists
if ($ForceRebuild -or -not $imageExists) {
    $buildSuccess = Build-Image
    if (-not $buildSuccess) {
        exit 1
    }
} else {
    Write-TestResult "Docker image exists" $true "Using existing image"
}

# Test 3: Container help command
$helpTest = Test-ContainerHelp

# Test 4: Container nmap version
$versionTest = Test-ContainerVersion

# Test 5: Quick scan test
$scanTest = Test-QuickScan

# Summary
Write-Host ""
Write-Host "Test Summary:" -ForegroundColor Cyan
Write-Host "=============" -ForegroundColor Cyan

$passedTests = @($dockerAvailable, $helpTest, $versionTest, $scanTest) | Where-Object { $_ -eq $true }
$totalTests = 4

Write-Host "Passed: $($passedTests.Count)/$totalTests tests" -ForegroundColor $(if ($passedTests.Count -eq $totalTests) { "Green" } else { "Yellow" })

if ($passedTests.Count -eq $totalTests) {
    Write-Host ""
    Write-Host "✓ All tests passed! Your nmap container is working correctly." -ForegroundColor Green
    Write-Host "You can now use: .\nmap-scan.ps1 -Target ""192.168.75.1""" -ForegroundColor Green
} else {
    Write-Host ""
    Write-Host "✗ Some tests failed. Please check the issues above." -ForegroundColor Red
    exit 1
}