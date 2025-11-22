<#
.SYNOPSIS
    Analyzes a PowerPoint (PPTX) file to count total and hidden slides.

.DESCRIPTION
    This script extracts and analyzes a PPTX file to determine:
    - Total number of slides in the presentation
    - Number of hidden slides
    - Number of visible slides

    PPTX files are ZIP archives containing XML files. This script extracts
    the archive, parses the slide XML files, and checks for the show="0"
    attribute which indicates a hidden slide.

.PARAMETER FilePath
    The full path to the PPTX file to analyze.

.EXAMPLE
    .\Get-PPTXSlideInfo.ps1 -FilePath "C:\Presentations\MySlides.pptx"

    Analyzes MySlides.pptx and displays slide count information.

.EXAMPLE
    .\Get-PPTXSlideInfo.ps1 "D:\Documents\Presentation.pptx"

    Analyzes Presentation.pptx using positional parameter.

.NOTES
    Author: @tazwake
    Purpose: Digital forensics and presentation file analysis
    Requirements: PowerShell 5.0 or higher

    The script uses .NET System.IO.Compression classes to extract the PPTX
    file and XML parsing to analyze slide properties.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0, HelpMessage="Path to the PPTX file")]
    [ValidateNotNullOrEmpty()]
    [string]$FilePath
)

# Initialize variables
$totalSlides = 0
$hiddenSlides = 0
$visibleSlides = 0
$tempDir = $null

# Display header
Write-Host -ForegroundColor Blue "=================================="
Write-Host -ForegroundColor Cyan "   PPTX Slide Analysis Tool"
Write-Host -ForegroundColor Cyan "        @tazwake"
Write-Host -ForegroundColor Blue "=================================="
Write-Host ""

try {
    # Validate file exists
    if (-not (Test-Path -Path $FilePath)) {
        Write-Host -ForegroundColor Red "[!] Error: File not found at path: $FilePath"
        exit 1
    }

    # Validate file extension
    $fileExtension = [System.IO.Path]::GetExtension($FilePath)
    if ($fileExtension -ne ".pptx") {
        Write-Host -ForegroundColor Red "[!] Error: File must be a .pptx file. Found: $fileExtension"
        exit 1
    }

    # Get file information
    $fileInfo = Get-Item -Path $FilePath
    Write-Host -ForegroundColor Gray "[*] Analyzing: $($fileInfo.Name)"
    Write-Host -ForegroundColor Gray "[*] File size: $([math]::Round($fileInfo.Length / 1MB, 2)) MB"
    Write-Host -ForegroundColor Gray "[*] Last modified: $($fileInfo.LastWriteTime)"
    Write-Host ""

    # Create temporary extraction directory
    $tempDir = Join-Path -Path $env:TEMP -ChildPath "PPTX_Analysis_$(Get-Random)"
    Write-Host -ForegroundColor Yellow "[+] Creating temporary directory: $tempDir"
    New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

    # Extract PPTX file (it's a ZIP archive)
    Write-Host -ForegroundColor Yellow "[+] Extracting PPTX archive..."
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::ExtractToDirectory($FilePath, $tempDir)

    # Locate slides directory
    $slidesPath = Join-Path -Path $tempDir -ChildPath "ppt\slides"

    if (-not (Test-Path -Path $slidesPath)) {
        Write-Host -ForegroundColor Red "[!] Error: No slides directory found in PPTX file"
        Write-Host -ForegroundColor Red "[!] This may not be a valid PowerPoint presentation"
        exit 1
    }

    # Get all slide XML files (exclude slide layouts and masters)
    Write-Host -ForegroundColor Yellow "[+] Analyzing slide files..."
    $slideFiles = Get-ChildItem -Path $slidesPath -Filter "slide*.xml" | Where-Object {
        $_.Name -match '^slide\d+\.xml$'
    }

    $totalSlides = $slideFiles.Count

    if ($totalSlides -eq 0) {
        Write-Host -ForegroundColor Yellow "[!] Warning: No slides found in presentation"
        exit 0
    }

    # Analyze each slide for hidden status
    foreach ($slideFile in $slideFiles) {
        # Load XML content
        [xml]$slideXml = Get-Content -Path $slideFile.FullName -Raw

        # Check for show attribute in the main slide element
        # The namespace prefix might vary, so we check the first element
        $slideElement = $slideXml.DocumentElement

        # Check if the slide has a "show" attribute set to "0"
        $showAttribute = $slideElement.GetAttribute("show")

        if ($showAttribute -eq "0") {
            $hiddenSlides++
            Write-Host -ForegroundColor DarkGray "    [H] $($slideFile.Name) - Hidden"
        } else {
            $visibleSlides++
            Write-Host -ForegroundColor Green "    [V] $($slideFile.Name) - Visible"
        }
    }

    # Display results
    Write-Host ""
    Write-Host -ForegroundColor Blue "=================================="
    Write-Host -ForegroundColor Cyan "        Analysis Results"
    Write-Host -ForegroundColor Blue "=================================="
    Write-Host -ForegroundColor White "Total Slides:   " -NoNewline
    Write-Host -ForegroundColor Cyan "$totalSlides"
    Write-Host -ForegroundColor White "Visible Slides: " -NoNewline
    Write-Host -ForegroundColor Green "$visibleSlides"
    Write-Host -ForegroundColor White "Hidden Slides:  " -NoNewline
    Write-Host -ForegroundColor Yellow "$hiddenSlides"
    Write-Host -ForegroundColor Blue "=================================="
    Write-Host ""

    # Show warning if hidden slides exist
    if ($hiddenSlides -gt 0) {
        Write-Host -ForegroundColor Yellow "[!] Warning: This presentation contains $hiddenSlides hidden slide(s)"
        Write-Host -ForegroundColor Gray "[*] Hidden slides may contain additional content not visible during normal playback"
    }

} catch {
    Write-Host -ForegroundColor Red "[!] Error occurred during analysis:"
    Write-Host -ForegroundColor Red "    $($_.Exception.Message)"
    Write-Host -ForegroundColor Red "    $($_.ScriptStackTrace)"
    exit 1
} finally {
    # Clean up temporary directory
    if ($tempDir -and (Test-Path -Path $tempDir)) {
        Write-Host -ForegroundColor Gray "[*] Cleaning up temporary files..."
        Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host -ForegroundColor Gray "[*] Cleanup complete"
    }
}

Write-Host -ForegroundColor Green "[+] Analysis complete!"
exit 0
