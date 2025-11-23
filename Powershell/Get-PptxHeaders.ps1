<#
.SYNOPSIS
    Extract slide headers (titles) from a PPTX file using PowerPoint COM automation.

.DESCRIPTION
    Opens a PPTX file via PowerPoint COM, iterates through slides, and returns
    the slide number, header text, and hidden status. Output can be plain text,
    CSV, or JSON. Optionally exclude hidden slides.

.PARAMETER PptxPath
    Path to the PPTX file (relative or absolute).

.PARAMETER OutputFormat
    Output format: Text, CSV, or JSON. Default is Text.

.PARAMETER OutputFile
    Optional file path to save Text output. Only applicable with -OutputFormat Text.
    When specified, output is written to the file instead of the console.

.PARAMETER HideHidden
    Switch. If set, hidden slides are excluded from the output.

.PARAMETER Help
    Show detailed help.

.PARAMETER H
    Alias for Help.

.EXAMPLE
    .\Get-PptxHeaders.ps1 -PptxPath .\deck.pptx
    Display slide headers with color-coded output (default Text format).

.EXAMPLE
    .\Get-PptxHeaders.ps1 -PptxPath .\deck.pptx -HideHidden
    Display only visible slides, excluding hidden ones.

.EXAMPLE
    .\Get-PptxHeaders.ps1 -PptxPath .\deck.pptx -OutputFile headers.txt
    Save text output to headers.txt file.

.EXAMPLE
    .\Get-PptxHeaders.ps1 -PptxPath "C:\Slides\deck.pptx" -OutputFormat CSV
    Export slide headers to CSV file (slide_headers.csv).

.EXAMPLE
    .\Get-PptxHeaders.ps1 -PptxPath "C:\Slides\deck.pptx" -OutputFormat JSON
    Output slide headers as JSON format.

.EXAMPLE
    .\Get-PptxHeaders.ps1 -Help
    Display detailed help information.

.NOTES
    Requires Microsoft PowerPoint installed.
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$PptxPath,

    [ValidateSet("Text","CSV","JSON")]
    [string]$OutputFormat = "Text",

    [Parameter(Mandatory=$false)]
    [string]$OutputFile,

    [switch]$HideHidden,

    [Alias("H")]
    [switch]$Help
)

# --- Show help if requested ---
if ($Help) {
    Get-Help $MyInvocation.MyCommand.Definition -Detailed
    exit
}

# --- Validate PptxPath is provided ---
if (-not $PptxPath) {
    Write-Error "The -PptxPath parameter is required. Use -Help or -H for usage information."
    exit 1
}

# --- Resolve path ---
if (-not (Test-Path $PptxPath)) {
    Write-Error "File not found: $PptxPath"
    exit 1
}
$PptxPath = (Resolve-Path $PptxPath).Path

# --- Launch PowerPoint COM object ---
$ppApp = New-Object -ComObject PowerPoint.Application
# Do NOT set Visible to avoid error

# --- Open presentation (read-only, no window) ---
$presentation = $ppApp.Presentations.Open($PptxPath, $true, $false, $false)

$results = @()

foreach ($slide in $presentation.Slides) {
    $header = $null

    # Try to get the title placeholder text
    try {
        $header = $slide.Shapes.Title.TextFrame.TextRange.Text
    } catch {
        # Fallback: first text-containing shape
        foreach ($shape in $slide.Shapes) {
            if ($shape.HasTextFrame -eq -1 -and $shape.TextFrame.HasText -eq -1) {
                $header = $shape.TextFrame.TextRange.Text
                break
            }
        }
        if (-not $header) { $header = "" }
    }

    $hidden = $slide.SlideShowTransition.Hidden -eq -1

    $results += [PSCustomObject]@{
        SlideNumber = $slide.SlideIndex
        Header      = $header
        Hidden      = $hidden
    }
}

# --- Sort numerically by slide index ---
$results = $results | Sort-Object SlideNumber

# --- Calculate summary stats before filtering ---
$totalSlides = $results.Count
$hiddenSlides = ($results | Where-Object { $_.Hidden }).Count
$visibleSlides = $totalSlides - $hiddenSlides

# --- Optionally exclude hidden slides ---
if ($HideHidden) {
    $results = $results | Where-Object { -not $_.Hidden }
}

# --- Output formatting ---
switch ($OutputFormat) {
    "Text" {
        if ($OutputFile) {
            # Write to file (plain text, no color codes)
            $output = @()
            $output += "=" * 80
            $output += "PowerPoint Slide Headers"
            $output += "File: $PptxPath"
            $output += "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
            $output += "=" * 80
            $output += ""

            foreach ($r in $results) {
                if ($r.Hidden) {
                    $output += "Slide $($r.SlideNumber): $($r.Header) (Hidden)"
                } else {
                    $output += "Slide $($r.SlideNumber): $($r.Header)"
                }
            }

            $output += ""
            $output += "Summary:"
            $output += "Total slides: $totalSlides"
            $output += "Visible slides: $visibleSlides"
            $output += "Hidden slides: $hiddenSlides"

            $output | Out-File -FilePath $OutputFile -Encoding UTF8
            Write-Host "Output written to: $OutputFile" -ForegroundColor Cyan
        } else {
            # Console output with colors
            Write-Host ("=" * 80) -ForegroundColor Cyan
            Write-Host "PowerPoint Slide Headers" -ForegroundColor Cyan
            Write-Host "File: " -ForegroundColor Cyan -NoNewline
            Write-Host "$PptxPath"
            Write-Host "Generated: " -ForegroundColor Cyan -NoNewline
            Write-Host "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
            Write-Host ("=" * 80) -ForegroundColor Cyan
            Write-Host ""

            foreach ($r in $results) {
                Write-Host "Slide $($r.SlideNumber)" -ForegroundColor Green -NoNewline
                Write-Host ": $($r.Header)" -NoNewline
                if ($r.Hidden) {
                    Write-Host " (Hidden)" -ForegroundColor DarkYellow
                } else {
                    Write-Host ""
                }
            }

            # Summary
            Write-Host ""
            Write-Host "Summary:"
            Write-Host "Total slides: " -NoNewline
            Write-Host "$totalSlides" -ForegroundColor Green
            Write-Host "Visible slides: " -NoNewline
            Write-Host "$visibleSlides" -ForegroundColor Green
            Write-Host "Hidden slides: " -NoNewline
            Write-Host "$hiddenSlides" -ForegroundColor DarkYellow
        }
    }
    "CSV" {
        $results | Export-Csv -Path "slide_headers.csv" -NoTypeInformation
        Write-Host "CSV written to slide_headers.csv"
    }
    "JSON" {
        $results | ConvertTo-Json -Depth 2
    }
}

# --- Cleanup ---
$presentation.Close()
$ppApp.Quit()
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($ppApp) | Out-Null
