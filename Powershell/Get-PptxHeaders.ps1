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

.PARAMETER HideHidden
    Switch. If set, hidden slides are excluded from the output.

.PARAMETER Help
    Show detailed help.

.PARAMETER H
    Alias for Help.

.EXAMPLE
    .\Get-PptxHeaders.ps1 -PptxPath .\deck.pptx -OutputFormat Text

.EXAMPLE
    .\Get-PptxHeaders.ps1 -PptxPath "C:\Slides\deck.pptx" -OutputFormat CSV -HideHidden

.EXAMPLE
   # Plain text output with summary
   .\Get-PptxHeaders.ps1 -PptxPath .\deck.pptx -OutputFormat Text

.EXAMPLE
   # Exclude hidden slides
   .\Get-PptxHeaders.ps1 -PptxPath .\deck.pptx -OutputFormat Text -HideHidden

.EXAMPLE
   # CSV output
   .\Get-PptxHeaders.ps1 -PptxPath "C:\Slides\deck.pptx" -OutputFormat CSV

.EXAMPLE
   # JSON output
   .\Get-PptxHeaders.ps1 -PptxPath "C:\Slides\deck.pptx" -OutputFormat JSON

.NOTES
    Requires Microsoft PowerPoint installed.
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$PptxPath,

    [ValidateSet("Text","CSV","JSON")]
    [string]$OutputFormat = "Text",

    [switch]$HideHidden,

    [Alias("H")]
    [switch]$Help
)

# --- Show help if requested ---
if ($Help) {
    Get-Help $MyInvocation.MyCommand.Definition -Detailed
    exit
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

# --- Optionally exclude hidden slides ---
if ($HideHidden) {
    $results = $results | Where-Object { -not $_.Hidden }
}

# --- Output formatting ---
switch ($OutputFormat) {
    "Text" {
        foreach ($r in $results) {
            if ($r.Hidden) {
                "Slide $($r.SlideNumber): $($r.Header) (Hidden)"
            } else {
                "Slide $($r.SlideNumber): $($r.Header)"
            }
        }
        # Summary
        $total = $results.Count
        $hiddenCount = ($results | Where-Object { $_.Hidden }).Count
        $visibleCount = $total - $hiddenCount
        ""
        "Summary:"
        "Total slides: $total"
        "Visible slides: $visibleCount"
        "Hidden slides: $hiddenCount"
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
