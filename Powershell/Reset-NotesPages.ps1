<#
.SYNOPSIS
    Reset notes page layout for all slides to match the Notes Master.

    WARNING!
    WARNING! This is not yet functional! When run, it breaks the notes part of the notes pages and does not fully reset the page structure.
    The test example used had notes pages with a top box for the slide (as shown) and a bottom box for the speaker's notes. This script
    seems to shrink the speaker's notes to a few pixels wide and makes no changes to the top box.
    WARNING!
    WARNING!

.DESCRIPTION
    Iterates through every slide in a PPTX presentation and reasserts the
    Notes Master settings (positions and sizes of notes text box and slide image).
    Produces a colour-coded report of changes. Supports dry-run mode.
    By default saves to a new file with "_fixed" appended to the filename,
    unless -Overwrite is specified.

.PARAMETER PptxPath
    Path to the PPTX file (relative or absolute).

.PARAMETER ReportPath
    Optional path to save the report (text file). If omitted, only console output is shown.

.PARAMETER DryRun
    Switch. If set, no changes are applied — only differences are reported.

.PARAMETER Overwrite
    Switch. If set, changes are saved back into the original file instead of creating a new "_fixed" file.

.EXAMPLE
    # Preview differences only (no changes applied)
    .\Reset-NotesPages.ps1 -PptxPath .\deck.pptx -DryRun

.EXAMPLE
    # Apply changes and save as new file deck_fixed.pptx
    .\Reset-NotesPages.ps1 -PptxPath .\deck.pptx

.EXAMPLE
    # Apply changes and overwrite original file
    .\Reset-NotesPages.ps1 -PptxPath .\deck.pptx -Overwrite

.EXAMPLE
    # Apply changes and save report to file
    .\Reset-NotesPages.ps1 -PptxPath .\deck.pptx -ReportPath "C:\report.txt"

.NOTES
    Requires Microsoft PowerPoint installed.
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$PptxPath,

    [string]$ReportPath,

    [switch]$DryRun,

    [switch]$Overwrite
)

# Resolve path
if (-not (Test-Path $PptxPath)) {
    Write-Error "File not found: $PptxPath"
    exit 1
}
$PptxPath = (Resolve-Path $PptxPath).Path

# Launch PowerPoint COM
$ppApp = New-Object -ComObject PowerPoint.Application

# Open presentation (editable, untitled = false, withWindow = true)
$presentation = $ppApp.Presentations.Open($PptxPath, $false, $false, $true)

# Grab Notes Master reference
$notesMaster = $presentation.NotesMaster

# Collect default positions/sizes from master
$masterShapes = @{}
foreach ($shape in $notesMaster.Shapes) {
    if ($shape.HasTextFrame -eq -1 -and $shape.TextFrame.HasText -eq -1) {
        $masterShapes["NotesText"] = @{
            Left   = $shape.Left
            Top    = $shape.Top
            Width  = $shape.Width
            Height = $shape.Height
        }
    }
    elseif ($shape.Type -eq 13) { # ppPlaceholderPicture
        $masterShapes["SlideImage"] = @{
            Left   = $shape.Left
            Top    = $shape.Top
            Width  = $shape.Width
            Height = $shape.Height
        }
    }
}

$report = @()
$totalSlides = $presentation.Slides.Count
$currentSlide = 0

# Loop through slides and reset notes page shapes
foreach ($slide in $presentation.Slides) {
    $currentSlide++
    Write-Host "Processing slide $currentSlide of $totalSlides..." -ForegroundColor Cyan

    $changed = $false
    try {
        foreach ($shape in $slide.NotesPage.Shapes) {
            if ($shape.HasTextFrame -eq -1 -and $shape.TextFrame.HasText -eq -1 -and $masterShapes.ContainsKey("NotesText")) {
                $m = $masterShapes["NotesText"]
                if ($shape.Left -ne $m.Left -or $shape.Top -ne $m.Top -or $shape.Width -ne $m.Width -or $shape.Height -ne $m.Height) {
                    if (-not $DryRun) {
                        $shape.Left   = $m.Left
                        $shape.Top    = $m.Top
                        $shape.Width  = $m.Width
                        $shape.Height = $m.Height
                    }
                    $changed = $true
                }
            }
            elseif ($shape.Type -eq 13 -and $masterShapes.ContainsKey("SlideImage")) {
                $m = $masterShapes["SlideImage"]
                if ($shape.Left -ne $m.Left -or $shape.Top -ne $m.Top -or $shape.Width -ne $m.Width -or $shape.Height -ne $m.Height) {
                    if (-not $DryRun) {
                        $shape.Left   = $m.Left
                        $shape.Top    = $m.Top
                        $shape.Width  = $m.Width
                        $shape.Height = $m.Height
                    }
                    $changed = $true
                }
            }
        }

        if ($changed) {
            if ($DryRun) {
                Write-Host "Slide $($slide.SlideIndex): WOULD RESET to master" -ForegroundColor Yellow
                $report += "Slide $($slide.SlideIndex): WOULD RESET to master"
            } else {
                Write-Host "Slide $($slide.SlideIndex): RESET to master" -ForegroundColor Yellow
                $report += "Slide $($slide.SlideIndex): RESET to master"
            }
        } else {
            Write-Host "Slide $($slide.SlideIndex): OK (matches master)" -ForegroundColor Green
            $report += "Slide $($slide.SlideIndex): OK (matches master)"
        }
    }
    catch {
        Write-Host "Slide $($slide.SlideIndex): ERROR resetting notes page" -ForegroundColor Red
        $report += "Slide $($slide.SlideIndex): ERROR resetting notes page"
    }
}

# Summary
$resetCount = ($report | Where-Object { $_ -like "*RESET*" }).Count
$okCount = ($report | Where-Object { $_ -like "*OK*" }).Count
$errorCount = ($report | Where-Object { $_ -like "*ERROR*" }).Count

Write-Host ""
Write-Host "Summary:" -ForegroundColor Cyan
Write-Host "Total slides: $totalSlides" -ForegroundColor Cyan
Write-Host "Reset slides: $resetCount" -ForegroundColor Yellow
Write-Host "Unchanged slides: $okCount" -ForegroundColor Green
Write-Host "Errors: $errorCount" -ForegroundColor Red

$report += ""
$report += "Summary:"
$report += "Total slides: $totalSlides"
$report += "Reset slides: $resetCount"
$report += "Unchanged slides: $okCount"
$report += "Errors: $errorCount"

# Save report if requested
if ($ReportPath) {
    $resolvedPath = $null
    try { $resolvedPath = (Resolve-Path $ReportPath -ErrorAction Stop).Path } catch { $resolvedPath = $ReportPath }
    $report | Out-File -FilePath $resolvedPath -Encoding UTF8
    Write-Host "Report saved to $resolvedPath" -ForegroundColor Cyan
}

# --- Save presentation ---
if (-not $DryRun) {
    try {
        if ($Overwrite) {
            $presentation.Save()
            Write-Host "Presentation saved over original file." -ForegroundColor Cyan
        } else {
            $dir = Split-Path $PptxPath
            $base = [System.IO.Path]::GetFileNameWithoutExtension($PptxPath)
            $ext = [System.IO.Path]::GetExtension($PptxPath)
            $newPath = Join-Path $dir ($base + "_fixed" + $ext)
            $presentation.SaveCopyAs($newPath)
            Write-Host "Presentation saved as new file: $newPath" -ForegroundColor Cyan
        }
    } catch {
        Write-Host "ERROR: Could not save presentation." -ForegroundColor Red
    }
}

# Cleanup
try { $presentation.Close() } catch {}
$ppApp.Quit()
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($ppApp) | Out-Null
