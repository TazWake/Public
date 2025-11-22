<#
.SYNOPSIS
    Collect file timestamps for forensic timeline analysis

.DESCRIPTION
    This script reports key details about files in a given folder, including filename,
    filesize (in bytes), creation/access/write times in UTC. The output is suitable for
    import into timeline analysis tools.

.PARAMETER TargetPath
    The path to scan for files. Defaults to current directory.

.PARAMETER OutputPath
    The directory where the timestamps.csv file will be created. Defaults to current directory.

.PARAMETER Recurse
    Scan subdirectories recursively

.PARAMETER OutputToConsole
    Display results to console in addition to (or instead of) CSV file

.EXAMPLE
    .\collect_timestamps.ps1

    Collects timestamps from current directory to timestamps.csv

.EXAMPLE
    .\collect_timestamps.ps1 -TargetPath C:\Windows\temp -OutputPath D:\incidentresponse\

    Scans C:\Windows\temp and outputs CSV to D:\incidentresponse\timestamps.csv

.EXAMPLE
    .\collect_timestamps.ps1 -TargetPath C:\Users -Recurse

    Recursively scans all files under C:\Users

.LINK
    https://github.com/TazWake/

.NOTES
    Author: @tazwake
    Purpose: Digital forensics file timestamp collection
    All timestamps are reported in UTC for consistency
#>

[CmdletBinding()]
param(
    [Parameter(Position=0, HelpMessage="Path to scan for files")]
    [string]$TargetPath = ".",

    [Parameter(Position=1, HelpMessage="Directory for output CSV file")]
    [string]$OutputPath = ".",

    [Parameter(HelpMessage="Scan subdirectories recursively")]
    [switch]$Recurse,

    [Parameter(HelpMessage="Display results to console")]
    [switch]$OutputToConsole
)

Write-Host -ForegroundColor Cyan "========== File Timestamp Collection =========="
Write-Host -ForegroundColor Gray "[*] Target path: $TargetPath"
Write-Host -ForegroundColor Gray "[*] Output path: $OutputPath"
Write-Host -ForegroundColor Gray "[*] Recursive: $Recurse"
Write-Host ""

try {
    # Validate and resolve paths
    if (-not (Test-Path -Path $TargetPath)) {
        Write-Host -ForegroundColor Red "[!] ERROR: Target path does not exist: $TargetPath"
        exit 1
    }

    # Ensure output directory exists
    if (-not (Test-Path -Path $OutputPath)) {
        Write-Host -ForegroundColor Yellow "[*] Creating output directory: $OutputPath"
        New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
    }

    # Construct output file path
    $outputFile = Join-Path -Path $OutputPath -ChildPath "timestamps.csv"

    # Resolve full paths
    $TargetPath = Resolve-Path -Path $TargetPath
    $outputFile = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($outputFile)

    Write-Host -ForegroundColor Yellow "[*] Collecting file information..."
    Write-Host -ForegroundColor Gray "[*] This may take some time for large directories"

    # Get all files
    $getChildItemParams = @{
        Path        = $TargetPath
        File        = $true
        Force       = $true
        ErrorAction = 'SilentlyContinue'
    }

    if ($Recurse) {
        $getChildItemParams['Recurse'] = $true
    }

    $files = Get-ChildItem @getChildItemParams

    if (-not $files) {
        Write-Host -ForegroundColor Yellow "[!] No files found in target path"
        exit 0
    }

    Write-Host -ForegroundColor Green "[+] Found $($files.Count) file(s)"

    # Collect timestamp information using efficient pipeline
    Write-Host -ForegroundColor Yellow "[*] Processing file timestamps..."

    $fileData = $files | ForEach-Object {
        try {
            [PSCustomObject]@{
                'Name'                       = $_.FullName
                'Size(bytes)'                = $_.Length
                'Creation Time (UTC)'        = $_.CreationTimeUtc
                'Last Access Time (UTC)'     = $_.LastAccessTimeUtc
                'Last Write Time (UTC)'      = $_.LastWriteTimeUtc
            }
        } catch {
            Write-Host -ForegroundColor Red "[!] Error processing file: $($_.FullName)"
            Write-Host -ForegroundColor Red "    $($_.Exception.Message)"
            # Return null for failed files, will be filtered out
            $null
        }
    } | Where-Object { $null -ne $_ }

    # Export to CSV
    Write-Host -ForegroundColor Yellow "[*] Writing to CSV file: $outputFile"
    $fileData | Export-Csv -Path $outputFile -NoTypeInformation -Force

    Write-Host -ForegroundColor Green "[+] CSV export completed successfully"
    Write-Host -ForegroundColor Cyan "[*] Output file: $outputFile"
    Write-Host -ForegroundColor Cyan "[*] Total files processed: $($fileData.Count)"

    # Optionally display to console
    if ($OutputToConsole) {
        Write-Host ""
        Write-Host -ForegroundColor Cyan "========== File Timestamp Data =========="
        $fileData | Format-Table -AutoSize
    }

    Write-Host ""
    Write-Host -ForegroundColor Green "[+] Collection completed successfully"

} catch {
    Write-Host -ForegroundColor Red "[!] ERROR: $($_.Exception.Message)"
    Write-Host -ForegroundColor Red "    $($_.ScriptStackTrace)"
    exit 1
}
