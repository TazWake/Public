<#
.SYNOPSIS
    Extract folder metadata for timeline analysis

.DESCRIPTION
    This script searches a given folder and returns the Name, Modification timestamps
    and Creation timestamps for any subfolders in CSV format. Useful for forensic
    timeline analysis and identifying suspicious directory creation patterns.

.PARAMETER DirectoryPath
    The path to the directory to analyze. Defaults to current directory.

.PARAMETER OutputFile
    The path and filename of the CSV file to create. Defaults to .\folder_timestamps.csv

.PARAMETER Recurse
    Include all subdirectories recursively

.EXAMPLE
    .\FolderCheck.ps1

    Analyzes current directory and creates folder_timestamps.csv

.EXAMPLE
    .\FolderCheck.ps1 -DirectoryPath "C:\Users" -OutputFile "C:\Evidence\users_folders.csv"

    Analyzes C:\Users and outputs to specified CSV file

.EXAMPLE
    .\FolderCheck.ps1 -DirectoryPath "C:\Program Files" -Recurse

    Recursively analyzes all subdirectories under C:\Program Files

.NOTES
    Author: @tazwake
    Purpose: Digital forensics folder timestamp collection
#>

[CmdletBinding()]
param(
    [Parameter(Position=0, HelpMessage="Path to directory to analyze")]
    [ValidateScript({Test-Path -Path $_ -PathType Container})]
    [string]$DirectoryPath = ".",

    [Parameter(Position=1, HelpMessage="Output CSV file path")]
    [string]$OutputFile = ".\folder_timestamps.csv",

    [Parameter(HelpMessage="Recursively analyze subdirectories")]
    [switch]$Recurse
)

Write-Host -ForegroundColor Cyan "========== Folder Metadata Collection =========="
Write-Host -ForegroundColor Gray "[*] Target directory: $DirectoryPath"
Write-Host -ForegroundColor Gray "[*] Output file: $OutputFile"
Write-Host -ForegroundColor Gray "[*] Recursive: $Recurse"
Write-Host ""

try {
    # Resolve full path
    $DirectoryPath = Resolve-Path -Path $DirectoryPath

    # Get subfolders
    Write-Host -ForegroundColor Yellow "[*] Scanning for subdirectories..."

    if ($Recurse) {
        $subfolders = Get-ChildItem -Path $DirectoryPath -Directory -Recurse -ErrorAction SilentlyContinue
    } else {
        $subfolders = Get-ChildItem -Path $DirectoryPath -Directory -ErrorAction SilentlyContinue
    }

    if (-not $subfolders) {
        Write-Host -ForegroundColor Yellow "[!] No subdirectories found in $DirectoryPath"
        exit 0
    }

    Write-Host -ForegroundColor Green "[+] Found $($subfolders.Count) folder(s)"

    # Collect folder information using efficient pipeline
    Write-Host -ForegroundColor Yellow "[*] Collecting folder metadata..."

    $folderInfo = $subfolders | ForEach-Object {
        [PSCustomObject]@{
            FolderName       = $_.Name
            FullPath         = $_.FullName
            LastModifiedDate = $_.LastWriteTime
            CreationDate     = $_.CreationTime
            LastAccessDate   = $_.LastAccessTime
        }
    }

    # Export to CSV
    Write-Host -ForegroundColor Yellow "[*] Exporting to CSV..."
    $folderInfo | Export-Csv -Path $OutputFile -NoTypeInformation -Force

    Write-Host -ForegroundColor Green "[+] Export completed successfully"
    Write-Host -ForegroundColor Cyan "[*] Output file: $OutputFile"
    Write-Host -ForegroundColor Cyan "[*] Total folders: $($folderInfo.Count)"
    Write-Host ""

} catch {
    Write-Host -ForegroundColor Red "[!] ERROR: $($_.Exception.Message)"
    Write-Host -ForegroundColor Red "    $($_.ScriptStackTrace)"
    exit 1
}

Write-Host -ForegroundColor Green "[+] Collection complete"
