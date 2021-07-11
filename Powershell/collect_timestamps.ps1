<#

.SYNOPSIS
Script to display the Creation, Access and Write times of files in a given folder.

.DESCRIPTION
This script reports key details about files in a given folder. It identifies the filename, filesize (in bytes), creation/access/write times.
If no path is provided with the execution it looks at files in the current path.

.EXAMPLE
timestamps.ps1

.EXAMPLE
timestamps.ps1 -targetPath C:\Windows\temp -outputPath D:\incidentresponse\

.LINK
https://github.com/TazWake/

.NOTES
Under development

#>
param(
    [Parameter(Mandatory=$false)][string]$targetPath,
    [Parameter(Mandatory=$false)][string]$outputPath
    )
function outData {
    $output = "$outputPath\timestamps.csv"
    if ((Test-Path -Path $output) -eq $false) {
        New-Item $output -ItemType file
        'Name,Size(bytes),Creation Time (UTC),Last Access Time (UTC), Last Write Time (UTC)' | Out-File -FilePath $output -Append -Encoding ascii -Force
    }
    return $output
}
function writeCSV ($scanpath, $outpath) {
    $files = Get-ChildItem $scanpath -Recurse -force
    foreach ($file in $files) {
        $box = Get-ItemProperty $file.FullName
        $data = $box.FullName + "," + $box.Length + "," + $box.CreationTimeUtc + "," + $box.LastAccessTimeUtc + "," + $box.LastWriteTimeUtc
        $data | Out-File -FilePath $outpath -Append -Encoding ascii -Force
        }
}
$scanpath = "*"
if ($targetPath) {
    $scanpath = $targetPath
    }
Write-Host "Starting collection"
if ($outputPath) {
    $filepath = outData
    $filepath = "$outputPath\timestamps.csv" <# fudge to get round an odd issue #>
    writeCSV $scanpath $filepath
}
Get-ItemProperty -Path $scanpath | Format-list -Property Name, Length, CreationTimeUtc, LastAccessTimeUtc, LastWriteTimeUtc
Write-Host "Collection completed"
