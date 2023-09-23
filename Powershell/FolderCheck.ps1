#
# This script searches a given folder and returns the Name, Modification timestamps and
# Creation timestamps ($SI) for any subfolders in CSV format.
#
# To use:
#    Change <DIRECTORY PATH HERE> to the folder you want to check.
#    Change <OUTPUT FILENAME> to the path/filename of the CSV you want to create.

$directoryPath = "<DIRECTORY PATH HERE>"
$subfolders = Get-ChildItem -Path $directoryPath -Directory

$folderInfo = @()

foreach ($subfolder in $subfolders) {
    $folderName = $subfolder.Name
    $lastModifiedDate = $subfolder.LastWriteTime
    $creationDate = $subfolder.CreationTime
    $folderObject = New-Object PSObject -Property @{
        FolderName = $folderName
        LastModifiedDate = $lastModifiedDate
        CreationDate = $creationDate
    }
    $folderInfo += $folderObject
}

$folderInfo | Export-Csv -Path "<OUTPUT FILENAME>" -NoTypeInformation
