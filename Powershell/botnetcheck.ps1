<#
.SYNOPSIS
A PowerShell script to assist incident responders in hunting down suspicious network connections

.DESCRIPTION
Using network IOCs, huntBotNets searches for connections to identified malicious IP addresses.
Output is stored into a text file.

Must be invoked with an IP address to search for.

Can be invoked with a path to where you want the output file saved.

.Example
botnetcheck.ps1 -BotNetIP 192.168.2.1

.Example 
botnetcheck.ps1 -BotNetIP 192.168.2.1 -OutPath C:\DFIRLOGS\

.LINK
https://github.com/TazWake/
#>

param(
     [Parameter(Mandatory=$true)][string]$BotNetIP,
     [string]$OutPath = ".\"
     )

# Initial data for logging
$HostName = (gi env:\Computername).Value
$DirPath = (gi env:\userprofile).value
$UserName = (gi env:\USERNAME).value
$Date = (Get-Date).ToString('dd.MM.yyyy')

# Notify User
Write-Host "[+] Beginning Data Collection on $HostName"

# Write log
Add-Content $OutPath\conncheck.txt "------------------------"
Add-Content $OutPath\conncheck.txt "- Checking for BotNets -"
Add-Content $OutPath\conncheck.txt "------------------------"
$b = "Hostname: " + $HostName
Add-Content $OutPath\conncheck.txt $b
$b = "Path: " + $DirPath
Add-Content $OutPath\conncheck.txt $b
$b = "User Name: " + $UserName
Add-Content $OutPath\conncheck.txt $b
$b = "Date: " + $Date
Add-Content $OutPath\conncheck.txt $b
Add-Content $OutPath\conncheck.txt "------------------------"


$cmd = netstat -nao | select-string $BotNetIP

foreach ($element in $cmd)
{
    $data = $element -split ' ' | where {$_ -ne ''}
    $ConnCheck = @{
        'Local IP : Port#'=$data[1];
        'Remote IP : Port#'=$data[2];
        'Process ID'= $data[4];
        'Process Name'=((Get-process |where {$_.ID -eq $data[4]})).Name
        'Process File Path'=((Get-process |where {$_.ID -eq $data[4]})).path
        'Process Start Time'=((Get-process |where {$_.ID -eq $data[4]})).starttime
        'Associated DLLs and Path'=((Get-process |where {$_.ID -eq $data[4]})).Modules |select @{Name='Modules';Expression={$_.filename -join '; ' } } |out-string
        }
    New-Object -TypeName psobject –Property $ConnCheck | out-file -append "$OutPath\conncheck.txt" -Encoding ascii
 }

 # Notify User
Write-Host "[+] Collection Complete - Results in $OutPath\conncheck.txt"
