<#
.SYNOPSIS
    Hunt for suspicious network connections to known malicious IP addresses

.DESCRIPTION
    Using network IOCs, this script searches for active connections to identified
    malicious IP addresses. Useful for incident responders hunting for botnet
    command and control (C2) communications or other malicious network activity.

    Output includes connection details, associated process information, and loaded DLLs.

.PARAMETER BotNetIP
    The IP address to search for in active network connections (required)

.PARAMETER OutPath
    Path where the output file (conncheck.txt) will be saved. Defaults to current directory.

.EXAMPLE
    .\botnetcheck.ps1 -BotNetIP 192.168.2.1

    Searches for connections to 192.168.2.1 and saves results to .\conncheck.txt

.EXAMPLE
    .\botnetcheck.ps1 -BotNetIP 10.0.0.50 -OutPath C:\DFIRLOGS\

    Searches for connections and outputs to C:\DFIRLOGS\conncheck.txt

.NOTES
    Author: @tazwake
    Purpose: Incident response and botnet detection
    Requires: Windows PowerShell 5.1 or higher (for Get-NetTCPConnection)

.LINK
    https://github.com/TazWake/
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0, HelpMessage="Malicious IP address to search for")]
    [ValidateNotNullOrEmpty()]
    [string]$BotNetIP,

    [Parameter(Position=1, HelpMessage="Output directory path")]
    [string]$OutPath = "."
)

# Display header
Write-Host -ForegroundColor Cyan "========== Botnet Connection Hunter =========="
Write-Host -ForegroundColor Gray "[*] Target IP: $BotNetIP"
Write-Host -ForegroundColor Gray "[*] Output path: $OutPath"
Write-Host ""

try {
    # Validate and create output directory if needed
    if (-not (Test-Path -Path $OutPath)) {
        Write-Host -ForegroundColor Yellow "[*] Creating output directory: $OutPath"
        New-Item -Path $OutPath -ItemType Directory -Force | Out-Null
    }

    # Construct output file path
    $outputFile = Join-Path -Path $OutPath -ChildPath "conncheck.txt"

    # Collect system information
    $HostName = $env:COMPUTERNAME
    $UserName = $env:USERNAME
    $Date = (Get-Date).ToString('dd.MM.yyyy HH:mm:ss')

    Write-Host -ForegroundColor Yellow "[+] Beginning data collection on $HostName"

    # Initialize output file
    $header = @"
------------------------
- Checking for BotNets -
------------------------
Hostname: $HostName
User Name: $UserName
Date: $Date
Target IP: $BotNetIP
------------------------

"@
    Set-Content -Path $outputFile -Value $header -Force

    # Get all TCP connections
    Write-Host -ForegroundColor Yellow "[*] Scanning active TCP connections..."

    try {
        $connections = Get-NetTCPConnection -ErrorAction Stop | Where-Object {
            $_.RemoteAddress -eq $BotNetIP -or $_.LocalAddress -eq $BotNetIP
        }
    } catch {
        Write-Host -ForegroundColor Red "[!] ERROR: Failed to retrieve network connections"
        Write-Host -ForegroundColor Red "    $($_.Exception.Message)"
        Write-Host -ForegroundColor Yellow "[*] Ensure you have appropriate permissions and PowerShell 5.1+"
        exit 1
    }

    if (-not $connections) {
        Write-Host -ForegroundColor Green "[+] No connections found to $BotNetIP"
        Add-Content -Path $outputFile -Value "No connections found to target IP address."
        Write-Host -ForegroundColor Cyan "[*] Output file: $outputFile"
        exit 0
    }

    Write-Host -ForegroundColor Red "[!] ALERT: Found $($connections.Count) connection(s) to $BotNetIP"

    # Cache all process information to avoid repeated lookups
    Write-Host -ForegroundColor Yellow "[*] Gathering process information..."
    $processCache = @{}
    $uniquePIDs = $connections | Select-Object -ExpandProperty OwningProcess -Unique

    foreach ($pid in $uniquePIDs) {
        try {
            $process = Get-Process -Id $pid -ErrorAction Stop
            $processCache[$pid] = @{
                Name      = $process.Name
                Path      = $process.Path
                StartTime = $process.StartTime
                Modules   = ($process.Modules | Select-Object -ExpandProperty FileName) -join '; '
            }
        } catch {
            # Process may have terminated or access denied
            $processCache[$pid] = @{
                Name      = "UNKNOWN (PID: $pid)"
                Path      = "Process terminated or access denied"
                StartTime = "N/A"
                Modules   = "N/A"
            }
        }
    }

    # Process each connection
    Write-Host -ForegroundColor Yellow "[*] Processing connection details..."

    foreach ($conn in $connections) {
        $processInfo = $processCache[$conn.OwningProcess]

        $connDetails = [PSCustomObject]@{
            'Local IP : Port'           = "$($conn.LocalAddress):$($conn.LocalPort)"
            'Remote IP : Port'          = "$($conn.RemoteAddress):$($conn.RemotePort)"
            'State'                     = $conn.State
            'Process ID'                = $conn.OwningProcess
            'Process Name'              = $processInfo.Name
            'Process File Path'         = $processInfo.Path
            'Process Start Time'        = $processInfo.StartTime
            'Associated DLLs and Path'  = $processInfo.Modules
        }

        # Append to output file
        $connDetails | Format-List | Out-String | Add-Content -Path $outputFile
        Add-Content -Path $outputFile -Value "------------------------`n"

        # Display to console with color coding
        Write-Host -ForegroundColor Red "    [MATCH] $($conn.LocalAddress):$($conn.LocalPort) <-> $($conn.RemoteAddress):$($conn.RemotePort)"
        Write-Host -ForegroundColor Yellow "            Process: $($processInfo.Name) (PID: $($conn.OwningProcess))"
        Write-Host -ForegroundColor Yellow "            Path: $($processInfo.Path)"
    }

    Write-Host ""
    Write-Host -ForegroundColor Green "[+] Collection complete"
    Write-Host -ForegroundColor Cyan "[*] Results saved to: $outputFile"
    Write-Host -ForegroundColor Red "[!] ALERT: $($connections.Count) suspicious connection(s) detected!"
    Write-Host ""

} catch {
    Write-Host -ForegroundColor Red "[!] ERROR: $($_.Exception.Message)"
    Write-Host -ForegroundColor Red "    $($_.ScriptStackTrace)"
    exit 1
}
