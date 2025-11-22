<#
.SYNOPSIS
    Ensure baseline auditing for Windows systems

.DESCRIPTION
    This script establishes baseline audit settings for Windows 10, Server 2016,
    or newer systems. Configuration is based on recommendations from Malware Archaeology.

    IMPORTANT: This script only affects FUTURE logging. Retrospective auditing is not possible.

.PARAMETER Force
    Skip advanced auditing prompt and apply recommended baseline only

.PARAMETER EnableAdvanced
    Automatically enable advanced auditing options without prompting

.EXAMPLE
    .\setAuditing.ps1

    Runs baseline auditing and prompts for advanced options

.EXAMPLE
    .\setAuditing.ps1 -Force

    Applies baseline auditing only, skipping advanced options prompt

.EXAMPLE
    .\setAuditing.ps1 -EnableAdvanced

    Applies baseline AND advanced auditing without prompting

.NOTES
    Author: Taz Wake
    Last Edit: $(Get-Date -Format 'dd MMMM yyyy')
    Version 1.4 - Added admin check, error handling, Force parameter, removed legacy code
    Version 1.3 - Firewall logging removed
    Version 1.2 - Updated to increase logsizes and include USB logging

    Based on: https://www.malwarearchaeology.com/cheat-sheets/

    Requires: Administrator privileges
#>

[CmdletBinding()]
param(
    [Parameter(HelpMessage="Skip advanced auditing prompt")]
    [switch]$Force,

    [Parameter(HelpMessage="Enable advanced auditing automatically")]
    [switch]$EnableAdvanced
)

# Check for Administrator privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host -ForegroundColor Red "`n[!] ERROR: This script requires Administrator privileges"
    Write-Host -ForegroundColor Yellow "[*] Please run PowerShell as Administrator and try again`n"
    exit 1
}

# Display header
Write-Host -ForegroundColor Cyan "`n========== Windows Baseline Auditing Configuration =========="
Write-Host -ForegroundColor Yellow "[!] This script will establish baseline auditing"
Write-Host -ForegroundColor Yellow "[!] NOTE: Retrospective auditing is not possible - this affects future events only"
Write-Host -ForegroundColor Gray "[*] Based on Malware Archaeology recommendations"
Write-Host ""

try {
    # Configure Event Log Sizes
    Write-Host -ForegroundColor Yellow "[*] Configuring event log sizes..."

    Write-Host "[+] Setting Security log to 1GB (ensures ~7 days retention minimum)"
    wevtutil sl Security /ms:1048576000

    Write-Host "[+] Setting System and Application logs to 250MB"
    wevtutil sl System /ms:262144000
    wevtutil sl Application /ms:262144000

    Write-Host "[+] Setting PowerShell logs to 512MB minimum"
    wevtutil sl "Windows PowerShell" /ms:524288000
    wevtutil sl "Microsoft-Windows-PowerShell/Operational" /ms:524288000

    Write-Host -ForegroundColor Green "[+] Event log sizes configured"
    Write-Host ""

    # Enable PowerShell Logging
    Write-Host -ForegroundColor Yellow "[*] Enabling PowerShell auditing..."

    Write-Host "[+] Enabling PowerShell Module Logging"
    reg add "hklm\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v EnableModuleLogging /t REG_DWORD /d 1 /f | Out-Null

    Write-Host "[+] Enabling PowerShell ScriptBlock Logging"
    reg add "hklm\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f | Out-Null

    Write-Host -ForegroundColor Green "[+] PowerShell auditing enabled"
    Write-Host ""

    # Enable Process Command Line Auditing
    Write-Host -ForegroundColor Yellow "[*] Enabling process auditing..."

    Write-Host "[+] Enabling Command Line Auditing (Event ID 4688 enhancement)"
    reg add "hklm\software\microsoft\windows\currentversion\policies\system\audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f | Out-Null

    Write-Host -ForegroundColor Green "[+] Process auditing enabled"
    Write-Host ""

    # Enable Additional Event Sources
    Write-Host -ForegroundColor Yellow "[*] Enabling additional event sources..."

    Write-Host "[+] Enabling DNS Client Logging"
    wevtutil sl "Microsoft-Windows-DNS-Client/Operational" /e:true

    Write-Host "[+] Enabling Task Scheduler Logging"
    reg add "hklm\software\microsoft\windows\currentversion\WINEVT\Channels\Microsoft-Windows-TaskScheduler/Operational" /v Enabled /t REG_DWORD /d 1 /f | Out-Null

    Write-Host "[+] Enabling USB History Logging"
    reg add "hklm\software\microsoft\windows\currentversion\WINEVT\Channels\Microsoft-Windows-DriverFrameworks-UserMode/Operational" /v Enabled /t REG_DWORD /d 1 /f | Out-Null

    Write-Host -ForegroundColor Green "[+] Additional event sources enabled"
    Write-Host ""

    # Force Advanced Auditing Policy
    Write-Host -ForegroundColor Yellow "[*] Configuring advanced audit policy framework..."

    Write-Host "[+] Forcing advanced auditing policy (disabling legacy audit policy)"
    reg add "hklm\System\CurrentControlSet\Control\Lsa" /v SCENoApplyLegacyAuditPolicy /t REG_DWORD /d 1 /f | Out-Null

    Write-Host -ForegroundColor Green "[+] Advanced audit policy framework enabled"
    Write-Host ""

    # Apply Audit Policies
    Write-Host -ForegroundColor Yellow "[*] Applying audit policies..."

    # Baseline Audit Policies - Success Only
    Write-Host "[+] Configuring success-only audit policies..."
    Auditpol /set /subcategory:"Plug and Play Events" /success:enable /failure:disable | Out-Null
    Auditpol /set /subcategory:"Token Right Adjusted Events" /success:enable /failure:disable | Out-Null
    Auditpol /set /subcategory:"Account Lockout" /success:enable /failure:disable | Out-Null
    Auditpol /set /subcategory:"Group Membership" /success:enable /failure:disable | Out-Null
    Auditpol /set /subcategory:"Logoff" /success:enable /failure:disable | Out-Null
    Auditpol /set /subcategory:"Detailed File Share" /success:enable /failure:disable | Out-Null
    Auditpol /set /subcategory:"File System" /success:enable /failure:disable | Out-Null
    Auditpol /set /subcategory:"Registry" /success:enable /failure:disable | Out-Null
    Auditpol /set /subcategory:"SAM" /success:enable /failure:disable | Out-Null
    Auditpol /set /subcategory:"Filtering Platform Policy Change" /success:enable /failure:disable | Out-Null
    Auditpol /set /subcategory:"IPsec Driver" /success:enable /failure:disable | Out-Null

    # Baseline Audit Policies - Failure Only
    Write-Host "[+] Configuring failure-only audit policies..."
    Auditpol /set /subcategory:"Other System Events" /success:disable /failure:enable | Out-Null

    # Baseline Audit Policies - Success and Failure
    Write-Host "[+] Configuring success and failure audit policies..."
    Auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable | Out-Null
    Auditpol /set /subcategory:"Other Account Logon Events" /success:enable /failure:enable | Out-Null
    Auditpol /set /category:"Account Management" /success:enable /failure:enable | Out-Null
    Auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable | Out-Null
    Auditpol /set /subcategory:"RPC Events" /success:enable /failure:enable | Out-Null
    Auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable | Out-Null
    Auditpol /set /subcategory:"Logon" /success:enable /failure:enable | Out-Null
    Auditpol /set /subcategory:"Network Policy Server" /success:enable /failure:enable | Out-Null
    Auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable | Out-Null
    Auditpol /set /subcategory:"Special Logon" /success:enable /failure:enable | Out-Null
    Auditpol /set /subcategory:"Application Generated" /success:enable /failure:enable | Out-Null
    Auditpol /set /subcategory:"Certification Services" /success:enable /failure:enable | Out-Null
    Auditpol /set /subcategory:"File Share" /success:enable /failure:enable | Out-Null
    Auditpol /set /subcategory:"Removable Storage" /success:enable /failure:enable | Out-Null
    Auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable | Out-Null
    Auditpol /set /subcategory:"Authentication Policy Change" /success:enable /failure:enable | Out-Null
    Auditpol /set /subcategory:"Authorization Policy Change" /success:enable /failure:enable | Out-Null
    Auditpol /set /subcategory:"Security State Change" /success:enable /failure:enable | Out-Null
    Auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable | Out-Null

    # Intentionally Disabled Policies (noisy with limited DFIR value)
    Write-Host "[+] Disabling noisy audit policies with limited forensic value..."
    Auditpol /set /subcategory:"Sensitive Privilege Use" /success:disable /failure:disable | Out-Null
    Auditpol /set /subcategory:"System Integrity" /success:disable /failure:disable | Out-Null

    Write-Host -ForegroundColor Green "[+] Baseline audit policies applied"
    Write-Host -ForegroundColor Yellow "[!] Note: 'Sensitive Privilege Use' and 'System Integrity' auditing disabled (very noisy)"
    Write-Host ""

} catch {
    Write-Host -ForegroundColor Red "[!] ERROR applying baseline auditing:"
    Write-Host -ForegroundColor Red "    $($_.Exception.Message)"
    Write-Host -ForegroundColor Yellow "[*] Some settings may not have been applied"
    exit 1
}

# Advanced Auditing Section
Write-Host -ForegroundColor Cyan "========== Advanced Auditing Options =========="
Write-Host -ForegroundColor Yellow "[!] Advanced auditing generates significantly more events"
Write-Host -ForegroundColor Yellow "[!] Only enable if required - most systems don't need this level"
Write-Host ""

if ($Force) {
    Write-Host -ForegroundColor Cyan "[*] Force mode enabled - skipping advanced auditing"
    $enableAdvanced = $false
} elseif ($EnableAdvanced) {
    Write-Host -ForegroundColor Yellow "[*] EnableAdvanced flag set - applying advanced auditing"
    $enableAdvanced = $true
} else {
    $response = Read-Host "[?] Do you want to enable advanced auditing? (Y/N)"
    $enableAdvanced = $response -match "^[Yy]"
}

if ($enableAdvanced) {
    try {
        Write-Host -ForegroundColor Yellow "[*] Applying advanced auditing policies..."

        Auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable | Out-Null
        Auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable | Out-Null
        Auditpol /set /subcategory:"Process Termination" /success:enable /failure:disable | Out-Null
        Auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable | Out-Null
        Auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable | Out-Null
        Auditpol /set /subcategory:"Handle Manipulation" /success:enable /failure:disable | Out-Null
        Auditpol /set /subcategory:"Token Right Adjusted Events" /success:enable /failure:enable | Out-Null
        Auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable | Out-Null
        Auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable | Out-Null

        Write-Host -ForegroundColor Green "[+] Advanced auditing enabled successfully"
        Write-Host -ForegroundColor Yellow "[!] Note: Firewall auditing NOT enabled to reduce noise"

    } catch {
        Write-Host -ForegroundColor Red "[!] ERROR applying advanced auditing:"
        Write-Host -ForegroundColor Red "    $($_.Exception.Message)"
    }
} else {
    Write-Host -ForegroundColor Cyan "[*] Advanced auditing skipped"
}

Write-Host ""
Write-Host -ForegroundColor Green "[+] Script execution completed successfully!"
Write-Host -ForegroundColor Cyan "========================================`n"
