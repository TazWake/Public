<#
.SYNOPSIS
    Ensure baseline auditing

.DESCRIPTION
    This script establishes baseline audit settings
    for windows 10 / server 2016 or newer systems.
    This script is based on the settings found in 
    https://www.malwarearchaeology.com/cheat-sheets/
    NOTE: This script must be run with elevated privs

.EXAMPLE
    .setAuditing.ps1
    
.NOTES
    Author: Taz Wake
    Last Edit: 17 September 2023
    Version 1.2 - Updated to increase logsizes and include USB logging.
    Version 1.3 - Firewall logging removed

#>

# Initial
write-host "This script will ensure baseline audting has been applied. NOTE: It requires admin rights to run and retrospective auditing is not possible"

write-host "[!] Setting Security log to 1048576000 - this should ensure 7 days logs are retained as a minimum."
wevtutil sl Security /ms:1048576000
#reg add hklm\system\CurrentControlSet\services\eventlog\Security /v MaxSize /t REG_DWORD /d 524288000 /f

write-host "[!] Setting System and Application logs to 262144000 - this should ensure 7 days logs are retained as a minimum."
wevtutil sl System /ms:262144000
#reg add hklm\system\CurrentControlSet\services\eventlog\System /v MaxSize /t REG_DWORD /d 262144000 /f
wevtutil sl Application /ms:262144000
#reg add hklm\system\CurrentControlSet\services\eventlog\Application /v MaxSize /t REG_DWORD /d 262144000 /f

write-host "[!] Setting Powershell logging to a minimum of 512mb. This can be increased if needed and you should set up powershell command line history."
wevtUtil sl "Windows PowerShell" /ms:524288000
#reg add "hklm\system\CurrentControlSet\services\eventlog\Windows PowerShell" /v MaxSize /t REG_DWORD /d 262144000 /f
wevtUtil sl "Microsoft-Windows-PowerShell/Operational" /ms:524288000
#reg add "hklm\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PowerShell/Operational" /v MaxSize /t REG_DWORD /d 524288000 /f

write-host "[!] Enabling Powershell Module Logging and ScriptBlock Logging."
reg add "hklm\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v EnableModuleLogging /t REG_DWORD /d 1 
reg add "hklm\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1

write-host "[!] Enabling Command Line Auditing. This makes event ID 4688 useful."
reg add "hklm\software\microsoft\windows\currentversion\policies\system\audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1

write-host "[!] Enabling DNS Client Logging"
wevtutil sl "Microsoft-Windows-DNS-Client/Operational" /e:true
#reg add "hklm\software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DNS-Client/Operational" /v Enabled /t REG_DWORD /d 1

write-host "[!] Enabling Task Scheduler Logging"
reg add "hklm\software\microsoft\windows\currentversion\WINEVT\Channels\Microsoft-Windows-TaskScheduler/Operational" /v Enabled /t REG_DWORD /d 1
#wevtutil set-log Microsoft-Windows-TaskScheduler/Operational /enabled:true

write-host "[!] Enabling USB History Logging"
reg add "hklm\software\microsoft\windows\currentversion\WINEVT\Channels\Microsoft-Windows-DriverFrameworks-UserMode/Operational" /v Enabled /t REG_DWORD /d 1

write-host "[!] Forcing advanced auditing policy."
reg add "hklm\System\CurrentControlSet\Control\Lsa" /v SCENoApplyLegacyAuditPolicy /t REG_DWORD /d 1

write-host "[!] Setting auditing policies now."

# set success only
Auditpol /set /subcategory:"Plug and Play Events" /success:enable /failure:disable
Auditpol /set /subcategory:"Token Right Adjusted Events" /success:enable /failure:disable
Auditpol /set /subcategory:"Account Lockout" /success:enable /failure:disable
Auditpol /set /subcategory:"Group Membership" /success:enable /failure:disable
Auditpol /set /subcategory:"Logoff" /success:enable /failure:disable
Auditpol /set /subcategory:"Detailed File Share" /success:enable /failure:disable
Auditpol /set /subcategory:"File System" /success:enable /failure:disable
Auditpol /set /subcategory:"Registry" /success:enable /failure:disable
Auditpol /set /subcategory:"SAM" /success:enable /failure:disable
Auditpol /set /subcategory:"Filtering Platform Policy Change" /success:enable /failure:disable
Auditpol /set /subcategory:"IPsec Driver" /success:enable /failure:disable
write-host "[!] Success only audit policies set."

# set failure only
Auditpol /set /subcategory:"Other System Events" /success:disable /failure:enable

# set success and failure to enable
Auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
Auditpol /set /subcategory:"Other Account Logon Events" /success:enable /failure:enable
Auditpol /set /category:"Account Management" /success:enable /failure:enable
Auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
Auditpol /set /subcategory:"RPC Events" /success:enable /failure:enable
Auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable
Auditpol /set /subcategory:"Logon" /success:enable /failure:enable
Auditpol /set /subcategory:"Network Policy Server" /success:enable /failure:enable
Auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable
Auditpol /set /subcategory:"Special Logon" /success:enable /failure:enable
Auditpol /set /subcategory:"Application Generated" /success:enable /failure:enable
Auditpol /set /subcategory:"Certification Services" /success:enable /failure:enable
Auditpol /set /subcategory:"File Share" /success:enable /failure:enable
Auditpol /set /subcategory:"Removable Storage" /success:enable /failure:enable
Auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable
Auditpol /set /subcategory:"Authentication Policy Change" /success:enable /failure:enable
Auditpol /set /subcategory:"Authorization Policy Change" /success:enable /failure:enable
write-host "[ ] "
write-host "[!] Sensitive Privilege Use auditing has been disabled. This is very noisy with limited DFIR value. If you require it, please run"
write-host "     auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable"
write-host "    Enabling it will make your policies compliant with the Malwarearcheology recommendations."
Auditpol /set /subcategory:"Sensitive Privilege Use" /success:disable /failure:disable
# This is VERY noisy and doesn't offer much value - if you really must enable it, uncomment the next line
# Auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable
# write-host "[ ] If you absolutely require Sensitive Privilege Use auditing, please edit the script and re-run it or"
# write-host "[ ] run + Auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable + from a command prompt."
# write-host "[ ] "
write-host "[ ] "
Auditpol /set /subcategory:"Security State Change" /success:enable /failure:enable
Auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable
# This is VERY noisy
write-host "[!] NOTE System Integrity auditing will be disabled. This may generate a very large number of ID 5061 events that are simply down to normal system use."
Auditpol /set /subcategory:"System Integrity" /success:disable /failure:disable 
write-host "[ ] if you need to log this, run + Auditpol /set /subcategory:"System Integrity" /success:enable /failure:enable + from a command prompt."
write-host "[ ] "
write-host "[ ] "
write-host "[!] Advanced auditing options can generate a lot more events and should only be enabled if required. Most systems will not need this level of auditing."
write-host "[ ] "
$adv = Read-Host -Prompt "[?] Do you want to enable advanced auditing? [y/n]"
if ($adv -eq "y") {
    write-host "[!] Advanced auditing enabled"
    Auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable
    Auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
    Auditpol /set /subcategory:"Process Termination" /success:enable /failure:disable
    write-host "[!] NOTE: The firewall settings have not been changed to reduce noise."
    #Auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable
    #Auditpol /set /subcategory:"Filtering Platform Packet Drop" /success:enable /failure:disable
    Auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable
    Auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable
    Auditpol /set /subcategory:"Handle Manipulation" /success:enable /failure:disable
    Auditpol /set /subcategory:"Token Right Adjusted Events" /success:enable /failure:enable
    Auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
    Auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
    write-host "[!] Advanced auditing established"
} else {
    write-host "[ ] No advanced auditing selected."
    write-host " "
}

write-host "Script execution has completed. Thank you!"
