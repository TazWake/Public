<#
This script is deprecated - please use https://github.com/TazWake/Public/blob/master/Powershell/setAuditing.ps1
#>

reg add hklm\system\CurrentControlSet\services\eventlog\Security /v MaxSize /t REG_DWORD /d 524288000 /f
reg add "hklm\system\CurrentControlSet\services\eventlog\Windows PowerShell" /v MaxSize /t REG_DWORD /d 262144000 /f
reg add "hklm\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PowerShell/Operational" /v MaxSize /t REG_DWORD /d 524288000 /f
reg add hklm\system\CurrentControlSet\services\eventlog\System /v MaxSize /t REG_DWORD /d 262144000 /f
reg add hklm\system\CurrentControlSet\services\eventlog\Application /v MaxSize /t REG_DWORD /d 262144000 /f
reg add "hklm\software\microsoft\windows\currentversion\policies\system\audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1
reg add "hklm\software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DNS-Client/Operational" /v Enabled /t REG_DWORD /d 1
reg add "hklm\software\microsoft\windows\currentversion\WINEVT\Channels\Microsoft-Windows-DriverFrameworks-UserMode/Operational" /v Enabled /t REG_DWORD /d 1
reg add "hklm\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v EnableModuleLogging /t REG_DWORD /d 1
reg add "hklm\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1
reg add "hklm\System\CurrentControlSet\Control\Lsa" /v SCENoApplyLegacyAuditPolicy /t REG_DWORD /d 1
Auditpol /set /category:"Account Management" /success:enable /failure:enable
Auditpol /set /category:"System" /success:enable /failure:enable
Auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
Auditpol /set /subcategory:"Other Account Logon Events" /success:enable /failure:enable
Auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable
Auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
Auditpol /set /subcategory:"Process Termination" /success:enable /failure:enable
Auditpol /set /subcategory:"RPC Events" /success:enable /failure:enable
Auditpol /set /subcategory:"Logon" /success:enable /failure:enable
Auditpol /set /subcategory:"Network Policy Server" /success:enable /failure:enable
Auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable
Auditpol /set /subcategory:"Special Logon" /success:enable /failure:enable
Auditpol /set /subcategory:"Application Generated" /success:enable /failure:enable
Auditpol /set /subcategory:"Certification Services" /success:enable /failure:enable
Auditpol /set /subcategory:"File Share" /success:enable /failure:enable
Auditpol /set /subcategory:"Kernel Object" /success:enable /failure:enable
Auditpol /set /subcategory:"Removable Storage" /success:enable /failure:enable
Auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable
Auditpol /set /subcategory:"Authentication Policy Change" /success:enable /failure:enable
Auditpol /set /subcategory:"Authorization Policy Change" /success:enable /failure:enable
Auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable
Auditpol /set /subcategory:"Security State Change" /success:enable /failure:enable
Auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable
Auditpol /set /subcategory:"System Integrity" /success:enable /failure:enable
Auditpol /set /subcategory:"Plug and Play Events" /success:enable /failure:disable
Auditpol /set /subcategory:"Token Right Adjusted Events" /success:enable /failure:disable
Auditpol /set /subcategory:"Account Lockout" /success:enable /failure:disable
Auditpol /set /subcategory:"Group Membership" /success:enable /failure:disable
Auditpol /set /subcategory:"Logoff" /success:enable /failure:disable
Auditpol /set /subcategory:"Detailed File Share" /success:enable /failure:disable
Auditpol /set /subcategory:"File System" /success:enable /failure:disable
Auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:disable
Auditpol /set /subcategory:"Registry" /success:enable /failure:disable
Auditpol /set /subcategory:"Filtering Platform Policy Change" /success:enable /failure:disable
Auditpol /set /subcategory:"IPsec Driver" /success:enable /failure:disable
Auditpol /set /subcategory:"Other System Events" /success:disable /failure:enable
