<#
collectEvidence.ps1

Purpose:
    This script will capture essential triage data from a device and store the resulting files on a removable disk.
    
Requirements:
    1. A USB or other storage location large enough to store output. 
        NOTE: Bear in mind, memory capture can result in a file approximately 5-10% larger than the system memory. The triage VHDX can be approximately 0.5gb in size.
    2. This script on the root of the USB.
    3. A correctly licenced copy of KAPE with appropriate targets/modules on in a folder called Kape at the root of the USB.
    4. A copy of Magnet Ram Capture (MRC.exe) on root of the USB.

Execution:
    1. Run powershell with Administrator privileges.
    2. Navigate to the USB.
    3. .\collectEvidence.ps1
#>

write-host -ForegroundColor Blue "++++++++++++++++++++++++++"
write-host -ForegroundColor DarkCyan "+ Triage Data Collection +"
write-host -ForegroundColor DarkCyan "+   Starting Collection  +"
write-host -ForegroundColor DarkCyan "+       @tazwake         +"
write-host -ForegroundColor Blue "++++++++++++++++++++++++++"
# Set up evidence and logging
mkdir Evidence\$env:COMPUTERNAME-force
Write-host -ForegroundColor Gray 'Artifact collection initiated at' $(get-date)
Set-Content -Path \Evidence\$env:COMPUTERNAME\log.txt -Value "Evidence collection started: $((Get-Date).ToString())"
Add-Content -Path \Evidence\$env:COMPUTERNAME\log.txt -Value "Initial folder created."

Add-Content -Path \Evidence\$env:COMPUTERNAME\log.txt -Value "Memory capture initiated: $((Get-Date).ToString())"
.\MRC.exe /accepteula /go /silent
Start-Sleep -Seconds 3
Write-host -ForegroundColor Yellow "[ ] Launching Magnet RAM Capture to collect a memory image."
Write-host -ForegroundColor Yellow "[!] This may take a long time. "
Wait-Process -Name "MRC"
Write-host -ForergroundColor DarkYellow "[X] Capture complete, logging OS build data. Renaming evidence."
[System.Environment]::OSVersion.Version > .\Evidence\$env:COMPUTERNAME\OS_build_version.txt
Get-ChildItem -Filter 'MagnetRAMCapture*' -Recurse | Rename-Item -NewName {$_.name -replace 'MagnetRAMCapture', $env:COMPUTERNAME }
Move-Item -Path .\*.txt -Destination .\Evidence\$env:COMPUTERNAME\
Move-Item -Path .\*.raw -Destination .\Evidence\$env:COMPUTERNAME\
Get-FileHash -Algorithm MD5 .\Evidence\$env:COMPUTERNAME\*.raw | Out-File .\Evidence\$env:COMPUTERNAME\MemoryCapture_MD5Hashes.txt
Write-host -ForergroundColor Yellow "[ ] Memory capture completed."
Add-Content -Path \Evidence\$env:COMPUTERNAME\log.txt -Value "Memory capture completed: $((Get-Date).ToString())"

Start-Sleep -Seconds 1
Add-Content -Path \Evidence\$env:COMPUTERNAME\log.txt -Value "KAPE triage date collection initiated: $((Get-Date).ToString())"
Write-host -ForegroundColor Green "[ ] Collecting OS Artifacts."
.\Kape\kape.exe --tsource C: --tdest .\Evidence\$env:COMPUTERNAME --target !SANS_Triage --vhdx $env:COMPUTERNAME --zv false
Set-Content -Path \Evidence\$env:COMPUTERNAME\Finished.txt -Value "Evidence collection complete: $((Get-Date).ToString())"
Get-FileHash -Algorithm MD5 .\Evidence\$env:COMPUTERNAME\*.vhdx | Out-File .\Evidence\$env:COMPUTERNAME\KapeOutput_MD5Hashes.txt
Add-Content -Path \Evidence\$env:COMPUTERNAME\log.txt -Value "Collection completed: $((Get-Date).ToString())"
Write-Host -ForegroundColor Green "[ ] Collection completed"
