function Check-LoggingStatus {
    $results = [ordered]@{}

    # Script Block Logging
    $path = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    $results["Script Block Logging"] = if ((Test-Path $path) -and ((Get-ItemProperty -Path $path -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue).EnableScriptBlockLogging -eq 1)) {
        "Enabled"
    } else {
        "Disabled"
    }

    # Module Logging
    $path = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
    $results["Module Logging"] = if ((Test-Path $path) -and ((Get-ItemProperty -Path $path -Name EnableModuleLogging -ErrorAction SilentlyContinue).EnableModuleLogging -eq 1)) {
        "Enabled"
    } else {
        "Disabled"
    }

    # Transcription Logging
    $path = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription"
    $transcriptionEnabled = $false
    if (Test-Path $path) {
        $val = (Get-ItemProperty -Path $path -Name EnableTranscripting -ErrorAction SilentlyContinue).EnableTranscripting
        $transcriptionEnabled = ($val -eq 1)
    }
    $results["Transcription Logging"] = if ($transcriptionEnabled) { "Enabled" } else { "Disabled" }

    return $results
}

function Enable-AllLogging {
    Write-Host "`n🔧 Enabling all PowerShell auditing settings..."

    # Script Block Logging
    New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force | Out-Null
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1 -Force

    # Module Logging
    New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Force | Out-Null
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -Value 1 -Force
    New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" -Force | Out-Null
    New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" -Name "*" -Value "*" -PropertyType String -Force

    # Transcription Logging
    New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription" -Force | Out-Null
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "IncludeInvocationHeader" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableInvocationHeader" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "OutputDirectory" -Value "C:\Transcripts" -Force

    # Create transcription directory if needed
    if (-not (Test-Path "C:\Transcripts")) {
        New-Item -ItemType Directory -Path "C:\Transcripts" | Out-Null
    }

    Write-Host "[x] All logging settings have been enabled.`n"
}

# Run checks and display
$logStatus = Check-LoggingStatus
Write-Host "`n PowerShell Logging Status:`n"
$logStatus.GetEnumerator() | ForEach-Object {
    Write-Host ("- {0}: {1}" -f $_.Key, $_.Value)
}

# Prompt to enable
$response = Read-Host "`nWould you like to enable all three logging features? (Y/N)"
if ($response -match "^[Yy]") {
    Enable-AllLogging
    Write-Host "[!] Re-checking status..."
    $updatedStatus = Check-LoggingStatus
    $updatedStatus.GetEnumerator() | ForEach-Object {
        Write-Host ("- {0}: {1}" -f $_.Key, $_.Value)
    }
} else {
    Write-Host "[|] No changes were made."
}
