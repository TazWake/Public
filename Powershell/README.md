# PowerShell DFIR Tools

This directory contains PowerShell scripts for digital forensics, incident response, and Windows system hardening. All scripts are designed for defensive security and forensic analysis purposes.

## Overview

These scripts support evidence collection, system auditing, forensic analysis, and Windows configuration for enhanced logging and security monitoring. They are production-ready tools used in enterprise environments and educational settings.

## Scripts

### Evidence Collection & Triage

#### `collectEvidence.ps1`
Comprehensive triage data collection script for Windows systems.

**Purpose**: Captures essential triage data from a device including memory dumps and filesystem artifacts using KAPE and Magnet RAM Capture.

**Requirements**:
- Administrator privileges
- USB or storage device with sufficient space (memory capture ~5-10% larger than RAM)
- Licensed copy of KAPE in `/Kape` directory
- Magnet RAM Capture (MRC.exe) in root directory

**Usage**:
```powershell
# Run from USB root with admin privileges
.\collectEvidence.ps1
```

**Output**: Creates `/Evidence/$COMPUTERNAME/` directory containing:
- Memory capture (.raw file)
- KAPE triage VHDX
- MD5 hashes
- Collection logs

---

#### `collect_timestamps.ps1`
File timestamp collection and reporting tool.

**Purpose**: Exports creation, access, and write times for files in a specified directory to CSV format for timeline analysis.

**Usage**:
```powershell
# Collect timestamps from current directory
.\collect_timestamps.ps1

# Specify target and output paths
.\collect_timestamps.ps1 -targetPath C:\Windows\temp -outputPath D:\incidentresponse\
```

**Output**: CSV file with columns:
- Name
- Size (bytes)
- Creation Time (UTC)
- Last Access Time (UTC)
- Last Write Time (UTC)

---

### Forensic Analysis Tools

#### `Get-PPTXSlideInfo.ps1`
PowerPoint presentation analysis tool for detecting hidden slides.

**Purpose**: Analyzes PPTX files to identify total slides, visible slides, and hidden slides. Useful for forensic examination of presentations that may contain concealed content.

**Requirements**: PowerShell 5.0 or higher

**Usage**:
```powershell
# Basic analysis (non-verbose)
.\Get-PPTXSlideInfo.ps1 "C:\Path\To\Presentation.pptx"

# Detailed analysis with per-slide information
.\Get-PPTXSlideInfo.ps1 "C:\Path\To\Presentation.pptx" -Detail

# Display help
.\Get-PPTXSlideInfo.ps1 -h
```

**Technical Details**: Extracts PPTX as ZIP archive, parses slide XML files, and checks for `show="0"` attribute indicating hidden slides.

---

#### `FolderCheck.ps1`
Folder metadata extraction utility.

**Purpose**: Extracts folder names, modification timestamps, and creation timestamps for subfolders in a specified directory.

**Configuration Required**:
- Edit `$directoryPath` variable to set target directory
- Edit output CSV filename path

**Usage**:
```powershell
# After editing configuration variables
.\FolderCheck.ps1
```

**Output**: CSV file with folder names and timestamp data.

---

### Network Analysis & Threat Hunting

#### `botnetcheck.ps1`
Network connection analyzer for botnet C2 detection.

**Purpose**: Hunts for suspicious network connections to known malicious IP addresses. Assists incident responders in identifying compromised systems communicating with botnet command and control infrastructure.

**Usage**:
```powershell
# Search for connections to specific IP
.\botnetcheck.ps1 -BotNetIP 192.168.2.1

# Specify custom output path
.\botnetcheck.ps1 -BotNetIP 192.168.2.1 -OutPath C:\DFIRLOGS\
```

**Output**: `conncheck.txt` file containing:
- Hostname
- User information
- Network connection status
- Detection timestamp

---

### System Hardening & Auditing

#### `Enable_PowerShellDetailedAuditing.ps1`
PowerShell comprehensive auditing configuration tool.

**Purpose**: Enables and configures PowerShell Script Block Logging, Module Logging, and Transcription Logging for enhanced security monitoring and incident detection.

**Requirements**: Administrator privileges

**Features**:
- Checks current logging status
- Enables all PowerShell auditing mechanisms
- Creates transcript directory
- Provides status reporting

**Usage**:
```powershell
# Run with admin privileges
.\Enable_PowerShellDetailedAuditing.ps1
```

**Logging Configured**:
- Script Block Logging (HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging)
- Module Logging for all modules (*)
- Transcription Logging with invocation headers
- Transcript directory: `C:\Transcripts`

---

#### `setAuditing.ps1`
Windows baseline auditing configuration script.

**Purpose**: Establishes comprehensive baseline audit settings for Windows 10, Server 2016, or newer systems based on Malware Archaeology cheat sheets.

**Requirements**:
- Administrator privileges
- Windows 10 / Server 2016 or newer

**Note**: Retrospective auditing is not possible. This configures logging going forward only.

**Usage**:
```powershell
# Run with admin privileges
.\setAuditing.ps1
```

**Configurations Applied**:
- **Event Log Sizes**:
  - Security: 1048576000 bytes (~7 days minimum)
  - System/Application: 262144000 bytes
  - PowerShell logs: 524288000 bytes
- **PowerShell Logging**: Module and ScriptBlock logging
- **Command Line Auditing**: Enables process creation command line recording (Event ID 4688)
- **DNS Client Logging**: Operational log enabled
- **USB/Removable Storage**: Audit logging enabled
- **Comprehensive Audit Policies**:
  - Account Management
  - Logon/Logoff events
  - Process Creation/Termination
  - File Share access
  - Registry access
  - Authentication changes
  - Privilege use
  - And many more (50+ audit categories)

**Based On**: [Malware Archaeology Cheat Sheets](https://www.malwarearchaeology.com/cheat-sheets/)

---

#### `set_logging.ps1`
**DEPRECATED** - Use `setAuditing.ps1` instead.

Legacy script for configuring Windows logging. Replaced by more comprehensive `setAuditing.ps1`.

---

### Windows Customization

#### `setContextMenu.ps1`
DFIR tools context menu creator for Windows Explorer.

**Purpose**: Creates a right-click context menu in Windows Explorer providing quick access to commonly-used DFIR tools.

**Requirements**:
- Administrator privileges
- DFIR tools installed at specified paths

**Configuration Required**:
Edit the `$apps` hashtable to specify your tool names and paths:
```powershell
$apps = @{
    "Timeline Explorer"   = "D:\DFIR\TimelineExplorer\TimelineExplorer.exe"
    "PEStudio"  = "D:\DFIR\pestudio\pestudio.exe"
    "Registry Explorer" = "D:\DFIR\RegistryExplorer\RegistryExplorer.exe"
    "ShellBags Explorer" = "D:\DFIR\ShellBagsExplorer\ShellBagsExplorer.exe"
    "OllyDBG" = "D:\DFIR\OllyDBG\OLLYDBG.exe"
}
```

**Usage**:
```powershell
# After editing tool paths, run with admin privileges
.\setContextMenu.ps1
```

**Result**: Right-click on Windows Desktop or Explorer background to access "DFIR Tools" submenu with quick-launch shortcuts.

**Credit**: Based on concept by Mohamed Talaat ([LinkedIn Post](https://www.linkedin.com/posts/muhammadtalaat_dfir-forensics-windows-activity-7300469718484750337-Vk_J))

---

## Common Use Cases

### Incident Response Triage
```powershell
# 1. Collect evidence from compromised system
.\collectEvidence.ps1

# 2. Hunt for botnet connections
.\botnetcheck.ps1 -BotNetIP [MALICIOUS_IP] -OutPath .\Evidence\$env:COMPUTERNAME\

# 3. Collect file timestamps from suspicious directories
.\collect_timestamps.ps1 -targetPath C:\Users\[USERNAME]\AppData\ -outputPath .\Evidence\$env:COMPUTERNAME\
```

### System Hardening
```powershell
# Enable comprehensive auditing and logging
.\setAuditing.ps1
.\Enable_PowerShellDetailedAuditing.ps1
```

### Forensic Analysis
```powershell
# Analyze presentation files for hidden content
.\Get-PPTXSlideInfo.ps1 "C:\Evidence\suspicious.pptx" -Detail

# Extract folder metadata for timeline analysis
# (After editing FolderCheck.ps1 configuration)
.\FolderCheck.ps1
```

## Best Practices

1. **Always run with appropriate privileges**: Most scripts require Administrator rights
2. **Validate output paths**: Ensure sufficient disk space before evidence collection
3. **Maintain chain of custody**: Use logging features and hash verification
4. **Test in lab environment first**: Validate scripts before production deployment
5. **Review audit settings regularly**: Ensure log sizes accommodate retention requirements
6. **Use signed commits**: All git commits should be GPG-signed per repository policy

## Security Considerations

- All scripts are designed for **defensive security and forensic analysis only**
- Evidence collection follows RFC3227 guidelines
- Scripts include integrity verification (MD5/SHA1 hashing where applicable)
- Audit logging configurations based on industry best practices (Malware Archaeology)
- PowerShell execution policies should be configured appropriately for your environment

## Requirements Summary

### General Requirements
- Windows 10 / Server 2016 or newer (for most scripts)
- PowerShell 5.0 or higher
- Administrator privileges (for system configuration scripts)

### External Tools Required
- **collectEvidence.ps1**: KAPE (licensed), Magnet RAM Capture (MRC.exe)
- **setContextMenu.ps1**: DFIR tools installed at configured paths

### No External Dependencies
- collect_timestamps.ps1
- Get-PPTXSlideInfo.ps1
- FolderCheck.ps1
- botnetcheck.ps1
- Enable_PowerShellDetailedAuditing.ps1
- setAuditing.ps1

## Author

**@tazwake**

## Additional Resources

- [Malware Archaeology Cheat Sheets](https://www.malwarearchaeology.com/cheat-sheets/)
- [GitHub Repository](https://github.com/TazWake/Public)
- Project Documentation: See `/CLAUDE.md` files in repository

## License

These scripts are provided for educational and defensive security purposes. Use in accordance with applicable laws and organizational policies.
