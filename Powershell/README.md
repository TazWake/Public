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

#### `Get-PptxHeaders.ps1`
PowerPoint slide header extraction tool with multiple output formats.

**Purpose**: Extracts slide titles/headers from PPTX files for forensic analysis, documentation, or content review. Identifies hidden slides and provides summary statistics. Useful for quickly cataloging presentation content without opening PowerPoint.

**Requirements**:
- PowerShell 5.0 or higher
- Microsoft PowerPoint installed (uses COM automation)

**Usage**:
```powershell
# Display help
.\Get-PptxHeaders.ps1 -Help
.\Get-PptxHeaders.ps1 -H

# Basic analysis with color-coded console output
.\Get-PptxHeaders.ps1 -PptxPath .\presentation.pptx

# Exclude hidden slides from output
.\Get-PptxHeaders.ps1 -PptxPath .\presentation.pptx -HideHidden

# Save text output to file
.\Get-PptxHeaders.ps1 -PptxPath .\presentation.pptx -OutputFile headers.txt

# Export to CSV format
.\Get-PptxHeaders.ps1 -PptxPath .\presentation.pptx -OutputFormat CSV

# Export to JSON format
.\Get-PptxHeaders.ps1 -PptxPath .\presentation.pptx -OutputFormat JSON
```

**Output Formats**:
- **Text** (default): Color-coded console output or plain text file
  - Slide numbers in green
  - Hidden slide indicator in orange
  - Professional header with file path and timestamp
  - Summary statistics (total, visible, hidden counts)
- **CSV**: Exports to `slide_headers.csv` with columns: SlideNumber, Header, Hidden
- **JSON**: Structured JSON output for programmatic processing

**Features**:
- Uses PowerPoint COM object for reliable content extraction
- Attempts title placeholder first, falls back to first text shape
- Preserves original slide numbering even when filtering hidden slides
- Summary always shows actual file statistics regardless of `-HideHidden` flag
- Optional file output for text format (plain text, no ANSI codes)

**Technical Details**: Opens PPTX via PowerPoint COM automation, iterates through slides extracting title text from shape objects, and identifies hidden slides via `SlideShowTransition.Hidden` property.

---

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

#### `Reset-NotesPages.ps1`
**⚠️ EXPERIMENTAL - NOT FULLY FUNCTIONAL ⚠️**

PowerPoint notes page layout analysis and reset tool.

**Current Status**: This script correctly **identifies and reports** which slides have notes pages that don't match the Notes Master layout, but the reset functionality is **broken**. When attempting to apply changes, it corrupts the notes pages (shrinks speaker notes to a few pixels wide without fixing the slide image box).

**Purpose**: Intended to standardize notes page layouts across all slides by reapplying Notes Master settings. Currently useful only for **auditing/reporting** which slides have non-standard layouts.

**Requirements**:
- PowerShell 5.0 or higher
- Microsoft PowerPoint installed (uses COM automation)

**Safe Usage** (Reporting Only):
```powershell
# Identify slides with non-standard notes pages (SAFE - no changes made)
.\Reset-NotesPages.ps1 -PptxPath .\presentation.pptx -DryRun

# Generate report file of layout discrepancies
.\Reset-NotesPages.ps1 -PptxPath .\presentation.pptx -DryRun -ReportPath .\notes_audit.txt
```

**Unsafe Usage** (Do Not Use):
```powershell
# WARNING: These commands will corrupt your notes pages
# .\Reset-NotesPages.ps1 -PptxPath .\presentation.pptx              # BROKEN
# .\Reset-NotesPages.ps1 -PptxPath .\presentation.pptx -Overwrite   # BROKEN
```

**What Works**:
- Reads Notes Master layout settings (positions and sizes)
- Iterates through all slides and their notes pages
- Compares each notes page layout to the master
- Generates color-coded console reports:
  - Green: Slides matching master layout
  - Yellow: Slides that differ from master
  - Red: Errors accessing notes pages
- Summary statistics (total, reset needed, OK, errors)
- Dry-run mode for safe analysis
- Report file generation

**What's Broken**:
- Applying layout changes corrupts notes pages
- Shrinks speaker notes text box to unusable size
- Does not properly reset slide image box
- Results in broken presentations if changes are saved

**Use Case**: Use this script in `-DryRun` mode to audit presentation files and identify which slides have manually-adjusted notes page layouts that deviate from the standard Notes Master. This can help identify presentations that may have formatting inconsistencies or have been manually edited.

**Technical Details**: Uses PowerPoint COM automation to access `NotesMaster` and `NotesPage` objects. Compares shape positions and dimensions (Left, Top, Width, Height) between master and individual notes pages. The reporting logic is sound, but the shape property assignment causes layout corruption.

**Development Status**: Requires further investigation into PowerPoint COM object model for proper notes page layout reset methodology. Consider alternative approaches such as XML manipulation or different COM properties.

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
