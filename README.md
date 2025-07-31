# DFIR Tools Repository

A comprehensive collection of Digital Forensics and Incident Response (DFIR) tools, scripts, and containerized environments for cybersecurity professionals and researchers.

## 📁 Repository Structure

### 🔧 Applications/
**C and Go implementations of analysis tools**
- `malreview.c` - C implementation of malware analysis utility for file examination
- `malreview.go` - Go implementation of malware analysis utility for file examination

### 🐚 Bash/
**Production-ready shell scripts for Linux/macOS forensic operations**

#### Evidence Collection & System Analysis
- `evidence_collector.sh` - Comprehensive Linux evidence collection following RFC3227 guidelines
- `triageScan.sh` - Quick system triage and suspicious activity detection
- `triage_template.sh` - Template for standardized triage procedures
- `docker_triage.sh` - Container-specific forensic data collection
- `cron_collector.sh` - Automated collection of scheduled task artifacts

#### Memory Analysis
- `memory_precook.sh` - Automated Volatility analysis battery for memory images
- `proc_dumper.sh` - Process memory dumping utility
- `install_vol.sh` - Volatility framework installation script

#### File System & Disk Analysis
- `VMDK_Carver.sh` - NTFS data carving from VMDK images using TSK
- `ext4_inode_extractor.sh` - Extract inode information from ext4 filesystems
- `xfs_inode_converter.sh` - XFS filesystem inode analysis tool
- `check_lvm2.sh` - LVM2 logical volume analysis
- `apfs_setup.sh` - APFS filesystem preparation and analysis

#### Malware Analysis
- `malanalyze.sh` - Basic malware analysis with output formatted for LLM analysis
- `malanlyze_chatgpt.sh` - Malware analysis specifically formatted for ChatGPT input
- `mkbomb.sh` - Test file generation for analysis validation

#### Network & Security
- `iplookups.sh` - Bulk IP address WHOIS analysis for threat intelligence
- `authCheck.sh` - Authentication and authorization audit script
- `setAuditD.sh` - Configure auditd for comprehensive system monitoring
- `setAuditD_RHEL.sh` - RHEL-specific auditd configuration

#### Log Analysis
- `journalConverter.sh` - Convert systemd journal logs for analysis
- `journalTriage.sh` - Triage systemd journal entries for incidents
- `timestampCheck.sh` - Timestamp analysis and validation

#### Specialized Tools
- `GenELF_file_better.sh` - Generate sample ELF files for testing
- `multi_Files.sh` - Batch file processing utility
- `fileshred.sh` - Secure file deletion utility
- `exifevidence.sh` - EXIF metadata extraction from images
- `class_prep.sh` - Classroom/lab environment preparation
- `sift_mac_apt.sh` - SIFT workstation macOS APT installation
- `macos_evidence.sh` - macOS-specific evidence collection
- `dockAnalyse.sh` - Docker container analysis
- `install_container_diff.sh` - Container diff tool installation

#### Rootkits/ (Educational)
- `Makefile` - Build configuration for kernel module compilation
- `sample_LKM.c` - Sample Linux Kernel Module for educational purposes

### 🐍 Python/
**Python utilities for forensic analysis**
- `exifcheck.py` - DOCX metadata extraction utility
- `fastfluxfinder.py` - Network analysis tool for detecting fast flux DNS patterns
- `inode_reader.py` - Low-level filesystem inode analysis tool

### 💻 Powershell/
**Windows-specific forensic and security scripts**
- `collectEvidence.ps1` - Comprehensive Windows evidence collection with KAPE and MRC
- `Enable_PowerShellDetailedAuditing.ps1` - Enable detailed PowerShell execution logging
- `set_logging.ps1` - Configure Windows security logging
- `setAuditing.ps1` - Windows audit policy configuration
- `setContextMenu.ps1` - Custom context menu entries for forensic tools
- `FolderCheck.ps1` - Directory integrity and analysis script
- `botnetcheck.ps1` - Botnet infection detection script
- `collect_timestamps.ps1` - Windows timestamp collection and analysis

### 🧠 Vol2.6/ (Deprecated)
**Volatility 2.6 memory analysis plugins**
- `ramscan.py` - Process listing with VAD analysis for suspicious RWX memory regions
- `triagecheck.py` - Quick memory triage for obvious malicious activity indicators
- `cmdcheck.py` - Analyzes cmd.exe handles for backdoor detection
- `Fastvadscan.py` - Fast VAD scanning without file extraction
- `pathcheck.py` - Identifies executables loaded from suspicious locations

### 🧠 Vol3/
**Volatility 3 memory analysis plugins**
- `fasttriage.py` - Modernized triage plugin for Volatility 3 framework

### 🐳 docker/
**Containerized analysis and testing environments**

#### Analysis_ELK/
- Complete ELK stack (Elasticsearch, Kibana, Filebeat) for log analysis
- Pre-configured for Apache, auditd, syslog, messages, auth.log, and secure logs
- Access Kibana at http://localhost:8889

#### Analysis_OpenSearch/
- OpenSearch alternative to ELK stack
- Access dashboards at http://localhost:8899

#### testingweb/
- Vulnerable PHP/MySQL web application for security testing
- Includes phpMyAdmin interface
- MySQL credentials: root/NINJAROOTPASSWORD

#### Additional Containers
- `maldoc/` - Malicious document analysis environment
- `nmaper/` - Containerized nmap scanning environment

### 🎯 Range/
**Multi-container network testing environment**
- Kali Linux container (10.10.10.10) - Attack platform
- Nmap scanner container (10.10.10.11) - Network reconnaissance
- Ubuntu target container (10.10.10.12) - Victim system
- Isolated 10.10.10.0/24 network for safe testing

### 📊 EvidenceGenerator/
**Synthetic evidence generation for training and testing**
- `generate_data.py` - Generate realistic forensic artifacts
- `webgen.py` - Web log generation utility

### 📚 Examples/
**Sample data and documentation**
- `GenericPotato.md` - Privilege escalation technique documentation
- `GenericPotato.zip` - Sample files for potato attack vectors

### 📋 Configuration Files
- `dfir_collection.md` - DFIR collection methodology documentation
- `Test2.ipynb` - Jupyter notebook for data analysis examples

### 🔍 plaso/
**Log2timeline/plaso configuration files**
- `filter_linux.txt` - Linux-specific timeline filtering rules
- `filter_linux.yaml` - YAML format Linux timeline filters

## 🚀 Quick Start

### Docker Environments
```bash
# Start ELK stack for log analysis
cd docker/Analysis_ELK && docker-compose up -d

# Start testing range
cd Range && docker-compose up -d

# Start vulnerable web app
cd docker/testingweb && docker-compose up -d
```

### Memory Analysis
```bash
# Automated Volatility analysis
./Bash/memory_precook.sh memory.img Win7SP1x64

# Quick triage with Vol3
python vol.py -p Vol3 -f memory.img windows.fasttriage
```

### Evidence Collection
```bash
# Linux evidence collection
sudo ./Bash/evidence_collector.sh /mnt/evidence

# Windows evidence collection
.\Powershell\collectEvidence.ps1
```

## ⚠️ Important Notes

- **Defensive Use Only**: All tools are designed for defensive security and legitimate forensic analysis
- **Educational Purpose**: Sample exploits and vulnerabilities are for educational use only
- **Root/Admin Required**: Many scripts require elevated privileges for system access
- **Evidence Integrity**: All collection scripts include hash verification and logging
- **RFC3227 Compliance**: Evidence collection follows established forensic guidelines

## 📖 Documentation

- See `CLAUDE.md` for detailed development and usage guidance
- Individual scripts contain usage instructions in their headers
- Docker environments include README files with setup instructions

## 🔒 Security Context

This repository contains legitimate cybersecurity tools for:
- Digital forensic investigations
- Incident response procedures
- Security research and education
- Vulnerability assessment (defensive)

All tools should be used responsibly and only on systems where you have proper authorization.