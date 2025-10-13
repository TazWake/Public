# Bash Scripts - DFIR Tools Collection

This directory contains production-ready shell scripts for digital forensics and incident response operations. All scripts are designed for defensive security purposes and legitimate forensic analysis.

## 📋 Script Categories

### 🔍 Evidence Collection & System Triage

#### Core Evidence Collection

- **`evidence_collector.sh`** - Comprehensive Linux evidence collection following RFC3227 guidelines
  - Requires: LiME, dwarfdump, ewfacquire (or dd as fallback)
  - Usage: `sudo ./evidence_collector.sh /path/to/storage/device`
  - Collects memory dumps, disk images, system artifacts with integrity verification

- **`triageScan.sh`** - Scaled triage collection tool for subnet-wide analysis
  - Example script for running CyLR across multiple systems via SSH
  - Requires modification for specific environments
  - Status: Template/Example - needs customization

- **`triage_template.sh`** - Standardized triage procedure template
  - Framework for consistent incident response procedures

#### Specialized Evidence Collection

- **`docker_triage.sh`** - Container-specific forensic data collection
  - Docker environment analysis and artifact extraction

- **`cron_collector.sh`** - Automated collection of scheduled task artifacts
  - Cron job analysis and persistence mechanism detection

- **`macos_evidence.sh`** - macOS-specific evidence collection
  - Apple filesystem and artifact collection tools

- **`mk_collector.sh`** - Custom evidence collector utility

### 🧠 Memory Analysis

- **`memory_precook.sh`** - Automated Volatility analysis battery
  - Usage: `./memory_precook.sh memory.img VOLATILITY_PROFILE`
  - Runs standardized memory analysis tools against memory images
  - Requires: vol.py in PATH, established Volatility profile
  - Generates checksums and logs for all output files

- **`proc_dumper.sh`** - Process memory dumping utility
  - Live process memory extraction tools

- **`install_vol.sh`** - Volatility framework installation script
  - Automated setup for memory analysis environment

### 💾 File System & Disk Analysis

#### Disk and Image Analysis

- **`VMDK_Carver.sh`** - NTFS data carving from VMDK images using The Sleuth Kit
  - Forensic analysis of virtual machine disk images

- **`ext4_inode_extractor.sh`** - Extract inode information from ext4 filesystems
  - Low-level filesystem analysis for Linux systems

- **`xfs_inode_converter.sh`** - XFS filesystem inode analysis tool
  - XFS-specific forensic analysis utilities

- **`XFS_Extent_Address_Parser.py`** - XFS extent address parsing utility
  - Python tool for XFS filesystem forensics

- **`check_lvm2.sh`** - LVM2 logical volume analysis
  - Linux Volume Manager forensic analysis

- **`apfs_setup.sh`** - APFS filesystem preparation and analysis
  - Apple File System forensic preparation tools

#### File Operations and Analysis

- **`multi_Files.sh`** - Batch file processing utility
  - Mass file operation and analysis tool

- **`fileshred.sh`** - Secure file deletion utility
  - Forensically secure file destruction

- **`exifevidence.sh`** - EXIF metadata extraction from images
  - Image metadata forensic analysis

- **`timestampCheck.sh`** - Timestamp analysis and validation
  - Temporal analysis for forensic timelines

### 🦠 Malware Analysis

- **`malanalyze.sh`** - Basic malware analysis with LLM-formatted output
  - Usage: `./malanalyze.sh -f filename`
  - Automated suspicious file analysis for AI/LLM consumption
  - Status: DRAFT v0.0.1

- **`malanlyze_chatgpt.sh`** - Malware analysis specifically formatted for ChatGPT
  - ChatGPT-optimized malware analysis output

- **`mkbomb.sh`** - Test file generation for analysis validation
  - Creates test files for malware analysis tool validation

### 🌐 Network & Security Analysis

- **`iplookups.sh`** - Bulk IP address WHOIS analysis for threat intelligence
  - Mass IP reputation and geolocation analysis

- **`authCheck.sh`** - Authentication and authorization audit script
  - System authentication mechanism analysis

### 📊 Log Analysis & System Monitoring

#### Log Processing

- **`journalConverter.sh`** - Convert systemd journal logs for analysis
  - Systemd journal forensic extraction and conversion

- **`journalTriage.sh`** - Triage systemd journal entries for incidents
  - Rapid journal log analysis for incident response

#### System Auditing

- **`setAuditD.sh`** - Configure auditd for comprehensive system monitoring
  - Linux audit daemon configuration for forensic logging

- **`setAuditD_RHEL.sh`** - RHEL-specific auditd configuration
  - Red Hat Enterprise Linux audit configuration

### 🐳 Container & Virtualization

- **`dockAnalyse.sh`** - Docker container analysis
  - Container forensic analysis and artifact extraction

- **`install_container_diff.sh`** - Container diff tool installation
  - Automated installation of container comparison utilities

### 🔧 Development & Testing Tools

- **`GenELF_file.sh`** - Generate sample ELF files for testing
  - ELF file generation for forensic tool testing

- **`GenELF_file_better.sh`** - Enhanced ELF file generation utility
  - Improved version of ELF file generator

- **`class_prep.sh`** - Classroom/lab environment preparation
  - Educational environment setup for DFIR training

- **`sift_mac_apt.sh`** - SIFT workstation macOS APT installation
  - SANS SIFT toolkit installation for macOS

### 🔐 Educational Security Tools

#### rootkits/ Directory

- **`Makefile`** - Build configuration for kernel module compilation
  - Educational kernel module development
  - Usage: `make all` to build, `make clean` to clean

- **`sample_LKM.c`** - Sample Linux Kernel Module for educational purposes
  - Educational rootkit development example
  - Requires kernel headers for compilation

## 🚀 Quick Start Guide

### Prerequisites

```bash
# Essential tools (install as needed)
sudo apt-get install volatility-tools sleuthkit ewf-tools
pip install volatility3

# For memory analysis
export PATH=$PATH:/path/to/volatility
```

### Common Usage Patterns

#### Evidence Collection

```bash
# Full Linux evidence collection
sudo ./evidence_collector.sh /mnt/evidence_drive

# macOS evidence collection  
sudo ./macos_evidence.sh

# Container analysis
./docker_triage.sh
```

#### Memory Analysis

```bash
# Automated memory analysis
./memory_precook.sh memory.dump Win7SP1x64

# Install Volatility framework
./install_vol.sh
```

#### Malware Analysis

```bash
# Analyze suspicious file
./malanalyze.sh -f suspicious_file.exe

# Generate test files
./mkbomb.sh
```

#### System Configuration

```bash
# Setup audit logging
sudo ./setAuditD.sh

# Authentication audit
./authCheck.sh
```

## ⚠️ Important Notes

### Security Context

- All tools are designed for **defensive security and legitimate forensic analysis**
- Educational components (rootkits/) are for learning purposes only
- Many scripts require root/sudo privileges for system access

### Prerequisites & Dependencies

- Most scripts assume standard Unix utilities (dd, find, grep, etc.)
- Specific tools noted in individual script headers
- Python scripts may require additional packages
- Some tools require external forensic utilities (TSK, Volatility, etc.)

### Evidence Handling

- Scripts follow RFC3227 guidelines for digital evidence
- Automatic integrity verification (MD5/SHA1 hashing)
- Comprehensive logging of all operations
- Chain of custody documentation included

### Script Status

- **Production**: Tested and ready for operational use
- **Template**: Examples requiring customization  
- **DRAFT**: Under development or testing

## 📖 Individual Script Documentation

Each script contains detailed usage instructions in its header comments. For specific usage:

```bash
# View script help/documentation
head -30 script_name.sh

# Most scripts support help flags
./script_name.sh -h
./script_name.sh --help
```

## 🔗 Related Directories

- **`../Vol2.6/`** - Volatility 2.6 memory analysis plugins
- **`../Vol3/`** - Volatility 3 memory analysis plugins  
- **`../Python/`** - Python forensic utilities
- **`../Powershell/`** - Windows-specific forensic scripts
- **`../docker/`** - Containerized analysis environments
