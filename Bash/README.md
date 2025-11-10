# Bash Scripts - DFIR Tools Collection

This directory contains production-ready shell scripts for digital forensics and incident response operations. All scripts are designed for defensive security purposes and legitimate forensic analysis.

## 📂 Directory Structure

```
Bash/
├── Core Scripts (root level) - Production forensic tools
├── lab_ctf_generators/ - Educational and CTF lab preparation scripts
└── rootkits/ - Educational kernel modules for security training
    ├── sample_LKM.c - Basic example
    └── lkm_example_2/ - Advanced example with detection
```

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

- **`example_proc_check.sh`** - Example process checking and analysis script
  - Template for process monitoring and suspicious activity detection

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

- **`check_lvm2.sh`** - LVM2 logical volume analysis
  - Linux Volume Manager forensic analysis

- **`LVM_ImageMounter.sh`** - LVM volume image mounting utility
  - Automated mounting of LVM volumes from forensic images
  - Handles complex volume group configurations

- **`apfs_setup.sh`** - APFS filesystem preparation and analysis
  - Apple File System forensic preparation tools

#### File Operations and Analysis

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

- **`systemdJournalConverter.sh`** - Convert systemd journal logs for analysis
  - Systemd journal forensic extraction and conversion
  - Exports journal data to standard log formats

- **`OS_Journal_Triage.sh`** - Triage systemd journal entries for incidents
  - Rapid journal log analysis for incident response
  - Automated detection of suspicious system events

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

- **`sift_mac_apt.sh`** - SIFT workstation macOS APT installation
  - SANS SIFT toolkit installation for macOS

#### lab_ctf_generators/ Directory

Educational and CTF lab preparation scripts:

- **`GenELF_file.sh`** - Generate sample ELF files for testing
  - ELF file generation for forensic tool testing
  - Creates controlled malformed binaries for analysis practice

- **`GenELF_file_better.sh`** - Enhanced ELF file generation utility
  - Improved version with more configuration options
  - Better control over generated binary characteristics

- **`class_prep.sh`** - Classroom/lab environment preparation
  - Educational environment setup for DFIR training
  - Automated student environment configuration

- **`multi_Files.sh`** - Batch file processing utility
  - Mass file operation and analysis tool
  - Useful for creating test datasets

### 🔐 Educational Security Tools

#### rootkits/ Directory

Educational kernel module examples for learning defensive security and rootkit detection:

- **`Makefile`** - Build configuration for kernel module compilation
  - Educational kernel module development
  - Usage: `make all` to build, `make clean` to clean

- **`sample_LKM.c`** - Sample Linux Kernel Module for educational purposes
  - Basic educational rootkit development example
  - Requires kernel headers for compilation

##### lkm_example_2/ Subdirectory

Advanced educational rootkit with detection examples:

- **`educational_rootkit.c`** - Advanced educational kernel module
  - Demonstrates common rootkit techniques for defensive training
  - Includes syscall hooking, process hiding, and file hiding examples

- **`demo.sh`** - Demonstration script
  - Shows rootkit functionality in action
  - Educational walkthrough of rootkit capabilities

- **`detect.sh`** - Detection script
  - Demonstrates various rootkit detection techniques
  - Shows how to identify hidden processes and files

- **`INSTRUCTOR_GUIDE.md`** - Teaching guide
  - Instructions for using in educational settings
  - Lesson plans and learning objectives

- **`README.md`** - Detailed documentation
  - Technical explanation of rootkit components
  - Compilation and usage instructions

- **`Makefile`** - Build configuration for the educational rootkit

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

#### Log Analysis

```bash
# Convert systemd journal to standard format
./systemdJournalConverter.sh

# Triage journal entries for incidents
./OS_Journal_Triage.sh
```

#### LVM and Advanced Filesystem Analysis

```bash
# Mount LVM volumes from forensic images
sudo ./LVM_ImageMounter.sh /path/to/image

# Analyze LVM2 logical volumes
./check_lvm2.sh
```

#### Educational Tools

```bash
# Generate test ELF files
cd lab_ctf_generators/
./GenELF_file_better.sh

# Prepare classroom environment
./class_prep.sh

# Educational rootkit demonstration (requires kernel headers)
cd rootkits/lkm_example_2/
make
sudo ./demo.sh
./detect.sh
```

## ⚠️ Important Notes

### Security Context

- All tools are designed for **defensive security and legitimate forensic analysis**
- Educational components (rootkits/) are for learning purposes only
  - Use only in isolated lab environments (VMs or containers)
  - Designed to teach defensive security professionals how to detect and analyze rootkits
  - Never deploy on production systems
  - Includes detection scripts to demonstrate identification techniques
- Many scripts require root/sudo privileges for system access

### Prerequisites & Dependencies

- Most scripts assume standard Unix utilities (dd, find, grep, etc.)
- **Windows Users**: These scripts should be executed via WSL2 (Windows Subsystem for Linux) or in Docker containers
- Specific tools noted in individual script headers
- Python scripts may require additional packages
- Some tools require external forensic utilities (TSK, Volatility, etc.)
- Educational rootkit modules require Linux kernel headers package (`linux-headers-$(uname -r)`)

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
