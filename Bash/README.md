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

- **`triageScan.sh`** - Scaled triage collection tool for subnet-wide analysis (TEMPLATE)
  - Example script for running CyLR across multiple systems via SSH
  - Requires modification for specific environments
  - Not intended for direct "as-is" usage - customize for your network
  - Shows pattern for automated multi-host evidence collection

- **`triage_template.sh`** - Standardized triage procedure template (TEMPLATE)
  - Framework for consistent incident response procedures
  - Requires customization for specific organizational needs
  - Provides structure for systematic evidence collection

#### Specialized Evidence Collection

- **`docker_triage.sh`** - Container-specific forensic data collection
  - Docker environment analysis and artifact extraction

- **`cron_collector.sh`** - Automated collection of scheduled task artifacts
  - Cron job analysis and persistence mechanism detection

- **`macos_evidence.sh`** - macOS-specific evidence collection
  - Apple filesystem and artifact collection tools

- **`mk_collector.sh`** - Evidence collection device preparation utility
  - Prepares USB devices or storage media as evidence collection kits
  - Installs required forensic tools and scripts
  - Creates standardized directory structure for evidence storage

- **`example_proc_check.sh`** - Example process validation and checking script
  - Demonstrates usage of proc_check.py for process analysis
  - Template for process monitoring and suspicious activity detection
  - Shows how to validate process attributes and detect anomalies

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

#### Process Artifact Recovery

- **`proc_recovery.sh`** - Forensic process artifact recovery tool (current/preferred)
  - Usage: `sudo ./proc_recovery.sh -p <pid> -d <dest> [-j] [-J]` or `-n <name>` to match by process name
  - Recovers the executable via `/proc/<pid>/exe`, detects memfd-backed (fileless) and deleted-on-disk binaries
  - Falls back to `/proc/<pid>/maps` + `/proc/<pid>/mem` segment extraction for executable memory regions
  - SHA-256 hashes every recovered artifact and always writes a `<prefix>_report.csv` manifest (process metadata,
    source path, output file, size, hash, permissions, address range, status/notes) for investigator review
  - Optional `-j`/`-J` flags add a JSON summary and/or JSONL event log alongside the CSV
  - Requires root privileges

- **`recover_exe_deleted_process.sh`** - Simpler exe-only recovery script
  - Usage: `sudo ./recover_exe_deleted_process.sh <PID> <destination_directory>`
  - Recovers just the `/proc/<pid>/exe` binary (metadata, hashes, filetype) for a single process
  - Predecessor to `proc_recovery.sh`; kept for lightweight/quick recovery when memory-segment extraction
    and CSV/JSON reporting aren't needed

### 💾 File System & Disk Analysis

#### Disk and Image Analysis

- **`VMDK_Carver.sh`** - NTFS data carving from VMDK images using The Sleuth Kit
  - Forensic analysis of virtual machine disk images

- **`ext4_inode_extractor.sh`** - Extract inode information from ext4 filesystems
  - Low-level filesystem analysis for Linux systems

- **`xfs_inode_converter.sh`** - XFS filesystem inode analysis tool
  - XFS-specific forensic analysis utilities

- **`btrfs_extract.sh`** / **`btrfs_extract.py`** - Extract a file's inode, timestamps, and content from a btrfs
  image without mounting it
  - Usage: `./btrfs_extract.sh <filename> <btrfs_image>` (root directory files only)
  - Bash and Python implementations provided; functionally equivalent

- **`btrfs_extract_copilot.sh`** / **`btrfs_extract_copilot.py`** - Alternate btrfs single-file extraction utility
  - Usage: `./btrfs_extract_copilot.sh <btrfs_image> <path_in_fs>`
  - Copilot-generated example variant, kept alongside `btrfs_extract.sh` for comparison

- **`bulk_E01_check.sh`** - Batch-scan a directory tree for `.E01` images and run `mmls` against each
  - Usage: `./bulk_E01_check.sh /path/to/search`
  - Quick partition-layout triage across a large evidence collection

- **`check_lvm2.sh`** - LVM2 detection and validation utility
  - Quick check if LVM2 is in use on live filesystem
  - Linux Volume Manager preliminary analysis

- **`LVM_automount_update.sh`** - Unified LVM forensic image mounting tool
  - Automated mounting of LVM volumes from forensic images
  - E01/EWF image support via ewfmount
  - Mount single LV or all LVs in volume group
  - Comprehensive filesystem support (ext*, XFS, btrfs, NTFS, FAT, etc.)
  - Forensically sound: read-only mounts with noexec,nodev,nosuid
  - Automatic cleanup with trap mechanism (optional keep-mounted)
  - Gracefully handles logical images without partition tables
  - Usage: Single LV: `sudo ./LVM_automount_update.sh [OPTIONS] IMAGE MOUNTPOINT`
  - Usage: All LVs: `sudo ./LVM_automount_update.sh --all IMAGE`

- **`apfs_setup.sh`** - APFS filesystem preparation and analysis
  - Apple File System forensic preparation tools

#### File Operations and Analysis

- **`fileshred.sh`** - Secure file deletion utility
  - Forensically secure file destruction

- **`exifevidence.sh`** - EXIF metadata extraction from images
  - Image metadata forensic analysis

- **`timestampCheck.sh`** - Timestamp analysis and validation
  - Temporal analysis for forensic timelines

#### Timeline & Bulk Processing

- **`bulk_plaso_run.sh`** - Batch log2timeline/plaso processing across multiple evidence images
  - Usage: `./bulk_plaso_run.sh /path/to/input/folder` (supports `OUT_DIR`/`WORK_DIR`/`SCRATCH_DIR` env overrides)
  - Runs plaso against a whole folder of images and writes a CSV run manifest

- **`bodyfile_extract.sh`** - Bulk-extract bodyfile entries from a large number of UAC collection archives
  - Usage: `./bodyfile_extract.sh [source_dir] [dest_dir]`
  - Prepares bodyfiles for `mactime`-based timeline generation

- **`converBodyFiles.sh`** - Bulk-convert bodyfiles into human-readable timelines via `mactime.pl`
  - Usage: `./converBodyFiles.sh [input_dir] [output_dir]`

- **`historyStack.sh`** - Stack-rank bash history command usage across multiple disk images
  - Usage: `./historyStack.sh [--clean] [--strict] IMAGE_DIR`
  - Runs `target-query` (Dissect) bashhistory plugin across `.E01`/`.Ex01`/`.raw`/`.dd`/`.img` images and
    produces a frequency-ranked command list
  - Requires: `target-query`, `jq`

### 🦠 Malware Analysis

- **`WebShellHuntr.sh`** - Read-only, multi-language web-shell hunter for live Linux hosts and mounted/captured evidence
  - Discovers Apache/httpd, nginx/OpenResty, Lighttpd, Caddy, OpenLiteSpeed, Java application servers and common hosting-panel web roots
  - Combines filename, source, obfuscation, masquerading, permissions, known-good, local hash IOC, cron, access-log and live process-ancestry checks
  - Records candidate SHA-256 hashes, pre-read metadata, normalised TSV findings, an action log and a final report manifest
  - Optional local YARA and ClamAV integration; never uploads evidence to an external service
  - Usage: `sudo ./WebShellHuntr.sh --help`

- **`malanalyze.sh`** - Basic malware analysis with LLM-formatted output (DRAFT v0.0.1)
  - Usage: `./malanalyze.sh -f filename`
  - Automated suspicious file analysis for AI/LLM consumption
  - Offline version without API requirements
  - Extracts strings, metadata, and file characteristics

- **`malanalyze_chatgpt.sh`** - Advanced malware analysis with ChatGPT API integration (DRAFT v0.0.3)
  - More mature version with ChatGPT API integration
  - Enhanced error checking and command validation
  - Requires `OPENAI_API_KEY` environment variable set before running
  - Direct API-based analysis and reporting

- **`mkbomb.sh`** - Zipbomb/decompression bomb generator for testing
  - Creates zipbomb test files for analysis validation
  - Tests decompression handling and resource limits
  - Useful for validating malware analysis sandboxes

- **`shadowhs_LiveHunter.sh`** - Live-system detection for the ShadowHS fileless Linux post-exploitation
  framework
  - Usage: `sudo ./shadowhs_LiveHunter.sh [output_directory]`
  - Checks for memfd_create()-based memory-only execution, argv spoofing, GSocket C2 tunneling, cryptomining
    payloads, and LKM persistence
  - Exit codes: `0` clean, `1` findings detected, `2` execution error
  - Findings are leads for further investigation, not definitive proof of compromise (false positives possible)

### 🌐 Network & Security Analysis

- **`iplookups.sh`** - Bulk IP address WHOIS analysis for threat intelligence
  - Mass IP reputation and geolocation analysis

- **`authCheck.sh`** - Authentication and authorization audit script
  - System authentication mechanism analysis

- **`serviceTunnel.sh`** - SSH tunnel helper for reaching SIEM (Kibana) and EDR (Velociraptor) consoles
  - Usage: `./serviceTunnel.sh --siem`, `--edr`, `--background`, `--status`, `--stop`
  - Wraps SSH local port-forwarding using `~/.ssh/config` aliases (`siem`/`edr`) so analysts don't have to
    remember tunnel syntax; supports foreground or backgrounded tunnels with PID-file tracking

### 📊 Log Analysis & System Monitoring

#### Log Processing

- **`systemdJournalConverter.sh`** - Convert systemd journal logs for analysis
  - Systemd journal forensic extraction and conversion
  - Exports journal data to standard log formats
  - Converts binary journal to text/CSV formats

- **`OS_Journal_Triage.sh`** - Triage systemd journal entries for incidents
  - Rapid journal log analysis for incident response
  - Automated detection of suspicious system events
  - Filters and highlights potential malicious activity

- **`rapid_logGrabber.sh`** - Rapid collection of key event logs from multiple Linux hosts over SSH
  - Usage: `./rapid_logGrabber.sh -H host1,host2,... | -f hostfile`
  - Pulls Debian/Ubuntu (`syslog`/`auth.log`) and RHEL/CentOS/Fedora (`messages`/`secure`) logs, only if present
  - Requires superuser SSH access to each target (root login must be permitted)
  - Example/template script - test before use in your environment

#### System Auditing

- **`setAuditD.sh`** - Configure auditd for comprehensive system monitoring (DRAFT)
  - Linux audit daemon configuration for forensic logging
  - Ubuntu/Debian-specific implementation
  - Sets up comprehensive system call auditing rules

- **`setAuditD_RHEL.sh`** - RHEL-specific auditd configuration (DRAFT)
  - Red Hat Enterprise Linux audit configuration
  - Optimized for RHEL/CentOS/Fedora/SuSE systems
  - Platform-specific audit rules and paths

### 🐳 Container & Virtualization

- **`dockAnalyse.sh`** - Docker container analysis
  - Container forensic analysis and artifact extraction

- **`install_container_diff.sh`** - Container diff tool installation
  - Automated installation of container comparison utilities

### ☁️ Cloud Evidence Upload Helpers (Python)

These are Python (not Bash) utilities kept alongside the collection scripts they support - each generates a
time-limited S3 presigned URL so a remote host can upload evidence without holding AWS credentials.

- **`AvmlPresignedUrlCreator.py`** - Presigned URL for uploading an AVML memory dump (`memory.lime`)
- **`Dwarf2jsonPresignedUrlCreator.py`** - Presigned URL for uploading Volatility symbol files (dwarf2json
  output + `System.map`, as a `.tar.gz`)
- **`UacPresignedUrlCreator.py`** - Presigned URL for uploading UAC (Unix-like Artifacts Collector) output
  (`UAC.tar.gz`)
  - All three: require `boto3`, edit `BUCKET_NAME`/`REGION` before use, object key includes hostname + timestamp
  - Usage: `./AvmlPresignedUrlCreator.py --help` (each supports `-h`/`--help` for full options)

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

- **`multi_Files.sh`** - Batch ELF file generator for CTF challenges
  - Generates multiple ELF test files with varying characteristics
  - Creates diverse forensic artifacts for lab exercises
  - Useful for creating comprehensive test datasets for students

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
  - FOR EDUCATIONAL USE ONLY - teaches defensive security

- **`demo.sh`** - Rootkit functionality demonstration script
  - Interactive demonstration showing rootkit capabilities in action
  - Shows process hiding, file hiding, and privilege escalation
  - Educational walkthrough for understanding attacker techniques
  - Usage: `sudo ./demo.sh` (after loading the kernel module)

- **`detect.sh`** - Rootkit detection techniques demonstration
  - Demonstrates various methods to detect hidden processes and files
  - Shows discrepancies between /proc and system calls
  - Teaches defensive security analysts how to identify rootkits
  - Usage: `./detect.sh` (while rootkit is loaded)

- **`INSTRUCTOR_GUIDE.md`** - Teaching guide for classroom use
  - Instructions for using in educational settings
  - Lesson plans and learning objectives
  - Safety precautions and VM requirements

- **`USAGE_GUIDE.md`** - Student/practitioner usage guide (Version 2.0)
  - Documents the current file-hiding implementation (`getdents64` hooking) and configuration options
  - Built and tested against kernel 5.15.0-124-generic and newer

- **`README.md`** - Detailed technical documentation
  - Technical explanation of rootkit components
  - Compilation and usage instructions
  - Architecture and detection methodology

- **`Makefile`** - Build configuration for the educational rootkit
  - Compiles kernel module against current kernel headers
  - Usage: `make` to build, `make clean` to remove artifacts

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

#### Process Artifact Recovery

```bash
# Full recovery (exe + memory segments) with CSV, JSON and JSONL output
sudo ./proc_recovery.sh -p 1234 -d /evidence/proc_1234 -j -J

# Same, matching by process name instead of PID
sudo ./proc_recovery.sh -n "python.*server" -d /evidence

# Quick exe-only recovery of a deleted binary
sudo ./recover_exe_deleted_process.sh 1234 /evidence
```

#### Malware Analysis

```bash
# Analyze suspicious file (offline, no API)
./malanalyze.sh -f suspicious_file.exe

# Analyze suspicious file with ChatGPT API integration
OPENAI_API_KEY=your_key_here ./malanalyze_chatgpt.sh -f suspicious_file.exe

# Generate zipbomb test file
./mkbomb.sh

# Live-hunt for ShadowHS fileless malware indicators
sudo ./shadowhs_LiveHunter.sh /evidence/shadowhs_hunt
```

#### System Configuration

```bash
# Setup audit logging
sudo ./setAuditD.sh

# Authentication audit
./authCheck.sh

# Tunnel to SIEM (Kibana) and EDR (Velociraptor) consoles over SSH
./serviceTunnel.sh --siem --background
./serviceTunnel.sh --edr --status
```

#### Log Analysis

```bash
# Convert systemd journal to standard format
./systemdJournalConverter.sh

# Triage journal entries for incidents
./OS_Journal_Triage.sh

# Rapid log collection from a fleet of hosts (requires root SSH access)
./rapid_logGrabber.sh -H host1,host2,host3
```

#### Timeline & Bulk Processing

```bash
# Batch plaso run against a folder of evidence images
./bulk_plaso_run.sh /cases/images

# Scan a directory tree for .E01 images and list partitions
./bulk_E01_check.sh /mnt/evidence

# Extract bodyfiles from a bulk UAC collection, then convert to timelines
./bodyfile_extract.sh /mnt/uac_collections /mnt/bodyfiles
./converBodyFiles.sh /mnt/bodyfiles /mnt/timelines

# Stack-rank bash history commands across multiple disk images
./historyStack.sh --strict /cases/images
```

#### btrfs Analysis (No Mount Required)

```bash
# Extract a single file from a btrfs image by name
./btrfs_extract.sh passwd /mnt/evidence/disk.btrfs.img

# Alternate implementation, addressed by in-filesystem path
./btrfs_extract_copilot.sh disk.btrfs.img /etc/passwd
```

#### LVM and Advanced Filesystem Analysis

```bash
# Mount single root LV from forensic image
sudo ./LVM_automount_update.sh /path/to/image.dd /mnt/evidence

# Mount single root LV from E01 image
sudo ./LVM_automount_update.sh case001.E01 /mnt/case001

# Mount all LVs from raw image (auto-creates /mnt/lvmevidence1, 2, 3...)
sudo ./LVM_automount_update.sh --all /path/to/image.raw

# Mount all LVs and keep them mounted for extended analysis
sudo ./LVM_automount_update.sh --all --keep-mounted evidence.dd

# Mount specific LV (e.g., 'home' instead of 'root')
sudo ./LVM_automount_update.sh --lv-name home disk.dd /mnt/home

# Check if LVM2 is in use on live system
./check_lvm2.sh
```

#### Cloud Evidence Upload (Presigned S3 URLs)

```bash
# Generate a presigned URL for an AVML memory dump upload
./AvmlPresignedUrlCreator.py --help

# Generate a presigned URL for Volatility symbol files
./Dwarf2jsonPresignedUrlCreator.py --help

# Generate a presigned URL for a UAC collection archive
./UacPresignedUrlCreator.py --help
```

#### Educational Tools

```bash
# Generate test ELF files
cd lab_ctf_generators/
./GenELF_file_better.sh

# Generate multiple test files for lab exercises
./multi_Files.sh

# Prepare classroom environment
./class_prep.sh

# Educational rootkit demonstration (requires kernel headers)
cd rootkits/lkm_example_2/
make                    # Build the kernel module
sudo insmod educational_rootkit.ko    # Load the module
sudo ./demo.sh         # Demonstrate rootkit functionality
./detect.sh            # Show detection techniques
sudo rmmod educational_rootkit        # Unload the module
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
