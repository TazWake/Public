# DFIR Tools Repository

A comprehensive collection of Digital Forensics and Incident Response (DFIR) tools, scripts, and containerized environments for cybersecurity professionals and researchers.

## 📁 Repository Structure

### 🔧 Applications/

C and Go implementations of analysis tools

- `malreview.c` - C implementation of malware analysis utility for file examination
- `malreview.go` - Go implementation of malware analysis utility for file examination

### 🐚 Bash/

Production-ready shell scripts for Linux/macOS forensic operations

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

Python utilities for forensic analysis

- `exifcheck.py` - DOCX metadata extraction utility
- `fastfluxfinder.py` - Network analysis tool for detecting fast flux DNS patterns
- `inode_reader.py` - Low-level filesystem inode analysis tool

### 💻 Powershell/

Windows-specific forensic and security scripts

- `collectEvidence.ps1` - Comprehensive Windows evidence collection with KAPE and MRC
- `Enable_PowerShellDetailedAuditing.ps1` - Enable detailed PowerShell execution logging
- `set_logging.ps1` - Configure Windows security logging
- `setAuditing.ps1` - Windows audit policy configuration
- `setContextMenu.ps1` - Custom context menu entries for forensic tools
- `FolderCheck.ps1` - Directory integrity and analysis script
- `botnetcheck.ps1` - Botnet infection detection script
- `collect_timestamps.ps1` - Windows timestamp collection and analysis

### 🧠 Vol2.6/ (Deprecated)

Volatility 2.6 memory analysis plugins

- `ramscan.py` - Process listing with VAD analysis for suspicious RWX memory regions
- `triagecheck.py` - Quick memory triage for obvious malicious activity indicators
- `cmdcheck.py` - Analyzes cmd.exe handles for backdoor detection
- `Fastvadscan.py` - Fast VAD scanning without file extraction
- `pathcheck.py` - Identifies executables loaded from suspicious locations

### 🧠 Vol3/

Volatility 3 memory analysis plugins

- `fasttriage.py` - Modernized triage plugin for Volatility 3 framework

### 🐳 docker/

Containerized analysis and testing environments

#### Log Analysis Platforms

**Analysis_ELK/**
- Complete ELK stack (Elasticsearch, Kibana, Filebeat) for log analysis
- Pre-configured for Apache, auditd, syslog, messages, auth.log, and secure logs
- Expects logs in `/cases/logstore` directory
- Access Kibana at <http://localhost:8889>

**Analysis_OpenSearch/**
- OpenSearch alternative to ELK stack
- Access dashboards at <http://localhost:8899>

**LogFileAnalysisWithElastic/**
- Enhanced log analysis environment with automated setup
- Includes setup scripts for ingest pipelines and timestamp parsing
- Run `./setup.sh` for automated configuration
- Status checking via `./check-status.sh`

#### Malware Analysis Environments

**MalwareAnalyzer/**
- Containerized malware analysis environment
- Isolated environment for safe malware examination
- Mounts current directory to `/analysis` for file analysis
- Results written to `./results` directory

**maldoc/**
- Specialized environment for analyzing malicious documents
- Tools for document metadata extraction and embedded object analysis

#### Security Testing Environments

**testingweb/**
- Vulnerable PHP/MySQL web application for security testing
- Includes phpMyAdmin interface
- MySQL credentials: root/NINJAROOTPASSWORD
- Access web interface at <http://localhost:9999>

**nmap_real/**
- Production-ready nmap scanning environment with monitoring
- Includes Grafana dashboards and Prometheus metrics
- Optimized for large-scale scanning operations

**nmaper/**
- Lightweight containerized nmap scanning environment
- Quick deployment for network reconnaissance tasks

**re_docker/**
- Reverse engineering Docker environment
- Tools for binary analysis and reverse engineering tasks

### 🎯 Range/

Multi-container network testing environment

- Kali Linux container (10.10.10.10) - Attack platform
- Nmap scanner container (10.10.10.11) - Network reconnaissance
- Ubuntu target container (10.10.10.12) - Victim system
- Isolated 10.10.10.0/24 network for safe testing

### 📊 EvidenceGenerator/

Synthetic evidence generation for training and testing

- `generate_data.py` - Generate realistic forensic artifacts
- `webgen.py` - Web log generation utility
- Filter generated logs to remove private IP addresses using provided grep patterns

### 📚 Examples/

Sample data and documentation

- `GenericPotato.md` - Privilege escalation technique documentation
- `GenericPotato.zip` - Sample files for potato attack vectors

### 📓 JupyterNotebooks/

Jupyter notebooks for data analysis and forensic workflows

- `Test2.ipynb` - Example notebook demonstrating data analysis techniques
- Interactive environment for forensic data exploration and visualization

### 🔍 plaso/

Log2timeline/plaso configuration files

- `filter_linux.txt` - Linux-specific timeline filtering rules
- `filter_linux.yaml` - YAML format Linux timeline filters
- Pre-configured filters for efficient timeline analysis on Linux systems

### 📋 Documentation

- `dfir_collection.md` - DFIR collection methodology documentation
- `README.md` - This file, comprehensive repository documentation
- `CLAUDE.md` - Guidelines for Claude Code when working with this repository

## 🚀 Quick Start

### Docker Environments

```bash
# Start ELK stack for log analysis
cd docker/Analysis_ELK && docker-compose up -d
# Access Kibana at http://localhost:8889

# Start enhanced log analysis with automated setup
cd docker/LogFileAnalysisWithElastic
./setup.sh
docker-compose up -d

# Start OpenSearch alternative
cd docker/Analysis_OpenSearch && docker-compose up -d
# Access dashboards at http://localhost:8899

# Start malware analysis environment
cd docker/MalwareAnalyzer && docker-compose up -d

# Start testing range (isolated network)
cd Range && docker-compose up -d

# Start vulnerable web app for security testing
cd docker/testingweb && docker-compose up -d
# Access at http://localhost:9999

# Start nmap scanning environment with monitoring
cd docker/nmap_real && docker-compose up -d
```

### Memory Analysis with Volatility

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

### Building Applications

```bash
# C applications (requires C++17 support)
g++ -std=c++17 -o malreview Applications/malreview.c -lstdc++fs

# Go applications (requires Go 1.16+)
go build -o malreview Applications/malreview.go

# Kernel modules (requires kernel headers)
cd Bash/rootkits/
make all    # Build kernel module
make clean  # Clean build artifacts
```

## 📦 Prerequisites & Dependencies

### Core Requirements

- **Docker & Docker Compose** - For containerized analysis environments
- **Python 3.x** - For Python utilities and Volatility plugins
- **Bash/Shell** - For shell script execution (WSL2 on Windows)

### Memory Analysis

- **Volatility Framework** - vol.py must be in PATH
- **Appropriate memory profiles** - Match your memory image OS version
- **dwarfdump utility** - For advanced memory analysis

### Evidence Collection Tools

- **LiME (Linux Memory Extractor)** - For memory capture on Linux
- **The Sleuth Kit (TSK)** - For VMDK carving and filesystem analysis
- **ewfacquire** - For disk imaging (or dd as fallback)

### Log Analysis Platforms

- **ELK Stack** - Expects logs in `/cases/logstore` directory
- Create `/cases/logstore` if missing before starting ELK containers

### Development Tools

- **C++17 compiler** - For C application compilation
- **Go 1.16+** - For Go application development
- **Kernel headers** - For Linux kernel module development (`linux-headers-$(uname -r)`)
- **ShellCheck** - Recommended for bash script validation

### Optional Tools

- **KAPE** - Windows evidence collection (collectEvidence.ps1)
- **MRC (Magnet Response Collection)** - Windows forensics
- **Jupyter** - For interactive data analysis notebooks

## ⚠️ Important Notes

### Security Context

All tools in this repository are designed for **defensive security and legitimate forensic analysis only**. The repository contains:
- Educational materials (kernel modules, rootkits)
- Legitimate forensic utilities
- Security testing environments

### Evidence Handling

Scripts follow RFC3227 guidelines for digital evidence:
- Automatic integrity verification (MD5/SHA1 hashing)
- Comprehensive logging of all operations
- Chain of custody documentation included

### Best Practices

- Always run evidence collection scripts with appropriate privileges
- Verify checksums of collected evidence
- Maintain proper chain of custody documentation
- Use isolated environments for malware analysis
- Review script headers for specific dependencies

## 📄 License

See [LICENSE](LICENSE) for details.

## 🤝 Contributing

This repository contains production DFIR tools. Contributions should:
- Follow existing code style and structure
- Include appropriate documentation
- Use descriptive variable/function names
- Add error handling and logging
- Follow security best practices outlined in `.cursor/rules/`

## 📚 Additional Resources

- **CLAUDE.md** - Guidelines for AI assistants working with this repository
- **dfir_collection.md** - DFIR collection methodology
- **Bash/README.md** - Detailed bash script documentation
- Individual script headers contain usage instructions
