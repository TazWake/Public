# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

This is a comprehensive DFIR (Digital Forensics and Incident Response) tools repository containing production-ready forensic analysis scripts, containerized lab environments, and specialized plugins for memory analysis frameworks.

## Common Commands

### Docker Lab Environments
Multiple containerized environments are available for testing and analysis:

```bash
# Range testing environment (Kali, nmap, target containers)
cd D:\Development\Public\Range\
docker-compose up -d

# ELK Stack for log analysis
cd D:\Development\Public\docker\Analysis_ELK\
docker-compose up -d
# Access Kibana at http://localhost:8889

# OpenSearch alternative
cd D:\Development\Public\docker\Analysis_OpenSearch\
docker-compose up -d
# Access dashboards at http://localhost:8899

# Testing web environment with PHP/MySQL
cd D:\Development\Public\docker\testingweb\
docker-compose up -d
# Access at http://localhost:9999
```

### Memory Analysis (Volatility)
Scripts assume vol.py is in PATH or modify accordingly:

```bash
# Volatility 2.6 plugins (deprecated but functional)
python vol.py --plugins=D:\Development\Public\Vol2.6 --profile=PROFILE -f memory.img ramscan
python vol.py --plugins=D:\Development\Public\Vol2.6 --profile=PROFILE -f memory.img triagecheck

# Volatility 3 plugins  
python vol.py -p D:\Development\Public\Vol3 -f memory.img windows.fasttriage

# Automated memory analysis
cd /path/to/memory/image
D:\Development\Public\Bash\memory_precook.sh memory.img VOLATILITY_PROFILE
```

### Evidence Collection
```bash
# Linux evidence collection (requires elevated privileges)
sudo D:\Development\Public\Bash\evidence_collector.sh /path/to/storage/device

# Automated evidence extraction scripts
D:\Development\Public\Bash\triageScan.sh
D:\Development\Public\Bash\docker_triage.sh
```

### Linux Kernel Module Development
```bash
# In the rootkits directory for educational purposes
cd D:\Development\Public\Bash\rootkits\
make all  # Builds kernel module
make clean  # Cleans build artifacts
```

## Architecture and Structure

### Core Components
- **Bash/**: Production shell scripts for evidence collection, memory analysis automation, and system triage
- **Python/**: Forensic analysis utilities including EXIF extraction and network analysis tools  
- **Powershell/**: Windows-specific scripts for auditing, logging configuration, and evidence collection
- **Vol2.6/** & **Vol3/**: Volatility framework plugins for memory forensics analysis
- **docker/**: Containerized analysis environments (ELK, OpenSearch, testing web apps)

### Key Technologies
- **Volatility Framework**: Memory forensics analysis (both v2.6 and v3)
- **Docker & Docker Compose**: Containerized lab and analysis environments
- **ELK Stack**: Log analysis and visualization (Elasticsearch, Kibana, Filebeat)
- **OpenSearch**: Alternative search and analytics platform
- **Bash/Shell**: Primary automation and collection scripting
- **Python**: Forensic utilities and Volatility plugin development

### Memory Analysis Plugins
#### Volatility 2.6 (Deprecated)
- **ramscan.py**: Process listing with VAD analysis for suspicious RWX memory regions
- **triagecheck.py**: Quick triage tool checking for obvious malicious activity indicators
- **cmdcheck.py**: Analyzes cmd.exe handles for backdoor detection
- **fastvadscan.py**: Fast VAD scanning without file extraction
- **pathcheck.py**: Identifies executables loaded from suspicious locations

#### Volatility 3
- **fasttriage.py**: Modernized triage plugin for Vol3 framework

### Docker Environments
#### Analysis Platforms
- **Analysis_ELK/**: Full ELK stack with Filebeat for log ingestion (assumes logs in `/cases/logstore`)
- **Analysis_OpenSearch/**: Alternative to ELK using OpenSearch and Dashboards

#### Testing/Lab Environments  
- **Range/**: Multi-container network with Kali (10.10.10.10), nmap scanner (10.10.10.11), and Ubuntu target (10.10.10.12)
- **testingweb/**: Vulnerable PHP/MySQL web application for testing (MySQL root: NINJAROOTPASSWORD)

### Evidence Collection Scripts
- **evidence_collector.sh**: Comprehensive Linux evidence collection following RFC3227
- **memory_precook.sh**: Automated volatility analysis battery
- **docker_triage.sh**: Container-specific forensic collection
- **triageScan.sh**: Quick system triage and suspicious activity detection

### File Analysis Tools
- **exifcheck.py**: DOCX metadata extraction
- **fastfluxfinder.py**: Network analysis for fast flux detection  
- **inode_reader.py**: Low-level filesystem analysis

## Important Notes

### Security Context
All tools are designed for **defensive security and forensic analysis only**. The repository contains educational materials and legitimate forensic utilities.

### Dependencies
- Most Bash scripts assume standard Unix utilities are available
- Python scripts may require additional packages (check individual script headers)
- Volatility requires appropriate profiles for memory analysis
- Docker environments require Docker and Docker Compose

### Evidence Handling
- Scripts follow RFC3227 guidelines for evidence collection
- All collection scripts include integrity verification (MD5/SHA1 hashing)
- Log files and checksums are automatically generated during collection processes