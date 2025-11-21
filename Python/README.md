# Python DFIR Tools

A collection of Python-based digital forensics and incident response (DFIR) utilities for security analysis, network forensics, filesystem analysis, and system validation.

## Overview

This directory contains production-ready Python scripts designed for forensic analysis, security investigations, and incident response. Each tool addresses specific forensic challenges encountered during security assessments and digital investigations.

## Tools

### Document Analysis

#### exifcheck.py

Extracts metadata from Microsoft Word DOCX files for forensic analysis.

**Purpose**: Quick extraction of document metadata without requiring full EXIF tools, useful for batch processing and integration with other forensic workflows.

**Key Features**:

- Author, creation date, and modification timestamps
- Document title, subject, and keywords
- Language and version information
- Content status and categorization

**Usage**:

```bash
python3 exifcheck.py -i document.docx
```

**Dependencies**:

- python-docx

**Installation**:

```bash
pip3 install python-docx
```

**Example Output**:

```bash
Opening : suspicious_document.docx
Author: John Doe
Created: 2024-01-15 10:30:00
Modified: 2024-01-20 14:45:00
Title: Confidential Report
Language: en-US
```

---

### Network Forensics

#### fastfluxfinder.py

Analyzes network packet captures to detect fast flux DNS patterns commonly used by botnets and malware command-and-control infrastructure.

**Purpose**: Identifies domains with unusually high numbers of unique IP addresses, a key indicator of fast flux networks used for malware resilience.

**Key Features**:

- Parses PCAP files for DNS responses
- Counts unique IP addresses per domain
- Identifies potential fast flux domains

**Usage**:

```bash
# Edit line 17 to specify your PCAP file path
python3 fastfluxfinder.py
```

**Configuration**:
Edit the script to update the PCAP file path:

```python
packets = rdpcap('/path/to/your/capture.pcap')
```

**Dependencies**:

- scapy

**Installation**:

```bash
pip3 install scapy
```

**Example Output**:

```bash
[+] malicious-domain.com has 247 unique IPs
[+] legitimate-site.com has 2 unique IPs
[+] botnet-c2.net has 156 unique IPs
```

**Interpretation**: Domains with dozens or hundreds of unique IPs may indicate fast flux networks.

---

### Filesystem Forensics

#### inode_reader.py

Extracts data directly from filesystem inodes in disk images using The Sleuth Kit Python bindings.

**Purpose**: Low-level filesystem analysis for recovering data from specific inodes, useful when filesystem metadata is damaged or when conducting deep forensic analysis.

**Key Features**:

- Direct inode data extraction
- Works with raw disk images
- Supports multiple filesystem types via pytsk3

**Usage**:

```bash
python3 inode_reader.py disk_image.dd inode_number
```

**Examples**:

```bash
# Extract data from inode 12345
python3 inode_reader.py evidence.dd 12345

# Extract from VMDK or E01 images
python3 inode_reader.py image.vmdk 67890
```

**Dependencies**:

- pytsk3 (The Sleuth Kit Python bindings)

**Installation**:

```bash
pip3 install pytsk3
```

**Use Cases**:

- Recovering deleted file data
- Analyzing filesystem structures
- Validating file locations
- Deep forensic carving

---

#### XFS_Extent_Address_Parser.py

Parses XFS filesystem extent addresses to extract file location information from inode data.

**Purpose**: Educational tool for FOR577 students to validate manually carved XFS extent addresses and understand XFS filesystem internals.

**Key Features**:

- Parses 128-bit XFS extent addresses
- Displays flag, logical offset, start block, and block count
- Shows binary, decimal, and hexadecimal representations
- Validates input format

**Usage**:

```bash
python3 XFS_Extent_Address_Parser.py
# Enter 128-bit binary string when prompted
```

**Example**:

```python
Enter 128-bit binary string: 0000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000001000000000000001000000001000000

Parsed Extent Entry:
  Flag:
    Binary : 0
    Decimal: 0
    Hex    : 0x0
  Logical Offset:
    Binary : 000000000000000000000000000000000000000000000000000001
    Decimal: 1
    Hex    : 0x1
  Start Block:
    Binary : 0000000000000000000000000000000000000000001000000000
    Decimal: 512
    Hex    : 0x200
  Block Count:
    Binary : 000001000000001000000
    Decimal: 8256
    Hex    : 0x2040
```

**Dependencies**: None (pure Python)

**Educational Context**: Created for SANS FOR577 course to help students understand XFS filesystem structure and extent-based file allocation.

---

### Authentication and Login Analysis

#### parse_loginData.py

Comprehensive parser for Linux utmp-style binary files (wtmp, btmp, utmp) that track user authentication events with support for multiple output formats.

**Purpose**: Extract and analyze login/logout records, system boots, and authentication failures for incident response and forensic analysis. Supports machine-readable formats for integration with SIEM systems and analysis tools.

**Key Features**:

- Parses wtmp (login history), btmp (failed logins), and utmp (current logins)
- Decodes IPv4 and IPv6 addresses
- Multiple output formats: table (human-readable), CSV, and JSONL
- Event-based labeling for intuitive record interpretation (login/logout/boot/etc.)
- Filters by record type (USER_PROCESS, BOOT_TIME, etc.)
- Human-readable timestamp formatting
- Optional filtering to hide empty records

**Usage**:

```bash
# Parse login history (default table format)
python3 parse_loginData.py /var/log/wtmp

# Parse failed login attempts
python3 parse_loginData.py /var/log/btmp

# Show only user login events
python3 parse_loginData.py --type USER_PROCESS /var/log/wtmp

# Include all records, even empty ones
python3 parse_loginData.py --show-empty /var/log/wtmp

# Output as CSV for spreadsheet analysis
python3 parse_loginData.py --format csv /var/log/wtmp > logins.csv

# Output as JSONL for log aggregation systems
python3 parse_loginData.py --format jsonl /var/log/wtmp > logins.jsonl

# Filter by multiple types with CSV output
python3 parse_loginData.py --type USER_PROCESS --type BOOT_TIME --format csv /var/log/wtmp
```

**Output Formats**:

*Table Format (Default)*:
```
2025-01-15 09:23:41  LOGIN    USER_PROCESS   user=admin            line=pts/0        host=192.168.1.100                   pid=1234
2025-01-15 10:15:22  BOOT     BOOT_TIME      user=-               line=~            host=5.10.0-28-amd64                 pid=0
2025-01-15 14:30:05  LOGOUT   DEAD_PROCESS   user=-               line=pts/0        host=-                               pid=1234
```

*CSV Format*:
```csv
timestamp_iso,event,type,type_name,user,line,host,ip,pid,session,exit_termination,exit_status,tv_sec,tv_usec
2025-01-15 09:23:41,login,7,USER_PROCESS,admin,pts/0,192.168.1.100,,1234,0,0,0,1705315421,0
```

*JSONL Format*:
```json
{"timestamp_iso": "2025-01-15 09:23:41", "event": "login", "type": 7, "type_name": "USER_PROCESS", "user": "admin", "line": "pts/0", "host": "192.168.1.100", "ip": null, "pid": 1234, "session": 0, "exit_termination": 0, "exit_status": 0, "tv_sec": 1705315421, "tv_usec": 0}
```

**Command-Line Options**:

- `--show-empty` - Include empty records (default: skip them)
- `--type TYPE` - Filter by record type name (can be specified multiple times)
- `--format {table,csv,jsonl}` or `-F` - Select output format (default: table)

**Record Types**:

- EMPTY (0): Empty record slot
- RUN_LVL (1): System runlevel change
- BOOT_TIME (2): System boot
- NEW_TIME (3): System time changed (new time)
- OLD_TIME (4): System time changed (old time)
- INIT_PROCESS (5): Init process spawn
- LOGIN_PROCESS (6): Login process initiated
- USER_PROCESS (7): User login session
- DEAD_PROCESS (8): Process/session termination
- ACCOUNTING (9): Accounting record

**Event Labels**:

For enhanced readability, records include semantic event labels:
- `login` (USER_PROCESS) - User session started
- `logout` (DEAD_PROCESS) - User session ended
- `boot` (BOOT_TIME) - System boot event
- `runlevel` (RUN_LVL) - Runlevel change
- `login-process` (LOGIN_PROCESS) - Login process started
- `time-change-new`/`time-change-old` - System time modifications

**Dependencies**: None (pure Python using standard library)

**Forensic Applications**:

- Timeline analysis of user activity (JSONL output for Elasticsearch/Splunk)
- Identifying unauthorized access attempts (btmp analysis)
- Tracking remote connections and source IPs
- System boot/shutdown correlation
- Brute force attack detection (failed login patterns in btmp)
- CSV export for spreadsheet pivot analysis
- Automated log aggregation and SIEM integration

---

### System Security Validation

#### proc_check.py

Advanced security tool that validates running processes against /proc filesystem entries to detect rootkits, hidden processes, and system anomalies.

**Purpose**: Cross-validates process information from ps command with /proc directory entries to identify discrepancies that may indicate kernel-level compromise or process hiding techniques.

**Key Features**:

- Hidden process detection (visible in /proc but not in ps)
- Command line validation and tampering detection
- Executable file verification
- Suspicious pattern identification
- JSON export for SIEM integration
- Comprehensive logging and reporting

**Usage**:

```bash
# Basic validation
python3 proc_check.py

# Verbose output
python3 proc_check.py --verbose

# Log to file with JSON output
python3 proc_check.py --log validation.log --output results.json

# Quiet mode for automation
python3 proc_check.py --quiet --output /var/log/proc_check.json
```

**Anomaly Types Detected**:

- **hidden_process**: Process in /proc but missing from ps (potential rootkit)
- **edited_command**: Command line mismatch between ps and /proc/cmdline
- **missing_file**: Executable file is missing or deleted (fileless malware)
- **missing_proc**: Process in ps but not in /proc (filesystem corruption)
- **anomaly**: Suspicious patterns (deleted executables, unusual paths, binary data in cmdline)

**Exit Codes**:

- 0: No anomalies detected
- 1: Error occurred
- 2: Anomalies found

**Dependencies**: None (pure Python using standard library)

**Example Output**:

```python
[INFO] Found 245 processes from ps command
[INFO] Found 245 processes from /proc directory
[WARN] ANOMALY [HIDDEN_PROCESS] PID 1337: Process exists in /proc but missing in ps output
[WARN] ANOMALY [ANOMALY] PID 5678: Executable in suspicious location: /tmp/malware

============================================================
Process Validation Summary
============================================================
⚠ Found 2 anomaly(ies):
  Anomaly: 1
  Hidden Process: 1
============================================================
```

**Detailed Documentation**: See [proc_check_README.md](proc_check_README.md) for comprehensive usage guide.

**Security Applications**:

- Rootkit detection
- Incident response validation
- Security auditing
- Compliance monitoring
- Automated threat detection

---

## Installation and Dependencies

### System Requirements

- Python 3.6 or higher
- Linux operating system (for proc_check.py and parse_loginData.py)
- Root/administrator privileges (recommended for full functionality)

### Installing Dependencies

```bash
# Install all dependencies at once
pip3 install python-docx scapy pytsk3

# Or install individually as needed
pip3 install python-docx      # For exifcheck.py
pip3 install scapy            # For fastfluxfinder.py
pip3 install pytsk3           # For inode_reader.py
```

### Making Scripts Executable

```bash
chmod +x *.py
```

---

## Security Context

All tools in this directory are designed for **defensive security, digital forensics, and authorized security testing only**. These utilities are intended for:

- Digital forensic investigations
- Incident response activities
- Security auditing and compliance
- Educational and training purposes
- Authorized penetration testing

### Responsible Use

- Obtain proper authorization before analyzing systems
- Follow chain of custody procedures for evidence
- Respect privacy and legal requirements
- Use only in controlled environments or with explicit permission
- Document all forensic activities

---

## Integration with DFIR Workflows

### Timeline Analysis

```bash
# Extract login events and combine with other artifacts
python3 parse_loginData.py /var/log/wtmp > timeline_logins.txt
```

### Automated Security Monitoring

```bash
#!/bin/bash
# Cron job example for continuous monitoring
python3 proc_check.py --quiet --output /var/log/proc_check_$(date +%Y%m%d_%H%M%S).json
if [ $? -eq 2 ]; then
    # Send alert
    mail -s "Process Anomalies Detected" security@company.com < /var/log/proc_check_latest.json
fi
```

### Document Triage

```bash
# Batch process documents for metadata extraction
for doc in evidence/*.docx; do
    echo "=== $doc ===" >> metadata_report.txt
    python3 exifcheck.py -i "$doc" >> metadata_report.txt
done
```

---

## Troubleshooting

### Common Issues

**Import Errors**:

```bash
# Ensure dependencies are installed
pip3 install --upgrade python-docx scapy pytsk3
```

**Permission Denied**:

```bash
# Some tools require elevated privileges
sudo python3 proc_check.py
sudo python3 parse_loginData.py /var/log/wtmp
```

**Module Not Found**:

```bash
# Verify Python 3 is being used
python3 --version
which python3
```

---

## Development Notes

### Coding Standards

All scripts in this directory follow these principles:

- Descriptive variable names
- Comprehensive error handling
- Input validation and sanitization
- Detailed logging for forensic auditing
- Help output and usage documentation

### Path Handling

- Scripts use absolute paths where appropriate for security
- File path validation prevents command injection
- Cross-platform compatibility considered where applicable

---

## Additional Resources

### Related Tools

- **Bash Scripts**: See `D:\Development\Public\Bash\` for shell-based forensic tools
- **PowerShell Scripts**: See `D:\Development\Public\Powershell\` for Windows forensic utilities
- **Volatility Plugins**: See `D:\Development\Public\Vol2.6\` and `D:\Development\Public\Vol3\` for memory analysis plugins

### Documentation

- Individual tool help: Run any script with `-h` or `--help`
- proc_check detailed guide: [proc_check_README.md](proc_check_README.md)
- Project overview: `D:\Development\Public\CLAUDE.md`

---

## Contributing

When modifying or extending these tools:

1. Follow existing code structure and style
2. Add comprehensive error handling
3. Include usage examples in docstrings
4. Update this README with new functionality
5. Test on representative datasets
6. Consider forensic integrity and chain of custody

---

## License

These tools are part of the Public DFIR Tools repository. Use responsibly and in accordance with applicable laws and regulations.

---

**Last Updated**: 2025-01-21
**Maintained By**: Security Team
**Purpose**: Digital Forensics and Incident Response
