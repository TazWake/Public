# Process Validation Tool

A comprehensive security tool that validates running processes against `/proc` entries to detect potential security anomalies, rootkits, and system compromises.

## Overview

The Process Validation Tool compares process information from the `ps` command with corresponding entries in the `/proc` filesystem to identify discrepancies that may indicate:

- **Hidden processes** (rootkits or malware)
- **Edited command lines** (process hiding techniques)
- **Missing executables** (fileless malware or deleted binaries)
- **Suspicious process behavior** (anomalous patterns)

## Features

### Core Detection Capabilities

- **Hidden Process Detection**: Identifies processes visible in `/proc` but missing from `ps` output
- **Command Line Validation**: Compares command lines between `ps` and `/proc/cmdline`
- **Executable Verification**: Checks if process executables exist and are accessible
- **Suspicious Pattern Detection**: Identifies unusual process behaviors and locations

### Security Analysis

- **Rootkit Detection**: Finds processes that may be hidden by kernel-level rootkits
- **Fileless Malware Detection**: Identifies processes with missing or deleted executables
- **Process Injection Detection**: Detects processes with modified command lines
- **Anomaly Classification**: Categorizes different types of security anomalies

### Reporting and Logging

- **Real-time Alerts**: Immediate notification of detected anomalies
- **Detailed Logging**: Comprehensive audit trails for security analysis
- **JSON Export**: Machine-readable results for integration with SIEM systems
- **Color-coded Output**: Easy-to-read status indicators

## Installation

### Prerequisites

- Python 3.6 or higher
- Linux operating system (requires `/proc` filesystem)
- Root privileges for full functionality

### Setup

```bash
# Make the script executable
chmod +x proc_check.py

# Verify Python is available
python3 --version

# Test the script
python3 proc_check.py --help
```

## Usage

### Basic Usage

```bash
# Run basic validation
python3 proc_check.py

# Verbose output for detailed information
python3 proc_check.py --verbose

# Quiet mode (errors only)
python3 proc_check.py --quiet
```

### Advanced Usage

```bash
# Log results to file
python3 proc_check.py --log validation.log

# Save detailed results to JSON
python3 proc_check.py --output results.json

# Full logging and output
python3 proc_check.py --verbose --log log.txt --output results.json
```

### Command Line Options

- `-h, --help` - Show help message
- `-v, --verbose` - Enable verbose output
- `-q, --quiet` - Suppress all output except errors
- `-l, --log FILE` - Log results to specified file
- `-o, --output FILE` - Save detailed results to JSON file
- `-V, --version` - Show version information

## Anomaly Types

### Hidden Process

**Detection**: Process exists in `/proc` but missing from `ps` output
**Significance**: May indicate rootkit or kernel-level malware
**Example**: Process visible in `/proc/1234/` but not listed by `ps`

### Edited Command

**Detection**: Command line in `ps` differs from `/proc/cmdline`
**Significance**: May indicate process hiding or command line obfuscation
**Example**: `ps` shows `/bin/bash` but `/proc/cmdline` shows different arguments

### Missing File

**Detection**: Executable file is missing or inaccessible
**Significance**: May indicate fileless malware or deleted binaries
**Example**: Process executable path returns "No such file or directory"

### Missing Proc

**Detection**: Process in `ps` output but missing from `/proc`
**Significance**: May indicate filesystem corruption or kernel issues
**Example**: Process listed by `ps` but `/proc/PID/` directory doesn't exist

### Anomaly

**Detection**: Other suspicious patterns or behaviors
**Significance**: May indicate various types of compromise
**Examples**:

- Empty command lines
- Executables in suspicious locations (`/tmp/`, `/dev/shm/`)
- Processes with deleted executables
- Unusually long command lines
- Binary data in command lines

## Output Examples

### Normal Operation

```bash
[INFO] Found 245 processes from ps command
[INFO] Found 245 processes from /proc directory
[INFO] Comparing 245 total processes

============================================================
Process Validation Summary
============================================================
✓ No anomalies detected
All processes appear to be normal
============================================================
```

### Anomalies Detected

```bash
[WARN] ANOMALY [HIDDEN_PROCESS] PID 1234: Process exists in /proc but missing in ps output
[WARN] ANOMALY [EDITED_COMMAND] PID 5678: Command line mismatch - PS: '/bin/bash' vs PROC: '/bin/bash -c hidden_command'

============================================================
Process Validation Summary
============================================================
⚠ Found 2 anomaly(ies):
  Edited Command: 1
  Hidden Process: 1
============================================================
```

### JSON Output

```json
{
  "timestamp": "2024-01-15T14:30:00.123456",
  "total_anomalies": 2,
  "anomalies": [
    {
      "type": "hidden_process",
      "pid": 1234,
      "description": "Process exists in /proc but missing in ps output",
      "timestamp": "2024-01-15T14:30:00.123456"
    },
    {
      "type": "edited_command",
      "pid": 5678,
      "description": "Command line mismatch - PS: '/bin/bash' vs PROC: '/bin/bash -c hidden_command'",
      "timestamp": "2024-01-15T14:30:00.123456"
    }
  ]
}
```

## Security Considerations

### Detection Methodology

The tool uses a multi-layered approach to detect anomalies:

1. **Process Enumeration**: Collects process information from both `ps` and `/proc`
2. **Cross-Validation**: Compares data between sources to find discrepancies
3. **File System Verification**: Checks if executable files exist and are accessible
4. **Pattern Analysis**: Identifies suspicious behaviors and locations

### Limitations

- **False Positives**: Some legitimate processes may trigger alerts
- **Kernel Dependencies**: Requires access to `/proc` filesystem
- **Privilege Requirements**: Full functionality requires root privileges
- **Platform Specific**: Designed for Linux systems only

### Best Practices

- **Regular Monitoring**: Run validation periodically for ongoing security
- **Baseline Establishment**: Run on clean systems to establish baselines
- **Correlation**: Use with other security tools for comprehensive analysis
- **Verification**: Always investigate findings before taking action

## Automation and Integration

### Cron Job Example

```bash
# Add to crontab for hourly checks
0 * * * * /usr/local/bin/proc_check.py --quiet --log /var/log/proc_check.log --output /var/log/proc_check.json
```

### SIEM Integration

The JSON output format is designed for easy integration with SIEM systems:

- Structured data with timestamps
- Categorized anomaly types
- Machine-readable format
- Detailed descriptions for analysis

### Script Integration

```bash
#!/bin/bash
# Example automation script

python3 proc_check.py --quiet --output /tmp/proc_check.json

if [ $? -eq 2 ]; then
    echo "Anomalies detected!"
    # Send alert or take action
    mail -s "Process Anomalies Detected" admin@company.com < /tmp/proc_check.json
fi
```

## Troubleshooting

### Common Issues

**Permission Denied Errors**:

- Ensure script has read access to `/proc` directory
- Run with appropriate privileges for full functionality
- Check file permissions on log and output files

**No Processes Found**:

- Verify system is running and processes are active
- Check if `/proc` filesystem is mounted
- Ensure `ps` command is available and working

**False Positives**:

- Review anomaly descriptions for context
- Check if processes are legitimate system processes
- Consider system-specific configurations

### Debug Mode

Use verbose mode for detailed debugging:

```bash
python3 proc_check.py --verbose
```

### Log Analysis

Check log files for detailed information:

```bash
tail -f validation.log
grep "ANOMALY" validation.log
```

## Exit Codes

- `0` - No anomalies detected
- `1` - Error occurred (script failure, permission issues, etc.)
- `2` - Anomalies found (security issues detected)

## Performance Considerations

- **Memory Usage**: Minimal memory footprint, processes data incrementally
- **CPU Usage**: Low CPU impact, primarily I/O bound operations
- **Execution Time**: Typically completes in seconds on modern systems
- **Scalability**: Handles thousands of processes efficiently

## Compliance and Auditing

This tool supports various compliance requirements:

- **Security Audits**: Regular process validation for security assessments
- **Compliance Reporting**: Detailed logs for regulatory requirements
- **Incident Response**: Rapid detection of system compromises
- **Forensic Analysis**: Historical process validation data

## Contributing

When contributing to this tool:

- Follow established coding standards
- Add comprehensive error handling
- Include detailed documentation
- Test on various Linux distributions
- Consider security implications of changes

## License

This project is licensed under the terms specified in the project's LICENSE file.

## Support

For issues, questions, or contributions:

- Review the troubleshooting section
- Check script help output (`--help`)
- Ensure all prerequisites are met
- Verify system compatibility

---

**Security Note**: This tool is designed for security analysis and should be used responsibly. Always ensure you have proper authorization before running security tools on systems, and respect privacy and security policies in your environment.
