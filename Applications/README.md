# Malware Analysis Applications

This directory contains static malware analysis tools implemented in multiple languages for automated binary analysis and AI-assisted threat assessment.

## Overview

The `malanalyze` tool performs comprehensive static analysis on suspicious binaries and integrates with OpenAI's GPT-4 API for automated malware assessment. Both C++ and Go implementations provide identical functionality with different runtime characteristics.

## Applications

### malreview.c (C++ Implementation)
- **Language**: C++17
- **Advantages**: Minimal dependencies, fast execution, native performance
- **Best for**: Resource-constrained environments, offline analysis stations

### malreview.go (Go Implementation)
- **Language**: Go 1.16+
- **Advantages**: Memory safety, better error handling, cross-compilation support
- **Best for**: Production environments, containerized workflows

## Features

- Static binary analysis using standard forensic tools
- Automated evidence collection with timestamped logging
- Integrity verification (SHA-1 and SHA-256 hashing)
- AI-assisted malware assessment via OpenAI API
- Structured output storage for documentation and reporting
- RFC3227-compliant evidence handling

## Compilation

### C++ Version
```bash
g++ -std=c++17 -o malanalyze malreview.c -lstdc++fs
```

**Requirements**:
- GCC/Clang with C++17 support
- Standard C++ filesystem library
- POSIX-compliant system (Linux/macOS/WSL2)

### Go Version
```bash
go build -o malanalyze malreview.go
```

**Requirements**:
- Go 1.16 or later
- Standard Go toolchain
- POSIX-compliant system (Linux/macOS/WSL2)

## Dependencies

Both implementations require the following system utilities:
- `file` - File type identification
- `sha1sum` - Hash calculation
- `sha256sum` - Evidence integrity verification
- `readelf` - ELF header analysis
- `objdump` - Disassembly and binary inspection
- `strings` - String extraction (minimum length 8)
- `ldd` - Dynamic library dependency analysis

On Debian/Ubuntu systems:
```bash
sudo apt-get install coreutils binutils file
```

## Usage

```bash
malanalyze -f <suspicious_binary>
```

### Example
```bash
./malanalyze -f /tmp/suspicious.elf
```

## Configuration

Set the OpenAI API key as an environment variable:
```bash
export API="your-openai-api-key-here"
./malanalyze -f sample.bin
```

**Note**: The tool requires a valid OpenAI API key for AI-assisted analysis. Analysis will fail without this credential.

## Output Structure

The tool creates an `evidence/` directory in the current working directory:

```
evidence/
├── log.txt              # Timestamped execution log with all commands
├── file.txt             # File type identification output
├── sha1hash.txt         # SHA-1 hash of the analyzed binary
├── readelf.txt          # ELF header and section analysis
├── objdump.txt          # Complete disassembly listing
├── strings.txt          # Extracted printable strings (8+ chars)
└── ldd.txt              # Dynamic library dependencies

Analysis_Response_YYYY-MM-DD_HH-MM-SS.json  # AI analysis results
```

## Security Considerations

### Forensic Best Practices
- All commands and outputs are logged with UTC timestamps
- SHA-256 hash of the log file is computed for evidence integrity
- Original file hash (SHA-1) is captured before analysis
- No modifications are made to the analyzed binary

### Operational Security
- **Sandboxing**: Run in isolated VM or container environment
- **Network**: Consider offline analysis to prevent malware communication
- **API Key Protection**: Never hardcode API keys; use environment variables
- **Evidence Chain**: Preserve original files and maintain separate evidence copies

### Limitations
- Static analysis only (does not execute the binary)
- Requires Linux/Unix utilities (not Windows-native)
- Limited to ELF binaries (Linux executables)
- May produce false positives/negatives

## Use Cases

1. **Incident Response**: Quick triage of suspicious binaries discovered during investigations
2. **Malware Research**: Automated collection of static analysis artifacts
3. **Threat Intelligence**: Bulk analysis of malware samples with AI classification
4. **Security Training**: Educational tool for learning static analysis techniques
5. **CTF Competitions**: Rapid binary analysis for reverse engineering challenges

## Integration Examples

### Docker Container
```bash
docker run -it --rm \
  -v "$(pwd)":/analysis \
  -e API="${API}" \
  forensics/malanalyze \
  malanalyze -f /analysis/sample.bin
```

### Batch Analysis
```bash
#!/bin/bash
for binary in /samples/*.elf; do
  ./malanalyze -f "$binary"
  mv evidence "evidence_$(basename "$binary")"
  mv Analysis_Response_*.json "$(basename "$binary").json"
done
```

### CI/CD Pipeline
```yaml
# Example GitHub Actions workflow
- name: Analyze Binary
  env:
    API: ${{ secrets.OPENAI_API_KEY }}
  run: |
    ./malanalyze -f build/output/binary
    cat Analysis_Response_*.json
```

## AI Analysis

The tool sends both the original binary content and static analysis logs to GPT-4 with the following prompt:

> "Please review the attached file and provide an assessment of what the sample does, and if it is likely to be malicious."

The response includes:
- Behavioral analysis based on static artifacts
- Identified suspicious indicators
- Malware family classification (if applicable)
- Recommended next steps for investigation

## Troubleshooting

### "API key not found" Error
Set the `API` environment variable:
```bash
export API="sk-..."
./malanalyze -f sample
```

### "File not found" Error
Ensure the file path is correct and the file exists:
```bash
ls -la /path/to/file
./malanalyze -f /absolute/path/to/file
```

### Missing Tool Dependencies
Install required utilities:
```bash
# Debian/Ubuntu
sudo apt-get install binutils coreutils file

# Red Hat/CentOS
sudo yum install binutils coreutils file
```

### Compilation Errors (C++)
Ensure C++17 support:
```bash
g++ --version  # Should be GCC 7+ or Clang 5+
g++ -std=c++17 -o malanalyze malreview.c -lstdc++fs
```

## Related Tools

- **Volatility Plugins**: See `/Vol2.6` and `/Vol3` for memory analysis tools
- **evidence_collector.sh**: Comprehensive Linux evidence collection (`/Bash`)
- **VMDK_Carver.sh**: NTFS carving from virtual disk images (`/Bash`)
- **ELK Stack**: Log analysis environment for processing results (`/docker/Analysis_ELK`)

## License

Part of the DFIR Tools Repository. For educational and authorized security testing purposes only.

## Author Notes

Both implementations produce identical output and are maintained in parallel to provide deployment flexibility. Choose based on your environment:

- **Use C++ version**: Minimal footprint, static linking, embedded systems
- **Use Go version**: Modern codebases, containerized deployments, cross-platform builds

---

For more information about the broader DFIR toolkit, see the main repository README.
