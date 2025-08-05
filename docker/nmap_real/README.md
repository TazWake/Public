# Containerized Nmap Scanner

A production-ready containerized nmap solution for network security professionals and system administrators. This container provides a secure, isolated environment for network scanning with comprehensive output management and flexible configuration options.

## 🎯 Purpose

This containerized nmap application is designed for:
- **Security Professionals**: Conduct authorized network reconnaissance
- **System Administrators**: Monitor and audit network infrastructure  
- **Incident Response Teams**: Rapid network assessment during investigations
- **Compliance Auditing**: Network security posture assessments

## 🚀 Quick Start

### Prerequisites
- Docker installed and running
- PowerShell (for Windows users) or bash (for Linux/macOS)
- Network access to target systems
- **Proper authorization** to scan target networks

### Basic Usage

#### Option 1: PowerShell Wrapper (Recommended for Windows)
```powershell
# Default comprehensive scan
.\nmap-scan.ps1 -Target "192.168.1.0/24"

# Quick scan (top 1000 ports)
.\nmap-scan.ps1 -Target "192.168.1.1" -Quick

# Custom arguments
.\nmap-scan.ps1 -Arguments "-sS -p 80,443,8080 192.168.1.0/24"
```

#### Option 2: Docker Compose
```bash
# Build the image
docker-compose build

# Default scan
docker-compose run --rm nmap-scanner 192.168.1.0/24

# Quick scan service
docker-compose run --rm nmap-quick 192.168.1.1

# Custom arguments
docker-compose run --rm nmap-scanner -sS -p 80,443 192.168.1.1
```

#### Option 3: Direct Docker Commands
```bash
# Build the image
docker build -t nmap-scanner .

# Run default scan
docker run --rm --network=host -v $(pwd)/output:/output nmap-scanner 192.168.1.0/24

# Run custom scan
docker run --rm --network=host -v $(pwd)/output:/output nmap-scanner -sS -p 80,443 192.168.1.1
```

## 📁 File Structure

```
nmap_real/
├── Dockerfile              # Container definition
├── docker-compose.yml      # Multi-service configuration
├── entrypoint.sh           # Container entrypoint script
├── nmap-scan.ps1           # PowerShell wrapper script
├── README.md               # This documentation
└── output/                 # Scan results directory (created automatically)
```

## 🔧 Default Scan Configuration

The container uses the following default nmap arguments when only a target is specified:

```bash
-Pn -sC -sV -oA scan_tcp -vvvvvvvvv --reason -T4 -p-
```

**Breakdown:**
- `-Pn`: Skip host discovery (assume hosts are up)
- `-sC`: Enable default NSE scripts
- `-sV`: Version detection
- `-oA scan_tcp`: Output in all formats (normal, XML, grepable)
- `-vvvvvvvvv`: Maximum verbosity
- `--reason`: Show reason for port state
- `-T4`: Aggressive timing template
- `-p-`: Scan all 65535 ports

## 📊 Output Files

All scan results are automatically saved to the `./output` directory with timestamps:

```
output/
├── nmap_192.168.1.0-24_20250805_143022.nmap    # Normal format
├── nmap_192.168.1.0-24_20250805_143022.xml     # XML format
└── nmap_192.168.1.0-24_20250805_143022.gnmap   # Grepable format
```

## 🛡️ Security Features

### Container Security
- **Multi-stage build**: Optimized image size with minimal attack surface
- **Non-root execution**: Runs as unprivileged user (uid 1000) with locked account
- **Read-only filesystem**: Prevents container tampering with minimal writeable tmpfs
- **Resource limits**: CPU and memory constraints with intelligent optimization
- **No new privileges**: Security flag prevents privilege escalation
- **Capability restrictions**: Only NET_RAW and NET_ADMIN when required
- **Tini init system**: Proper signal handling and zombie process reaping
- **Health checks**: Continuous container health monitoring

### Enhanced Input Validation
- **Whitelist validation**: Strict character validation for targets and arguments
- **Command injection prevention**: Comprehensive dangerous pattern detection
- **Argument sanitization**: Multi-layer validation with dangerous command filtering
- **Path traversal protection**: Directory traversal attempt prevention
- **Cross-platform validation**: Consistent security across PowerShell and Bash wrappers

### Production Security
- **Network isolation**: Custom bridge networks with ICC disabled
- **Seccomp profiles**: Custom security computing profiles for system call filtering
- **AppArmor/SELinux**: Mandatory access control integration
- **User namespace remapping**: Additional isolation layer
- **Audit logging**: Comprehensive security event logging with structured format

### Audit Trail
- **Comprehensive logging**: All scan operations with performance metrics
- **Timestamped output**: Forensic-ready file naming with integrity verification
- **Command preservation**: Full audit trail of all executed commands
- **Performance monitoring**: Resource usage tracking and optimization metrics

## 🎛️ Configuration Options

### Docker Compose Services

#### `nmap-scanner` (Default)
- Full-featured scanning with comprehensive resource allocation
- Memory limit: 512MB
- CPU limit: 1.0 core
- Network mode: host (required for accurate scanning)

#### `nmap-quick` (Lightweight)
- Quick scans with reduced resource usage
- Memory limit: 256MB  
- CPU limit: 0.5 core
- Pre-configured for top 1000 ports

### Environment Variables

```yaml
environment:
  - TZ=UTC                    # Set timezone for consistent timestamps
  - NMAP_PRIVILEGED=false     # Disable privileged operations
```

## 📝 Usage Examples

### Network Discovery
```powershell
# Discover live hosts in subnet
.\nmap-scan.ps1 -Arguments "-sn 192.168.1.0/24"

# ARP ping scan for local network
.\nmap-scan.ps1 -Arguments "-PR 192.168.1.0/24"
```

### Port Scanning
```powershell
# TCP SYN scan on common ports
.\nmap-scan.ps1 -Arguments "-sS --top-ports 1000 192.168.1.0/24"

# UDP scan on DNS servers
.\nmap-scan.ps1 -Arguments "-sU -p 53 192.168.1.1,192.168.1.2"

# Comprehensive scan with OS detection
.\nmap-scan.ps1 -Arguments "-sS -sV -O -p- 192.168.1.1"
```

### Service Detection
```powershell
# Web server enumeration
.\nmap-scan.ps1 -Arguments "-sS -sV -p 80,443,8080,8443 --script=http-enum 192.168.1.0/24"

# SMB/NetBIOS discovery
.\nmap-scan.ps1 -Arguments "-sS -p 445,139 --script=smb-enum* 192.168.1.0/24"
```

### Performance Tuning
```powershell
# Stealth scan (slower, less detectable)
.\nmap-scan.ps1 -Arguments "-sS -T2 -f 192.168.1.1"

# Aggressive scan (faster, more detectable)  
.\nmap-scan.ps1 -Arguments "-sS -T5 --min-parallelism 100 192.168.1.0/24"
```

## 🚨 Important Legal and Ethical Considerations

### Authorization Required
- **Only scan networks you own or have explicit permission to test**
- Unauthorized network scanning may violate laws and policies
- Always obtain written authorization before scanning third-party networks

### Responsible Use
- Respect network resources and avoid overwhelming target systems
- Consider scan timing to minimize business impact
- Document all scanning activities for audit purposes
- Follow your organization's security testing policies

### Detection Considerations
- Network scans will be logged by target systems and security devices
- Coordinate with security teams to avoid triggering incident response
- Consider using stealth scanning options for sensitive environments

## 🔧 Troubleshooting

### Common Issues

#### Docker Permission Errors
```bash
# Linux: Add user to docker group
sudo usermod -aG docker $USER

# Or run with sudo
sudo docker-compose run --rm nmap-scanner 192.168.1.1
```

#### Network Access Issues
```bash
# Verify Docker can access host network
docker run --rm --network=host alpine ping -c 1 8.8.8.8

# Check firewall settings
# Windows: Ensure Docker Desktop has firewall exceptions
# Linux: Configure iptables if necessary
```

#### Output Directory Permissions
```powershell
# Create output directory manually
New-Item -ItemType Directory -Path ".\output" -Force

# Set appropriate permissions (Linux)
chmod 755 ./output
```

#### Container Build Failures
```bash
# Force rebuild without cache
docker-compose build --no-cache

# Check Docker daemon status
docker version
```

### Performance Optimization

#### Memory Usage
- Use `-T2` or `-T3` timing templates for lower memory usage
- Limit concurrent operations with `--max-parallelism`
- Scan smaller network ranges in batches

#### Network Efficiency
- Use `--top-ports` instead of `-p-` for faster scans
- Enable host discovery optimizations with `-Pn` when appropriate
- Consider `--min-rate` and `--max-rate` for bandwidth control

## 🔄 Updates and Maintenance

### Container Updates
```bash
# Rebuild with latest packages
docker-compose build --pull --no-cache

# Update base image
docker pull ubuntu:22.04
```

### Log Management
```bash
# View container logs
docker-compose logs nmap-scanner

# Clean up old scan results
find ./output -name "*.nmap" -mtime +30 -delete
```

## 📞 Support and Contributing

### Issue Reporting
- Check existing documentation first
- Provide detailed error messages and system information
- Include steps to reproduce issues

### Security Considerations
- Report security vulnerabilities responsibly
- Test in isolated environments before production use
- Keep Docker and system packages updated

---

**⚠️ Legal Disclaimer**: This tool is provided for authorized security testing only. Users are responsible for ensuring they have proper authorization before scanning any networks. Unauthorized network scanning may violate laws and organizational policies.