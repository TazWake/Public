# Docker DFIR and Security Lab Environments

This directory contains containerized environments for digital forensics, incident response, malware analysis, and security testing. All environments are designed for educational purposes and defensive security research.

## Overview

These Docker Compose environments provide isolated, reproducible analysis platforms for log analysis, malware investigation, network scanning, and vulnerability testing. Each environment can be started independently and includes pre-configured tools and services.

## Quick Start

```bash
# Navigate to desired environment directory
cd D:\Development\Public\docker\[environment-name]\

# Start the environment
docker-compose up -d

# View running containers
docker-compose ps

# View logs
docker-compose logs -f

# Stop the environment
docker-compose down

# Stop and remove volumes (clean slate)
docker-compose down -v
```

## Environments

### Log Analysis Platforms

#### Analysis_ELK
Full ELK (Elasticsearch, Logstash, Kibana) stack with Filebeat for comprehensive log analysis.

**Purpose**: Production-grade log aggregation, analysis, and visualization platform for security monitoring and forensic investigation.

**Services**:
- Elasticsearch (port 9200)
- Kibana (http://localhost:8889)
- Filebeat (log shipper)

**Features**:
- Auto-configured ingest pipelines for common log formats
- Supports Apache logs, auditd, syslog, auth.log
- Assumes logs stored in `/cases/logstore` directory
- Pre-built visualizations and dashboards

**Usage**:
```bash
cd D:\Development\Public\docker\Analysis_ELK\

# Ensure log directory exists
mkdir -p /cases/logstore

# Place log files in /cases/logstore
# Start the stack
docker-compose up -d

# Access Kibana at http://localhost:8889
```

**Data Persistence**: Elasticsearch data persists in Docker volumes between restarts.

---

#### Analysis_OpenSearch
Alternative open-source search and analytics platform based on OpenSearch.

**Purpose**: Elasticsearch alternative for log analysis with similar capabilities but fully open-source licensing.

**Services**:
- OpenSearch
- OpenSearch Dashboards (http://localhost:8899)

**Usage**:
```bash
cd D:\Development\Public\docker\Analysis_OpenSearch\
docker-compose up -d

# Access dashboards at http://localhost:8899
```

**Use Case**: Drop-in replacement for ELK stack for organizations requiring fully open-source solutions.

---

#### LogFileAnalysisWithElastic
Enhanced Elasticsearch environment with automated setup scripts and optimized configurations.

**Purpose**: Streamlined log analysis with automated ingest pipeline configuration and timestamp parsing.

**Features**:
- Automated setup via `setup.sh` script
- Pre-configured ingest pipelines
- Status checking script (`check-status.sh`)
- Optimized for large log file ingestion

**Usage**:
```bash
cd D:\Development\Public\docker\LogFileAnalysisWithElastic\

# Run automated setup (first time)
./setup.sh

# Start the environment
docker-compose up -d

# Check system status
./check-status.sh
```

**Advantages**: Reduced manual configuration, faster deployment, better suited for workshop/training environments.

---

### Malware Analysis

#### MalwareAnalyzer
Isolated containerized environment for safe malware analysis.

**Purpose**: Provides sandboxed environment for examining malicious files without risking host system compromise.

**Features**:
- Isolated network (no external connectivity by default)
- Mounts current directory to `/analysis` inside container
- Results written to `./results` directory
- Pre-installed analysis tools

**Usage**:
```bash
cd D:\Development\Public\docker\MalwareAnalyzer\

# Place malware samples in current directory
docker-compose up -d

# Access container for interactive analysis
docker-compose exec malware-analyzer bash

# Samples available at /analysis
# Write results to /analysis/results
```

**Safety**: Container is isolated from host network. Always follow safe malware handling procedures.

---

#### maldoc
Specialized container for analyzing malicious documents (Office files, PDFs, etc.).

**Purpose**: Dedicated environment for examining suspicious documents with appropriate tools for extracting macros, embedded objects, and identifying exploits.

**Usage**:
```bash
cd D:\Development\Public\docker\maldoc\
docker-compose up -d

# Access container for document analysis
docker-compose exec maldoc bash
```

**Common Tools** (typically included):
- oletools (olevba, oledump, etc.)
- pdfid, pdf-parser
- yara
- strings, binwalk

---

### Network Scanning and Testing

#### nmap_real
Production-ready nmap scanning environment with monitoring and metrics.

**Purpose**: Large-scale network scanning with performance monitoring via Grafana dashboards and Prometheus metrics collection.

**Services**:
- nmap container
- Prometheus (metrics collection)
- Grafana (visualization dashboards)

**Features**:
- Optimized for large IP range scans
- Real-time performance metrics
- Historical scan data visualization
- Resource usage monitoring

**Usage**:
```bash
cd D:\Development\Public\docker\nmap_real\
docker-compose up -d

# Access Grafana dashboards for scan monitoring
```

**Use Case**: Enterprise network discovery, asset inventory, continuous network monitoring.

---

#### nmaper
Nmap scanning environment (lightweight variant).

**Purpose**: Simplified nmap container for basic network scanning tasks.

**Usage**:
```bash
cd D:\Development\Public\docker\nmaper\
docker-compose up -d
```

---

### Web Application Testing

#### testingweb
Intentionally vulnerable PHP/MySQL web application for security testing and training.

**Purpose**: Provides vulnerable web application environment for practicing web application security testing, SQL injection, XSS, and other OWASP Top 10 vulnerabilities.

**Services**:
- PHP web server (http://localhost:9999)
- MySQL database
- phpMyAdmin (database management interface)

**Credentials**:
- MySQL root password: `NINJAROOTPASSWORD`

**Usage**:
```bash
cd D:\Development\Public\docker\testingweb\
docker-compose up -d

# Access web application at http://localhost:9999
# Access phpMyAdmin for database inspection
```

**Security Warning**: This application is INTENTIONALLY VULNERABLE. Never expose to public networks. Use only in isolated lab environments.

**Use Cases**:
- Web application penetration testing training
- SQL injection practice
- XSS vulnerability demonstration
- Security tool testing (Burp Suite, OWASP ZAP, sqlmap)

---

## Related Environments

For additional Docker environments, see:
- **D:\Development\Range\**: Multi-container network testing environment with Kali, nmap, and Ubuntu target (10.10.10.0/24 isolated network)
- **D:\Development\ghosts\**: Analytics environment with PostgreSQL and Grafana containers

## Common Operations

### Resource Management

```bash
# View resource usage
docker stats

# Clean up unused images and containers
docker system prune

# Remove all stopped containers
docker container prune

# Remove unused volumes
docker volume prune
```

### Troubleshooting

```bash
# View container logs
docker-compose logs [service-name]

# Follow logs in real-time
docker-compose logs -f [service-name]

# Restart specific service
docker-compose restart [service-name]

# Rebuild containers after configuration changes
docker-compose up -d --build

# Access container shell for debugging
docker-compose exec [service-name] bash
```

### Data Management

```bash
# Backup Docker volumes
docker run --rm -v [volume-name]:/data -v $(pwd):/backup alpine tar czf /backup/backup.tar.gz -C /data .

# Restore Docker volumes
docker run --rm -v [volume-name]:/data -v $(pwd):/backup alpine tar xzf /backup/backup.tar.gz -C /data

# List all volumes
docker volume ls

# Inspect volume
docker volume inspect [volume-name]
```

## Port Reference

Quick reference for default service ports:

| Service | Port | Environment |
|---------|------|-------------|
| Kibana | 8889 | Analysis_ELK |
| OpenSearch Dashboards | 8899 | Analysis_OpenSearch |
| Testing Web App | 9999 | testingweb |
| Elasticsearch | 9200 | Analysis_ELK, LogFileAnalysisWithElastic |

## Best Practices

### Security

1. **Isolation**: Never expose vulnerable or analysis environments to public networks
2. **Network Segmentation**: Use Docker networks to isolate containers
3. **Credential Management**: Change default passwords in production-like scenarios
4. **Malware Handling**: Always use dedicated analysis containers for examining malicious files
5. **Container Updates**: Regularly update container images for security patches

### Performance

1. **Resource Limits**: Configure memory and CPU limits in docker-compose.yml for resource-intensive services
2. **Volume Cleanup**: Regularly clean up unused volumes to free disk space
3. **Log Rotation**: Configure log rotation for long-running services
4. **Monitoring**: Use `docker stats` to monitor container resource usage

### Data Management

1. **Persistent Storage**: Use named volumes for data that must persist
2. **Backup Strategy**: Implement regular backups of important Docker volumes
3. **Case Organization**: Maintain organized directory structure for logs and analysis outputs
4. **Documentation**: Document custom configurations and non-standard setups

## Requirements

### System Requirements

- Docker Engine 20.10 or newer
- Docker Compose 1.29 or newer
- Minimum 8GB RAM (16GB+ recommended for ELK stack)
- Minimum 20GB free disk space
- Windows with WSL2, Linux, or macOS

### Host Environment

- **Windows**: Use PowerShell or WSL2 for Docker commands
- **Paths**: Windows paths work in docker-compose.yml on Windows hosts
- **WSL2**: Recommended for better performance on Windows

## Troubleshooting Guide

### Common Issues

#### Port Already in Use
```bash
# Find process using port
netstat -ano | findstr :8889  # Windows
lsof -i :8889                 # Linux/macOS

# Change port in docker-compose.yml
ports:
  - "8890:5601"  # Changed from 8889
```

#### Out of Memory
```bash
# Increase Docker Desktop memory allocation
# Or add memory limits to docker-compose.yml
mem_limit: 2g
```

#### Containers Won't Start
```bash
# Check logs for errors
docker-compose logs

# Remove and recreate
docker-compose down -v
docker-compose up -d --force-recreate
```

#### Permission Denied (Linux)
```bash
# Add user to docker group
sudo usermod -aG docker $USER
# Log out and back in
```

## Additional Resources

- [Docker Documentation](https://docs.docker.com/)
- [Docker Compose Documentation](https://docs.docker.com/compose/)
- [ELK Stack Documentation](https://www.elastic.co/guide/index.html)
- [OpenSearch Documentation](https://opensearch.org/docs/)
- Parent Directory README: `D:\Development\Public\README.md`
- Project Documentation: `D:\Development\Public\CLAUDE.md`

## Author

**@tazwake**

## License

These Docker environments are provided for educational and defensive security purposes. Use in accordance with applicable laws and organizational policies.

**WARNING**: Some environments contain intentionally vulnerable applications. Never deploy to production or expose to untrusted networks.
