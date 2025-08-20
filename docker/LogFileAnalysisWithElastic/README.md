# Linux Log Forensics ELK Stack

A Docker Compose setup for rapid deployment of Elasticsearch, Kibana, and Filebeat for Linux log analysis during incident response investigations.

## System Requirements

### Hardware Requirements
- **RAM:** Minimum 6GB system RAM (4GB allocated to Elasticsearch, 1GB to Kibana, 512MB to Filebeat)
- **CPU:** Minimum 2 CPU cores (Elasticsearch requires 2 cores, Kibana 1 core, Filebeat 0.5 cores)
- **Disk:** Minimum 20GB available space (varies based on log volume and retention)
- **Network:** Internet access for Docker image downloads

### Software Requirements
- **Operating System:** Linux (Ubuntu 20.04+, RHEL/CentOS 8+, SUSE Linux Enterprise 15+)
- **Docker:** Version 20.10+ with Docker Compose support
- **curl:** For health checks and testing connectivity
- **Git:** For cloning the repository (optional)

## Pre-Installation Setup

### Ubuntu 20.04+ / Debian 11+

```bash
# Update package lists
sudo apt update

# Install required packages
sudo apt install -y \
    apt-transport-https \
    ca-certificates \
    curl \
    gnupg \
    lsb-release \
    software-properties-common \
    git

# Add Docker's official GPG key
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg

# Add Docker repository
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Update package lists
sudo apt update

# Install Docker Engine
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

# Add user to docker group (replace $USER with your username)
sudo usermod -aG docker $USER

# Start and enable Docker service
sudo systemctl start docker
sudo systemctl enable docker

# Verify Docker installation
docker --version
docker compose version

# Log out and back in for group changes to take effect
# Or run: newgrp docker
```

### Red Hat Enterprise Linux 8+ / CentOS 8+ / Rocky Linux 8+

```bash
# Enable required repositories
sudo dnf install -y epel-release
sudo dnf config-manager --add-repo=https://download.docker.com/linux/centos/docker-ce.repo

# Install required packages
sudo dnf install -y \
    curl \
    git \
    policycoreutils-python-utils

# Install Docker Engine
sudo dnf install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

# Start and enable Docker service
sudo systemctl start docker
sudo systemctl enable docker

# Add user to docker group (replace $USER with your username)
sudo usermod -aG docker $USER

# Verify Docker installation
docker --version
docker compose version

# Log out and back in for group changes to take effect
# Or run: newgrp docker
```

### SUSE Linux Enterprise 15+ / openSUSE 15+

```bash
# Update package lists
sudo zypper refresh

# Install required packages
sudo zypper install -y \
    curl \
    git \
    python3-pip

# Add Docker repository
sudo zypper addrepo https://download.docker.com/linux/sles/docker-ce.repo

# Install Docker Engine
sudo zypper install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

# Start and enable Docker service
sudo systemctl start docker
sudo systemctl enable docker

# Add user to docker group (replace $USER with your username)
sudo usermod -aG docker $USER

# Verify Docker installation
docker --version
docker compose version

# Log out and back in for group changes to take effect
# Or run: newgrp docker
```

### System Configuration

```bash
# Increase virtual memory for Elasticsearch
echo 'vm.max_map_count=262144' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# Set proper file descriptor limits
echo '* soft nofile 65536' | sudo tee -a /etc/security/limits.conf
echo '* hard nofile 65536' | sudo tee -a /etc/security/limits.conf

# For RHEL/CentOS/SUSE, also add to /etc/security/limits.d/99-docker.conf
echo 'root soft nofile 65536' | sudo tee /etc/security/limits.d/99-docker.conf
echo 'root hard nofile 65536' | sudo tee -a /etc/security/limits.d/99-docker.conf
```

## Quick Start

1. **Clone or download the project:**
   ```bash
   git clone <repository-url>
   cd LogFileAnalysisWithElastic
   # Or download and extract the ZIP file
   ```

2. **Setup the environment:**
   ```bash
   chmod +x setup.sh
   ./setup.sh
   ```

3. **Place evidence files:**
   Copy your collected log files into the `evidence/` directory. Supported log types:
   - `syslog`, `messages` (system logs)
   - `access.log`, `access_log` (Apache access logs)  
   - `error.log`, `error_log` (Apache error logs)
   - `audit.log` (Linux audit logs)
   - `auth.log`, `secure` (authentication logs)
   - `dmesg`, `kern.log` (kernel logs)
   - `journal*.log` (systemd journal exports)

4. **Access Kibana:**
   Open http://localhost:5601 in your browser (wait 3-5 minutes for full initialization)

5. **Create Data View in Kibana 9.x:**
   - Click the hamburger menu (☰) in the top-left
   - Navigate to **Management** → **Stack Management**
   - Under **Kibana** section, click **Data Views**
   - Click **Create data view**
   - Name: `Forensics Logs`
   - Index pattern: `forensics-logs-*`
   - Select `@timestamp` as timestamp field
   - Click **Save data view to Kibana**

## Log Type Filtering

6. **Access your data:**
   - Go to **Analytics** → **Discover** 
   - Select your **Forensics Logs** data view
   - You should now see all ingested log data

## Timestamp Parsing

By default, Filebeat uses ingestion timestamps. To parse original event timestamps from log messages:

```bash
./setup-timestamp-parsing.sh
```

This creates an Elasticsearch ingest pipeline that extracts timestamps from various log formats:
- **ISO 8601**: `2025-07-23T16:01:48.376244+01:00`
- **Syslog**: `Aug 20 17:45:01`
- **Apache**: `[20/Aug/2025:17:45:08 +0000]`
- **RFC 3339**: `2025-08-20 17:45:01`

After setup, new log entries will use their original event timestamps instead of ingestion time.

## Log Type Filtering

Use the `log_type` field in Kibana to filter logs by source:
- `log_type:forensic` - All log files from evidence directory
- `log_type:misc_evidence` - Non-log files from evidence directory
- `log_type:apache_access` - Apache access logs
- `log_type:apache_error` - Apache error logs  
- `log_type:audit` - Linux audit logs
- `log_type:auth` - Authentication logs
- `log_type:dmesg` - Kernel/dmesg logs
- `log_type:journal` - Systemd journal logs
- `log_type:generic` - Other log files

## Directory Structure

```
├── docker-compose.yml      # Main orchestration file
├── setup.sh               # Automated setup script
├── evidence/              # Place log files here
├── filebeat/
│   └── filebeat.yml       # Log ingestion configuration
└── kibana/
    └── kibana.yml         # Kibana configuration
```

## Resource Requirements

- **RAM:** Minimum 6GB system RAM
  - Elasticsearch: 2-4GB allocated
  - Kibana: 512MB-1GB allocated
  - Filebeat: 256MB-512MB allocated
- **CPU:** Minimum 2 CPU cores
- **Disk:** Varies based on log volume and retention period
- **Ports:** 9200 (Elasticsearch), 5601 (Kibana)

## Management Commands

```bash
# Start the stack
docker compose up -d

# Stop the stack  
docker compose down

# View service logs
docker compose logs -f filebeat
docker compose logs -f elasticsearch
docker compose logs -f kibana

# Restart Filebeat after adding new files
docker compose restart filebeat

# Check service status
docker compose ps

# Check resource usage
docker stats
```

## Evidence File Placement

The system monitors the `evidence/` directory for these file patterns:

**System Logs:**
- `evidence/syslog*`
- `evidence/messages*`
- `evidence/var/log/syslog*`
- `evidence/var/log/messages*`

**Web Server Logs:**
- `evidence/access.log*`
- `evidence/error.log*`
- `evidence/var/log/apache*/access*.log*`
- `evidence/var/log/httpd/error*.log*`

**Security Logs:**
- `evidence/audit.log*`
- `evidence/auth.log*`
- `evidence/secure*`
- `evidence/var/log/audit/audit.log*`

**Kernel Logs:**
- `evidence/dmesg*`
- `evidence/var/log/dmesg*`
- `evidence/var/log/kern.log*`

**Journal Logs:**
- `evidence/journal*.log*`
- `evidence/systemd*.log*`

## Troubleshooting

**Docker not found:**
- Ensure Docker is installed and running: `sudo systemctl status docker`
- Verify user is in docker group: `groups $USER`
- Restart Docker service: `sudo systemctl restart docker`

**Elasticsearch won't start:**
- Ensure sufficient RAM (minimum 6GB system RAM)
- Check virtual memory settings: `sysctl vm.max_map_count`
- Check Docker memory limits: `docker stats`
- Verify system limits: `ulimit -n`

**No data in Kibana:**
- Verify files are in `evidence/` directory
- Check Filebeat logs: `docker compose logs filebeat`
- Restart Filebeat: `docker compose restart filebeat`
- Verify file permissions: `ls -la evidence/`
- Ensure you created the Data View with correct index pattern: `forensics-logs-*`
- Check data exists in Elasticsearch: `curl 'http://localhost:9200/_cat/indices/forensics-logs-*?v'`
- If using data streams (.ds- indices), run: `./create-alias.sh` to create a simpler alias

**Permission issues:**
- Ensure evidence files are readable: `chmod -R 644 evidence/`
- Check container logs for permission errors
- Verify Docker user permissions: `docker compose exec filebeat ls -la /evidence`

**Performance issues:**
- Adjust ES heap size in docker-compose.yml `ES_JAVA_OPTS`
- Reduce log ingestion by limiting file patterns in filebeat.yml
- Monitor resource usage: `docker stats`
- Check system resource limits: `ulimit -a`

**Port conflicts:**
- Check if ports 9200 or 5601 are already in use: `netstat -tlnp | grep -E ':(9200|5601)'`
- Stop conflicting services or modify ports in docker-compose.yml

## Security Considerations

This setup disables Elasticsearch security for rapid deployment. For production investigations:
- Enable authentication and TLS
- Use dedicated networks
- Implement proper access controls
- Consider using Elastic Security features
- Restrict Docker daemon access
- Use read-only volumes where possible

## Support and Maintenance

### Updating Components
```bash
# Pull latest images
docker compose pull

# Restart services with new images
docker compose up -d

# Clean up old images
docker image prune -f
```

### Backup and Recovery
```bash
# Backup Elasticsearch data
docker run --rm -v elasticsearch_data:/data -v $(pwd):/backup alpine tar czf /backup/elasticsearch_backup.tar.gz -C /data .

# Restore from backup
docker run --rm -v elasticsearch_data:/data -v $(pwd):/backup alpine tar xzf /backup/elasticsearch_backup.tar.gz -C /data
```

### Log Rotation
The system automatically rotates Docker logs to prevent disk space issues. Logs are kept for 7 days with a maximum size of 10MB per file.
