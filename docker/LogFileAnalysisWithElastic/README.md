# Linux Log Forensics ELK Stack

A Docker Compose setup for rapid deployment of Elasticsearch, Kibana, and Filebeat for Linux log analysis during incident response investigations.

## Quick Start

1. **Setup the environment:**
   ```bash
   chmod +x setup.sh
   ./setup.sh
   ```

2. **Place evidence files:**
   Copy your collected log files into the `evidence/` directory. Supported log types:
   - `syslog`, `messages` (system logs)
   - `access.log`, `access_log` (Apache access logs)  
   - `error.log`, `error_log` (Apache error logs)
   - `audit.log` (Linux audit logs)
   - `auth.log`, `secure` (authentication logs)
   - `dmesg`, `kern.log` (kernel logs)
   - `journal*.log` (systemd journal exports)

3. **Access Kibana:**
   Open http://localhost:5601 in your browser

4. **Create index pattern:**
   - Go to Stack Management → Index Patterns
   - Create pattern: `forensics-logs-*`
   - Select `@timestamp` as time field

## Log Type Filtering

Use the `log_type` field in Kibana to filter logs by source:
- `log_type:syslog` - System logs (syslog/messages)
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

- **RAM:** Minimum 4GB (2GB allocated to Elasticsearch)
- **Disk:** Varies based on log volume
- **Ports:** 9200 (Elasticsearch), 5601 (Kibana)

## Management Commands

```bash
# Start the stack
docker-compose up -d

# Stop the stack  
docker-compose down

# View service logs
docker-compose logs -f filebeat
docker-compose logs -f elasticsearch
docker-compose logs -f kibana

# Restart Filebeat after adding new files
docker-compose restart filebeat

# Check service status
docker-compose ps
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

**Elasticsearch won't start:**
- Ensure sufficient RAM (minimum 4GB system RAM)
- Check Docker memory limits: `docker stats`

**No data in Kibana:**
- Verify files are in `evidence/` directory
- Check Filebeat logs: `docker-compose logs filebeat`
- Restart Filebeat: `docker-compose restart filebeat`

**Permission issues:**
- Ensure evidence files are readable: `chmod -R 644 evidence/`
- Check container logs for permission errors

**Performance issues:**
- Adjust ES heap size in docker-compose.yml `ES_JAVA_OPTS`
- Reduce log ingestion by limiting file patterns in filebeat.yml

## Security Considerations

This setup disables Elasticsearch security for rapid deployment. For production investigations:
- Enable authentication and TLS
- Use dedicated networks
- Implement proper access controls
- Consider using Elastic Security features
