#!/bin/bash

# Linux Log Analysis ELK Stack Setup Script
set -e

echo "Setting up Linux Log Analysis ELK Stack..."

# Create directory structure
mkdir -p evidence
mkdir -p filebeat/modules.d
mkdir -p kibana

# Set proper permissions
chmod 755 evidence filebeat kibana
chmod 644 filebeat/filebeat.yml kibana/kibana.yml 2>/dev/null || true

# Create .env file for configuration
cat > .env << EOF
COMPOSE_PROJECT_NAME=forensics-elk
ES_JAVA_OPTS=-Xms2g -Xmx2g
EOF

echo "Directory structure created:"
echo "  evidence/          <- Place your log files here"
echo "  filebeat/          <- Filebeat configuration"
echo "  kibana/            <- Kibana configuration"
echo ""

# Check if Docker and Docker Compose are available
if ! command -v docker &> /dev/null; then
    echo "ERROR: Docker is not installed or not in PATH"
    exit 1
fi

if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    echo "ERROR: Docker Compose is not installed or not in PATH"
    exit 1
fi

echo "Starting ELK stack..."

# Start the stack
if command -v docker-compose &> /dev/null; then
    docker-compose up -d
else
    docker compose up -d
fi

echo ""
echo "Waiting for services to be ready..."
sleep 30

# Check if Elasticsearch is ready
echo "Checking Elasticsearch health..."
for i in {1..30}; do
    if curl -s "http://localhost:9200/_cluster/health" > /dev/null 2>&1; then
        echo "Elasticsearch is ready!"
        break
    fi
    if [ $i -eq 30 ]; then
        echo "ERROR: Elasticsearch failed to start within timeout"
        exit 1
    fi
    sleep 2
done

# Check if Kibana is ready
echo "Checking Kibana health..."
for i in {1..30}; do
    if curl -s "http://localhost:5601/api/status" > /dev/null 2>&1; then
        echo "Kibana is ready!"
        break
    fi
    if [ $i -eq 30 ]; then
        echo "ERROR: Kibana failed to start within timeout"
        exit 1
    fi
    sleep 2
done

echo ""
echo "=== ELK Stack is ready for forensic analysis! ==="
echo ""
echo "Instructions:"
echo "1. Place your log files in the './evidence/' directory"
echo "2. Access Kibana at: http://localhost:5601"
echo "3. Create an index pattern: 'forensics-logs-*'"
echo "4. Use the log_type field to filter by log source:"
echo "   - syslog (syslog/messages)"
echo "   - apache_access (Apache access logs)"
echo "   - apache_error (Apache error logs)"
echo "   - audit (Linux audit logs)"
echo "   - auth (auth.log/secure)"
echo "   - dmesg (kernel/dmesg logs)"
echo "   - journal (systemd journal logs)"
echo "   - generic (other log files)"
echo ""
echo "Services running:"
echo "  - Elasticsearch: http://localhost:9200"
echo "  - Kibana: http://localhost:5601"
echo ""
echo "To stop the stack: docker-compose down"
echo "To view logs: docker-compose logs -f [service_name]"