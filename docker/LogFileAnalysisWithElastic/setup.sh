#!/bin/bash

# Linux Log Analysis ELK Stack Setup Script
set -e

# Check for help option
if [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
    echo "ELK Stack Setup Script"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --clean, -c    Clean start: remove all existing data and containers first"
    echo "  --help, -h     Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0             # Normal setup"
    echo "  $0 --clean     # Clean start (removes all data)"
    echo ""
    exit 0
fi

# Check for clean start option
if [ "$1" = "--clean" ] || [ "$1" = "-c" ]; then
    echo "🧹 Clean start requested - running cleanup first..."
    if [ -f "./cleanup.sh" ]; then
        ./cleanup.sh
        echo ""
        echo "Proceeding with fresh setup..."
        echo ""
    else
        echo "❌ cleanup.sh not found. Please run cleanup manually if needed."
        exit 1
    fi
fi

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: This script requires root privileges to run Docker commands."
    echo "Please run with: sudo $0"
    echo ""
    echo "Note: Docker requires root privileges to manage containers and networks."
    echo "Alternatively, you can add your user to the docker group and run without sudo:"
    echo "  sudo usermod -aG docker \$USER"
    echo "  # Then log out and back in, or run: newgrp docker"
    exit 1
fi

echo "Setting up Linux Log Analysis ELK Stack..."

# Create directory structure
mkdir -p evidence
mkdir -p filebeat/modules.d
mkdir -p kibana

# Set proper permissions and ownership
chmod 755 evidence filebeat kibana
chmod 644 filebeat/filebeat.yml kibana/kibana.yml 2>/dev/null || true

# Check and fix file ownership for Docker compatibility
echo "Checking file ownership..."
CURRENT_USER=$(id -u):$(id -g)
if [ -f "filebeat/filebeat.yml" ]; then
    FILEBEAT_OWNER=$(stat -c "%u:%g" filebeat/filebeat.yml)
    if [ "$FILEBEAT_OWNER" != "$CURRENT_USER" ]; then
        echo "⚠️  WARNING: filebeat.yml ownership needs to be corrected"
        echo "   Current owner: $FILEBEAT_OWNER"
        echo "   Required owner: $CURRENT_USER"
        echo "   Fixing ownership..."
        chown $CURRENT_USER filebeat/filebeat.yml || {
            echo "❌ Failed to change ownership. Try running:"
            echo "   sudo chown $USER:$USER filebeat/filebeat.yml"
            exit 1
        }
        echo "✅ File ownership corrected"
    fi
fi

if [ -f "kibana/kibana.yml" ]; then
    KIBANA_OWNER=$(stat -c "%u:%g" kibana/kibana.yml)
    if [ "$KIBANA_OWNER" != "$CURRENT_USER" ]; then
        echo "⚠️  WARNING: kibana.yml ownership needs to be corrected"
        chown $CURRENT_USER kibana/kibana.yml 2>/dev/null || {
            echo "❌ Failed to change kibana.yml ownership. Try running:"
            echo "   sudo chown $USER:$USER kibana/kibana.yml"
        }
    fi
fi

# Set proper permissions for evidence directory
if [ -d "evidence" ]; then
    chown -R $CURRENT_USER evidence/ 2>/dev/null || true
    chmod -R 644 evidence/* 2>/dev/null || true
    chmod 755 evidence/ 2>/dev/null || true
fi

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
for i in {1..60}; do
    # First check if container is running
    if ! docker ps | grep -q kibana; then
        echo "Kibana container not running, checking logs..."
        docker-compose logs --tail 10 kibana
    fi
    
    # Check Kibana status endpoint
    if curl -s -I "http://localhost:5601" | grep -q "200\|302"; then
        echo "Kibana is ready!"
        break
    fi
    
    # More detailed check for Kibana API
    if curl -s "http://localhost:5601/api/status" > /dev/null 2>&1; then
        echo "Kibana API is ready!"
        break
    fi
    
    if [ $i -eq 60 ]; then
        echo "ERROR: Kibana failed to start within timeout"
        echo "Checking Kibana logs for errors:"
        docker-compose logs --tail 20 kibana
        echo ""
        echo "Checking container status:"
        docker-compose ps
        exit 1
    fi
    
    # Show progress every 10 iterations
    if [ $((i % 10)) -eq 0 ]; then
        echo "Still waiting for Kibana... ($i/60)"
        docker-compose logs --tail 5 kibana
    fi
    
    sleep 2
done

echo ""
echo "=== ELK Stack is ready for forensic analysis! ==="
echo ""
echo "⚠️  IMPORTANT: Kibana may take 3-5 minutes to fully initialize."
echo "    If http://localhost:5601 shows 'connection reset', wait a few minutes and try again."
echo ""

# Check if evidence files exist and show status
echo "📁 Evidence Directory Status:"
if [ -d "./evidence" ] && [ "$(ls -A ./evidence 2>/dev/null)" ]; then
    echo "   Files found in evidence directory:"
    ls -la ./evidence/ | grep -v "^total" | head -10
    if [ "$(ls ./evidence/ | wc -l)" -gt 10 ]; then
        echo "   ... and $(($(ls ./evidence/ | wc -l) - 10)) more files"
    fi
    echo ""
    echo "   ⏳ Filebeat will start processing these files automatically."
    echo "   🔍 Check data ingestion in 1-2 minutes with:"
    echo "      curl 'http://localhost:9200/_cat/indices/forensics-logs-*?v'"
else
    echo "   ⚠️  No files found in ./evidence/ directory"
    echo "   📝 Add your log files to ./evidence/ then restart Filebeat:"
    echo "      docker-compose restart filebeat"
fi
echo ""

echo "📋 Next Steps:"
echo "1. Place your log files in the './evidence/' directory"
echo "2. Access Kibana at: http://localhost:5601 (wait 3-5 minutes after setup)"
echo ""
echo "🔧 To view data in Kibana 9.x:"
echo "   • Click hamburger menu (☰) → Management → Stack Management"
echo "   • Under 'Kibana' section, click 'Data Views'"
echo "   • Click 'Create data view'"
echo "   • Name: 'Forensics Logs'"
echo "   • Index pattern: 'forensics-logs-*'"
echo "   • Timestamp field: '@timestamp'"
echo "   • Click 'Save data view to Kibana'"
echo "   • Go to Analytics → Discover to view your data"
echo ""
echo "🔍 Filter data using the log_type field:"
echo "   - log_type:forensic (log files from evidence)"
echo "   - log_type:misc_evidence (other files from evidence)"
echo ""
echo "⏰ To parse original timestamps from log messages:"
echo "   Run: ./setup-timestamp-parsing.sh"
echo "   This will extract event timestamps instead of ingestion time"
echo ""
echo "Services running:"
echo "  - Elasticsearch: http://localhost:9200"
echo "  - Kibana: http://localhost:5601"
echo ""
echo "🔧 Useful commands:"
echo "  - Stop the stack: docker compose down"
echo "  - View logs: docker compose logs -f [service_name]"
echo "  - Check data ingestion: curl 'http://localhost:9200/_cat/indices/forensics-logs-*?v'"
echo "  - Clean restart: ./setup.sh --clean"
echo ""
echo "📖 For detailed instructions, see README.md"