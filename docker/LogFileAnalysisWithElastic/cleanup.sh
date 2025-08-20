#!/bin/bash

# ELK Stack Cleanup Script
# Purges all data and containers while preserving Docker images

echo "=== ELK Stack Cleanup and Reset ==="
echo ""
echo "This will:"
echo "- Stop and remove all ELK containers"
echo "- Delete all Elasticsearch data and indices" 
echo "- Remove all Filebeat registry data"
echo "- Clear Docker volumes"
echo "- Preserve Docker images (no re-download needed)"
echo ""

read -p "Are you sure you want to proceed? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Cleanup cancelled."
    exit 0
fi

echo "Starting cleanup..."

# Stop all services
echo "1. Stopping all ELK services..."
docker-compose down 2>/dev/null || true

# Remove containers (if they exist)
echo "2. Removing containers..."
docker rm -f elasticsearch kibana filebeat 2>/dev/null || true

# Remove named volumes
echo "3. Removing Docker volumes..."
docker volume rm forensics-elk_elasticsearch_data 2>/dev/null || echo "   elasticsearch_data volume not found"
docker volume rm forensics-elk_filebeat_data 2>/dev/null || echo "   filebeat_data volume not found"
docker volume rm $(docker-compose config --volumes 2>/dev/null | grep -E "(elasticsearch|filebeat)_data") 2>/dev/null || true

# Remove any orphaned volumes
echo "4. Cleaning up orphaned volumes..."
docker volume prune -f 2>/dev/null || true

# Remove networks created by docker-compose
echo "5. Removing Docker networks..."
docker network rm forensics-elk_elk 2>/dev/null || echo "   ELK network not found"

# Clear any local state files
echo "6. Clearing local state files..."
rm -rf .env 2>/dev/null || true

# Reset file permissions to current user
echo "7. Resetting file permissions..."
CURRENT_USER=$(id -u):$(id -g)
chown -R $CURRENT_USER . 2>/dev/null || true
chmod -R 644 evidence/ filebeat/ kibana/ 2>/dev/null || true
# chmod 644 filebeat/filebeat.yml kibana/kibana.yml 2>/dev/null || true

echo ""
echo "✅ Cleanup complete!"
echo ""
echo "Images preserved:"
docker images | grep -E "(elasticsearch|kibana|filebeat)" | grep "9.1.2"
echo ""
echo "To start fresh, run: ./setup.sh"
echo ""

# Optional: Show disk space recovered
echo "Docker system disk usage:"
docker system df