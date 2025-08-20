#!/bin/bash

echo "=== Setting up Timestamp Parsing for Forensic Logs ==="
echo ""

echo "1. Creating Elasticsearch ingest pipeline..."
./create-ingest-pipeline.sh

echo ""
echo "2. Restarting Filebeat to apply new configuration..."
docker-compose restart filebeat

echo ""
echo "3. Waiting for Filebeat to restart..."
sleep 10

echo ""
echo "4. Checking Filebeat status..."
docker-compose ps filebeat

echo ""
echo "5. Monitoring Filebeat logs (Ctrl+C to stop)..."
echo "   Look for 'filebeat start running' message"
echo ""
docker-compose logs -f filebeat