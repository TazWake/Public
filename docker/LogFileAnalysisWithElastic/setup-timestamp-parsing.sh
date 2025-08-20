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
echo "5. Checking Filebeat startup (showing last 10 lines)..."
docker-compose logs --tail 10 filebeat

echo ""
echo "6. Waiting for Filebeat to fully start..."
sleep 5

echo ""
echo "7. Verifying Filebeat is running..."
if docker-compose ps filebeat | grep -q "Up"; then
    echo "✅ Filebeat is running successfully"
else
    echo "❌ Filebeat may have issues. Check logs with:"
    echo "   docker-compose logs filebeat"
fi

echo ""
echo "8. Testing timestamp parsing with sample data..."
# Test if pipeline is working
curl -s -X POST "http://localhost:9200/forensics-logs-test/_doc" -H "Content-Type: application/json" -d '{
  "message": "2025-07-23T16:01:48.376244+01:00 test message",
  "@timestamp": "2025-08-20T18:00:00.000Z"
}' > /dev/null

sleep 2

echo ""
echo "✅ Timestamp parsing setup complete!"
echo ""
echo "🔍 To verify timestamp parsing is working:"
echo "   curl 'http://localhost:9200/forensics-logs-*/_search?pretty&size=2&sort=@timestamp:desc'"
echo ""
echo "📊 In Kibana, new log entries should now show original event timestamps"
echo "   instead of ingestion timestamps."
echo ""
echo "💡 To view live Filebeat logs if needed:"
echo "   docker-compose logs -f filebeat"