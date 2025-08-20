#!/bin/bash

echo "=== ELK Stack Status Check ==="
echo ""

# Check container status
echo "📋 Container Status:"
docker-compose ps
echo ""

# Check if Elasticsearch is responding
echo "🔍 Elasticsearch Health:"
curl -s -X GET "http://localhost:9200/_cluster/health" | python3 -m json.tool 2>/dev/null || echo "Elasticsearch not responding"
echo ""

# Check indices
echo "📊 Available Indices:"
curl -s -X GET "http://localhost:9200/_cat/indices/forensics-logs-*?v" 2>/dev/null || echo "No forensics indices found"
echo ""

# Check if data exists
echo "📈 Data Sample (latest 2 entries):"
DATA_CHECK=$(curl -s -X GET "http://localhost:9200/forensics-logs-*/_search?size=2&sort=@timestamp:desc&pretty" 2>/dev/null)
if echo "$DATA_CHECK" | grep -q '"hits"'; then
    echo "$DATA_CHECK" | head -30
    echo "..."
    TOTAL_DOCS=$(echo "$DATA_CHECK" | grep '"value"' | head -1 | grep -o '[0-9]\+')
    echo "Total documents: $TOTAL_DOCS"
else
    echo "No data found in indices"
fi
echo ""

# Check Kibana access
echo "🌐 Kibana Access:"
KIBANA_STATUS=$(curl -s -I "http://localhost:5601" 2>/dev/null | head -1)
if echo "$KIBANA_STATUS" | grep -q "200\|302"; then
    echo "✅ Kibana is accessible at http://localhost:5601"
else
    echo "❌ Kibana not accessible"
fi
echo ""

# Check evidence directory
echo "📁 Evidence Directory:"
if [ -d "./evidence" ]; then
    FILE_COUNT=$(ls -1 ./evidence/ 2>/dev/null | wc -l)
    echo "Files in evidence directory: $FILE_COUNT"
    if [ $FILE_COUNT -gt 0 ]; then
        echo "Recent files:"
        ls -la ./evidence/ | head -5
    fi
else
    echo "No evidence directory found"
fi
echo ""

# Check if timestamp parsing is active
echo "⏰ Timestamp Parsing:"
PIPELINE_CHECK=$(curl -s -X GET "http://localhost:9200/_ingest/pipeline/forensics-timestamp-parser" 2>/dev/null)
if echo "$PIPELINE_CHECK" | grep -q '"description"'; then
    echo "✅ Timestamp parsing pipeline is active"
else
    echo "❌ Timestamp parsing not configured"
    echo "   Run: ./setup-timestamp-parsing.sh"
fi
echo ""

echo "=== Status Check Complete ==="