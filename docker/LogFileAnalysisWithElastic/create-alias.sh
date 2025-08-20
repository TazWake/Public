#!/bin/bash

echo "Creating Elasticsearch alias for easier Kibana access..."

# Create alias to make data streams accessible as regular indices
curl -X POST "http://localhost:9200/_aliases" -H "Content-Type: application/json" -d '
{
  "actions": [
    {
      "add": {
        "index": ".ds-forensics-logs-*",
        "alias": "forensics-logs"
      }
    }
  ]
}'

echo ""
echo "Verifying alias creation..."
curl -X GET "http://localhost:9200/_cat/aliases/forensics-logs?v"

echo ""
echo "Checking data through alias..."
curl -X GET "http://localhost:9200/forensics-logs/_search?size=1&pretty"

echo ""
echo "✅ Alias created! Now you can use 'forensics-logs' as your index pattern in Kibana."
echo ""
echo "In Kibana:"
echo "1. Go to Management → Stack Management → Data Views"
echo "2. Create data view with index pattern: forensics-logs"
echo "3. Select @timestamp as time field"