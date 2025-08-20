#!/bin/bash

echo "Creating Elasticsearch ingest pipeline for timestamp parsing..."

# Create ingest pipeline for parsing various log timestamp formats
curl -X PUT "http://localhost:9200/_ingest/pipeline/forensics-timestamp-parser" -H "Content-Type: application/json" -d '
{
  "description": "Parse timestamps from forensic log messages",
  "processors": [
    {
      "grok": {
        "field": "message",
        "patterns": [
          "%{TIMESTAMP_ISO8601:parsed_timestamp}",
          "%{SYSLOGTIMESTAMP:parsed_timestamp}",
          "\\[%{HTTPDATE:parsed_timestamp}\\]",
          "%{DATESTAMP:parsed_timestamp}"
        ],
        "ignore_failure": true
      }
    },
    {
      "date": {
        "field": "parsed_timestamp",
        "target_field": "@timestamp",
        "formats": [
          "yyyy-MM-dd'T'HH:mm:ss.SSSSSSXXXXX",
          "yyyy-MM-dd'T'HH:mm:ss.SSSXXXXX",
          "yyyy-MM-dd'T'HH:mm:ssXXXXX",
          "yyyy-MM-dd'T'HH:mm:ss.SSS",
          "yyyy-MM-dd'T'HH:mm:ss",
          "yyyy-MM-dd HH:mm:ss",
          "MMM dd HH:mm:ss",
          "MMM  d HH:mm:ss",
          "dd/MMM/yyyy:HH:mm:ss Z"
        ],
        "ignore_failure": true
      }
    },
    {
      "remove": {
        "field": "parsed_timestamp",
        "ignore_failure": true
      }
    }
  ]
}'

echo ""
echo "Ingest pipeline created!"
echo ""

# Test the pipeline with sample data
echo "Testing pipeline with sample log entries..."

curl -X POST "http://localhost:9200/_ingest/pipeline/forensics-timestamp-parser/_simulate" -H "Content-Type: application/json" -d '
{
  "docs": [
    {
      "_source": {
        "message": "2025-07-23T16:01:48.376244+01:00 snath kernel: pci_bus 0000:13: resource 0"
      }
    },
    {
      "_source": {
        "message": "Aug 20 17:45:01 server01 kernel: [12345.678] CPU: 0 PID: 1234"
      }
    },
    {
      "_source": {
        "message": "192.168.1.100 - - [20/Aug/2025:17:45:08 +0000] \"GET /index.html HTTP/1.1\" 200 1234"
      }
    }
  ]
}'

echo ""
echo ""
echo "✅ Pipeline ready! Now update Filebeat to use this pipeline:"
echo "Add this to filebeat.yml output.elasticsearch section:"
echo "  pipeline: forensics-timestamp-parser"