#!/bin/bash

echo "=== Filebeat Debug and Test Script ==="
echo ""

# Check what's in evidence directory
echo "1. Files in evidence directory:"
ls -la ./evidence/ 2>/dev/null || echo "No evidence directory found"
echo ""

# Create test data if evidence directory is empty
if [ ! -d "./evidence" ] || [ -z "$(ls -A ./evidence 2>/dev/null)" ]; then
    echo "2. Creating test evidence data..."
    mkdir -p ./evidence
    
    # Create sample syslog entries
    cat > ./evidence/syslog << EOF
Aug 20 17:45:01 server01 kernel: [12345.678] CPU: 0 PID: 1234 Comm: suspicious_process
Aug 20 17:45:02 server01 sshd[5678]: Failed login attempt from 192.168.1.100
Aug 20 17:45:03 server01 httpd: 404 error for /admin/config.php from 10.0.0.50
Aug 20 17:45:04 server01 kernel: [12346.789] segfault at 0x41414141 ip 0x41414141
EOF

    # Create sample auth log
    cat > ./evidence/auth.log << EOF
Aug 20 17:45:05 server01 sudo: user1 : TTY=pts/0 ; PWD=/home/user1 ; USER=root ; COMMAND=/bin/bash
Aug 20 17:45:06 server01 sshd[9876]: Accepted publickey for root from 203.0.113.1 port 12345 ssh2
Aug 20 17:45:07 server01 su: FAILED su for root from user2
EOF

    # Create sample access log  
    cat > ./evidence/access.log << EOF
192.168.1.100 - - [20/Aug/2025:17:45:08 +0000] "GET /index.html HTTP/1.1" 200 1234
10.0.0.50 - - [20/Aug/2025:17:45:09 +0000] "POST /login.php HTTP/1.1" 401 0
203.0.113.1 - - [20/Aug/2025:17:45:10 +0000] "GET /admin/backdoor.php HTTP/1.1" 404 156
EOF

    echo "   Created test files: syslog, auth.log, access.log"
else
    echo "2. Evidence directory has existing files:"
    ls -la ./evidence/
fi
echo ""

# Stop and restart services
echo "3. Restarting Filebeat service..."
docker-compose stop filebeat
sleep 2
docker-compose up -d filebeat
echo ""

# Wait a moment and check status
echo "4. Waiting for Filebeat to start..."
sleep 10

# Check container status
echo "5. Container status:"
docker-compose ps filebeat
echo ""

# Show recent logs
echo "6. Recent Filebeat logs:"
docker-compose logs --tail 20 filebeat
echo ""

# Test Filebeat configuration
echo "7. Testing Filebeat configuration:"
docker-compose exec filebeat filebeat test config 2>/dev/null || echo "Config test failed or container not ready"
echo ""

# Check if data is flowing to Elasticsearch
echo "8. Checking Elasticsearch for data:"
sleep 5
curl -s -X GET "http://localhost:9200/_cat/indices/forensics-logs-*?v" || echo "No forensics indices found"
echo ""

echo "9. Searching for any data:"
curl -s -X GET "http://localhost:9200/forensics-logs-*/_search?pretty&size=2" 2>/dev/null | head -20 || echo "No data found"
echo ""

echo "=== Debug complete ==="
echo ""
echo "If Filebeat is still failing:"
echo "- Check: docker-compose logs filebeat"  
echo "- Verify: ls -la ./evidence/"
echo "- Test config: docker-compose exec filebeat filebeat test config"