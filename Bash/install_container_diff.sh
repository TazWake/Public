#!/bin/bash

# This installs container diff on a Linux workstation.
# 
# This script needs to be run as root.

# Check perms

if [[ $EUID != 0 ]]; then
    echo "[!] This script must be run with root privileges!"
    echo "[!] Exiting"
    exit 255;
else
    echo "Initial check completed, script is running with correct privileges."
fi

# Install

echo "Installing"
mkdir -p /opt/container-diff
curl -L https://storage.googleapis.com/container-diff/latest/container-diff-linux-amd64 -o /opt/container-diff/container-diff-linux-amd64
install /opt/container-diff/container-diff-linux-amd64 /usr/local/bin/container-diff
echo "Installation completed"
