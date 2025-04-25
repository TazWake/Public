#!/bin/bash

# This script will automate setting up volatility 3 on an Ubuntu 24.04 linux system.
# Check Requirements
if [[ $EUID != 0 ]]; then
    echo "[!] This script must be run with root privileges!"
    echo "[!] Exiting"
    exit 255;
else
    echo "[ ] Running with correct privileges."
fi

echo "[ ] Installing dependencies"
apt update
apt install -y python3-pip python3-pefile python3-yara git
pip3 install pycryptodome --break-system-packages

echo "[ ] Setting up volatility"
mkdir -p /opt/tools
if [ ! -d "/opt/tools/volatility3" ]; then
  git clone https://github.com/volatilityfoundation/volatility3.git /opt/tools/volatility3
else
  echo "[ ] Updating existing volatility repository"
  cd /opt/tools/volatility3
  git pull
  cd - > /dev/null
fi
if [ ! -e /usr/local/bin/vol.py ]; then
  ln -s /opt/tools/volatility3/vol.py /usr/local/bin/vol.py
else
  echo "[ ] Symlink already exists"
fi
echo "[ ] Volatility now set up. Testing it is in the path."
vol.py -h | head -n1
