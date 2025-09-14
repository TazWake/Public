#!/bin/bash
# Educational script to demonstrate rootkit interaction
# For Linux Forensics Training

echo "=== Educational Rootkit Demonstration ==="
echo "This script demonstrates how to interact with the educational rootkit"
echo "for forensic analysis training."
echo ""

# Check if we're running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root to interact with kernel modules" 
   echo "Please run with sudo"
   exit 1
fi

echo "[*] Checking if educational_rootkit module is loaded..."
if lsmod | grep -q educational_rootkit; then
    echo "[+] Module is currently loaded"
else
    echo "[-] Module is not loaded"
fi

echo ""
echo "[*] Building the educational rootkit module..."
make clean
make

if [ $? -eq 0 ]; then
    echo "[+] Build successful"
else
    echo "[-] Build failed"
    exit 1
fi

echo ""
echo "[*] Loading the educational rootkit module..."
insmod educational_rootkit.ko

if [ $? -eq 0 ]; then
    echo "[+] Module loaded successfully"
else
    echo "[-] Failed to load module"
    exit 1
fi

echo ""
echo "[*] Checking kernel messages..."
dmesg | tail -10

echo ""
echo "[*] Checking /proc filesystem..."
ls -la /proc/rootkit_forensics 2>/dev/null
if [ $? -eq 0 ]; then
    echo "[+] Forensic log entry found"
else
    echo "[-] Forensic log entry not found"
fi

echo ""
echo "[*] Testing magic kill command (educational only)..."
# This demonstrates how rootkits might use signals for C&C
kill -64 1337

echo ""
echo "[*] Checking forensic log..."
if [ -f /proc/rootkit_forensics ]; then
    echo "--- Forensic Log Content ---"
    cat /proc/rootkit_forensics
    echo "--- End of Log ---"
else
    echo "Forensic log not available"
fi

echo ""
echo "[*] Module information:"
modinfo educational_rootkit.ko

echo ""
echo "[*] To unload the module, run:"
echo "sudo rmmod educational_rootkit"
echo ""
echo "=== End of Demonstration ==="