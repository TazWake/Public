#!/bin/bash
# Rootkit Detection Script for Educational Purposes
# Demonstrates forensic techniques for detecting the educational rootkit

echo "=== Rootkit Detection Script ==="
echo "This script demonstrates forensic techniques for detecting the educational rootkit."
echo ""

# Function to check for the rootkit
detect_rootkit() {
    echo "[*] Starting rootkit detection..."
    
    # 1. Check loaded modules
    echo "[1] Checking for suspicious kernel modules..."
    if lsmod | grep -q educational_rootkit; then
        echo "[ALERT] Educational rootkit module detected!"
        lsmod | grep educational_rootkit
    else
        echo "[-] Educational rootkit module not found in lsmod"
    fi
    
    # 2. Check /proc filesystem
    echo ""
    echo "[2] Checking /proc filesystem for anomalies..."
    if ls /proc/ | grep -q rootkit_forensics; then
        echo "[ALERT] Suspicious /proc entry found: rootkit_forensics"
        ls -la /proc/rootkit_forensics
    else
        echo "[-] No suspicious /proc entries found"
    fi
    
    # 3. Check kernel messages
    echo ""
    echo "[3] Checking kernel messages for rootkit loading..."
    dmesg_output=$(dmesg | grep educational_rootkit | tail -5)
    if [ -n "$dmesg_output" ]; then
        echo "[ALERT] Found educational rootkit messages in dmesg:"
        echo "$dmesg_output"
    else
        echo "[-] No educational rootkit messages found in dmesg"
    fi
    
    # 4. Check for hidden files (educational example)
    echo ""
    echo "[4] Checking for hidden files (educational example)..."
    # In a real forensic investigation, we would check various directories
    # For our educational example, we're just showing the concept
    echo "[-] No hidden files detected (educational rootkit doesn't actually hide files)"
    
    # 5. Check system call table (advanced detection)
    echo ""
    echo "[5] Advanced detection techniques..."
    echo "[-] In a real forensic investigation, we would analyze the syscall table"
    echo "[-] Tools like Volatility can be used for memory analysis"
    
    echo ""
    echo "[*] Detection complete."
}

# Function to collect forensic evidence
collect_evidence() {
    echo ""
    echo "=== Forensic Evidence Collection ==="
    
    echo "[*] Collecting evidence of rootkit presence..."
    
    # Create evidence directory
    evidence_dir="rootkit_evidence_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$evidence_dir"
    
    # Collect module information
    echo "[*] Collecting module information..."
    lsmod | grep educational_rootkit > "$evidence_dir/lsmod_output.txt" 2>/dev/null || echo "Module not loaded" > "$evidence_dir/lsmod_output.txt"
    
    # Collect kernel messages
    echo "[*] Collecting kernel messages..."
    dmesg | grep educational_rootkit > "$evidence_dir/dmesg_output.txt" 2>/dev/null || echo "No rootkit messages found" > "$evidence_dir/dmesg_output.txt"
    
    # Collect /proc information
    echo "[*] Collecting /proc information..."
    if [ -f /proc/rootkit_forensics ]; then
        cp /proc/rootkit_forensics "$evidence_dir/rootkit_forensics.txt"
    else
        echo "Forensic log not available" > "$evidence_dir/rootkit_forensics.txt"
    fi
    
    # Collect file information
    echo "[*] Collecting file information..."
    ls -la /proc/rootkit_forensics > "$evidence_dir/proc_listing.txt" 2>/dev/null || echo "Proc entry not found" > "$evidence_dir/proc_listing.txt"
    
    echo "[*] Evidence collected in $evidence_dir/"
    echo "[*] Evidence files:"
    ls -la "$evidence_dir"
}

# Main execution
echo "Rootkit Detection and Forensic Analysis"
echo "======================================="
echo ""

# Check if running as root (needed for some checks)
if [[ $EUID -ne 0 ]]; then
   echo "Warning: Not running as root. Some detection techniques may not work."
   echo ""
fi

# Run detection
detect_rootkit

# Collect evidence
collect_evidence

echo ""
echo "=== Analysis Summary ==="
echo "This educational example demonstrates common techniques used by real rootkits:"
echo "1. Kernel module loading"
echo "2. System call hooking"
echo "3. Proc filesystem manipulation"
echo "4. Kernel logging"
echo ""
echo "In real forensic investigations, additional techniques would be used:"
echo "- Memory analysis with tools like Volatility"
echo "- Syscall table integrity checking"
echo "- Network connection monitoring"
echo "- File system integrity checks"
echo ""
echo "For educational purposes, this rootkit is easily detectable because:"
echo "- It uses obvious module names"
echo "- It creates detectable /proc entries"
echo "- It logs its activities"
echo "- It doesn't actually hide itself well"