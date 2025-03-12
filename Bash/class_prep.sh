#!/bin/bash
# class_prep.sh - Script to clean system logs and prepare a fresh Linux VM for students

# Ensure the script is run as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (e.g., sudo ./class_prep.sh)"
    exit 1
fi

# Clear syslog and other log files
echo "[+] Clearing syslog and common log files..."
find /var/log -type f -exec truncate -s 0 {} \;

# Clear log rotation state
echo "[+] Resetting logrotate status..."
rm -f /var/lib/logrotate/status
logrotate -f /etc/logrotate.conf

# Clear user bash history
echo "[+] Clearing bash history..."
cat /dev/null > ~/.bash_history && history -c

# Clear temporary files
echo "[+] Clearing temporary files..."
rm -rf /tmp/*
rm -rf /var/tmp/*

# Clean package cache
echo "[+] Cleaning package cache..."
apt-get clean

# Clear systemd journal logs
echo "[+] Clearing systemd journal logs..."
journalctl --rotate
journalctl --vacuum-time=1s
rm -rf /var/log/journal/*
systemctl restart systemd-journald

# Final instructions
echo "[+] Cleanup complete. Reboot recommended."
read -p "Do you want to reboot now? (y/N): " choice
if [[ "$choice" =~ ^[Yy]$ ]]; then
    reboot
else
    echo "Reboot manually when ready."
fi
