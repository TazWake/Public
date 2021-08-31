#!/bin/bash

# This file is used to establish some auditing baselines related to CIS controls.
# STATUS: DRAFT
#
# USE:
# ./setAuditD.sh
# 
# NOTES:
# Must be run as root.
# It assumes auditd is installed - if it isnt:
#    apt install auditd audispd-plugins

# Check Requirements
if [[ $EUID != 0 ]]; then
    echo "[!] This script must be run with root privileges!"
    echo "[!] Exiting"
    exit 255;
else
    echo "[ ] Audit set-up script running. New files will be created with a 60-* prefix."
    echo "[ ] Running with correct privilges."
fi

# Ensure Auditd is running
temp=$(systemctl is-enabled auditd 2>/dev/null)
if [ $temp != "enabled" ]; then
    echo "[!] Enabling the service."
    systemctl --now enable auditd
fi

# Set up auditing modules
# Ensure Events that modify date and time information are collected
echo "[ ] Enabling auditing for date and time changes."
echo "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k timechange
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change" > /etc/audit/rules.d/60-time-change.rules

# Ensure events that modify user/group information are collected
echo "[ ] Auditing events that modify user/group information."
echo "-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity" > /etc/audit/rules.d/60-identity.rules


