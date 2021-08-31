#!/bin/bash

# This file is used to establish some auditing baselines related to CIS controls.
# STATUS: DRAFT
# Environment: 64bit Ubuntu
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

# Check for auditd
temp=$(dpkg -s auditd | grep installed | cut -d' ' -f3)
if [ $temp != "ok" ]; then
    echo "[!] auditd not installed. Installing it."
    apt install auditd audispd-plugins -y
fi

# Ensure Auditd is running
temp=$(systemctl is-enabled auditd 2>/dev/null)
if [ $temp != "enabled" ]; then
    echo "[!] Enabling the service."
    systemctl --now enable auditd
fi

# Noise reduction
# removing references to current working directory, SELinux AVC records, End of Entry events, Cronn noise, Chrony and key refs for public facing systems.
echo "[ ] Reducing noise."
auditctl -a always,exclude -F msgtype=CWD
auditctl -a always,exclude -F msgtype=AVC
auditctl -a always,exclude -F msgtype=EOE
auditctl -a never,user -F subj_type=crond_t
auditctl -a exit,never -F subj_type=crond_t
auditctl -a never,exit -F arch=b64 -S adjtimex -F auid=unset -F uid=chrony -F subj_type=chronyd_t
auditctl -a always,exclude -F msgtype=CRYPTO_KEY_USER

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

# Ensure events that modify the system's network environment are collected 
echo "[ ] Auditing events that modify network environment."
echo "-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/network -p wa -k system-locale" > /etc/audit/rules.d/60-system-locale.rules

# Ensure events that modify the system's Mandatory Access Controls are collected 
echo "[ ] Auditing events that modify mandatory access controls. This requires apparmor."
echo "-w /etc/apparmor/ -p wa -k MAC-policy
-w /etc/apparmor.d/ -p wa -k MAC-policy" > /etc/audit/rules.d/60-MAC-policy.rules

# Ensure login and logout events are collected 
echo "[ ] Auditing login and logout events in faillog/lastlog/tallylog."
echo "-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins" > /etc/audit/rules.d/60-logins.rules

# Ensure session initiation information is collected 
echo "[ ] Auditing session initiation data."
echo "-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k logins
-w /var/log/btmp -p wa -k logins" > /etc/audit/rules.d/60-session.rules

# Ensure discretionary access control permission modification events are collected
echo "[ ] Auditing discretionary access control events."
echo "-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" > /etc/audit/rules.d/60-perm_mod.rules

# Ensure unsuccessful unauthorized file access attempts are collected
echo "[ ] Auditing unsuccessful unauthorised file access."
echo "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" > /etc/audit/rules.d/60-access.rules


# ##################################
# ###         END BLOCK          ###
# ##################################
augenrules
systemctl restart auditd
