#!/bin/bash

# This file is used to establish some auditing baselines related to CIS controls.
# STATUS: DRAFT
# Environment: 64bit Ubuntu
#
# based on https://gist.github.com/Neo23x0/9fe88c0c5979e017a389b90fd19ddfee
#
# USE:
# ./setAuditD.sh
# 
# NOTES:
# Must be run as root.
# It assumes auditd is installed - if it isnt:
#    apt install auditd audispd-plugins
# 
# Warning:
# This can be noisy. You should consider tuning any activity logged by this 
# before using as a SIEM trigger.

# Check Requirements
if [[ $EUID != 0 ]]; then
    echo "[!] This script must be run with root privileges!"
    echo "[!] Exiting"
    exit 255;
else
    echo "[ ] Audit set-up script running. New files will be created with a 60-* prefix."
    echo "[ ] Running with correct privileges."
fi

# Check for auditd
temp=$(dpkg -s auditd 2>/dev/null | grep installed | cut -d' ' -f3)
if [[ $temp != "ok" ]]; then
    echo "[!] auditd not installed. Installing it."
    apt install auditd audispd-plugins -y
fi

# Ensure Auditd is running
temp=$(systemctl is-enabled auditd 2>/dev/null)
if [[ $temp != "enabled" ]]; then
    echo "[!] Enabling the service."
    systemctl --now enable auditd
fi

# Noise reduction
# removing references to current working directory, SELinux AVC records, End of Entry events, Cron noise, and key refs for public facing systems.
# This bit may be broken
#echo "[ ] Reducing noise."
#echo "-a always,exclude -F msgtype=CWD
#-a always,exclude -F msgtype=AVC
#-a always,exclude -F msgtype=EOE
#-a never,user -F subj_type=crond_t
#-a exit,never -F subj_type=crond_t
#-a always,exclude -F msgtype=CRYPTO_KEY_USER" > /etc/audit/rules.d/50-noisereduction.rules

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

# Ensure use of privileged commands is collected
echo "[ ] Auditing Privileged command use."
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f | awk '{print "-a always,exit -F path=" $1 " -F perm=x -F auid>='"$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"' -F auid!=4294967295 -k privileged" }' >> /etc/audit/rules.d/60-privileged.rules

# Ensure successful file system mounts are collected
echo "[ ] Auditing file system mount events."
echo "-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" > /etc/audit/rules.d/60-mounts.rules

# Ensure file deletion events by users are collected
echo "[ ] Auditing file deletion events."
echo "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" > /etc/audit/rules.d/60-delete.rules

# Ensure changes to system administration scope (sudoers) is collected
echo "[ ] Auditing changes to sudoers file."
echo "-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope" > /etc/audit/rules.d/60-scope.rules

# Ensure system administrator command executions (sudo) are collected
echo "[ ] Auditing sudo use."
echo "-a always,exit -F arch=b64 -C euid!=uid -F euid=0 -F auid>=1000 -F auid!=4294967295 -S execve -k actions
-a always,exit -F arch=b32 -C euid!=uid -F euid=0 -F auid>=1000 -F auid!=4294967295 -S execve -k actions" > /etc/audit/rules.d/60-actions.rules

# Ensure kernel module loading and unloading is collected
echo "[ ] Auditing kernel module loads."
echo "-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules" > /etc/audit/rules.d/60-modules.rules

# Look for attacker behaviour
echo "[ ] Creating rules to audit common attacker behaviour."
echo "-a always,exit -F arch=b32 -S all -k 32bit_api
-w /usr/bin/whoami -p x -k recon
-w /etc/issue -p r -k recon
-w /etc/hostname -p r -k recon
-w /usr/bin/wget -p x -k suspicious
-w /usr/bin/curl -p x -k suspicious
-w /usr/bin/base64 -p x -k suspicious
-w /bin/nc -p x -k suspicious
-w /bin/netcat -p x -k suspicious
-w /usr/bin/ncat -p x -k suspicious
-w /usr/bin/ssh -p x -k suspicious
-w /usr/bin/socat -p x -k suspicious
-w /usr/bin/wireshark -p x -k suspicious
-w /usr/bin/rawshark -p x -k suspicious
-w /usr/bin/rdesktop -p x -k suspicious
-w /sbin/iptables -p x -k suspicious 
-w /sbin/ifconfig -p x -k suspicious
-w /usr/sbin/tcpdump -p x -k suspicious
-w /usr/sbin/traceroute -p x -k suspicious
-a always,exit -F arch=b32 -S ptrace -k tracing
-a always,exit -F arch=b64 -S ptrace -k tracing
-a always,exit -F arch=b32 -S ptrace -F a0=0x4 -k code_injection
-a always,exit -F arch=b64 -S ptrace -F a0=0x4 -k code_injection
-a always,exit -F arch=b32 -S ptrace -F a0=0x5 -k data_injection
-a always,exit -F arch=b64 -S ptrace -F a0=0x5 -k data_injection
-a always,exit -F arch=b32 -S ptrace -F a0=0x6 -k register_injection
-a always,exit -F arch=b64 -S ptrace -F a0=0x6 -k register_injection
-a always,exit -F dir=/home -F uid=0 -F auid>=1000 -F auid!=4294967295 -C auid!=obj_uid -k power_abuse" > /etc/audit/rules.d/60-attacker.rules

# Ensure the audit configuration is immutable
echo "[ ] Setting configuration to immutable."
echo "-e 2" > /etc/audit/rules.d/99-final.rules

# ##################################
# ###         END BLOCK          ###
# ##################################
echo "[!] Rule creation completed. Generating new audit.rules file."
augenrules
echo "[!] Restarting auditd."
systemctl restart auditd
echo "[!] Script complete."
