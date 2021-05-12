#!/bin/bash

# This a starter template to help people build
# triage evidence collection scripts. It is not 
# complete and, without tailoring will not
# function. 

# OBJECTIVE
# Use this as a framework to build your own Linux
# rapid response triage scripts. If you want, you 
# can even create something similar to KAPE.

# USE
# Before you deploy this script, make sure you have
# tailored into something that collects the evidence 
# you want/need for the incident you are working on.
# Remember you need to also take into consideration
# the target distro - Ubuntu uses /var/log/auth.log
# CentOS uses /var/log/secure - etc.
#
# Next get the script onto the target with a place to 
# store data and with an account that has root privs.
# Then execute the script with the storage location
# as the first argument.
# Example: ./triage.sh /mnt/usb/case001/

# SET VARIABLES
EVIDENCEPATH=$1 
LOGFILE=$EVIDENCEPATH/evidencelog.txt
TEMPNAME=$(cat /dev/urandom | tr -cd 'a-f0-9' | head -c 8)
TEMPFILE=$EVIDENCEPATH/$TEMPNAME

# DEFINE FUNCTIONS
# Hashfile function - takes file hash and updates logs
# NOTE if large files are expected, use MD5 hashes
# to save time.
hashfile() {
	file=$1
	if [ -f "$file" ]; then
	    hash=$(sha1sum $file)
	    echo "[#] SHA1 Hash: $hash" >> $LOGFILE
	    echo " " >> $LOGFILE
	else
	    echo "[!] There is a problem with the hash. Exiting"
	    exit 255;
	fi
}

# Check running as root and storage location is writable
if [[ $EUID != 0 ]]; then
    echo "[!] This script must be run with root privileges!"
    echo "[!] Exiting"
    exit 255;
else
    echo "- Running with correct privilges."
fi
touch $TEMPFILE
if [ -f $TEMPFILE  ]; then
    echo "- Write to storage media successful."
    rm $TEMPFILE
else
    echo "[!] Unable to write to storage media."
    echo "[!] Exiting."
    exit 255;
fi

# Set up the log file
echo "*******************" >> $LOGFILE
echo "EVIDENCE COLLECTION" >> $LOGFILE
echo "*******************" >> $LOGFILE
echo "Collection Started at $(date | cut -d' ' -f4,5)" >> $LOGFILE
echo "Evidence storage location: $EVIDENCEPATH" >> $LOGFILE

# GATHER DATA
# Consider collection from:
# History files
# User account data
# Login Data
# Audit logs
# Webserver logs
# Network connections
# Running processess

# EXAMPLE - Gather user account data
mkdir $EVIDENCEPATH/user_details # create storage locations for user files
cp /etc/passwd $EVIDENCEPATH/user_details/passwd_file.txt
echo "[ ] /etc/passwd copied to $EVIDENCEPATH/user_details/passwd_file.txt at $(date | cut -d' ' -f4,5)" >> $LOGFILE
hashfile $EVIDENCEPATH/user_details/passwd_file.txt
stat /etc/passwd > $EVIDENCEPATH/user_details/stat_passwd.txt
echo "[ ] Passwd file status copied to $EVIDENCEPATH/user_details/stat_passwd.txt at $(date | cut -d' ' -f4,5)" >> $LOGFILE
hashfile $EVIDENCEPATH/user_details/stat_passwd.txt
echo "[!] Password file last modified at $(grep Modify $EVIDENCEPATH/user_details/stat_passwd.txt | cut -d' ' -f2-)" >> $LOGFILE
cp /etc/shadow $EVIDENCEPATH/user_details/shadow_file.txt
echo "[ ] /etc/shadow copied to $EVIDENCEPATH/user_details/shadow_file.txt at $(date | cut -d' ' -f4,5)" >> $LOGFILE
hashfile $EVIDENCEPATH/user_details/shadow_file.txt
stat /etc/shadow > $EVIDENCEPATH/user_details/stat_shadow.txt
echo "[ ] Shadow file status copied to $EVIDENCEPATH/user_details/stat_shadow.txt at $(date | cut -d' ' -f4,5)" >> $LOGFILE
hashfile $EVIDENCEPATH/user_details/stat_passwd.txt
echo "[!] Shadow file last modified at $(grep Modify $EVIDENCEPATH/user_details/stat_shadow.txt | cut -d' ' -f2-)" >> $LOGFILE
echo "[!] The following user accounts have login shells on the system:" >> $LOGFILE
cat /etc/passwd | grep -v nologin | grep -v shutdow | grep sh >> $LOGFILE
cp /etc/group $EVIDENCEPATH/user_details/group_file.txt
echo "[ ] /etc/shadow copied to $EVIDENCEPATH/user_details/group_file.txt at $(date | cut -d' ' -f4,5)" >> $LOGFILE
hashfile $EVIDENCEPATH/user_details/group_file.txt
stat /etc/group > $EVIDENCEPATH/user_details/stat_group.txt
echo "[ ] Groups file status copied to $EVIDENCEPATH/user_details/stat_group.txt at $(date | cut -d' ' -f4,5)" >> $LOGFILE
hashfile $EVIDENCEPATH/user_details/stat_group.txt
echo "[!] Groups file last modified at $(grep Modify $EVIDENCEPATH/user_details/stat_group.txt | cut -d' ' -f2-)" >> $LOGFILE
echo "- User / Login Data Extracted"

# EXAMPLE - Gather login data
mkdir $EVIDENCEPATH/logindata # create storage locations for login data
cp /var/log/btmp $EVIDENCEPATH/logindata/btmp
echo "[ ] BTMP extracted to $EVIDENCEPATH/logindata/btmp at $(date | cut -d' ' -f4,5)" >> $LOGFILE
hashfile $EVIDENCEPATH/logindata/btmp
cp /var/log/btmp $EVIDENCEPATH/logindata/wtmp
echo "[ ] WTMP extracted to $EVIDENCEPATH/logindata/wtmp at $(date | cut -d' ' -f4,5)" >> $LOGFILE
hashfile $EVIDENCEPATH/logindata/wtmp
cp /var/run/utmp $EVIDENCEPATH/logindata/utmp
echo "[ ] UTMP extracted to $EVIDENCEPATH/logindata/utmp at $(date | cut -d' ' -f4,5)" >> $LOGFILE
hashfile $EVIDENCEPATH/logindata/utmp

# EXAMPLE - Gather Root history
mkdir $EVIDENCEPATH/history # create storage locations for history files
cp /root/.bash_history $EVIDENCEPATH/history/root_bash_history.txt
echo "[ ] Root History copied to $EVIDENCEPATH/history/root_bash_history.txt at $(date | cut -d' ' -f4,5)" >> $LOGFILE
hashfile $EVIDENCEPATH/history/root_bash_history.txt
echo "- Root Bash History Extracted"
