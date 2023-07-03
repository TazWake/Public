#!/bin/bash

# This a template to help people build
# triage evidence collection scripts. It is not
# complete and, without tailoring will not
# function.

# ########
# WARNING
# ########
# In the format shown here, this is tailored to run
# on FOR608 data.
# This means the searches will look for specific 
# dates and specific user names. It WILL NOT work 
# in a different environment without modification.

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
DATA=$1
EVIDENCE=$2
LOGFILE=$EVIDENCE/triage-log-$(date | cut -d' ' -f2-3,6 | tr ' ' '_').txt
TEMPNAME=$(cat /dev/urandom | tr -cd 'a-f0-9' | head -c 8)
TEMPFILE=$EVIDENCE/$TEMPNAME

# DEFINE FUNCTIONS
hashfile() {
	file=$1
	sleep 0.25 # pause to ensure file writes have completed
	if [ -f "$file" ]; then
	    hash=$(sha1sum $file)
	    echo "[#] SHA1 Hash: $hash" >> $LOGFILE
	    echo " " >> $LOGFILE
	    sleep 0.25
	else
	    echo "[!] There is a problem with the hash. Exiting"
	    exit 255;
	fi
}

# CHECK PERMS
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

# INPUT DATES
# No sanitisation takes place here, other than to check a date has been entered.
# For a production script this should be modifited to prevent external parties compromising the server.
echo "Script exectuion will start soon. Please provide some additional details."
read -p "Enter the earliest date you want to search for (yyyy/mm/dd): " sdate
if [ "z$sdate" != "z" ] && date -d "$sdate" >/dev/null; then
    read -p "Enter the latest date you want to search for (yyyy/mm/dd):" edate
    if [ "z$edate" != "z" ] && date -d "$edate" >/dev/null; then
    echo "[*] Date ranges selected."
    echo "[*] Searches will run from $sdate to $edate."
    echo "[!] WARNING: The usernames hunted down will still include exercise date unless it has been manually changed"
    else
        echo "Invalid end date entered."
	exit 255;
    fi
else 
    echo "Invalid start date entered."
    exit 255;
fi

# SET UP LOGGING
echo "*******************" >> $LOGFILE
echo "EVIDENCE COLLECTION" >> $LOGFILE
echo "*******************" >> $LOGFILE
echo "Collection Started at $(date | cut -d' ' -f4,5)" >> $LOGFILE
echo "Evidence storage location: $EVIDENCE" >> $LOGFILE

# SYSTEM PROFILE
echo "System Information" > $EVIDENCE/environment.txt
echo "==================" >> $EVIDENCE/environment.txt
if [ -f $DATA/etc/os-release ]; then
    echo "# SYSTEM PROFILE #" >> $LOGFILE
    echo "[ ] OS / Build: $(cat $DATA/etc/os-release | grep PRETTY | cut -d'"' -f2)" >> $LOGFILE
    cat $DATA/etc/os-release >> $EVIDENCE/environment.txt
fi
echo "[ ] HOSTNAME: $(cat $DATA/etc/hostname)" >> $LOGFILE
echo "HOSTNAME: $(cat $DATA/etc/hostname)" >> $EVIDENCE/environment.txt
echo "FILESYSTEM:" >> $EVIDENCE/environment.txt
cat $DATA/etc/fstab >> $EVIDENCE/environment.txt

# CARVE DATA
# User Accounts
mkdir $EVIDENCE/user_details # create storage locations for user files
cp $DATA/etc/passwd $EVIDENCE/user_details/passwd_file.txt
echo "[ ] $DATA/etc/passwd copied to $EVIDENCE/user_details/passwd_file.txt" >> $LOGFILE
hashfile $EVIDENCE/user_details/passwd_file.txt
stat $DATA/etc/passwd > $EVIDENCE/user_details/stat_passwd.txt
echo "[ ] Passwd file status copied to $EVIDENCE/user_details/stat_passwd.txt" >> $LOGFILE
hashfile $EVIDENCE/user_details/stat_passwd.txt
echo "[!] Password file last modified at $(grep Modify $EVIDENCE/user_details/stat_passwd.txt | cut -d' ' -f2-)" >> $LOGFILE
cp $DATA/etc/shadow $EVIDENCE/user_details/shadow_file.txt
echo "[ ] $DATA/etc/shadow copied to $EVIDENCE/user_details/shadow_file.txt" >> $LOGFILE
hashfile $EVIDENCE/user_details/shadow_file.txt
stat $DATA/etc/shadow > $EVIDENCE/user_details/stat_shadow.txt
echo "[ ] Shadow file status copied to $EVIDENCE/user_details/stat_shadow.txt" >> $LOGFILE
hashfile $EVIDENCE/user_details/stat_passwd.txt
echo "[!] Shadow file last modified at $(grep Modify $EVIDENCE/user_details/stat_shadow.txt | cut -d' ' -f2-)" >> $LOGFILE
echo "[!] The following user accounts have login shells on the system:" >> $LOGFILE
cat $DATA/etc/passwd | grep -v nologin | grep -v shutdow | grep sh >> $LOGFILE
cp $DATA/etc/group $EVIDENCE/user_details/group_file.txt
echo "[ ] $DATA/etc/shadow copied to $EVIDENCE/user_details/group_file.txt" >> $LOGFILE
hashfile $EVIDENCE/user_details/group_file.txt
stat $DATA/etc/group > $EVIDENCE/user_details/stat_group.txt
echo "[ ] Groups file status copied to $EVIDENCE/user_details/stat_group.txt" >> $LOGFILE
hashfile $EVIDENCE/user_details/stat_group.txt
echo "[!] Groups file last modified at $(grep Modify $EVIDENCE/user_details/stat_group.txt | cut -d' ' -f2-)" >> $LOGFILE
echo "- User / Login Data Extracted"
# Authentication Data
mkdir $EVIDENCE/logindata # create storage locations for login data
cp $DATA/var/log/btmp* $EVIDENCE/logindata/
echo "[ ] BTMP extracted to $EVIDENCE/logindata/btmp" >> $LOGFILE
echo "[ ] Additonal BTMP files may also have been extracted." >> $LOGFILE
last -f $DATA/var/log/btmp >> $EVIDENCE/logindata/btmp_in_txt.txt
echo "[ ] last has been run against btmp and output is at $EVIDENCE/logindata/btmp_in_txt.txt" >> $LOGFILE
hashfile $EVIDENCE/logindata/btmp
hashfile $EVIDENCE/logindata/btmp_in_txt.txt

cp $DATA/var/log/wtmp* $EVIDENCE/logindata/
echo "[ ] WTMP extracted to $EVIDENCE/logindata/wtmp" >> $LOGFILE
echo "[ ] Additonal WTMP files may also have been extracted." >> $LOGFILE
last -f $DATA/var/log/wtmp >> $EVIDENCE/logindata/wtmp_in_txt.txt
echo "[ ] last has been run against wtmp and output is at $EVIDENCE/logindata/wtmp_in_txt.txt" >> $LOGFILE
hashfile $EVIDENCE/logindata/wtmp
hashfile $EVIDENCE/logindata/wtmp_in_txt.txt

# No collection of UTMP
# Gather User History files
mkdir $EVIDENCE/history # create storage locations for history files
cp $DATA/root/.bash_history $EVIDENCE/history/root_bash_history.txt
echo "[ ] Root History copied to $EVIDENCE/history/root_bash_history.txt" >> $LOGFILE
hashfile $EVIDENCE/history/root_bash_history.txt
echo "- Root Bash History Extracted"
# Gather other history files...
if test -f "$DATA/root/.lesshst"; then
    cp $DATA/root/.lesshst $EVIDENCE/history/root_lesshistory.txt
    echo "[ ] Root less history copied to $EVIDENCE/history/root_lesshistory.txt" >> $LOGFILE
    hashfile $EVIDENCE/history/root_lesshistory.txt
fi
if test -f "$DATA/root/.viminfo"; then
    cp $DATA/root/.viminfo $EVIDENCE/history/root_viminfo.txt
    echo "[ ] Root less history copied to $EVIDENCE/history/root_viminfo.txt" >> $LOGFILE
    hashfile $EVIDENCE/history/root_viminfo.txt
fi
if test -f "$DATA/root/.mysql_history"; then
    cp $DATA/root/.mysql_history $EVIDENCE/history/root_mysqlhistory.txt
    echo "[ ] Root less history copied to $EVIDENCE/history/root_mysqlhistory.txt" >> $LOGFILE
    hashfile $EVIDENCE/history/root_mysqlhistory.txt
fi
USRNAMES=$(cat $DATA/etc/passwd | grep sh | grep -v nologin | grep -v root | grep -v lib | cut -d':' -f 6 | cut -d'/' -f3 | sort | uniq | sed '/^$/d')
for i in $USRNAMES
do 
    echo "[ ] Collecting ${i} Bash History" >> $LOGFILE
    echo "[ ] Collecting ${i} Bash History"
    cp $DATA/home/${i}/.bash_history $EVIDENCE/history/${i}_bash_history.txt # grab bash history
    sleep 0.5 # add a pause to make sure processing runs smoothly.
    hashfile $EVIDENCE/history/${i}_bash_history.txt
    echo "- $i bash history extracted"
    
    if [ -f "$DATA/home/${i}/.lesshst" ]; then
        cp $DATA/home/$i/.lesshst $EVIDENCE/history/${i}_lesshistory.txt
        echo "[ ] ${i} less history copied to $EVIDENCE/history/${i}_lesshistory.txt" >> $LOGFILE
        hashfile $EVIDENCE/history/${i}_lesshistory.txt
    fi
    if [ -f "$DATA/home/${i}/.viminfo" ]; then
        cp $DATA/home/${i}/.viminfo $EVIDENCE/history/${i}_viminfo.txt
        echo "[ ] ${i} less history copied to $EVIDENCE/history/${i}_viminfo.txt" >> $LOGFILE
        hashfile $EVIDENCE/history/${i}_viminfo.txt
    fi
    if [ -f "$DATA/home/${i}/.mysql_history" ]; then
        cp $DATA/home/${i}/.mysql_history $EVIDENCE/history/${i}_mysqlhistory.txt
        echo "[ ] ${i} less history copied to $EVIDENCE/history/${i}_mysqlhistory.txt" >> $LOGFILE
        hashfile $EVIDENCE/history/${i}_mysqlhistory.txt
    fi
    echo "- $i other common history files extracted. Pausing."
    sleep 0.5 # add a pause
done

# Gather User File Info - root first
mkdir -p $EVIDENCE/homefolders # create storage locations for user file info
ls -aliht $DATA/root/ > $EVIDENCE/homefolders/root_folder_listing.txt
echo "[ ] Root home folder listing copied to $EVIDENCE/homefolders/root_folder_listing.txt" >> $LOGFILE
echo "[ ] Root home folder listing copied to $EVIDENCE/homefolders/root_folder_listing.txt" # update user
hashfile $EVIDENCE/homefolders/root_folder_listing.txt

if [ -f "$DATA/root/.ssh/authorized_keys" ]; then
    echo "- Copying root user's SSH authorized_keys file."
    cp $DATA/root/.ssh/authorized_keys $EVIDENCE/homefolders/root_authorized_keys.txt
    echo "[ ] Root authorized_keys copied to $EVIDENCE/homefolders/root_authorized_keys.txt" >> $LOGFILE
    echo "- hashing evidence."
    hashfile $EVIDENCE/homefolders/root_authorized_keys.txt
fi
if [ -f "$DATA/root/.ssh/known_hosts" ]; then
    cp $DATA/root/.ssh/known_hosts $EVIDENCE/homefolders/root_known_hosts.txt
    echo "[ ] Root known_hosts copied to $EVIDENCE/homefolders/root_known_hosts.txt" >> $LOGFILE
    hashfile $EVIDENCE/homefolders/root_known_hosts.txt
fi
# Gather users
USRNAMES=$(cat $DATA/etc/passwd | grep sh | grep -v nologin | grep -v root | grep -v lib | cut -d':' -f 6 | cut -d'/' -f3 | sort | uniq | sed '/^$/d')
for i in $USRNAMES
do
    echo "- Exporting user folder listings."
    ls -aliht $DATA/home/${i}/ > $EVIDENCE/homefolders/${i}_folder_listing.txt
    echo "[ ] ${i} home folder listing copied to $EVIDENCE/homefolders/${i}_folder_listing.txt" >> $LOGFILE
    hashfile $EVIDENCE/homefolders/${i}_folder_listing.txt
    echo "- home folder listings extracted"
    
    if [ -f "$DATA/home/${i}/.ssh/authorized_keys" ]; then
        cp $DATA/home/${i}/.ssh/authorized_keys $EVIDENCE/homefolders/${i}_authorized_keys.txt
        echo "[ ] ${i} authorized_keys copied to $EVIDENCE/homefolders/${i}_authorized_keys.txt" >> $LOGFILE
        hashfile $EVIDENCE/homefolders/${i}_authorized_keys.txt
    fi
    if [ -f "$DATA/home/${i}/.ssh/known_hosts" ]; then
        cp $DATA/home/${i}/.ssh/known_hosts $EVIDENCE/homefolders/${i}_known_hosts.txt
        echo "[ ] ${i} known_hosts copied to $EVIDENCE/homefolders/${i}_known_hosts.txt" >> $LOGFILE
        hashfile $EVIDENCE/homefolders/${i}_known_hosts.txt
    fi
done
echo "[!] Networking data not available in capture"  >> $LOGFILE
echo "[!] Running processes not available in capture" >> $LOGFILE
# Cron Tasks
mkdir $EVIDENCE/cron # create storage location for crontab data
cat $DATA/etc/crontab > $EVIDENCE/cron/crontab.txt
echo "[ ] Crontab copied to $EVIDENCE/cron/crontab.txt." >> $LOGFILE
hashfile $EVIDENCE/cron/crontab.txt
ls -alhit $DATA/etc/cron* > $EVIDENCE/cron/cron_list.txt
echo "[ ] Directory listing of cron data copied to $EVIDENCE/cron/cron_list.txt." >> $LOGFILE
echo "[!] Look for any timestamps during the time of the incident." >> $LOGFILE
hashfile $EVIDENCE/cron/cron_list.txt
echo "- Cron jobs listed"
# Find modified files
mkdir $EVIDENCE/files # create storage location for any file data collected
find $DATA -perm -4000 -exec ls -ldb {} \; > $EVIDENCE/files/suid_set.txt
echo "[ ] Search carried out for files with SUID bit set. Results saved to $EVIDENCE/files/suid_set.txt" >>$LOGFILE
echo "[!] Check for unexpected entries." >> $LOGFILE
echo "- Checked for files with SUID bit set."
hashfile $EVIDENCE/files/suid_set.txt
echo "[!] This script will now search the evidence for file modifications between $sdate and $edate. If this date range is not correct, please modify the script appropriately."
find $DATA -type f -newermt $sdate ! -newermt $edate -exec ls -alht {} \; | grep -v "/sess_" > $EVIDENCE/files/modified_during_window.txt # this is looking for files within the suspected incident timeline and has excluded php session files to reduce noise.
echo "[ ] A list of files modified between $sdate and $edate has been copied to $EVIDENCE/files/modified_during_window.txt" >> $LOGFILE
echo "[!] This date range is to cover the suspected incident timeframe. Check for unexpected entries, files that appear in other lists or even signs that attackers have caused processes to crash." >> $LOGFILE
echo "[!] There are $(wc -l $EVIDENCE/files/modified_modified_during_window.txt) lines in the file." >> $LOGFILE
hashfile $EVIDENCE/files/modified_during_window.txt

find $DATA -type f -newerct $sdate ! -newerct $edate -exec ls -alht {} \; | grep -v "/sess_" > $EVIDENCE/files/metachange_modified_during_window.txt # this is looking for files within the suspected incident timeline and has excluded php session files to reduce noise.
echo "[ ] A list of files where the metadata has changed between $sdate and $edate has been copied to $EVIDENCE/files/metachange_modified_during_window.txt" >> $LOGFILE
echo "- A list of files where the metadata has changed between $sdate and $edate has been copied to $EVIDENCE/files/metachange_modified_during_window.txt"
echo "[!] This date range is to cover the suspected incident timeframe. Check for unexpected entries, files that appear in other lists or even signs that attackers have caused processes to crash." >> $LOGFILE
echo "[!] There are $(wc -l $EVIDENCE/files/metachange_modified_during_window.txt) lines in the file." >> $LOGFILE
hashfile $EVIDENCE/files/metachange_modified_during_window.txt

echo "- Checking sudoers files."
cp $DATA/etc/sudoers $EVIDENCE/files/sudoers.txt
echo "[ ] Sudoers file copied to $EVIDENCE/files/sudoers.txt" >> $LOGFILE
hashfile $EVIDENCE/files/sudoers.txt

echo "- Primary sudoers checked, looking for child folders."

# NOTE:
# This will need to be modified if you wish to use this script outside the course evidence.
# Currently ths script only checks for the known rsydow-stark folder, it doesn't have a 
# way to iterate through all possible files.

if [ -f "$DATA/etc/sudoers.d/rsydow-stark" ]; then
    cp $DATA/etc/sudoers.d/rsydow-stark $EVIDENCE/files/sudoers_rsydow-stark.txt
    echo "[ ] User sudoers file copied to $EVIDENCE/files/sudoers_rsydow-stark.txt" >> $LOGFILE
    echo "[ ] File timestamps for this file are:" >> $LOGFILE
    stat $DATA/etc/sudoers.d/rsydow-stark >> $LOGFILE
    hashfile $EVIDENCE/files/sudoers_rsydow-stark.txt
fi
echo "- Sudoers completed."

mkdir $EVIDENCE/files/pam # create storage location for PAM
cp $DATA/etc/pam.d/* $EVIDENCE/files/pam/
echo "[!] PAM.d files copied to $EVIDENCE/files/pam/" >> $LOGFILE
echo "[!] Check for any unusual entries." >> $LOGFILE
echo "- Common files copied out"

# HOSTS and Network data
cp $DATA/etc/hosts $EVIDENCE/files/hosts.txt
echo "[ ] Hosts file copied to $EVIDENCE/files/hosts.txt" >> $LOGFILE
hashfile $EVIDENCE/files/hosts.txt
cat $DATA/etc/resolv.conf > $EVIDENCE/files/resolve_conf.txt
echo "[ ] Hosts file copied to $EVIDENCE/files/resolve_conf.txt" >> $LOGFILE
hashfile $EVIDENCE/files/resolve_conf.txt

# Looking for hidden files
find $DATA -type d -name .\* -exec ls -alht {} \; > $EVIDENCE/files/possible_hidden_directories.txt
echo "[ ] A list of possibly hidden directories and their contents has been copied to $EVIDENCE/files/possible_hidden_directories.txt" >> $LOGFILE
hashfile $EVIDENCE/files/possible_hidden_directories.txt

# Capture process/service startups
mkdir $EVIDENCE/systemd # create storage location for SystemD target/wants data
cp -R $DATA/etc/systemd/* $EVIDENCE/systemd/
echo "[ ] Files from /etc/systemd copied to $EVIDENCE/systemd/" >> $LOGFILE
ls -alhR $DATA/lib/systemd >> $EVIDENCE/systemd/lib_systemd_directoryListing.txt

# extract log data 
echo "- Extracting logfiles. If these are large it may take time. Individual files will not be hashed by this script."
mkdir $EVIDENCE/logs # create storage location for log data

if [ -f "$DATA/var/log/audit/audit.log" ]; then
    mkdir -p $EVIDENCE/logs/audit
    cp $DATA/var/log/audit/* $EVIDENCE/logs/audit
    echo "[ ] Audit logs extracted to $EVIDENCE/logs/audit" >> $LOGFILE
fi

if [ -f "$DATA/var/log/firewalld" ]; then
    cp $DATA/var/log/firewalld $EVIDENCE/logs/firewalld
    echo "[ ] Firewall Daemon logs extracted to $EVIDENCE/logs/firewalld" >> $LOGFILE
fi

if [ -f "$DATA/var/log/secure" ]; then
    cp $DATA/var/log/secure* $EVIDENCE/logs/
    echo "[ ] Secure logs extracted to $EVIDENCE/logs/" >> $LOGFILE
fi

if [ -f "$DATA/var/log/message*" ]; then
    cp $DATA/var/log/message* $EVIDENCE/logs/
    echo "[ ] Mesages extracted to $EVIDENCE/logs/" >> $LOGFILE
fi

if [ -f "$DATA/var/log/auth.log" ]; then
    cp $DATA/var/log/auth.log* $EVIDENCE/logs/
    echo "[ ] Auth.log extracted to $EVIDENCE/logs/" >> $LOGFILE
fi

if [ -f "$DATA/var/log/httpd/access.log" ]; then
    mkdir -p $EVIDENCE/logs/httpd
    cp $DATA/var/log/httpd/* $EVIDENCE/logs/httpd
    echo "[ ] HTTPD logs extracted to $EVIDENCE/logs/httpd" >> $LOGFILE
fi

if [ -f "$DATA/var/log/apache2/access.log" ]; then
    mkdir -p $EVIDENCE/logs/apache2
    cp $DATA/var/log/apache2/* $EVIDENCE/logs/apache2
    echo "[ ] Apache2 logs extracted to $EVIDENCE/logs/httpd" >> $LOGFILE
fi

if [ -f "$DATA/var/log/maillog" ]; then
    cat $DATA/var/log/maillog* > $EVIDENCE/logs/maillog_full.txt
    echo "[ ] Mail logs concatenated to $EVIDENCE/logs/maillog_full.txt" >> $LOGFILE
fi

if [ -f "$DATA/var/log/syslog" ]; then
    mkdir -p $EVIDENCE/logs/syslog
    cp $DATA/var/log/syslog* $EVIDENCE/logs/syslog/
    echo "[ ] Syslogs extracted to $EVIDENCE/logs/syslog/" >> $LOGFILE
fi

echo "- Log data extracted. Finalising documents."
echo "[!] Triage data extraction completed at $(date | cut -d' ' -f4,5)" >> $LOGFILE
# TO DO - add in tar routine
