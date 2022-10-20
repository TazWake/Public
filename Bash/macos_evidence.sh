#!/bin/zsh
# This script is a starter-script for capturing
# data from a suspected-compromised MacOS host.
#
# NOTE: THIS IS NOT A FINISHED PRODUCT!!!
# It is designed to provide a starting point for 
# your own tailored collection scripts.
#
# This is not a Forensic Evidence script. It is
# designed to support incident response.
#
# SYNTAX
#
# scriptname.sh <storage location>

# Check it is run as root
if  [[ $EUID -ne 0 ]]; then
    echo "This script requires root privileges to run."
    exit;
fi

# Set up environment
STORE="$1"
TEMPNAME=$(cat /dev/urandom | head -c 12 | shasum | head -c 8)
TEMPFILE=$STORE/$TEMPNAME
ERRLOG=$STORE/errors.txt
CSV=$STORE/evidence.csv
echo "COMMAND,OUTPUT" > $CSV # Set up headers and ensure the csv starts clean
exec 2> $ERRLOG

# Functions
function hashFile () {
    FILE="$1"
    if [ -f "$FILE" ]; then
        SHA1HASH=$(shasum $FILE)
        echo "SHA1 Hash: $SHA1HASH;" >> $LOG
    else
        echo "WARNING: There has been a problem hashing the file. This script will exit."
        exit;
    fi
}
# Check storage media is writeable
touch $TEMPFILE
if [ -f $TEMPFILE ]; then
    # The storage media can be written to.
    rm $TEMPFILE
else
    echo "We have been unable to write to the storage media."
    echo "Exiting now."
    exit;
fi

# Notify user
clear
echo "------------------------------------------------------------------"
echo " We are collecting critical system data to respond to an incident "
echo "  DO NOT TURN OFF THIS SYSTEM UNTIL THE COLLECTION HAS FINISHED"
echo "------------------------------------------------------------------"

# Set up logging
LOG="$STORE/collectionlog.txt"
echo "###########################################################" > $LOG
echo "#                                                         #" >> $LOG
echo "# Data collection initiated: $(date -u) #" >> $LOG
echo "#                                                         #" >> $LOG
echo "###########################################################" >> $LOG
echo "Storage Location: $STORE" >> $LOG
echo "Account Used: $(whoami)" >> $LOG
echo "Original Account: $(sh -c 'echo $SUDO_USER') - If this is blank the user has not elevated privileges with sudo" >> $LOG
echo "This script will gather key data from the target system to support incident response." >> $LOG
echo "When data is extracted it will be copied into relevant analysis files in the storage location." >> $LOG
echo "In addition, all data will be combined into a master CSV file for analysis." >> $LOG

# Gather SystemInfo
# This captures into a text document and CSV.
SYSTEM=$STORE/systeminfo.txt
rm $SYSTEM # ensure it starts clean
CMD=$(date)
echo "DATE: $CMD" >> $SYSTEM
echo "DATE,'$CMD'" >> $CSV
CMD=$(date -u)
echo "DATE (UTC): $CMD" >> $SYSTEM
echo "DATE (UTC),'$CMD'" >> $CSV
CMD=$(hostname)
echo "HOSTNAME: $CMD" >> $SYSTEM
echo "HOSTNAME,'$CMD'" >> $CSV
CMD=$(uname -a)
echo "UNAME -A: $CMD" >> $SYSTEM
echo "UNAME -A,'$CMD'" >> $CSV
CMD=$(sw_vers)
echo "SW_VERS: $CMD" >> $SYSTEM
echo "SW_VERS,'$CMD'" >> $CSV
CMD=$(uptime)
echo "UPTIME: $CMD" >> $SYSTEM
echo "UPTIME,'$CMD'" >> $CSV
CMD=$(spctl --status)
echo "SPTCL STATUS: $CMD" >> $SYSTEM
echo "SPTCL STATUS,'$CMD'" >> $CSV
CMD=$(bash --version)
echo "BASH VERSION: $CMD" >> $SYSTEM
echo "BASH VERSION,'$CMD'" >> $CSV
unset CMD
echo "System info collected and added to $SYSTEM." >> $LOG
hashFile $SYSTEM

# Capture NVRAM firmware variables
nvram -xp > $STORE/nvram.xml
echo "The system firmware NVRAM variable data has been exported to $STORE/nvram.xml" >> $LOG
hashFile $STORE/nvram.xml

# Gather User Data
mkdir -p $STORE/userdata
echo "User info and who based data is being carved and will be stored in $STORE/userdata." >> $LOG
ls -alhi /Users > $STORE/userdata/ls-al-output.txt
hashFile $STORE/userdata/ls-al-output.txt
who > $STORE/userdata/who.txt
echo "WHO,'$(who)'" >> $CSV
hashFile $STORE/userdata/who.txt
echo "WHOAMI: $(whoami)" >> $LOG
echo "WHOAMI,'$(whoami)'" >> $CSV
last > $STORE/userdata/last.txt
hashFile $STORE/userdata/last.txt
USER=$STORE/userdata/userInfo.txt
echo "*****************" > $USER
echo "* User Analysis *" >> $USER
echo "*****************" >> $USER
echo "Accounts on the system" >> $USER
dscl . -ls /Users >> $USER;
echo "*****************" >> $USER
echo "" >> $USER
echo "User Accounts: $(dscl . -ls /Users | grep -v ^_)" >> $LOG
echo "User Accounts, '$(dscl . -ls /Users | grep -v ^_)'" >> $CSV
dscl . ls /Users | egrep -v ^_ | while read user
    do
        echo "-----------------" >> $USER
        echo "ACCOUNT: $user" >> $USER
        echo "ID: $(id $user)" >> $USER
        echo "GROUPS: $(groups $user)" >> $USER
        echo "FINGER -M: $(finger -m $user)" >> $USER
        echo "-----------------" >> $USER
    done    
echo "Account data/use information stored at $USER" >> $LOG
hashFile $USER
unset USER

# Gather Network Data
mkdir -p $STORE/networkdata
NET=$STORE/networkdata
echo "Collecting Networking Data - files will be stored in $NET." >> $LOG
netstat > $NET/netstat.txt
head -n1 $NET/netstat.txt > $NET/estabished_connections.txt
grep ESTABLISHED $NET/netstat.txt >> $NET/established_connections.txt
hashFile $NET/netstat.txt
hashFile $NET/established_connections.txt
ifconfig > $NET/ifconfig
hashFile $NET/ifconfig
networksetup -listallhardwareports > $NET/networksetup_hardwareports.txt
hashFile $NET/networksetup_hardwareports.txt
CONS=$(lsof -i)
echo $CONS > $NET/lsof_i.txt
hashFile $NET/lsof_i.txt
echo "LSOF -I,'$(echo $CONS)'" >> $CSV
unset CONS
arp -a > $NET/arp.txt
hashFile $NET/arp.txt
echo "SECURITY TRUST SETTINGS: $(security dump-trust-settings)" >> $LOG
echo "SECURITY TRUST SETTINGS, '$(security dump-trust-settings)'" >> $CSV
smbutil statshares -a > $NET/smb_statshares.txt
hashFile $NET/smb_statshares.txt
echo "" >> $LOG

# Collect process information
mkdir -p $STORE/process
PROC=$STORE/process
echo "Collecting processor information. Data will be stored in $PROC." >> $LOG
ps aux > $PROC/ps_aux.txt
hashFile $PROC/ps_aux.txt
ps axo user,pid,ppid,start,command > $PROC/ps_axo.txt
hashFile $PROC/ps_axo.txt
lsof > $PROC/lsof.txt
hashFile $PROC/lsof.txt
kextstat > $PROC/kextstat.txt
hashFile $PROC/kextstat.txt

# Finalise Collection
echo "" >> $LOG
echo "Collection finished." >> $LOG
echo "The CSV file has been created at $CSV" >> $LOG
hashFile $CSV
echo "###########################################################" >> $LOG
echo "#                                                         #" >> $LOG
echo "# Data collection completed: $(date -u) #" >> $LOG
echo "#                                                         #" >> $LOG
echo "###########################################################" >> $LOG
echo "------------------------------------------------------------------"
echo "                      Collection has completed "
echo "------------------------------------------------------------------"
