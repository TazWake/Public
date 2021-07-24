#!/bin/zsh
# This script is a starter-script for capturing
# data from a suspected-compromised MacOS host.
#
# This is no a Forensic Evidence script. It is
# designed to support incident response.
#
# SYNTAX
#
# scriptname.sh <storage location>

# Set up environment
STORE="$1"
TEMPNAME=$(cat /dev/urandom | tr -cd 'a-f0-9' | head -c 8)
TEMPFILE=$STORE/$TEMPNAME
ERRLOG=$STORE/errors.txt
exec 2> $ERRLOG

# Check it is run as root
if  [[ $EUID -ne 0 ]]; then
    echo "This script requires root privileges to run."
    exit;
fi

# Functions
function hashFile () {
    FILE="$1"
    if [ -f "$FILE" ]; then
        SHA1HASH=$(sha1sum $FILE)
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

# Gather SystemInfo
# This captures into a text document and CSV.
SYSTEM=$STORE/systeminfo.txt
SYSTEMCSV=$STORE/systeminfo.csv
rm $SYSTEM # ensure it starts clean
rm $SYSTEMCSV # ensure it starts clean
echo "COMMAND,OUTPUT" >> $SYSTEMCSV
CMD=$(date)
echo "DATE: $CMD" >> $SYSTEM
echo "DATE,'$CMD'" >> $SYSTEMCSV
CMD=$(date -u)
echo "DATE (UTC): $CMD" >> $SYSTEM
echo "DATE (UTC),'$CMD'" >> $SYSTEMCSV
CMD=$(hostname)
echo "HOSTNAME: $CMD" >> $SYSTEM
echo "HOSTNAME,'$CMD'" >> $SYSTEMCSV
CMD=$(uname -a)
echo "UNAME -A: $CMD" >> $SYSTEM
echo "UNAME -A,'$CMD'" >> $SYSTEMCSV
CMD=$(sw_vers)
echo "SW_VERS: $CMD" >> $SYSTEM
echo "SW_VERS,'$CMD'" >> $SYSTEMCSV
CMD=$(nvram)
echo "NVRAM: $CMD" >> $SYSTEM
echo "NVRAM,'$CMD'" >> $SYSTEMCSV
CMD=$(uptime)
echo "UPTIME: $CMD" >> $SYSTEM
echo "UPTIME,'$CMD'" >> $SYSTEMCSV
CMD=$(spctl --status)
echo "SPTCL STATUS: $CMD" >> $SYSTEM
echo "SPTCL STATUS,'$CMD'" >> $SYSTEMCSV
CMD=$(bash --version)
echo "BASH VERSION: $CMD" >> $SYSTEM
echo "BASH VERSION,'$CMD'" >> $SYSTEMCSV
unset CMD
echo "System info collected and added to $SYSTEM." >> $LOG
hashFile $SYSTEM
echo "A CSV of the system info is at $SYSTEMCSV." >> $LOG
hashFile $SYSTEMCSV
