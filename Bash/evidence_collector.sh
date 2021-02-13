#!/bin/bash

# Evidence collection script for Linux hosts
#
# Useage:
# This script needs to be run with root privs. 
# Run script to copy memory and disk image to external storage media.
# ./evidence_collector.sh /path/to/storage/device
# sudo ./evidence_collector.sh /path/to/storage/device
# 
# eg: ./evidence_collector.sh /mnt/usb/evidencefolder
#
# Primary consideration: https://tools.ietf.org/html/rfc3227

PATH=$1
TEMPNAME=$(cat /dev/urandom | tr -cd 'a-f0-9' | head -c 6)
TEMPFILE=$PATH/$TEMPNAME

# validate storage path
touch $TEMPFILE
if [ -f $TEMPFILE  ]; then
    echo "[+] Write to storage media successful."
    rm $TEMPFILE
else
    echo "[!] Unable to write to storage media."
    echo "[!] Exiting."
    exit
fi

# Set up logging
dtg=$(date | cut -d" " -f4,5)
LOGFILE=$PATH/datacollection_$dtg.txt
echo "***********************" > $LOGFILE
echo "* Evidence Collection *" >> $LOGFILE
echo "***********************" >> $LOGFILE
echo "Collection Started at: $dtg" >> $LOGFILE
echo "Storage location: $PATH" >> $LOGFILE

# Grap network data - arp cache, routing cache.
arp -a > $PATH/arp_export.txt
dtg=$(date | cut -d" " -f4,5)
echo "[ ] ARP cache exported to $PATH/arp_export.txt at $dtg." >> $LOGFILE
hash=$(sha1sum $PATH/arp_export.txt)
echo "[ ] SHA1 hash: $hash" >> $LOGFILE

route -n > $PATH/route_table.txt
dtg=$(date | cut -d" " -f4,5)
echo "[ ] Route table exported to $PATH/route_table.txt at $dtg." >> $LOGFILE
hash=$(sha1sum $PATH/route_table.txt)
echo "[ ] SHA1 hash: $hash" >> $LOGFILE

netstat -ano > $PATH/netstat.txt
dtg=$(date | cut -d" " -f4,5)
echo "[ ] Route table exported to $PATH/netstat.txt at $dtg." >> $LOGFILE
hash=$(sha1sum $PATH/netstat.txt)
echo "[ ] SHA1 hash: $hash" >> $LOGFILE

# Grab memory



# Collect network data

# Get disk image

# Close down
dtg=$(date | cut -d" " -f4,5)
echo "Data collection complete at $dtg" >> $LOGFILE
echo "***********************" >> $LOGFILE
echo "* EXTRACTION COMPLETE *" >> $LOGILE
echo "***********************" >> $LOGFILE
sha1=$(sha1sum $LOGFILE)
echo "Logfile hash: $sha1" >> $PATH/logfile_hash.txt
echo "[+] Evidence extraction complete."
echo "[+] Logfile is stored at $LOGFILE"
echo "[+] SHA1 hash of the logfile is $sha1"
echo "[+] A copy of the hash is stored at $PATH/logfile_hash.txt"
