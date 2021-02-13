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

EVIDENCEPATH=$1
TEMPNAME=$(cat /dev/urandom | tr -cd 'a-f0-9' | head -c 6)
TEMPFILE=$EVIDENCEPATH/$TEMPNAME

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
LOGFILE=$EVIDENCEPATH/datacollection_$dtg.txt
echo "***********************" > $LOGFILE
echo "* Evidence Collection *" >> $LOGFILE
echo "***********************" >> $LOGFILE
echo "Collection Started at: $dtg" >> $LOGFILE
echo "Storage location: $EVIDENCEPATH" >> $LOGFILE

# Grap network data - arp cache, routing cache.
echo "[ ] Collecting ARP"
arp -a > $EVIDENCEPATH/arp_export.txt
dtg=$(date | cut -d" " -f4,5)
echo "[ ] ARP cache exported to $EVIDENCEPATH/arp_export.txt at $dtg." >> $LOGFILE
hash=$(sha1sum $EVIDENCEPATH/arp_export.txt)
echo "[ ] SHA1 hash: $hash" >> $LOGFILE

echo "[ ] Collecting route data"
route -n > $EVIDENCEPATH/route_table.txt
dtg=$(date | cut -d" " -f4,5)
echo "[ ] Route table exported to $EVIDENCEPATH/route_table.txt at $dtg." >> $LOGFILE
hash=$(sha1sum $EVIDENCEPATH/route_table.txt)
echo "[ ] SHA1 hash: $hash" >> $LOGFILE

echo "[ ] Collecting netstat"
netstat -ano > $EVIDENCEPATH/netstat.txt
dtg=$(date | cut -d" " -f4,5)
echo "[ ] Route table exported to $EVIDENCEPATH/netstat.txt at $dtg." >> $LOGFILE
hash=$(sha1sum $EVIDENCEPATH/netstat.txt)
echo "[ ] SHA1 hash: $hash" >> $LOGFILE

# Grab memory



# Collect network data

# Get disk image

# Close down
dtg=$(date | cut -d" " -f4,5)
echo "Data collection complete at $dtg" >> $LOGFILE
echo "***********************" >> $LOGFILE
echo "* EXTRACTION COMPLETE *" >> $LOGFILE
echo "***********************" >> $LOGFILE
sha1=$(sha1sum $LOGFILE)
echo "Logfile hash: $sha1" >> $EVIDENCEPATH/logfile_hash.txt
echo "[+] Evidence extraction complete."
echo "[+] Logfile is stored at $LOGFILE"
echo "[+] SHA1 hash of the logfile is $sha1"
echo "[+] A copy of the hash is stored at $EVIDENCEPATH/logfile_hash.txt"
