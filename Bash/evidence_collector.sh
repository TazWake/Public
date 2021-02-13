#!/bin/bash

# Evidence collection script for Linux hosts
#
# Requirements.
#     ewfaquire - if this isn't on the system dd can be used.
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

hashfile() {
    file=$1
    if [ -f "$file" ]; then
	    hash=$(sha1sum $file)
        echo "[#] SHA1 hash: $hash" >> $LOGFILE
    else
	    echo "[!] There is a problem with logging the hash - exiting!"
        exit 255;
	fi
}
# Check Requirements
if [[ $EUID != 0 ]]; then
    echo "[!] This script must be run with root privileges!"
    echo "[!] Exiting"
    exit 255;
else
    echo "[ ] Running with correct privilges."
fi
touch $TEMPFILE
if [ -f $TEMPFILE  ]; then
    echo "[+] Write to storage media successful."
    rm $TEMPFILE
else
    echo "[!] Unable to write to storage media."
    echo "[!] Exiting."
    exit 255;
fi

# Set up logging
LOGFILE=$EVIDENCEPATH/datacollection.txt
dtg=$(date | cut -d" " -f4,5)
echo "***********************" > $LOGFILE
echo "* Evidence Collection *" >> $LOGFILE
echo "***********************" >> $LOGFILE
echo "Collection Started at: $dtg" >> $LOGFILE
echo "Storage location: $EVIDENCEPATH" >> $LOGFILE

# Grab network data - arp cache, routing cache.
echo "[ ] Collecting ARP"
arp -a > $EVIDENCEPATH/arp_export.txt
chmod 444 $EVIDENCEPATH/arp_export.txt
dtg=$(date | cut -d" " -f4,5)
echo "[ ] ARP cache exported to $EVIDENCEPATH/arp_export.txt at $dtg." >> $LOGFILE
hashfile $EVIDENCEPATH/arp_export.txt

echo "[ ] Collecting route data"
route -n > $EVIDENCEPATH/route_table.txt
chmod 444 $EVIDENCEPATH/route_table.txt
dtg=$(date | cut -d" " -f4,5)
echo "[ ] Route table exported to $EVIDENCEPATH/route_table.txt at $dtg." >> $LOGFILE
hashfile $EVIDENCEPATH/route_table.txt

echo "[ ] Collecting netstat"
netstat -ano > $EVIDENCEPATH/netstat.txt
chmod 444 $EVIDENCEPATH/netstat.txt
dtg=$(date | cut -d" " -f4,5)
echo "[ ] Route table exported to $EVIDENCEPATH/netstat.txt at $dtg." >> $LOGFILE
hashfile $EVIDENCEPATH/netstat.txt

# Capture running processes
dtg=$(date | cut -d" " -f4,5)
echo "[ ] Capturing process table at $dtg" >> $LOGFILE
echo "[ ] Capturing process table."
ps -aux > $EVIDENCEPATH/running_processes.txt
dtg=$(date | cut -d" " -f4,5)
echo "[+] Process table exported to $EVIDENCEPATH/running_processes.txt at $dtg" >> $LOGFILE
hashfile $EVIDENCEPATH/running_processes.txt
echo "[+] Process table exported"
chmod 444 $EVIDENCEPATH/running_processes.txt

# Grab memory
# TBD

# Get disk image
DISK=$(df | grep "/$" | cut -d' ' -f 1)
IMAGEFILENAME=$(hostname)_disk_image.raw

if ! command -v ewfacquire &> /dev/null
then
    dtg=$(date | cut -d" " -f4,5)
    echo "[!] ewfaquire not found. Using dd instead. Disk image will be larger, tar will be used to compress."
    echo "[!] THIS MIGHT TAKE SOME TIME!"
    echo "[ ] Using DD for image capture." >> $LOGFILE
    echo "[ ] Writing to $EVIDENCEPATH/$IMAGEFILENAME"
    echo "[ ] Writing disk image to $EVIDENCEPATH/$IMAGEFILENAME at $dtg" >> $LOGFILE
    dd if=$DISK of=$EVIDENCEPATH/$IMAGEFILENAME bs=64K conv=noerror,sync
    dtg=$(date | cut -d" " -f4,5)
    echo "[+] Disk copy completed at $dtg." >> $LOGFILE
    echo "[ ] Image collection complete, hashing"
    diskhash=$(sha1sum $EVIDENCEPATH/$IMAGEFILENAME)
    echo $diskhash > $EVIDENCEPATH/sha1hash.txt
    echo "[ ] Disk hash: $(echo $diskhash | cut -d' ' -f1)" >> $LOGFILE
    echo "[+] Image hash: $(echo $diskhash | cut -d' ' -f1)\n[ ] Compressing disk image."
    tar -cvzf $EVIDENCEPATH/disk_image.tar.gz $EVIDENCEPATH/$IMAGEFILENAME $EVIDENCEPATH/sha1hash.txt
    comphash=$(sha1sum $EVIDENCEPATH/disk_image.tar.gz)
    echo "[+] Compression completed. Hash: $(echo comphash | cut -d' ' -f1)"
    echo "[+] Compressed tar file created." >> $LOGFILE
    echo "[ ] Reference details: $comphash" >> $LOGFILE
    rm $EVIDENCEPATH/$IMAGEFILENAME
    echo "[ ] Original disk image deleted from file system"
else
    echo "[!] ewfaquire found. Will create E01 image."
fi

# Close down
dtg=$(date | cut -d" " -f4,5)
echo "Data collection complete at $dtg" >> $LOGFILE
echo "***********************" >> $LOGFILE
echo "* EXTRACTION COMPLETE *" >> $LOGFILE
echo "***********************" >> $LOGFILE
sha1=$(sha1sum $LOGFILE)
echo "Logfile hash:\n $sha1" > $EVIDENCEPATH/logfile_hash.txt
echo "[+] Evidence extraction complete."
echo "[+] Logfile is stored at $LOGFILE"
echo "[+] SHA1 hash of the logfile is $(echo $sha1 | cut -d' ' -f1)"
echo "[+] A copy of the hash is stored at $EVIDENCEPATH/logfile_hash.txt"
chmod 444 $EVIDENCEPATH/logfile_hash.txt
chmod 444 $LOGFILE
