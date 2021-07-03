#!/bin/bash

# This script carves VMDK images
#
#
#
# Syntax
# VMDK_Carver.sh /path/to/vmdk/name.vmdk /path/to/storage/

# SET UP GLOBALS
VMDK=$1
FILENAME=basename "$VMDK"
FILE=$FILENAME | cut -d'.' -f1
OUTPATH=$2
RAWFILW=$OUTPATH/$FILE.raw
TEMPNAME=$(cat /dev/urandom | tr -cd 'a-f0-9' | head -c 8)
TEMPFILE=$OUTPATH/$TEMPNAME
$LOGFILE=$OUTPATH/CollectionLog.txt

# SET UP FUNCTIONS
hashfile() {
    file=$1
    if [ -f "$file" ]; then
	hash=$(sha1sum $file)
        echo "[#] SHA1 hash: $hash" >> $LOGFILE
	echo " " >> $LOGFILE
    else
	echo "[!] There is a problem with logging the hash - exiting!"
        exit 255;
    fi
}
quickhash() {
    file=$1
    if [ -f "$file" ]; then
	hash=$(md5sum $file)
        echo "[#] MD5 hash: $hash" >> $LOGFILE
	echo " " >> $LOGFILE
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
    echo "[+] Running with correct privilges."
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
dtg=$(date -u | cut -d" " -f5-6)
echo "********************************" > $LOGFILE
echo "* VMDK Conversion and analysis *" >> $LOGFILE
echo "********************************" >> $LOGFILE
echo "logile opened on $(date -u '+%Y-%m-%d')." > $LOGFILE
echo "Conversion Started at: $dtg" >> $LOGFILE
echo "Storage location: $OUTPATH" >> $LOGFILE
echo "********************************" >> $LOGFILE

# Convert VMDK to RAW
# NOTES: This can create a large disk image - the raw file will be the
# maximum size of the disk and this can create issues. Ensure the storage
# device has sufficient space.
# MD5 hashes are used for disk images (and other large files) for speed.
#
echo "[ ] Converting VMDK to raw file. Hashing the file might take a long time!"
initialhash=quickhash($VMDK)
echo "VMDK Conversion" > $LOGFILE
echo "[ ] VMDK MD5 Hash: $initialhash" > $LOGFILE
qemu-img convert -f VMDK -O RAW $VMDK $RAWFILE
echo "[ ] Conversion Complete - hashing."
echo "[ ] Conversion Complted at $(date | cut -d" " -f5,6)" >> $LOGFILE
rawhash=quickhash($RAWFILE)
echo "[ ] Raw file MD5 Hash: $rawhash" > $LOGFILE
echo "[ ] Hashing completed."

# Partition Analysis
echo "[ ] Analysing partitions"
mmls $RAWFILE > $OUTPATH/mmls.txt
echo "[ ] MMLS ran at at $(date | cut -d" " -f5,6). File stored at $OUTPATH/mmls.txt" >> $LOGFILE
hashfile $OUTPATH/mmls.txt
if grep -q NTFS $OUTPATH/mmls.txt
then
    echo "[!] NTFS Partitions detected."
    
else
    echo "[!] No NTFS Partitions detected."
    echo "[!] No NTFS Partitions detected in the raw image." >> $LOGFILE
    echo "[ ] Exiting at $(date | cut -d" " -f5,6)." >> $LOGFILE
    exit()