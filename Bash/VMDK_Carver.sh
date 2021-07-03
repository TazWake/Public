#!/bin/bash

# This script carves NTFS data out of VMDK images.
#
# REQUIREMENTS
#   1. This script must be run with root permissions.
#   2. TSK must be installed.
#   3. A VMDK containing NTFS partitions and a storage location is required.
#   4. If analyzeMFT is installed that will be used to convert MFT to CSV.
#
# Syntax
# VMDK_Carver.sh /path/to/vmdk/name.vmdk /path/to/storage
#
# Example
# VMDK_Carver.sh /cases/suspicousimage.vmdk /cases/rawfile

# SET UP GLOBALS
VMDK=$1
FILENAME=$(basename "$VMDK")
FILE=$(echo $FILENAME | cut -d'.' -f1)
OUTPATH=$2
RAWFILE=$OUTPATH/$FILE.raw
TEMPNAME=$(cat /dev/urandom | tr -cd 'a-f0-9' | head -c 8)
TEMPFILE=$OUTPATH/$TEMPNAME
LOGFILE=$OUTPATH/CollectionLog.txt

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
echo "********************************" > $LOGFILE
echo "* VMDK Conversion and analysis *" >> $LOGFILE
echo "********************************" >> $LOGFILE
echo "logile opened on $(date -u '+%Y-%m-%d')." >> $LOGFILE
echo "Conversion Started at: $(date -u | cut -d" " -f5-6)" >> $LOGFILE
echo "Storage location: $OUTPATH" >> $LOGFILE
echo "********************************" >> $LOGFILE

# Convert VMDK to RAW
# NOTES: This can create a large disk image - the raw file will be the
# maximum size of the disk and this can create issues. Ensure the storage
# device has sufficient space.
# MD5 hashes are used for disk images (and other large files) for speed.
#
echo "[ ] Converting VMDK to raw file. Hashing the file might take a long time!"
initialhash=$(md5sum $VMDK)
echo "VMDK Conversion" >> $LOGFILE
echo "[ ] VMDK MD5 Hash: $initialhash" >> $LOGFILE
qemu-img convert -f vmdk -O raw $VMDK $RAWFILE
echo "[ ] Conversion Complete - hashing."
echo "[ ] Conversion Completed at $(date | cut -d" " -f5,6)" >> $LOGFILE
rawhash=$(md5sum $RAWFILE) 
echo "[ ] Raw file MD5 Hash: $rawhash" >> $LOGFILE
echo "[ ] Hashing completed."

# Partition Analysis
echo "[ ] Analysing partitions"
mmls $RAWFILE > $OUTPATH/mmls.txt
chmod 444 $OUTPATH/mmls.txt
echo "[ ] MMLS ran at at $(date | cut -d" " -f5,6). File stored at $OUTPATH/mmls.txt" >> $LOGFILE
hashfile $OUTPATH/mmls.txt
if grep -q NTFS $OUTPATH/mmls.txt
then
    echo "[!] NTFS Partitions detected."
    echo "[ ] Processing NTFS Partitions in the RAW image." >> $LOGFILE
    for i in $(grep -i ntfs $OUTPATH/mmls.txt | cut -d' ' -f6)
    do
        # Carve partition data with fsstat
        echo "[ ] Offset $i contains NTFS data." >> $LOGFILE
        echo "Data at offset $i" > $OUTPATH/fsstat-$i.txt
        fsstat -o $i $RAWFILE >> $OUTPATH/fsstat-$i.txt
        echo "[ ] fsstat data written to $OUTPATH/fsstat-$i.txt" >> $LOGFILE
        chmod 444 $OUTPATH/fsstat-$i.txt
        hashfile $OUTPATH/fsstat-$i.txt
        # extract MFT
        echo "[ ] Extracting MFT at $(date -u | cut -d" " -f5-6)." >> $LOGFILE
        echo "[ ] Extracting MFT to $OUTPATH/$FILE-mft-$i.raw."
        icat -o $i $RAWFILE 0 > $OUTPATH/$FILE-mft-$i.raw
        echo "[ ] MFT extract complete. File is at $OUTPATH/$FILE-mft-$i.raw" >> $LOGFILE
        quickhash $OUTPATH/$FILE-mft-$i.raw
        # analyse MFT
        if ! command -v analyzeMFT.py &> /dev/null
        then
            echo "[!] Unable to find analyzeMFT - no MFT analysis will take place." 
            echo "[!] Unable to find analyzeMFT - no MFT analysis will take place." >> $LOGFILE
        else
            echo "[ ] Running analyzeMFT"
            echo "[ ] analyzeMFT started at $(date -u | cut -d" " -f5-6)." >> $LOGFILE
            analyzeMFT.py -f $OUTPATH/$FILE-mft-$i.raw -o $OUTPATH/$FILE-analyzed-MFT-$i.csv
            echo "[ ] analyzeMFT completed at $(date -u | cut -d" " -f5-6)." >> $LOGFILE
            echo "[ ] Output stored at $OUTPATH/$FILE-analyzed-MFT-$i.csv." >> $LOGFILE
            hashfile $OUTPATH/$FILE-analyzed-MFT-$i.csv
            chmod 444 $OUTPATH/$FILE-analyzed-MFT-$i.csv
            echo "[ ] analyzeMFT completed."
            echo "[!] Analysis Note: Some carved data may be incomplete - validate the partition and its role in the VM."
        fi
        echo "[ ] Offset $i MFT processing completed at $(date -u | cut -d" " -f5-6)." >> $LOGFILE
        # Generate FLS timeline.
        echo "[ ] Creating timeline with FLS and MACTIME."
        fls -i raw -f ntfs -o $i -m C: -r $RAWFILE > $OUTPUTPATH/$i-BodyFile
        echo "[ ] Bodyfile for partition at offset $i created." >> $LOGFILE
        hashfile $OUTPUTPATH/$i-BodyFile
        mactime -b $OUTPUTPATH/$i-BodyFile -z UTC > $OUTPUTPATH/$i-timeline.txt
        echo "[ ] Timeline for partition at offset $i created." >> $LOGFILE
        chmod 444 $OUTPUTPATH/$i-BodyFile
        chmod 444 $OUTPUTPATH/$i-timeline.txt
        echo "[ ] FLS/MACTIME timeline created."
    done
else
    echo "[!] No NTFS Partitions detected in the raw image." >> $LOGFILE
    echo "[!] No NTFS Partitions detected. This script will now exit"
fi
echo "[+] Analysis completed." >> $LOGFILE
echo "[ ] Exiting at $(date -u | cut -d" " -f5,6)" >> $LOGFILE
echo "[ ] Log closed on $(date -u '+%Y-%m-%d')." >> $LOGFILE
chmod 444 $LOGFILE
echo "[ ] Processing completed at $(date -u | cut -d" " -f5-6)."