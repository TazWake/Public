#!/bin/bash

# Evidence collection script for Linux hosts. 
# NOTE: MD5 is used to hash disk images to save time.
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
TEMPNAME=$(cat /dev/urandom | tr -cd 'a-f0-9' | head -c 8)
TEMPFILE=$EVIDENCEPATH/$TEMPNAME

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

################ CAPTURE VOLATILE DATA ##################################

# Copy proc files
# This is commented out as it can take hours.
#dtg=$(date | cut -d" " -f4,5)
#mkdir $EVIDENCEPATH/procs
#echo "[ ] Copying /proc to the storage media. This may take some time."
#echo "[~] Created folder at $EVIDENCEPATH/procs" >> $LOGFILE
#echo "[~] Copying /proc data at $dtg." 
#echo "[~] Errors will be suppressed and copy may be incomplete." >> $LOGFILE
#cp -R /proc/ $EVIDENCEPATH/procs 2>/dev/null
#dtg=$(date | cut -d" " -f4,5)
#echo "[~] Collection completed at $dtg." >> $LOGFILE
#echo "[ ] Copy complete."

# Capture bash history
dtg=$(date | cut -d" " -f4,5)
echo "[ ] Collecting bash history at $dtg" >> $LOGFILE
echo "[ ] Collecting bash history."
mkdir $EVIDENCEPATH/history # create storage locations
cp /root/.bash_history $EVIDENCEPATH/history/root_bash_history.txt # get root history
USRNAMES=$(getent passwd | grep sh | grep -v nologin | grep -v root | grep -v lib | cut -d':' -f 6 | cut -d'/' -f3 | sort | uniq | sed '/^$/d')
for i in $USRNAMES
do 
    mkdir $EVIDENCEPATH/history/$i # create user folders
    cp /home/$i/.bash_history $EVIDENCEPATH/history/$i/bash_history.txt # grab bash history
done
dtg=$(date | cut -d" " -f4,5)
echo "[+] Collection complete at $dtg." >> $LOGFILE
echo " " >> $LOGFILE
echo "[+] Bash history collection complete."

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

# Grab memory
# TBD

# Get disk image
DISK=$(df | grep "/$" | cut -d' ' -f 1)

if ! command -v ewfacquire &> /dev/null
then
    dtg=$(date | cut -d" " -f4,5)
    IMAGEFILENAME=$EVIDENCEPATH/$(hostname)_disk_image.raw
    echo "[!] ewfaquire not found. Using dd instead. Disk image will be larger, tar will be used to compress."
    echo "[!] THIS MIGHT TAKE SOME TIME!"
    echo "[ ] Using DD for image capture." >> $LOGFILE
    echo "[ ] Writing to $IMAGEFILENAME"
    echo "[ ] Writing disk image to $IMAGEFILENAME at $dtg" >> $LOGFILE
    dd if=$DISK of=$IMAGEFILENAME bs=64K conv=noerror,sync
    dtg=$(date | cut -d" " -f4,5)
    echo "[+] Disk copy completed at $dtg." >> $LOGFILE
    echo "[ ] Image collection complete, hashing"
    diskhash=$(md5sum $IMAGEFILENAME)
    echo $diskhash > $EVIDENCEPATH/diskimage_md5hash.txt
    dtg=$(date | cut -d" " -f4,5)
    echo "[#] Disk image MD5 hash: $(echo $diskhash | cut -d' ' -f1) $dtg" >> $LOGFILE
    echo "[+] Image MD% hash: $(echo $diskhash | cut -d' ' -f1)"
    echo "[ ] Compressing disk image. This will take a LONG time."
    tar -cvzf $EVIDENCEPATH/disk_image.tar.gz $IMAGEFILENAME $EVIDENCEPATH/sha1hash.txt
    echo "[ ] Compression completed, hashing with MD5."
    comphash=$(md5sum $EVIDENCEPATH/disk_image.tar.gz)
    echo "[+] MD5 Hash completed. Hash: $(echo comphash | cut -d' ' -f1)"
    dtg=$(date | cut -d" " -f4,5)
    echo "[+] Compressed tar file created at $dtg." >> $LOGFILE
    echo "[ ] Reference details: $comphash" >> $LOGFILE
    rm $IMAGEFILENAME
    echo "[ ] Original disk image deleted from file system"
else
    IMAGEFILENAME=$EVIDENCEPATH/$(hostname)_disk_image
    dtg=$(date | cut -d" " -f4,5)
    echo "[!] ewfaquire found. Will create E01 image."
    echo "[!] THIS MIGHT TAKE SOME TIME!"
    echo "[ ] Writing to $IMAGEFILENAME.E01"
    echo "[ ] Using ewfacquire for image capture." >> $LOGFILE
    echo "[ ] Writing disk image to $IMAGEFILENAME.E01 at $dtg" >> $LOGFILE
    ewfacquire -t $IMAGEFILENAME $DISK -f ewf -D "Automatic Evidence Capture at $dtg." -c best -S 2G -o 0 -b 64 -l $EVIDENCEPATH/ewflog.txt
    dtg=$(date | cut -d" " -f4,5)
    echo "[+] E01 disk image created at $dtg" >> $LOGFILE
    echo "[ ] Image creation completed, hashing using MD5"
    hash=$(md5sum $IMAGEFILENAME.E01)
    echo "[#] MD5 hash: $hash" >> $LOGFILE
    echo " " >> $LOGFILE
    echo "[*] Hashing Complete."
    ewfinfo $IMAGEFILENAME.E01 > $EVIDENCEPATH/ewfinfo.txt
fi

# Close down
dtg=$(date | cut -d" " -f4,5)
echo "Data collection complete at $dtg" >> $LOGFILE
echo "***********************" >> $LOGFILE
echo "* EXTRACTION COMPLETE *" >> $LOGFILE
echo "***********************" >> $LOGFILE
sha1=$(sha1sum $LOGFILE)
echo "Logfile hash: \n $sha1" > $EVIDENCEPATH/logfile_hash.txt
echo "[+] Evidence extraction complete."
echo "[+] Logfile is stored at $LOGFILE"
echo "[+] SHA1 hash of the logfile is $(echo $sha1 | cut -d' ' -f1)"
echo "[+] A copy of the hash is stored at $EVIDENCEPATH/logfile_hash.txt"
chmod 444 $EVIDENCEPATH/logfile_hash.txt
chmod 444 $LOGFILE
