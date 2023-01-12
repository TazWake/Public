#!/bin/bash

# ####################################################
# use: scriptname.sh imagefilename volatilityprofile #
# ####################################################
#
# This script runs a standard battery of memory analysis tools against a sample image to provide a standardised set of artefacts
# Two arguments are required - the file name of the memory image and the volatility profile to be used
#
# With volatility 3 this script needs extensive modification.
#
# This script is provided "as is" - any issues or errors should be corrected locally.
#
# ASSUMPTIONS
# vol.py is in the path - if not update the script appropriately.
# You have already established the correct profile.
# The memory image is from a Windows machine, Win7/Server 2012 or newer.

fn=$1
profile=$2

update_logs() {
    file=$1
	if [ -f "$file" ]; then
	    holder=$(md5sum $file | cut -d" " -f1)
	    dtg=$(date | cut -d" " -f4,5)
	    echo "[+] $file : $holder : $dtg" >> checksum.txt
	    echo "[+] $file complete at $dtg, MD5 checksum added to checksum.txt." >> log.txt
    else
	    echo "$file does not exist."
		echo "[!] $file has not been extracted from the memory sample." >> log.txt
	fi
}

checksum_copy() {
    file=checksum.txt
	if [ -f "$file" ]; then
	    check=$(md5sum $file | cut -d" " -f1)
		cp checksum.txt $check.txt
		echo "The md5 of the checksum file is $check"
		echo "A copy of the checksum file has been created as $check.txt"
		echo "[*] A copy of the checksum has been created as $check.txt" >> log.txt
	else
	    echo "Unable to locate the checksum file"
	fi
}

echo "Automated data carving began at $(date)" > log.txt
echo "MD5 checksums stored in checksum.txt" >> log.txt
echo "MD5 checksums for $fn" > checksum.txt
echo "********************"
echo "Extracting Volatility Data"
# This is the basic run of commands with each plugin storing data to a text file.
vol.py -f $fn imageinfo --output-file=imageinfo.txt
update_logs imageinfo.txt
vol.py -f $fn --profile=$profile pslist --output-file=pslist.txt
update_logs pslist.txt
vol.py -f $fn --profile=$profile psscan --output-file=psscan.txt
update_logs psscan.txt
vol.py -f $fn --profile=$profile pstree --output-file=pstree.txt
update_logs pstree.txt
vol.py -f $fn --profile=$profile psxview --output-file=psxview.txt
update_logs psxview.txt
vol.py -f $fn --profile=$profile netscan --output-file=netscan.txt
update_logs netscan.txt
vol.py -f $fn --profile=$profile cmdscan --output-file=cmdscan.txt
update_logs cmdscan.txt
vol.py -f $fn --profile=$profile consoles --output-file=consoles.txt
update_logs consoles.txt
vol.py -f $fn --profile=$profile hivelist --output-file=hives.txt
update_logs hives.txt
vol.py -f $fn --profile=$profile prefetchparser --output-file=prefetchparser.txt
update_logs prefetchparser.txt
vol.py -f $fn --profile=$profile envars --output-file=envars.txt
update_logs envars.txt
vol.py -f $fn --profile=$profile dlllist --output-file=dlllist.txt
update_logs dlllist.txt
vol.py -f $fn --profile=$profile filescan --output-file=filescan.txt
update_logs filescan.txt
vol.py -f $fn --profile=$profile shimcache --output-file=shimcache.txt
update_logs shimcache.txt
vol.py -f $fn --profile=$profile shimcachemem --output-file=shimcachemem.txt
update_logs shimcachemem.txt
vol.py -f $fn --profile=$profile getservicesids --output-file=serviceSIDS.txt
update_logs serviceSIDS.txt
vol.py -f $fn --profile=$profile mimikatz --output-file=mimikatz.txt
update_logs mimikatz.txt
vol.py -f $fn --profile=$profile handles --output-file=handles.txt
update_logs handles.txt
vol.py -f $fn --profile=$profile getsids --output-file=AllSIDS.txt
update_logs AllSIDS.txt
vol.py -f $fn --profile=$profile svcscan --output-file=svcscan.txt
update_logs svcscan.txt
mkdir malfind
vol.py -f $fn --profile=$profile malfind -D ./malfind/ --output-file=malfind.txt
update_logs malfind.txt
echo "*** AV Scan on Malfind Output ***"
clamscan ./malfind/* > clamscan_malfind.txt
update_logs clamscan_malfind.txt
mkdir MFT
vol.py -f $fn --profile=$profile mftparser -D ./MFT/ --output-file=mft.txt
update_logs mft.txt
echo "*** carving network data ***"
# This is to create two easier to read text files showing established and listening connections
if [ -f "netscan.txt" ]; then
    head -n1 netscan.txt > established.txt
    grep ESTABLISHED netscan.txt >> established.txt
    update_logs established.txt
    head -n1 netscan.txt > listening.txt
    grep LISTENING netscan.txt >> listening.txt
    update_logs listening.txt
    echo "*** network data carved ***"
else
    echo "*** Network data not found ***"
fi
echo ""
echo "*** attempting hashdump ***"
# This will attempt to locate the SYSTEM and SAM hives and use them to dump hashes from the memory image.
syshive=$(egrep -i "system$" hives.txt | cut -d" " -f1)
samhive=$(egrep -i "SAM$" hives.txt | cut -d" " -f1)
vol.py -f $fn --profile=$profile hashdump -y $syshive -s $samhive --output-file=hashdump.txt
update_logs hashdump.txt
# Password hashes should be in a crackable format now if required.
echo "Volatility Extraction Completed"
echo "********************"
echo ""
echo "********************"
echo "Running Bulk Extractor"
echo "********************"
mkdir bulk_output
bulk_extractor $fn -o ./bulk_output
echo "[+] bulk_extractor completed at $(date | cut -d" " -f4,5), no checksums generated." >> log.txt
echo "********************"
echo ""
echo "********************"
echo "*** Running Strings ***"
# as a final catch all strings are run against the image
strings -n 8 $fn > strings8.txt
update_logs strings8.txt
strings -n 12 $fn > strings12.txt
update_logs strings12.txt
echo "********************"
echo ""
checksum_copy
echo "Automated Data carving completed at $(date)" >> log.txt
chmod 444 log.txt
echo "********************"
echo "Initial Assessment Completed"
echo "********************" 
