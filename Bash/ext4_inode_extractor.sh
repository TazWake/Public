#!/bin/bash

# This script takes two arguments, an inode number and drive, then dumps the block containing the inode.
# Set up the help function

Help()
{
    echo ""
    echo "This script will identify the block containing a given inode from an EXT4 image and export it to disk."
    echo ""
    echo "Syntax: $0 -i ARGUMENT -p ARGUMENT"
    echo "Arguments:"
    echo "    -i: inode number"
    echo "    -p: path to the disk image"
    echo ""
    echo "Also:"
    echo "    -h: Show this help file and exit."
    echo ""
}

# Check to see if the TSK components exist.

if ! command -v fsstat &>/dev/null
then
    echo "Unable to locate fsstat. This script will exit"
    exit
fi

if ! command -v blkcat &>/dev/null
then
    echo "Unable to locate blkcat. This script will exit"
    exit
fi

# Take command line arguments

while getopts ":i:p:h" option; do
    case $option in
        i) INODE=${OPTARG}
        ;;
        p) DRIVE=${OPTARG}
        ;;
        h) Help
           exit;;
    esac
done

# Check arguments have been supplied

if [ -z "${INODE}" ] || [ -z "${DRIVE}" ]
then
    Help
    exit;
fi

# Start processing
clear
echo "!! Starting EXT4 block extraction !!"
#read -p "What is the inode number? " INODE
#read -p "What is the path to the image? " DRIVE
# Check the device exists
if [ ! -f "$DRIVE" ]
then
    echo "The image - $DRIVE - does not exist. Exiting."
    exit
fi

echo ""
echo "[+] This will recover inode $INODE from $DRIVE."
echo ""

GROUP=$(($INODE/8192))
echo "[+] This inode is in Group: $GROUP"
echo ""

echo "[ ] Checking fsstat to confirm settings"
START=$(fsstat $DRIVE | grep "Group: $GROUP" -A12 | grep "Inode Table" | awk '{print $3}')
INODERANGE=$(fsstat $DRIVE | grep "Group: $GROUP" -A12 | grep "Inode Range" | awk '{print $3}')
echo "[+] The start of this block group is $START and the start of the inode range is $INODERANGE"

COUNTINTOGROUP=$(($INODE-$INODERANGE))
echo "[ ] Your inode is $COUNTINTOGROUP inodes into this block group."

OFFSET=$(($COUNTINTOGROUP/16))
echo "[ ] This is $OFFSET blocks into the group."

BLOCK=$(($START+$OFFSET))
echo "[ ] Extracting block $BLOCK."
blkcat $DRIVE $BLOCK > extracted_block_$BLOCK
echo "[X] The block is at ./extracted_block_$BLOCK."
echo ""
echo "[ ] Now extracting the inode from the block."
# Calculate hex offset
OFFS=$(expr $COUNTINTOGROUP % 16)
echo "[+] The inode offset is $OFFS"
HEXOFFS=$(($OFFS * 256))
echo "[+] The hex offset is $HEXOFFS"

xxd -s $HEXOFFS -l 256 extracted_block_$BLOCK > inode_$INODE.txt
echo "[+] The inode itself has been extracted to inode_$INODE.txt"
echo "[ ] Extraction complete."
