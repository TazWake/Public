#!/bin/bash

# This script takes two arguments, an inode number and drive, then dumps the block containing the inode.

clear
echo "!! Begining EXT4 block extraction !!"
read -p "What is the inode number? " INODE
read -p "What is the device or drive address? " DRIVE
echo ""
echo "[X] Recovering inode $INODE from $DRIVE."
echo ""
GROUP=$(($INODE/8192))
echo "[ ] This inode is in Group: $GROUP"
echo ""
echo "[ ] Checking fsstat to confirm settings"
START=$(fsstat $DRIVE | grep "Group: $GROUP" -A12 | grep "Inode Table" | awk '{print $3}')
INODERANGE=$(fsstat $DRIVE | grep "Group: $GROUP" -A12 | grep "Inode Range" | awk '{print $3}')
echo "[ ] The start of this block group is $START and the start of the inode range is $INODERANGE"
COUNTINTOGROUP=$(($INODE-$INODERANGE))
echo "[ ] Your inode is $COUNTINTOGROUP inodes into this block group."
OFFSET=$(($COUNTINTOGROUP/16))
echo "[ ] This is $OFFSET blocks into the group."
BLOCK=$(($START+$OFFSET))
echo "[ ] Extracting block $BLOCK."
blkcat $DRIVE $BLOCK > extracted_block_$BLOCK
echo "[X] Extraction complete. The block is at ./extracted_block_$BLOCK."
# Calculate hex offset
# use XXD to carve the block to find the specific inode
