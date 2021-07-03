#!/bin/bash

# This script carves VMDK images
#
#
#
# Syntax
# VMDK_Carver.sh /path/to/vmdk /path/to/storage

# SET UP
VMDK=$1
OUTPATH=$2
TEMPNAME=$(cat /dev/urandom | tr -cd 'a-f0-9' | head -c 8)
TEMPFILE=$OUTPATH/$TEMPNAME

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

# Convert VMDK to RAW
