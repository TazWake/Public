#!/bin/bash

#############################################################
### This script will create an evidence collection device ###
### ----------------------------------------------------- ###
###                                                       ###
### Ideally this should be run from a trusted device that ###
### contains the binaries listed below. This works well   ###
### when run from SANS Linux SIFT. Other systems may need ###
### validation or tool installation.                      ###
###                                                       ###
### ----------------------------------------------------- ###
###                                                       ###
### usage: SCRIPT_NAME <mount_point>                      ###
###                                                       ###
#############################################################

function create_folders {
    mkdir -p $mount_point/evidence
    mkdir -p $mount_point/collectiontools 
}

function check_space {
    available_space=$(df -BG "$mount_point" | awk 'NR==2 {print $4}' | sed 's/G//')
    if [ "$available_space" -lt 8 ]; then
        echo "[!] The storage device has less than 8Gb of storage space remaining. This is not suitable for evidence collection"
        exit 1
    elif [ "$available_space" -gt 60 ]; then
        echo "[ ] The storage device has more than 60gb of storage space remaining."
        echo "[ ] This will be effective at collecting triage data and memory in most situations."
        echo "[!] If this is insufficient, exit the script now."
    else
        echo "[ ] The mounted device has $available_space Gb free. Please ensure this is sufficient for your needs."
    fi
}
function install_tools {
    destination="$mount_point/collectiontools"
    echo "[ ] Installing the core tools."
    # This next section should only be used if source code is required and the tools will be built on the device
    # -----------------------------------------------------------------------------------------------------------
    #url="https://ftp.gnu.org/gnu/coreutils/coreutils-9.3.tar.gz"
    #wget -q "$url" -P "$destination"
    #if [ "$?" -ne 0 ]; then
    #    echo "[ ] Download failed. Exiting."
    #    exit 1
    #fi
    #tar --no-same-owner -xzf "$destination/coreutils-9.3.tar.gz" -C "$destination"
    #if [ "$?" -ne 0 ]; then
    #    echo "Extraction failed. Exiting."
    #    exit 1
    #fi
    # -----------------------------------------------------------------------------------------------------------
    
    # This will assume the script is being run from a trusted machine.
    cp $(which ls) "$destination"
    cp $(which cat) "$destination"
    cp $(which pwd) "$destination"
    cp $(which grep) "$destination"
    cp $(which zcat) "$destination"
    cp $(which zgrep) "$destination"
    cp $(which diff) "$destination"
    cp $(which xxd) "$destination"
    cp $(which gunzip) "$destination"
    cp $(which tar) "$destination"
    cp $(which zip) "$destination"
    cp $(which df) "$destination"
    cp $(which ping) "$destination"
    cp $(which wget) "$destination"
    cp $(which curl) "$destination"
    cp $(which md5sum) "$destination"
    cp $(which sha1sum) "$destination"
    cp $(which sha256sum) "$destination"
    cp $(which base64) "$destination"
    cp $(which json_pp) "$destination"
    cp $(which rm) "$destination"
    cp $(which scp) "$destination"
    cp $(which nano) "$destination"
    cp $(which chattr) "$destination"
    cp $(which chown) "$destination"
    cp $(which chgrp) "$destination"
    cp $(which dd) "$destination"
    cp $(which dcfldd) "$destination"
    cp $(which dc3dd) "$destination"
    cp $(which ewfacquire) "$destination"
    cp $(which ss) "$destination"
    cp $(which lsof) "$destination"
    cp $(which ps) "$destination"
    cp $(which netstat) "$destination"
    cp $(which stat) "$destination"
    cp $(which strace) "$destination"
    cp $(which nslookup) "$destination"
    cp $(which ngrep) "$destination"
    cp $(which tcpdump) "$destination"
    cp $(which du) "$destination"
    cp $(which dumpcap) "$destination"
    cp $(which echo) "$destination"
    cp $(which env) "$destination"
    cp $(which date) "$destination"
    cp $(which time) "$destination"
    cp $(which tee) "$destination"
    cp $(which top) "$destination"
    cp $(which exiftool) "$destination"
    cp $(which file) "$destination"
    cp $(which find) "$destination"
    cp $(which uniq) "$destination"
    cp $(which sort) "$destination"
    cp $(which unzip) "$destination"
    cp $(which gdb) "$destination"
    cp $(which lsattr) "$destination"
    cp $(which xargs) "$destination"
    cp $(which hostname) "$destination"
    cp $(which zless) "$destination"
    cp $(which zmore) "$destination"
    cp $(which head) "$destination"
    cp $(which tail) "$destination"
    cp $(which less) "$destination"
    cp $(which more) "$destination"
    cp $(which gdb) "$destination"
    cp $(which objdump) "$destination"
    cp $(which readelf) "$destination"
    cp $(which strings) "$destination"
    cp $(which size) "$destination"
    
    echo "[ ] The core tools have been copied to the device."
    echo "[ ] Ensuring AVML is installed."
    url="https://github.com/microsoft/avml/releases/download/v0.13.0/avml"
    wget -q "$url" -P "$destination"
    
    echo "[ ] Tools installed. Making executable now."
    chmod +x $destination/*
    
    remaining_space=$(df -BG "$mount_point" | awk 'NR==2 {print $4}' | sed 's/G//')
    echo "[ ] Privileges set. There is $remaining_space Gb remaining on the device."
}

# Check if the number of arguments provided is exactly 1
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <device_path_or_mount_point>"
    exit 1
fi

# Get the device path or mount point from the command line argument
input="$1"

# Check if the input is a valid device path
if [[ -b "$input" ]]; then
    # Input is a device path, find the associated mount point
    mount_point=$(findmnt -n -o TARGET --source "$input")
elif [[ -d "$input" ]]; then
    # Input is a directory, consider it as a mount point
    mount_point="$input"
else
    # Invalid input, exit the script
    echo "Invalid device path or mount point. Exiting."
    exit 1
fi

# Check if the device is mounted
if [ -n "$mount_point" ]; then
    clear
    echo "Evidence Collector - Creation Script."
    echo "-------------------------------------"
    echo "This script will validate the mount"
    echo "point you have provided. If a device"
    echo "is mounted correctly, it will create"
    echo "two folders on the device and begin "
    echo "to install the tools required."
    echo "-------------------------------------"
    echo ""
    echo "[ ] Device or mount point $input is mounted at $mount_point."
    read -p "[?] Do you want to continue? (press N to abort, anything else will continue): " response
    response=$(echo "$response" | tr '[:upper:]' '[:lower:]')
    if [[ "$response" == "n" ]]; then
        echo "[!] Exiting as requested."
        exit 0
    fi
    check_space
    create_folders
    install_tools
else
    echo "[!] Device or mount point $input is not mounted. Exiting."
    exit 1
fi
