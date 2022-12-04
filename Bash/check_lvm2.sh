#!/bin/bash

# This simple script is an example of how you can check a live filesystem to see if LVM2 is in use.

echo "> Checking for LVM2"
now=$(date +"%T")
echo "> Script running at $now" 
if  grep -Pq '/dev/(mapper/|disk/by-id/dm)' /etc/fstab  ||  mount | grep -q /dev/mapper/
then
    echo "> LVM *is* in use."
else
    echo "> LVM is NOT in use."
fi
echo "> Check complete."
