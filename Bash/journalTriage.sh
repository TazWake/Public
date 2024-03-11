#!/bin/bash
# This script will run some basic checks aganinst the system journal to see
# if there are any clear indications of malicious activity.

# Check arguments
if [ "$#" -ne 2 ]; then
    echo "Error: You must provide exactly two arguments." >&2
    echo "Usage: $0 arg1(journalpath) arg2(storagepath)" >&2
    echo "The first argument should point to the directory containing the Journal files to be analysed." >&2
    echo "The second argument should point to the location where any output is to be stored." >&2
    exit 1
fi

# Set up inputs
EVIDENCEPATH=$1
STORAGEPATH=$2
TEMPNAME=$(cat /dev/urandom | tr -cd 'a-f0-9' | head -c 8)
TEMPFILE=$STORAGEPATH/$TEMPNAME


# Check for invalid SSH logins and write to file.

journalctl -t sshd --directory $EVIDENCEPATH 2>/dev/null | grep 'invalid' | awk 'BEGIN {print "IP Address,Username,Count"} {userIP=$12 "," $11; count[userIP]++} END {for (pair in count) print pair "," count[pair]}' > $STORAGEPATH/FailedLogins.csv

