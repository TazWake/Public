#!/bin/zsh
# This script is a starter-script for capturing
# data from a suspected-compromised MacOS host.
#
# This is no a Forensic Evidence script. It is
# designed to support incident response.
#
# SYNTAX
#
# scriptname.sh <storage location>

# Set up environment
STORE="$1"


#  Check it is run as root
if  [[ $EUID -ne 0 ]]; then
    echo "This script requires root privileges to run"
    exit
fi

sudo -k
