#!/bin/bash

# ##########################################
# This script is to extract the bodyfile   #
# entries from a large number of UAC files #
# so you can run mactime against them.     #
# ##########################################

# Default values - You probably should change this or add an override. . . 
SOURCE_DIR="/mnt/tmp"
DEST_DIR="/mnt/tmp"

# Allow override via command line arguments
# Usage: ./script.sh [source_dir] [dest_dir]
if [ ! -z "$1" ]; then
    SOURCE_DIR="$1"
fi

if [ ! -z "$2" ]; then
    DEST_DIR="$2"
fi

# Ensure destination exists
mkdir -p "$DEST_DIR"

echo "Processing UAC archives in: $SOURCE_DIR"
echo "Outputting to: $DEST_DIR"
echo "------------------------------------------"

# Iterate through tar.gz files in the top level only (no recursion)
for ARCHIVE in "$SOURCE_DIR"/*.tar.gz; do
    
    # Skip if no files match the pattern
    [ -e "$ARCHIVE" ] || continue

    # Get the filename without the path
    BASENAME=$(basename "$ARCHIVE")
    
    # Extract the hostname (everything before _UAC.tar.gz)
    HOSTNAME="${BASENAME%%_UAC.tar.gz}"
    
    echo "Extracting bodyfile for: $HOSTNAME"

    # Extract ONLY the bodyfile to stdout and redirect to the new destination
    # --extract: pull file
    # --to-stdout: don't recreate the folder structure locally
    # --wildcards: handle the internal path
    tar -xzf "$ARCHIVE" --to-stdout "bodyfile/bodyfile.txt" > "$DEST_DIR/${HOSTNAME}.body"

    if [ $? -eq 0 ]; then
        echo "Successfully saved to ${HOSTNAME}.body"
    else
        echo "Error: Could not find bodyfile/bodyfile.txt in $BASENAME"
        # Remove the empty file if tar failed
        rm -f "$DEST_DIR/${HOSTNAME}.body"
    fi

done

echo "------------------------------------------"
echo "Processing complete."
