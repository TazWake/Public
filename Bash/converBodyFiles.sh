#!/bin/bash

# ##################################
# This script is to bulk convert a #
# large number of body files into  #
# human readable timelines, using  #
# the mactime.pl tool.             #
# ##################################

# Default values - you should change this or use overrides
BASE_DIR="/tmp/bodyfiles"
DATE_RANGE="2026-01-25..2026-05-07"

# Usage: ./script.sh [input_dir] [output_dir]
INPUT_DIR="${1:-$BASE_DIR}"
OUTPUT_DIR="${2:-$INPUT_DIR}"

# Ensure directories exist
if [ ! -d "$INPUT_DIR" ]; then
    echo "Error: Input directory $INPUT_DIR does not exist."
    exit 1
fi
mkdir -p "$OUTPUT_DIR"

echo "Processing .body files in: $INPUT_DIR"
echo "Date Range: $DATE_RANGE"
echo "------------------------------------------"

# Iterate through .body files (top level only)
for BODY_FILE in "$INPUT_DIR"/*.body; do

    # Check if files exist to avoid error if glob finds nothing
    [ -e "$BODY_FILE" ] || continue

    # Get filename without path and extension
    FILENAME=$(basename "$BODY_FILE" .body)
    
    echo "Processing: ${FILENAME}.body"

    # Run mactime
    # -d: Output in comma-delimited format (CSV)
    # -z: Set timezone to UTC
    # -b: Path to the body file
    mactime -d -z UTC -b "$BODY_FILE" "$DATE_RANGE" > "$OUTPUT_DIR/${FILENAME}.csv"

    if [ $? -eq 0 ]; then
        echo "Successfully created: ${FILENAME}.csv"
    else
        echo "Error processing ${FILENAME}.body"
    fi
done

echo "------------------------------------------"
echo "Timeline generation complete."
