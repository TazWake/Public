#!/bin/bash
# This script is designed to run some basic checks on a suspicious 
# file and save the output as a collection of text files, which can 
# then be passed to an LLM platform for analysis.
# Usage:
#    ./malanalyze.sh -f filename

# Version 0.0.1
# Status: DRAFT

# Set the evidence store location
PWDS=$(dirname "$(realpath "$0")")

# Define functions
show_help() {
    echo "Usage: $0 -f <filename>"
    exit 1
}
log_and_run() {
    local cmd="$1"
    local log_file="$2"
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    echo "[$timestamp] Running command: $cmd" >> "$log_file"
    $cmd >> "$log_file" 2>&1
}
resolve_full_path() {
    local filename="$1"
    FP=$(realpath "$filename")
    if [ ! -f "$FP" ]; then
        echo "Error: File $filename not found."
        exit 1
    fi
}

# Check the script has been called correctly
if [ "$#" -ne 2 ]; then
    show_help
fi
if [ "$1" != "-f" ]; then
    show_help
fi
# All seems to work, set variables
fn="$2"
resolve_full_path "$fn"

echo "[ ] Creating evidence store at $PWDS/evidence."
mkdir -p "$PWDS/evidence"
FOLDER=$PWDS/evidence
log_file="$FOLDER/log.txt"

echo "[ ] Collecting data on $FP now, please wait."
log_and_run "file $FP > $FOLDER/file.txt" "$log_file"
log_and_run "sha1sum $FP > $FOLDER/sha1hash.txt" "$log_file"
log_and_run "readelf -a $FP > $FOLDER/readelf.txt" "$log_file"
log_and_run "objdump -d $FP >  $FOLDER/objdump.txt" "$log_file"
log_and_run "strings -n8 $FP >  $FOLDER/strings.txt" "$log_file"

echo "[ ] Static analysis complete. Starting some additional checks."
log_and_run "gdb $FP -ex 'info files' -ex 'disassemble main' -ex 'info functions' -ex 'info variables' -ex 'backtrace' -ex 'quit' >  $FOLDER/gdb.txt" "$log_file"
if [ -x "$FP" ]; then
    log_and_run "timeout 30 strace -o $FOLDER/strace.txt $FP" "$log_file"
    if command -v ltrace &> /dev/null; then
        log_and_run "timeout 30 ltrace -o $FOLDER/ltrace.txt $FP" "$log_file"
    else
        echo "[!] ltrace is not installed, skipping ltrace analysis." >> "$log_file"
    fi
fi
echo "[ ] Dynamic analysis complete."

HASH=$(sha256sum "$log_file" | awk '{ print $1 }')

echo "[ ] Evidence is stored in $FOLDER and the log file is at $log_file."
echo "[*] The SHA256 hash of the log file is $HASH"
