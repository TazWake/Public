#!/bin/bash
# This script is designed to run some basic checks on a suspicious
# file and save the output as a collection of text files, which can
# then be passed to an LLM platform for analysis.

# NOTE: this requires a ChatGPT API Key.

# Usage:
#    ./malanalyze_chatgpt.sh -f filename

# Version 0.0.2
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
    local output_file="$2"
    local log_file="$3"
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    echo "[$timestamp] Running command: $cmd" >> "$log_file"
    bash -c "$cmd" > "$output_file" 2>> "$log_file"
}

resolve_full_path() {
    local filename="$1"
    FP=$(realpath "$filename")
    if [ ! -f "$FP" ]; then
        echo "Error: File $filename not found."
        exit 1
    fi
}

upload_to_chatgpt() {
    local filepath="$1"
    local logpath="$2"
    local api_key="<YOUR_API_KEY>"
    local prompt="Please review the attached file and provide an assessment of what the sample does, and if it is likely to be malicious."

    echo "[ ] Uploading $filepath and $logpath to ChatGPT for analysis..."

    # Combine the file and log content for a comprehensive analysis
    local file_content=$(cat "$filepath")
    local log_content=$(cat "$logpath")
    local combined_content="File Content:\n$file_content\n\nLog Content:\n$log_content"

    local response=$(curl -s -X POST "https://api.openai.com/v1/chat/completions" \
        -H "Authorization: Bearer $api_key" \
        -H "Content-Type: application/json" \
        -d '{
            "model": "gpt-4",
            "messages": [{"role": "user", "content": "'"$prompt\n\n$combined_content"'"}]
        }')

    echo "[ ] Response from ChatGPT:"
    echo "$response" | jq '.choices[0].message.content'
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
log_and_run "file $FP" "$FOLDER/file.txt" "$log_file"
log_and_run "sha1sum $FP" "$FOLDER/sha1hash.txt" "$log_file"
log_and_run "readelf -a $FP" "$FOLDER/readelf.txt" "$log_file"
log_and_run "objdump -d $FP" "$FOLDER/objdump.txt" "$log_file"
log_and_run "strings -n8 $FP" "$FOLDER/strings.txt" "$log_file"
log_and_run "ldd $FP" "$FOLDER/ldd.txt" "$log_file"

echo "[ ] Static analysis complete. "

HASH=$(sha256sum "$log_file" | awk '{ print $1 }')

echo "[ ] Evidence is stored in $FOLDER and the log file is at $log_file."
echo "[*] The SHA256 hash of the log file is $HASH."

upload_to_chatgpt "$FP" "$log_file"
