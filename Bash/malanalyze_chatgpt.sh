#!/bin/bash
# This script is designed to run some basic checks on a suspicious
# file and save the output as a collection of text files, which can
# then be passed to an LLM platform for analysis.

# NOTE: this requires a ChatGPT API Key, stored as an environment variable
#       before the script runs.
#
#       Ensure you run OPENAI_API_KEY=[YOUR API KEY]

# Usage:
#    ./malanalyze_chatgpt.sh -f filename

# Version 0.0.3
# Status: DRAFT

# Check if required commands are available
REQUIRED_COMMANDS=(realpath file sha256sum readelf objdump strings curl jq)
for cmd in "${REQUIRED_COMMANDS[@]}"; do
    if ! command -v "$cmd" &> /dev/null; then
        echo "Error: Required command '$cmd' is not installed."
        exit 1
    fi
done

# Set the evidence store location
PWDS=$(dirname "$(realpath "$0")")

# Set API Key from Environment Variable
API_KEY="${OPENAI_API_KEY}"

# Check if API Key is set
if [ -z "$API_KEY" ]; then
    echo "Error: OpenAI API Key is not set. Please set the OPENAI_API_KEY environment variable."
    exit 1
fi

# Define functions
show_help() {
    echo "Usage: $0 -f <filename>"
    echo
    echo "This script analyzes an executable and provides the output to ChatGPT for assessment. You need to ensure that the API Key has been set as an environment variable before execution."
    echo "NOTE: This script will only run static analysis tools."
    echo "Options:"
    echo "  -f <filename>   Specify the file to analyze."
    echo "  -h              Display this help message."
    exit 1
}

log_and_run() {
    local cmd="$1"
    local output_file="$2"
    local log_file="$3"
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    echo "[$timestamp] Running command: $cmd" >> "$log_file"
    if bash -c "$cmd" > "$output_file" 2>> "$log_file"; then
        echo "[$timestamp] Successfully executed: $cmd" >> "$log_file"
    else
        local exit_code=$?
        echo "[$timestamp] Error - Command failed with exit code $exit_code: $cmd" >> "$log_file"
    fi
}

resolve_full_path() {
    local filename="$1"
    FP=$(realpath "$filename")
    if [ ! -f "$FP" ]; then
        echo "Error: File $filename not found."
        exit 1
    fi
    if [ ! -r "$FP" ]; then
        echo "Error: File $FP is not readable."
        exit 1
    fi
}

upload_to_chatgpt() {
    local filepath="$1"
    local logpath="$2"
    local prompt="Please review the attached file and provide an assessment of what the sample does, and if it is likely to be malicious."

    echo "[ ] Uploading $filepath and $logpath to ChatGPT for analysis..."

    # Combine the file and log content for a comprehensive analysis
    local file_content=$(cat "$filepath")
    local log_content=$(cat "$logpath")
    local combined_content="File Content:\n$file_content\n\nLog Content:\n$log_content"

    local response=$(curl -s -w "%{http_code}" -X POST "https://api.openai.com/v1/chat/completions" \
        -H "Authorization: Bearer $API_KEY" \
        -H "Content-Type: application/json" \
        -d '{
            "model": "gpt-4",
            "messages": [{"role": "user", "content": "'"$prompt\n\n$combined_content"'"}]
        }')

    http_code=$(echo "$response" | tail -n1)
    response_body=$(echo "$response" | sed '$ d')

    if [ "$http_code" -ne 200 ]; then
        echo "Error: API request failed with status code $http_code."
        echo "Response: $response_body"
        exit 1
    fi

    TIMESTAMP=$(date -u +"%Y%m%dT%H%M%SZ")
    echo "$response_body" | jq '.choices[0].message.content' > "$FOLDER/chatgpt_response_$TIMESTAMP.txt"
    echo "[ ] ChatGPT response saved to $FOLDER/chatgpt_response_$TIMESTAMP.txt"

    echo "[ ] Response from ChatGPT:"
    echo "$response_body" | jq '.choices[0].message.content'
}

# Check the script has been called correctly
if [ "$#" -eq 0 ]; then
    show_help
fi

while getopts "f:h" opt; do
    case $opt in
        f)
            fn="$OPTARG"
            ;;
        h)
            show_help
            ;;
        *)
            show_help
            ;;
    esac
done

if [ -z "$fn" ]; then
    show_help
fi

resolve_full_path "$fn"

# Create timestamped evidence store directory
TIMESTAMP=$(date -u +"%Y%m%dT%H%M%SZ")
FOLDER="$PWDS/evidence_$TIMESTAMP"
mkdir -p "$FOLDER"
log_file="$FOLDER/log_$TIMESTAMP.txt"

echo "[ ] Collecting data on $FP now
