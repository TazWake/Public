#!/bin/bash

# Check if a path was provided
if [ -z "$1" ]; then
    echo "Usage: $0 /path/to/search"
    exit 1
fi

SEARCH_PATH="$1"

# Verify the path exists
if [ ! -d "$SEARCH_PATH" ]; then
    echo "Error: Directory $SEARCH_PATH does not exist."
    exit 1
fi

echo "Searching for .E01 files in: $SEARCH_PATH"
echo "------------------------------------------"

# Use find to locate files (case-insensitive) and execute mmls
# -type f: look for files only
# -iname: case-insensitive search for .E01
find "$SEARCH_PATH" -type f -iname "*.E01" | while read -r FILE; do
    echo "FILE: $FILE"
    mmls "$FILE"
    echo "------------------------------------------"
done
