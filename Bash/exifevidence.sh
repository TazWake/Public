#!/bin/bash

# This is a stub, the goal is to build a tool which can be used
# to search through directories and folders to find documents
# that have been modified during the time of an incident and then
# checks to see if the last modified by field looks odd.

# USE
# ./exifevidence.sh /path/to/folder


#FILE=$1
FOLDER="$1"

find $FOLDER -type f -name "*.*" -exec sh -c '
    for FILE do
        # echo "Found $FILE"
        lastmod=$(exiftool "$FILE" | grep "Last Modified By" | cut -d':' -f2)
        author=$(exiftool "$FILE" | grep "Creator" | cut -d':' -f2)
        modtime=$(exiftool "$FILE" | grep "File Modif" | cut -d':' -f2-)
        if [ "$lastmod" != "$author" ]
        then
            echo "Note: $FILE, was last modified by $author, not its creator."
            echo "This file was modified on $modtime."
        else
            echo "The documnet $FILE, was last modified by its author."
            echo "This file was modified on $modtime."
        fi
    done
' exec-sh {} +


# TODO

# 1. Add logic to search for modification timestamps in a date range
# 2. Add logic to search directories not specific files *DONE*


#    echo "Checking $FILE"
#    lastmod=$(exiftool "$FILE" | grep "Last Modified By" | cut -d':' -f2)
#    author=$(exiftool $FILE | grep "Creator" | cut -d':' -f2)
#    modtime=$(exiftool $FILE | grep "File Modif" | cut -d':' -f2)
#    if [[ "$lastmod" != "$author" ]]
#    then
#        echo "Note: $FILE, was last modified by $author, not its creator."
#        echo "This file was modified on $modtime."
#    else
#        echo "The documnet $FILE, was last modified by its author."
#        echo "This file was modified on $modtime."
#    fi
