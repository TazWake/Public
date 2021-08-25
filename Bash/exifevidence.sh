#!/bin/bash

# This is a stub, the goal is to build a tool which can be used
# to search through directories and folders to find documents
# that have been modified during the time of an incident and then
# checks to see if the last modified by field looks odd.
#
# USE
#
# filename.sh path start-date end-date
#
# EXAMPLE
#
# ./exifevidence.sh /mnt/ntfs/c/user/administrator/documents 2021-01-01 2021-09-30
#
# REQUIRES
# - exiftool

FOLDER="$1"
SDATE="$2"
EDATE="$3"

# Check dates exist
if [ -z "$2" ]
then
    SDATE=$(date -d '1 day ago' +%F)
fi
if [ -z "$3" ]
then
    EDATE=$(date +%F)
fi

# Build date string

DATES="-newermt $SDATE ! -newermt $EDATE"


# Check for exiftool

if ! command -v exiftool &>/dev/null
then
    echo "[!] Unable to find exiftool. Exiting"
    exit
fi

# Scan folder
echo -e "[ ] Checking EXIFdata to look for suspicious modifications during the time window specified.\n"
find $FOLDER -name "*.*" -type f $DATES -exec sh -c '
    for FILE do
        lastmod=$(exiftool "$FILE" | grep "Last Modified By" | cut -d':' -f2 | xargs)
        if [ -z "$lastmod" ]
        then
            lastmod="+No account name recorded+"
        fi
        author=$(exiftool "$FILE" | grep "Creator" | cut -d':' -f2 | xargs)
        if [ -z "$author" ]
        then
            author="+No account name recorded+"
        fi
        modtime=$(exiftool "$FILE" | grep "File Modif" | cut -d':' -f2- | xargs)
        language=$(exiftool "$FILE" | grep "Language Code" | cut -d':' -f2 | xargs)
        if [ -z "$language" ]
        then
            language="empty"
        fi
        if [ "$lastmod" != "$author" ]
        then
            echo "\n[!] $FILE, was last modified by a differemt account than its creator."
            echo "    This file was created by $author but modified by $lastmod." 
            echo "    The modification time is $modtime, and the language pack in use is $language.\n"
        else
            echo "The documnet $FILE appears unchanged."
        fi
    done
' exec-sh {} +
echo -e "\n[ ] Search complete. Any results will be shown above. If there are no entries, then no files were found at the path or within the timeframe specified."


# TODO

# 1. Add logic to search for modification timestamps in a date range *DONE*
# 2. Add logic to search directories not specific files *DONE*
# 3. Add test to check inputted dates are valid format.
