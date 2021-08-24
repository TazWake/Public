#!/bin/bash

# This is a stub, the goal is to build a tool which can be used
# to search through directories and folders to find documents
# that have been modified during the time of an incident and then
# checks to see if the last modified by field looks odd.

FILE=$1

lastmod=$(exiftool $FILE | grep "Last Modified By" | cut -d':' -f2)
author=$(exiftool $FILE | grep "Creator" | cut -d':' -f2)

if [[ "$lastmod" != "$author" ]]
then
    echo "Note: $FILE, was last modified by $author, not its creator."
else
    echo "The documnet $FILE, was last modified by its author."
fi
