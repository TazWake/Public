#!/bin/bash

if [ $# -lt 2 ]; then
    echo "Usage: $0 path_to_journals output_file_path"
    exit 1
fi

JOURNALS=$1
OUTPUT=$2

if [ -z "$(find $JOURNALS -name '*.journal')" ]; then
    echo "No journal files found in $JOURNALS. This script will exit"
    exit 1
else
    echo "Journal files found."
fi

touch $OUTPUT/journal.txt

echo "! Converting journal files into text."
cd $JOURNALS
for f in ./*.journal
do
    echo "Attempting to convert: $f"
    journalctl --file $f >> $OUTPUT/journal.txt
done
echo "! Journal conversion completed. There may have been errors in the output."
echo "! Converting text file into CSV."
sed 's/<\/Data><Data/<\/Data>,<Data/g' $OUTPUT/journal.txt > $OUTPUT/journal.csv
echo "! Script completed."
