#!/bin/bash

FILE=$1

echo "Wiping $FILE."
for a in {1..10}
do
    shred $FILE
done
echo "Shred complete."
rm $FILE
echo "$FILE has been removed."
