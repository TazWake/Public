#!/bin/bash

clear
echo "[ ] This script will test timestamps."
echo "[ ] First it will create a folder to store the logs."
mkdir -p ./logs

echo "[ ] Creating the test file. This will be called testfile and stored in the current directory."
echo "Nothing of value" > ./testfile && echo "Testfile created at: $(date)" > ./logs/timelog.txt && stat ./testfile >> ./logs/timelog.txt && echo "--------------------------" >> ./logs/timelog.txt
echo "[ ] Testfile created. The timestamps on FILE CREATION are:" && echo
stat ./testfile
sleep 2

echo "[ ] Accessing the file now."
cat ./testfile >> /dev/null && echo "Testfile accessed at $(date)" >> ./logs/timelog.txt && stat ./testfile >> ./logs/timelog.txt && echo "--------------------------" >> ./logs/timelog.txt
echo "[ ] Testfile accessed. The timestamps on FILE ACCESS are:" && echo
stat ./testfile
sleep 2

echo "[ ] Modifying file contents now."
echo "Adding more content to the file. Because we like adding more content to the file. Because it is fun" >> ./testfile && echo "Testfile modified at $(date)" >> ./logs/timelog.txt && stat ./testfile >> ./logs/timelog.txt && echo "--------------------------" >> ./logs/timelog.txt
echo "[ ] Testfile content modified. The timestamps on FILE MODIFICATION are:" && echo
stat ./testfile
sleep 2

echo "[ ] Copying the file now."
cp ./testfile ./newtest && echo "Testfile copied to newtest at $(date). Timestamps here are for newtest." >> ./logs/timelog.txt && stat ./newtest >> ./logs/timelog.txt && echo "--------------------------" >> ./logs/timelog.txt
echo "[ ] Testfile copied to newtest. Timestamps on FILE COPY - using newtest - are:" && echo
stat ./newtest && rm ./newtest

echo "[ ] Checking timestamps of the source file for the copy."
echo "Testfile was used as the source for the copy. Timestamps for testfile are now:" >> ./logs/timelog.txt && stat ./testfile >> ./logs/timelog.txt && echo "--------------------------" >> ./logs/timelog.txt
echo "[ ] Timestamps for testfile are:" && echo
stat ./testfile
sleep 2

echo "[ ] Move and rename are identical. Moving the file to a new name"
mv ./testfile ./renamed && echo "Testfile moved to renamed at $(date). Timestamps here are for renamed." >> ./logs/timelog.txt && stat ./renamed >> ./logs/timelog.txt && echo "--------------------------" >> ./logs/timelog.txt
echo "[ ] Testfile renamed to renamed. Timestamps on FILE MOVE - using renamed - are:" && echo
stat ./renamed

echo "[x] Testing complete."
