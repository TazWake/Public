#!/bin/bash
# This script will run some basic checks against the system journal to see
# if there are any clear indications of malicious activity.

# Check arguments
if [ "$#" -ne 2 ]; then
    echo "Error: You must provide exactly two arguments." >&2
    echo "Usage: $0 arg1(journalpath) arg2(storagepath)" >&2
    echo "[ ] The first argument should point to the directory containing the Journal files to be analysed." >&2
    echo "[ ] The second argument should point to the location where any output is to be stored." >&2
    exit 1
fi

# Set up inputs
EVIDENCEPATH=$1
STORAGEPATH=$2
TEMPNAME=$(cat /dev/urandom | tr -cd 'a-f0-9' | head -c 8)
TEMPFILE=$STORAGEPATH/$TEMPNAME

# Check Requirements
if [[ $EUID != 0 ]]; then
    echo "[!] This script must be run with root privileges!"
    echo "[!] Exiting"
    exit 255;
else
    echo "[ ] Running with correct privileges."
fi
if [ -d "$EVIDENCEPATH" ]; then
    # The directory exists, check if it holds Journal files
    journal_files_count=0
    for file in "$EVIDENCEPATH"/*; do
        # Check if the item is a file and ends with .journal or .journal~
        if [[ -f $file && ($file == *.journal || $file == *.journal~) ]]; then
            ((journal_files_count++))
        fi
    done
    if [ "$journal_files_count" -eq 0 ]; then
        echo "No journal files found in the directory '$EVIDENCEPATH'." >&2
        exit 1
    else
        echo "[ ] Found $journal_files_count journal file(s) in the directory '$EVIDENCEPATH'."
    fi
else
    echo "Error: The directory '$EVIDENCEPATH' does not exist." >&2
    exit 1
fi
touch $TEMPFILE
if [ -f $TEMPFILE  ]; then
    echo "[+] Write to storage media successful."
    rm $TEMPFILE
    echo "[ ] Analyzing the journal."
else
    echo "[!] Unable to write to storage media."
    echo "[!] Exiting."
    exit 255;
fi

# Create subfolder for evidence
mkdir -p $STORAGEPATH/JournalTriage
STORAGEPATH=$STORAGEPATH/JournalTriage

# Check for invalid SSH logins and write to file.
journalctl -t sshd --directory $EVIDENCEPATH 2>/dev/null | grep 'invalid' | awk 'BEGIN {print "IP Address,Username,Count"} {userIP=$12 "," $11; count[userIP]++} END {for (pair in count) print pair "," count[pair]}' > $STORAGEPATH/FailedLogins.csv
# Check for successful SSH logins and write to file.
journalctl -t sshd --directory $EVIDENCEPATH 2>/dev/null | grep 'Accepted' | awk 'BEGIN {print "IP Address,Username,Count"} {userIP=$9 "," $11; count[userIP]++} END {for (pair in count) print pair "," count[pair]}' > $STORAGEPATH/SuccessfulLogins.csv
echo "[ ] Logins checked"
# Check for sudo command use.
journalctl -t sudo --directory $EVIDENCEPATH 2>/dev/null | grep 'COMMAND' | awk 'BEGIN {print "User,Terminal,Directory,Running As,Command"}{user = gensub(/.*\]: +(\S+).*/, "\\1", 1);tty = gensub(/.*TTY=([^ ]+).*/, "\\1", 1);pwd = gensub(/.*PWD=([^ ;]+).*/, "\\1", 1);usr = gensub(/.*USER=([^ ;]+).*/, "\\1", 1);cmd = gensub(/.*COMMAND=(.*)/, "\\1", 1);print user "," tty "," pwd "," usr "," cmd}' > $STORAGEPATH/sudo_commands.csv
echo "[ ] Sudo commands checked."
# extract all command lines from Auditd data (if it exists)
journalctl -t audit --directory $EVIDENCEPATH 2>/dev/null | grep PROCTITLE | awk 'BEGIN { print "time,command" } {
    match($0, /proctitle=([0-9a-fA-F]+)/, arr);
    hex_encoded = arr[1];
    cmd = ""; 
    for(i = 1; i <= length(hex_encoded); i+=2) {
        c = strtonum("0x" substr(hex_encoded, i, 2));
        if(c != 0) 
            cmd = cmd sprintf("%c", c);
        else 
            cmd = cmd " ";
    }
    print $1 " " $2 " " $3 "," cmd;
}' | uniq > $STORAGEPATH/audit_commands.csv
echo "[ ] Auditd Command Lines Checked."
echo "[+] Analysis Complete - output is in $STORAGEPATH."
