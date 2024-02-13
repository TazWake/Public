#!/bin/bash

# This script will collect scheduled task data from a Linux system.
# This is provided "as is" and is mainly for demonstration purposes.
# Do not use it in a live incident or investigation without making
# sure the script will work as intended in your environment.

# Check if a storage location was provided
if [ -z "$1" ]; then
    echo "[!] Usage: $0 <storage_location>"
    exit 1
fi

# Check the script is running as root
if [[ $EUID != 0 ]]; then
    echo "[!] This script must be run with root privileges!"
    echo "[!] Exiting"
    exit 1;
else 
    echo "[+] Running as root."

fi

# Define the storage location and CSV file
STORAGE_LOCATION=$1
CSV_FILE="$STORAGE_LOCATION/Cron_data.csv"
touch $CSV_FILE
if [ -f $CSV_FILE  ]; then
    echo "[+] Write to storage successful."
    rm $CSV_FILE
    echo "[+] Cron collection will begin."
else
    echo "[!] Unable to write to storage media."
    echo "[!] Exiting."
    exit 1;
fi

# Create the CSV file
echo "Source filename,M Time,Task interval,User Account,Command/Filename" > "$CSV_FILE"

# Function to collect cron jobs
collect_cron_jobs() {
    local path=$1
    local user=$2
    for file in $path; do
        if [ -f "$file" ]; then
            local mtime=$(stat -c %y "$file")
            while IFS= read -r line; do
                if [[ "$line" =~ ^#.*$ || "$line" =~ ^$ ]]; then
                    continue
                fi
                echo "$file,$mtime,$(echo $line | cut -d' ' -f1-5),${user:-$(echo $line | cut -d' ' -f6)},$(echo $line | cut -d' ' -f7-)" >> "$CSV_FILE"
            done < "$file"
        fi
    done
}

# Collect cron jobs from /etc/crontab and /etc/cron.d/*
collect_cron_jobs "/etc/crontab" "root"
collect_cron_jobs "/etc/cron.d/*" "root"

# Collect user-specific cron jobs
for user in /var/spool/cron/crontabs/*; do
    collect_cron_jobs "$user" "$(basename $user)"
done

# Function to collect data from /etc/cron.{hourly,daily,weekly,monthly}
collect_cron_dirs() {
    local dir=$1
    local timing=$2
    for file in "$dir"/*; do
        if [ -f "$file" ]; then
            local mtime=$(stat -c %y "$file")
            echo "$file,$mtime,$timing,root,$(basename "$file")" >> "$CSV_FILE"
        fi
    done
}

# Collect data from cron directories
collect_cron_dirs "/etc/cron.hourly" "hourly"
collect_cron_dirs "/etc/cron.daily" "daily"
collect_cron_dirs "/etc/cron.weekly" "weekly"
collect_cron_dirs "/etc/cron.monthly" "monthly"

echo "[+] Cron data collection completed. File located at: $CSV_FILE"
