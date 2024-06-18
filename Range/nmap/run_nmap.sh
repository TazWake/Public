#!/bin/sh

# Run nmap to scan the local network and save the output to /nmap/scan.txt
nmap -Pn -oN /nmap/scan.txt $(ip -o -4 addr show dev eth0 | awk '{print $4}' | cut -d/ -f1)/24

# Copy the scan.txt file to the mounted volume
cp /nmap/scan.txt /output/scan.txt
