#!/bin/bash
# This script takes a file address, in hex, from an XFS inode
# converts it to binary to show you the working out and then
# converts it to a hex address.

# Input a 16 byte hex address.
# for example: 0000000000000000000000353F400001
hex_string="$1"
if [ "${#hex_string}" -ne 32 ]; then
  echo "Error: Input must be exactly 16 bytes or 32 hex digits. Do not supply spaces."
  exit 1
fi

# Convert to binary to show process is working:

binary_string=$(echo "$hex_string" | sed 's/../&\n/g' | while read -r byte; do echo "ibase=16; obase=2; $byte" | bc; done | awk '{printf "%08d", $1}')
# binary_string=(echo "ibase=16; obase=2"; echo "$hex_string" | sed 's/../&\n/g') | bc | awk '{printf "%08d", $1}'

echo ""
echo "Input string: $hex_string"
echo "Binary conversion: $binary_string"

# Split the string into chunks
chunk1="${binary_string:0:1}"
chunk2="${binary_string:1:54}"
chunk3="${binary_string:55:52}"
chunk4="${binary_string:107:21}"
# Output each chunk on its own line with some notes about what was found
echo ""
echo "FLAG: $chunk1"
echo "Logical Offset: $chunk2"
echo "Start Block: $chunk3"
echo "Block Count: $chunk4"
# Convert the start block:
echo ""
start=$(printf "obase=16; ibase=2; %s\n" "$chunk3" | bc)
echo "The start address in hex is: 0x${start}000"
