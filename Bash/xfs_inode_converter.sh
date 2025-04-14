#!/bin/bash
######################################################################
# This script takes a file address, in hex, from an XFS inode        #
# converts it to binary to show you the working out and then         #
# converts it to a hex address.                                      #
#                                                                    #
# The final output is the address in hex where the data should       #
# reside. Currently, this is displayed assuming the filesystem has   #
# 4096 (0x1000) bytes per block. If this is not correct, please      #
# adjust the output appropriately.                                   #
#                                                                    #
# This script uses a manual conversion, because previous versions    #
# using the bc command appeared to have erratic output. I have no    #
# idea why this was the case, but this appears more stable...        #
#                                                                    #
#                           ¯\_(ツ)_/¯                               #
#                                                                    #
######################################################################

# Input a 16-byte hex address.
# for example: 0000000000000000000000353F400001
hex_string="$1"
if [ "${#hex_string}" -ne 32 ]; then
  echo "Error: Input must be exactly 16 bytes or 32 hex digits. Do not supply spaces."
  exit 1
fi

# Use a more reliable method to convert hex to binary - if you can get this working with bc let me know.
binary=""
for (( i=0; i<${#hex_string}; i++ )); do
  case "${hex_string:$i:1}" in
    0) binary="${binary}0000" ;;
    1) binary="${binary}0001" ;;
    2) binary="${binary}0010" ;;
    3) binary="${binary}0011" ;;
    4) binary="${binary}0100" ;;
    5) binary="${binary}0101" ;;
    6) binary="${binary}0110" ;;
    7) binary="${binary}0111" ;;
    8) binary="${binary}1000" ;;
    9) binary="${binary}1001" ;;
    a|A) binary="${binary}1010" ;;
    b|B) binary="${binary}1011" ;;
    c|C) binary="${binary}1100" ;;
    d|D) binary="${binary}1101" ;;
    e|E) binary="${binary}1110" ;;
    f|F) binary="${binary}1111" ;;
  esac
done

echo ""
echo "Input string: $hex_string"
echo "Binary:       $binary"
echo ""

# Split the string into chunks per XFS extent format
chunk1="${binary:0:1}"        # FLAG (1 bit)
chunk2="${binary:1:54}"       # Logical Offset (54 bits)
chunk3="${binary:55:52}"      # Start Block (52 bits)
chunk4="${binary:107:21}"     # Block Count (21 bits)

# Output each chunk on its own line, with the field summary
echo "--------------------------------------------------------"
echo "Splitting data"
echo "FLAG:           $chunk1"
echo "Logical Offset: $chunk2"
echo "Start Block:    $chunk3"
echo "Block Count:    $chunk4"
echo "--------------------------------------------------------"

# Convert the Start Block binary data to decimal notation
start_dec=0
for (( i=0; i<${#chunk3}; i++ )); do
  bit="${chunk3:$i:1}"
  if [ "$bit" == "1" ]; then
    # Calculate 2^(length-position-1) and add to total
    power=$((${#chunk3} - $i - 1))
    value=$((2**$power))
    start_dec=$((start_dec + value))
  fi
done

# Calculate the final byte offset (multiply by block size 4096)
final_dec=$((start_dec * 4096))

# Convert decimal values to hex
start_hex=$(printf "%X" $start_dec)
final_hex=$(printf "%X" $final_dec)

echo ""
echo "Start block number (in hex): 0x${start_hex}"
echo "Start block number (in decimal): ${start_dec}"
echo ""
echo "The start address (in hex) is 0x${final_hex} bytes into the filesystem."
echo "The start address (in decimal) is ${final_dec} bytes into the filesystem."
echo ""
