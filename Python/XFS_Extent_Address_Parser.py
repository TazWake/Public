#!/usr/bin/env python3

# ################################### #
#
# This script was created for FOR577  #
# to provide a way to validate any    #
# XFS extent addresses being manually #
# carved from the inode.              #
# ################################### #

def parse_extent(binary_input):
    """XFS Inodes contain a 128 bit string that points to the address of the file on disk. This will parse the string, break it down to the component sectors, and provide the start block address for the file."""
    if len(binary_input) != 128 or not set(binary_input).issubset({'0', '1'}):
      raise ValueError("Input must be exactly 128 binary digits (0s and 1s).")

    # Define bit slices
    flag_bits = binary_input[0:1]
    logical_offset_bits = binary_input[1:55]
    start_block_bits = binary_input[55:107]
    block_count_bits = binary_input[107:128]

    # Convert to integers
    flag_val = int(flag_bits, 2)
    logical_offset_val = int(logical_offset_bits, 2)
    start_block_val = int(start_block_bits, 2)
    block_count_val = int(block_count_bits, 2)

    # Output with all representations
    print("Parsed Extent Entry:")
    print(f"  Flag:")
    print(f"    Binary : {flag_bits}")
    print(f"    Decimal: {flag_val}")
    print(f"    Hex    : {hex(flag_val)}")

    print(f"  Logical Offset:")
    print(f"    Binary : {logical_offset_bits}")
    print(f"    Decimal: {logical_offset_val}")
    print(f"    Hex    : {hex(logical_offset_val)}")

    print(f"  Start Block:")
    print(f"    Binary : {start_block_bits}")
    print(f"    Decimal: {start_block_val}")
    print(f"    Hex    : {hex(start_block_val)}")

    print(f"  Block Count:")
    print(f"    Binary : {block_count_bits}")
    print(f"    Decimal: {block_count_val}")
    print(f"    Hex    : {hex(block_count_val)}")

if __name__ == "__main__":
    test_input = input("Enter 128-bit binary string: ").strip()
    try:
        parse_extent(test_input)
    except ValueError as e:
        print(f"Error: {e}")
