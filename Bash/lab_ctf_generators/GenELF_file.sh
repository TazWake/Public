#!/bin/bash

# Define the output file
OUTPUT_FILE="fake_elf_binary"

# Create a minimal valid ELF header (64-bit)
# This creates just enough of a header to be recognized by the 'file' command
create_elf_header() {
  # ELF magic number (0x7F followed by "ELF")
  printf "\x7F\x45\x4C\x46" > "$OUTPUT_FILE"

  # Class (2 = 64-bit)
  printf "\x02" >> "$OUTPUT_FILE"

  # Data encoding (1 = little endian)
  printf "\x01" >> "$OUTPUT_FILE"

  # ELF version (1 = current)
  printf "\x01" >> "$OUTPUT_FILE"

  # OS ABI (0 = System V)
  printf "\x00" >> "$OUTPUT_FILE"

  # ABI Version (0)
  printf "\x00" >> "$OUTPUT_FILE"

  # Padding (7 bytes of zeros)
  printf "\x00\x00\x00\x00\x00\x00\x00" >> "$OUTPUT_FILE"

  # Object file type (2 = executable)
  printf "\x02\x00" >> "$OUTPUT_FILE"

  # Machine architecture (0x3E = x86-64)
  printf "\x3E\x00" >> "$OUTPUT_FILE"

  # ELF version (1)
  printf "\x01\x00\x00\x00" >> "$OUTPUT_FILE"

  # Entry point address (64-bit, just zeros for our fake binary)
  printf "\x00\x00\x00\x00\x00\x00\x00\x00" >> "$OUTPUT_FILE"

  # Program header offset (64-bit, using 64 which is size of ELF header)
  printf "\x40\x00\x00\x00\x00\x00\x00\x00" >> "$OUTPUT_FILE"

  # Section header offset (64-bit, just zeros for our fake binary)
  printf "\x00\x00\x00\x00\x00\x00\x00\x00" >> "$OUTPUT_FILE"

  # Flags (0)
  printf "\x00\x00\x00\x00" >> "$OUTPUT_FILE"

  # Header size (64 bytes)
  printf "\x40\x00" >> "$OUTPUT_FILE"

  # Program header entry size (56 bytes)
  printf "\x38\x00" >> "$OUTPUT_FILE"

  # Program header entry count (1)
  printf "\x01\x00" >> "$OUTPUT_FILE"

  # Section header entry size (64 bytes)
  printf "\x40\x00" >> "$OUTPUT_FILE"

  # Section header entry count (0)
  printf "\x00\x00" >> "$OUTPUT_FILE"

  # Section header string table index (0)
  printf "\x00\x00" >> "$OUTPUT_FILE"
}

# Generate a random file size between 900KB and 1.4MB
# 900KB = 921600 bytes, 1.4MB = 1468416 bytes
generate_random_data() {
  MIN_SIZE=92160
  MAX_SIZE=146841

  # Calculate a random size within our range
  RANDOM_SIZE=$(( RANDOM % (MAX_SIZE - MIN_SIZE + 1) + MIN_SIZE ))

  # Calculate how many bytes we need to add (subtract the ELF header we already added)
  HEADER_SIZE=64
  BYTES_TO_ADD=$((RANDOM_SIZE - HEADER_SIZE))

  echo "Adding $BYTES_TO_ADD bytes of random data (total file size will be $RANDOM_SIZE bytes)"

  # Append random data from /dev/urandom
  dd if=/dev/urandom bs=$BYTES_TO_ADD count=1 >> "$OUTPUT_FILE" 2>/dev/null
}

# Create the file
create_elf_header
generate_random_data

# Make the file executable
chmod +x "$OUTPUT_FILE"

# Verify with file command
file "$OUTPUT_FILE"

echo "Created fake ELF binary '$OUTPUT_FILE' with random data"
