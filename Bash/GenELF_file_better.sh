#!/bin/bash

# Define the output file
OUTPUT_FILE="fake_elf_binary"

# Create a more complete ELF header to match the requested file output
create_elf_header() {
  # Generate random SHA1 hash for BuildID
  SHA1_HASH=$(head -c 20 /dev/urandom | xxd -p)
  
  # Create ELF header and program headers structure
  # ELF Header (64 bytes)
  # Magic number and identification
  printf "\x7F\x45\x4C\x46" > "$OUTPUT_FILE"       # ELF magic
  printf "\x02" >> "$OUTPUT_FILE"                   # Class: 64-bit
  printf "\x01" >> "$OUTPUT_FILE"                   # Data: little endian (LSB)
  printf "\x01" >> "$OUTPUT_FILE"                   # Version: current
  printf "\x03" >> "$OUTPUT_FILE"                   # OS ABI: Linux
  printf "\x00" >> "$OUTPUT_FILE"                   # ABI Version
  printf "\x00\x00\x00\x00\x00\x00\x00" >> "$OUTPUT_FILE" # Padding

  # ELF Type, Machine, etc.
  printf "\x03\x00" >> "$OUTPUT_FILE"              # Type: DYN (Position Independent Executable - PIE)
  printf "\x3E\x00" >> "$OUTPUT_FILE"              # Machine: x86-64
  printf "\x01\x00\x00\x00" >> "$OUTPUT_FILE"      # Version: current

  # Entry point (arbitrary non-zero value)
  printf "\x80\x10\x00\x00\x00\x00\x00\x00" >> "$OUTPUT_FILE"

  # Program header offset (64 bytes, right after ELF header)
  printf "\x40\x00\x00\x00\x00\x00\x00\x00" >> "$OUTPUT_FILE"

  # Section header offset (after program headers)
  printf "\x00\x20\x00\x00\x00\x00\x00\x00" >> "$OUTPUT_FILE"

  # Flags (0)
  printf "\x00\x00\x00\x00" >> "$OUTPUT_FILE"

  # Header size (64 bytes)
  printf "\x40\x00" >> "$OUTPUT_FILE"

  # Program header entry size (56 bytes)
  printf "\x38\x00" >> "$OUTPUT_FILE"

  # Number of program headers (we need at least 3 for interpreter, dynamic linking)
  printf "\x05\x00" >> "$OUTPUT_FILE"

  # Section header entry size (64 bytes)
  printf "\x40\x00" >> "$OUTPUT_FILE"

  # Number of section headers (we need several for symbols, strings, dynamic info)
  printf "\x08\x00" >> "$OUTPUT_FILE"

  # Section header string table index
  printf "\x01\x00" >> "$OUTPUT_FILE"

  # Program Headers
  
  # PHDR program header - points to the program header table itself
  printf "\x06\x00\x00\x00" >> "$OUTPUT_FILE"      # Type: PHDR
  printf "\x04\x00\x00\x00" >> "$OUTPUT_FILE"      # Flags: Read
  printf "\x40\x00\x00\x00\x00\x00\x00\x00" >> "$OUTPUT_FILE" # Offset
  printf "\x40\x00\x00\x00\x00\x00\x00\x00" >> "$OUTPUT_FILE" # Virtual address
  printf "\x40\x00\x00\x00\x00\x00\x00\x00" >> "$OUTPUT_FILE" # Physical address
  printf "\xB0\x01\x00\x00\x00\x00\x00\x00" >> "$OUTPUT_FILE" # File size
  printf "\xB0\x01\x00\x00\x00\x00\x00\x00" >> "$OUTPUT_FILE" # Memory size
  printf "\x08\x00\x00\x00\x00\x00\x00\x00" >> "$OUTPUT_FILE" # Alignment

  # INTERP program header - points to the interpreter path
  printf "\x03\x00\x00\x00" >> "$OUTPUT_FILE"      # Type: INTERP
  printf "\x04\x00\x00\x00" >> "$OUTPUT_FILE"      # Flags: Read
  printf "\xF0\x01\x00\x00\x00\x00\x00\x00" >> "$OUTPUT_FILE" # Offset
  printf "\xF0\x01\x00\x00\x00\x00\x00\x00" >> "$OUTPUT_FILE" # Virtual address
  printf "\xF0\x01\x00\x00\x00\x00\x00\x00" >> "$OUTPUT_FILE" # Physical address
  printf "\x1C\x00\x00\x00\x00\x00\x00\x00" >> "$OUTPUT_FILE" # File size
  printf "\x1C\x00\x00\x00\x00\x00\x00\x00" >> "$OUTPUT_FILE" # Memory size
  printf "\x01\x00\x00\x00\x00\x00\x00\x00" >> "$OUTPUT_FILE" # Alignment

  # LOAD program header - for text segment
  printf "\x01\x00\x00\x00" >> "$OUTPUT_FILE"      # Type: LOAD
  printf "\x05\x00\x00\x00" >> "$OUTPUT_FILE"      # Flags: Read + Execute
  printf "\x00\x00\x00\x00\x00\x00\x00\x00" >> "$OUTPUT_FILE" # Offset
  printf "\x00\x00\x00\x00\x00\x00\x00\x00" >> "$OUTPUT_FILE" # Virtual address
  printf "\x00\x00\x00\x00\x00\x00\x00\x00" >> "$OUTPUT_FILE" # Physical address
  printf "\x00\x10\x00\x00\x00\x00\x00\x00" >> "$OUTPUT_FILE" # File size
  printf "\x00\x10\x00\x00\x00\x00\x00\x00" >> "$OUTPUT_FILE" # Memory size
  printf "\x00\x10\x00\x00\x00\x00\x00\x00" >> "$OUTPUT_FILE" # Alignment

  # LOAD program header - for data segment
  printf "\x01\x00\x00\x00" >> "$OUTPUT_FILE"      # Type: LOAD
  printf "\x06\x00\x00\x00" >> "$OUTPUT_FILE"      # Flags: Read + Write
  printf "\x00\x20\x00\x00\x00\x00\x00\x00" >> "$OUTPUT_FILE" # Offset
  printf "\x00\x20\x00\x00\x00\x00\x00\x00" >> "$OUTPUT_FILE" # Virtual address
  printf "\x00\x20\x00\x00\x00\x00\x00\x00" >> "$OUTPUT_FILE" # Physical address
  printf "\x00\x10\x00\x00\x00\x00\x00\x00" >> "$OUTPUT_FILE" # File size
  printf "\x00\x10\x00\x00\x00\x00\x00\x00" >> "$OUTPUT_FILE" # Memory size
  printf "\x00\x10\x00\x00\x00\x00\x00\x00" >> "$OUTPUT_FILE" # Alignment

  # DYNAMIC program header - for dynamic linking info
  printf "\x02\x00\x00\x00" >> "$OUTPUT_FILE"      # Type: DYNAMIC
  printf "\x06\x00\x00\x00" >> "$OUTPUT_FILE"      # Flags: Read + Write
  printf "\x10\x20\x00\x00\x00\x00\x00\x00" >> "$OUTPUT_FILE" # Offset
  printf "\x10\x20\x00\x00\x00\x00\x00\x00" >> "$OUTPUT_FILE" # Virtual address
  printf "\x10\x20\x00\x00\x00\x00\x00\x00" >> "$OUTPUT_FILE" # Physical address
  printf "\xA0\x00\x00\x00\x00\x00\x00\x00" >> "$OUTPUT_FILE" # File size
  printf "\xA0\x00\x00\x00\x00\x00\x00\x00" >> "$OUTPUT_FILE" # Memory size
  printf "\x08\x00\x00\x00\x00\x00\x00\x00" >> "$OUTPUT_FILE" # Alignment

  # Add interpreter string (/lib64/ld-linux-x86-64.so.2)
  printf "/lib64/ld-linux-x86-64.so.2\x00" >> "$OUTPUT_FILE"

  # BuildID Note section (to add SHA1 hash)
  printf "\x04\x00\x00\x00" >> "$OUTPUT_FILE"      # namesz = 4
  printf "\x14\x00\x00\x00" >> "$OUTPUT_FILE"      # descsz = 20 (SHA1 is 20 bytes)
  printf "\x03\x00\x00\x00" >> "$OUTPUT_FILE"      # type = NT_GNU_BUILD_ID (3)
  printf "GNU\x00" >> "$OUTPUT_FILE"               # name = "GNU\0"
  
  # Convert SHA1 hash from hex string to binary and write it
  for (( i=0; i<${#SHA1_HASH}; i+=2 )); do
    byte="\x${SHA1_HASH:$i:2}"
    printf "$byte" >> "$OUTPUT_FILE"
  done

  # OS ABI version - GNU/Linux 3.2.0
  # This is typically encoded in .note.ABI-tag section
  printf "\x04\x00\x00\x00" >> "$OUTPUT_FILE"      # namesz = 4
  printf "\x10\x00\x00\x00" >> "$OUTPUT_FILE"      # descsz = 16
  printf "\x01\x00\x00\x00" >> "$OUTPUT_FILE"      # type = NT_GNU_ABI_TAG (1)
  printf "GNU\x00" >> "$OUTPUT_FILE"               # name = "GNU\0"
  printf "\x00\x00\x00\x00" >> "$OUTPUT_FILE"      # OS = Linux (0)
  printf "\x03\x00\x00\x00" >> "$OUTPUT_FILE"      # major = 3
  printf "\x02\x00\x00\x00" >> "$OUTPUT_FILE"      # minor = 2
  printf "\x00\x00\x00\x00" >> "$OUTPUT_FILE"      # patch = 0
}

# Generate a random file size between 4KB and 30KB
# 4KB = 4096 bytes, 30KB = 30720 bytes
generate_random_data() {
  MIN_SIZE=4096
  MAX_SIZE=30720
  
  # Get the current file size
  CURRENT_SIZE=$(wc -c < "$OUTPUT_FILE")
  
  # Calculate a random total size within our range
  RANDOM_SIZE=$(( RANDOM % (MAX_SIZE - MIN_SIZE + 1) + MIN_SIZE ))
  
  # Calculate how many bytes we need to add
  BYTES_TO_ADD=$((RANDOM_SIZE - CURRENT_SIZE))
  
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
