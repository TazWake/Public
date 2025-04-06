#!/bin/bash

# Define the output file
OUTPUT_FILE="fake_elf_binary"

# Create an ELF file with specific header to match the requested file output
create_elf_file() {
  # Generate random SHA1 hash for BuildID (20 bytes)
  SHA1_HASH=$(head -c 20 /dev/urandom | xxd -p)
  
  # Remove any existing file
  rm -f "$OUTPUT_FILE"
  
  # Create the basic ELF header (64 bytes)
  # ELF magic number and identification
  printf "\x7F\x45\x4C\x46" > "$OUTPUT_FILE"       # ELF magic
  printf "\x02" >> "$OUTPUT_FILE"                   # Class: 64-bit
  printf "\x01" >> "$OUTPUT_FILE"                   # Data: little endian (LSB)
  printf "\x01" >> "$OUTPUT_FILE"                   # Version: current
  printf "\x00" >> "$OUTPUT_FILE"                   # OS ABI: SYSV
  printf "\x00" >> "$OUTPUT_FILE"                   # ABI Version
  printf "\x00\x00\x00\x00\x00\x00\x00" >> "$OUTPUT_FILE" # Padding

  # File type, architecture, etc.
  printf "\x03\x00" >> "$OUTPUT_FILE"              # Type: DYN (PIE executable)
  printf "\x3E\x00" >> "$OUTPUT_FILE"              # Machine: x86-64
  printf "\x01\x00\x00\x00" >> "$OUTPUT_FILE"      # Version: current

  # Entry point address (arbitrary non-zero value)
  printf "\x00\x10\x00\x00\x00\x00\x00\x00" >> "$OUTPUT_FILE"

  # Program header offset (64 bytes from start)
  printf "\x40\x00\x00\x00\x00\x00\x00\x00" >> "$OUTPUT_FILE"

  # Section header offset (we'll place it after our interpreter string)
  printf "\x40\x02\x00\x00\x00\x00\x00\x00" >> "$OUTPUT_FILE"

  # Flags (0)
  printf "\x00\x00\x00\x00" >> "$OUTPUT_FILE"

  # ELF header size (64 bytes)
  printf "\x40\x00" >> "$OUTPUT_FILE"

  # Program header entry size (56 bytes)
  printf "\x38\x00" >> "$OUTPUT_FILE"

  # Number of program headers (4: PHDR, INTERP, LOAD, DYNAMIC)
  printf "\x04\x00" >> "$OUTPUT_FILE"

  # Section header entry size (64 bytes)
  printf "\x40\x00" >> "$OUTPUT_FILE"

  # Number of section headers (7: NULL, .interp, .note.gnu.build-id, .dynamic, etc.)
  printf "\x07\x00" >> "$OUTPUT_FILE"

  # Section header string table index (1)
  printf "\x01\x00" >> "$OUTPUT_FILE"

  # Program Headers (4 entries, each 56 bytes)
  
  # 1. PHDR program header
  printf "\x06\x00\x00\x00" >> "$OUTPUT_FILE"      # Type: PHDR
  printf "\x04\x00\x00\x00" >> "$OUTPUT_FILE"      # Flags: Read
  printf "\x40\x00\x00\x00\x00\x00\x00\x00" >> "$OUTPUT_FILE" # Offset
  printf "\x40\x00\x00\x00\x00\x00\x00\x00" >> "$OUTPUT_FILE" # Virtual address
  printf "\x40\x00\x00\x00\x00\x00\x00\x00" >> "$OUTPUT_FILE" # Physical address
  printf "\xE0\x00\x00\x00\x00\x00\x00\x00" >> "$OUTPUT_FILE" # File size
  printf "\xE0\x00\x00\x00\x00\x00\x00\x00" >> "$OUTPUT_FILE" # Memory size
  printf "\x08\x00\x00\x00\x00\x00\x00\x00" >> "$OUTPUT_FILE" # Alignment

  # 2. INTERP program header
  printf "\x03\x00\x00\x00" >> "$OUTPUT_FILE"      # Type: INTERP
  printf "\x04\x00\x00\x00" >> "$OUTPUT_FILE"      # Flags: Read
  printf "\x20\x01\x00\x00\x00\x00\x00\x00" >> "$OUTPUT_FILE" # Offset
  printf "\x20\x01\x00\x00\x00\x00\x00\x00" >> "$OUTPUT_FILE" # Virtual address
  printf "\x20\x01\x00\x00\x00\x00\x00\x00" >> "$OUTPUT_FILE" # Physical address
  printf "\x1C\x00\x00\x00\x00\x00\x00\x00" >> "$OUTPUT_FILE" # File size
  printf "\x1C\x00\x00\x00\x00\x00\x00\x00" >> "$OUTPUT_FILE" # Memory size
  printf "\x01\x00\x00\x00\x00\x00\x00\x00" >> "$OUTPUT_FILE" # Alignment

  # 3. LOAD program header
  printf "\x01\x00\x00\x00" >> "$OUTPUT_FILE"      # Type: LOAD
  printf "\x05\x00\x00\x00" >> "$OUTPUT_FILE"      # Flags: Read + Execute
  printf "\x00\x00\x00\x00\x00\x00\x00\x00" >> "$OUTPUT_FILE" # Offset
  printf "\x00\x00\x00\x00\x00\x00\x00\x00" >> "$OUTPUT_FILE" # Virtual address
  printf "\x00\x00\x00\x00\x00\x00\x00\x00" >> "$OUTPUT_FILE" # Physical address
  printf "\x00\x20\x00\x00\x00\x00\x00\x00" >> "$OUTPUT_FILE" # File size
  printf "\x00\x20\x00\x00\x00\x00\x00\x00" >> "$OUTPUT_FILE" # Memory size
  printf "\x00\x10\x00\x00\x00\x00\x00\x00" >> "$OUTPUT_FILE" # Alignment

  # 4. DYNAMIC program header
  printf "\x02\x00\x00\x00" >> "$OUTPUT_FILE"      # Type: DYNAMIC
  printf "\x06\x00\x00\x00" >> "$OUTPUT_FILE"      # Flags: Read + Write
  printf "\x40\x01\x00\x00\x00\x00\x00\x00" >> "$OUTPUT_FILE" # Offset
  printf "\x40\x01\x00\x00\x00\x00\x00\x00" >> "$OUTPUT_FILE" # Virtual address
  printf "\x40\x01\x00\x00\x00\x00\x00\x00" >> "$OUTPUT_FILE" # Physical address
  printf "\x90\x00\x00\x00\x00\x00\x00\x00" >> "$OUTPUT_FILE" # File size
  printf "\x90\x00\x00\x00\x00\x00\x00\x00" >> "$OUTPUT_FILE" # Memory size
  printf "\x08\x00\x00\x00\x00\x00\x00\x00" >> "$OUTPUT_FILE" # Alignment

  # Interpreter string
  printf "/lib64/ld-linux-x86-64.so.2\x00" >> "$OUTPUT_FILE"

  # Dynamic section
  # Typical entries for a dynamically linked executable
  printf "\x01\x00\x00\x00\x00\x00\x00\x00" >> "$OUTPUT_FILE" # DT_NEEDED
  printf "\x01\x00\x00\x00\x00\x00\x00\x00" >> "$OUTPUT_FILE" # String table offset
  printf "\x0C\x00\x00\x00\x00\x00\x00\x00" >> "$OUTPUT_FILE" # DT_INIT
  printf "\x00\x10\x00\x00\x00\x00\x00\x00" >> "$OUTPUT_FILE" # Address
  printf "\x0D\x00\x00\x00\x00\x00\x00\x00" >> "$OUTPUT_FILE" # DT_FINI
  printf "\x20\x10\x00\x00\x00\x00\x00\x00" >> "$OUTPUT_FILE" # Address
  
  # Add GNU build ID note
  printf "\x04\x00\x00\x00" >> "$OUTPUT_FILE"      # Name size (4)
  printf "\x14\x00\x00\x00" >> "$OUTPUT_FILE"      # Desc size (20 - SHA1 size)
  printf "\x03\x00\x00\x00" >> "$OUTPUT_FILE"      # Type (NT_GNU_BUILD_ID)
  printf "GNU\x00" >> "$OUTPUT_FILE"               # Name

  # Convert SHA1 hash from hex string to binary and write it
  for (( i=0; i<${#SHA1_HASH}; i+=2 )); do
    byte="\x${SHA1_HASH:$i:2}"
    printf "$byte" >> "$OUTPUT_FILE"
  done

  # Add GNU ABI tag note for Linux 3.2.0
  printf "\x04\x00\x00\x00" >> "$OUTPUT_FILE"      # Name size (4)
  printf "\x10\x00\x00\x00" >> "$OUTPUT_FILE"      # Desc size (16)
  printf "\x01\x00\x00\x00" >> "$OUTPUT_FILE"      # Type (NT_GNU_ABI_TAG)
  printf "GNU\x00" >> "$OUTPUT_FILE"               # Name
  printf "\x00\x00\x00\x00" >> "$OUTPUT_FILE"      # Linux (0)
  printf "\x03\x00\x00\x00" >> "$OUTPUT_FILE"      # Major (3)
  printf "\x02\x00\x00\x00" >> "$OUTPUT_FILE"      # Minor (2)
  printf "\x00\x00\x00\x00" >> "$OUTPUT_FILE"      # Patch (0)

  # Add minimal section headers to appear as a stripped binary
  # Add enough bytes to reach our needed section headers offset
  dd if=/dev/zero bs=1 count=128 >> "$OUTPUT_FILE" 2>/dev/null
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
create_elf_file
generate_random_data

# Make the file executable
chmod +x "$OUTPUT_FILE"

# Verify with file command
file "$OUTPUT_FILE"

echo "Created fake ELF binary '$OUTPUT_FILE' with random data"
