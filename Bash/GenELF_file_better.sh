#!/bin/bash

# Output binary
OUTFILE="sample_elf"
TMPDIR=$(mktemp -d)
SOURCE="$TMPDIR/junk.cpp"
OBJ="$TMPDIR/junk.o"
JUNK_DATA="$TMPDIR/random.bin"

# Generate minimal C++ code that compiles to a PIE, dynamically linked ELF
cat <<EOF > "$SOURCE"
#include <iostream>
int main() {
    std::cout << "Just a placeholder program" << std::endl;
    return 0;
}
EOF

# Compile with flags to match file command output as closely as possible
g++ -fPIC -pie -Wno-narrowing "$SOURCE" -o "$OUTFILE" -s -Wl,--build-id=sha1

# Verify the file header (optional)
file "$OUTFILE"

# Generate random data between 49KB and 700KB
RANDOM_SIZE=$(( 49152 + RANDOM % (716800 - 49152 + 1) ))
dd if=/dev/urandom of="$JUNK_DATA" bs=1 count=$RANDOM_SIZE status=none

# Inject strings at 1/3 and 2/3 positions
ONE_THIRD=$(( RANDOM_SIZE / 3 ))
TWO_THIRD=$(( (2 * RANDOM_SIZE) / 3 ))

echo -n "WaveRCM_Carpet" | dd of="$JUNK_DATA" bs=1 seek=$ONE_THIRD conv=notrunc status=none
echo -n "BZG-BZG-BZG" | dd of="$JUNK_DATA" bs=1 seek=$TWO_THIRD conv=notrunc status=none

# Append random data with markers to the binary
cat "$JUNK_DATA" >> "$OUTFILE"

# Make sure it's executable
chmod +x "$OUTFILE"

# Output summary
echo "Binary generated: $OUTFILE"
file "$OUTFILE"
echo "SHA1 Build ID: $(readelf -n "$OUTFILE" | grep 'Build ID')"

# Clean up
rm -rf "$TMPDIR"
