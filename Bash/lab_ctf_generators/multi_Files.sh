#!/bin/bash

set -e

# File names for ELF binaries
elf_names=(
    auto_sketch sleeper documaint labhelp camera_raw adobe_photos googleupdater
    chrome_ad_remover bho_test darkmode screenview clipper car_connect k_D-3
    starwars.mov ones-and-zer0es.mpeg da3m0ns.mp4 br4ve-trave1er.asf nineteen passware
)

# Strings to embed
embed_strings=("Readdirnames" "runtime.offAddr" "WritePushPromise" "SkipAllQuestions")

# Create temp workspace
WORKDIR=$(mktemp -d)
echo "Using temp directory: $WORKDIR"
cd "$WORKDIR"

generate_random_strings() {
    # Shuffle and pick 2 or 3 strings
    shuf -e "${embed_strings[@]}" | head -n $((2 + RANDOM % 2))
}

generate_random_size() {
    echo $((10240 + RANDOM % (409600 - 10240 + 1)))
}

generate_random_buildid() {
    head -c 20 /dev/urandom | sha1sum | cut -d' ' -f1
}

create_elf_file() {
    local name="$1"
    local arch="$2"  # "32" or "64"
    local size
    size=$(generate_random_size)
    local cfile="prog.cpp"
    local outfile="$name"

    echo "#include <iostream>
int main() { return 0; }" > "$cfile"

    if [[ "$arch" == "32" ]]; then
        g++ -m32 -static -Wno-narrowing "$cfile" -o "$outfile" -s
    else
        g++ -fPIC -pie -Wno-narrowing "$cfile" -o "$outfile" -s -Wl,--build-id=sha1
    fi

    # Generate and embed random data
    dd if=/dev/urandom bs=1 count=$size of=data.bin status=none

    # Insert 2-3 strings at random positions
    for s in $(generate_random_strings); do
        offset=$((RANDOM % size))
        echo -n "$s" | dd of=data.bin bs=1 seek=$offset conv=notrunc status=none
    done

    # Append data to ELF
    cat data.bin >> "$outfile"
    chmod +x "$outfile"
    echo "Created ELF ($arch-bit): $outfile"
}

# Generate 10 64-bit and 10 32-bit ELF files
for i in "${!elf_names[@]}"; do
    if [[ $i -lt 10 ]]; then
        create_elf_file "${elf_names[$i]}" "64"
    else
        create_elf_file "${elf_names[$i]}" "32"
    fi
done

# --- Non-ELF files ---

generate_non_elf() {
    local name="$1"
    local header_hex="$2"
    local size=$((204800 + RANDOM % (409600 - 204800 + 1)))

    echo -n -e "$header_hex" > "$name"
    dd if=/dev/urandom bs=1 count=$((size - 16)) >> "$name" status=none

    for s in "${embed_strings[@]}"; do
        offset=$((RANDOM % (size - 32)))
        echo -n "$s" | dd of="$name" bs=1 seek=$offset conv=notrunc status=none
    done
    echo "Created non-ELF: $name"
}

# PDF files (first 4 bytes: %PDF)
generate_non_elf "dark_star22" "%PDF-1.4\n"
generate_non_elf "gome.pdf" "%PDF-1.7\n"

# PNG file (header 89 50 4E 47 0D 0A 1A 0A)
generate_non_elf "crystal.png" "\x89PNG\r\n\x1A\n"

# XZ file (header: FD 37 7A 58 5A 00)
generate_non_elf "cassius.xz" "\xFD7zXZ\x00"

# Move all files back to current dir
mv "$WORKDIR"/* .

# Clean up
rm -rf "$WORKDIR"
echo "All files generated."
