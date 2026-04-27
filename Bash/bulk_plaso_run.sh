#!/usr/bin/env bash
set -euo pipefail

# #######################################################################
# This script is an attempt to scale a large plaso run against multiple #
# evidence images, which have been provided in a variety of formats.    #
# #######################################################################
# Usage:
#   ./run_plaso_batch.sh /path/to/input/folder
#
# Optional environment overrides:
#   OUT_DIR=/tmp/plaso
#   WORK_DIR=/cases/plaso_work ./run_plaso_batch.sh /cases/images
#   SCRATCH_DIR=/cases/plaso_scratch ./run_plaso_batch.sh /cases/images

INPUT_DIR="${1:-}"

OUT_DIR="${OUT_DIR:-/mnt/host/SRLSkunkworks-2026/Precooked/plaso}"
WORK_DIR="${WORK_DIR:-/cases/plaso_work}"
SCRATCH_DIR="${SCRATCH_DIR:-/cases/plaso_scratch}"

PARSERS="filestat,linux,!bencode,!sqlite/google_drive,!sqlite/skype,!text/xchatlog,!text/xchatscrollback,jsonl/docker_container_config"

MANIFEST="${OUT_DIR}/plaso_batch_manifest.csv"

if [[ -z "$INPUT_DIR" ]]; then
    echo "Usage: $0 /path/to/input/folder"
    exit 1
fi

if [[ ! -d "$INPUT_DIR" ]]; then
    echo "ERROR: Input path is not a directory: $INPUT_DIR"
    exit 1
fi

command -v psteal.py >/dev/null || { echo "ERROR: psteal.py not found in PATH"; exit 1; }
command -v zstd >/dev/null || { echo "ERROR: zstd not found in PATH"; exit 1; }

mkdir -p "$OUT_DIR" "$WORK_DIR" "$SCRATCH_DIR"

if [[ ! -f "$MANIFEST" ]]; then
    echo "timestamp,input_file,source_used,storage_file,output_csv,status" > "$MANIFEST"
fi

safe_name() {
    local base
    base="$(basename "$1")"

    # Strip common forensic/image extensions.
    base="${base%.E01}"
    base="${base%.e01}"
    base="${base%.raw}"
    base="${base%.RAW}"
    base="${base%.img}"
    base="${base%.IMG}"
    base="${base%.dd}"
    base="${base%.DD}"
    base="${base%.zst}"
    base="${base%.ZST}"

    # Replace unsafe filename characters.
    echo "$base" | tr ' /:' '___' | tr -cd 'A-Za-z0-9._-'
}

process_image() {
    local input_file="$1"
    local name source storage_file output_csv log_file status
    local decompressed=""

    name="$(safe_name "$input_file")"
    source="$input_file"

    storage_file="${WORK_DIR}/plaso_${name}.dump"
    output_csv="${OUT_DIR}/${name}_Supertimeline.csv"
    log_file="${OUT_DIR}/${name}_psteal.log"
    status="FAILED"

    echo "[+] Processing: $input_file"
    echo "    Name: $name"

    if [[ "$input_file" =~ \.[zZ][sS][tT]$ ]]; then
        decompressed="${SCRATCH_DIR}/${name}.raw"

        if [[ -f "$decompressed" ]]; then
            echo "    Reusing existing decompressed file: $decompressed"
        else
            echo "    Decompressing zstd image to: $decompressed"
            zstd -d -T0 --keep --force "$input_file" -o "$decompressed"
        fi

        source="$decompressed"
    fi

    echo "    Source used: $source"
    echo "    Storage:     $storage_file"
    echo "    Output CSV:  $output_csv"
    echo "    Log:         $log_file"

    rm -f "$storage_file" "$output_csv"

    if psteal.py \
        --parsers "$PARSERS" \
        --storage_file "$storage_file" \
        --source "$source" \
        -o dynamic \
        -w "$output_csv" \
        >"$log_file" 2>&1
    then
        status="SUCCESS"
        echo "[+] Success: $output_csv"

        if [[ -n "$decompressed" ]]; then
            echo "    Removing decompressed temporary file: $decompressed"
            rm -f "$decompressed"
        fi
    else
        echo "[!] FAILED: $input_file"
        echo "    Review log: $log_file"
    fi

    echo "$(date -Is),\"$input_file\",\"$source\",\"$storage_file\",\"$output_csv\",$status" >> "$MANIFEST"
}

shopt -s nullglob nocaseglob

images=(
    "$INPUT_DIR"/*.E01
    "$INPUT_DIR"/*.e01
    "$INPUT_DIR"/*.raw
    "$INPUT_DIR"/*.RAW
    "$INPUT_DIR"/*.img
    "$INPUT_DIR"/*.IMG
    "$INPUT_DIR"/*.dd
    "$INPUT_DIR"/*.DD
    "$INPUT_DIR"/*.zst
    "$INPUT_DIR"/*.ZST
)

if [[ "${#images[@]}" -eq 0 ]]; then
    echo "No supported evidence files found in: $INPUT_DIR"
    exit 0
fi

echo "[+] Found ${#images[@]} candidate image(s)"
echo "[+] Output directory: $OUT_DIR"
echo "[+] Work directory:   $WORK_DIR"
echo "[+] Scratch dir:      $SCRATCH_DIR"
echo

for image in "${images[@]}"; do
    process_image "$image"
    echo
done

echo "[+] Batch complete"
echo "[+] Manifest: $MANIFEST"
