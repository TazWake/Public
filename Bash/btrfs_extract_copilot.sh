#!/usr/bin/env bash

# Bash script to read the details on a file in a btrfs image
# without mounting it. This script will identify the inode,
# metadata (e.g. timestamps) and then extract the file to a
# temp location for manual analysis.
#
# This version was created by Copilot as an example.

set -euo pipefail

# -----------------------------
# Argument checking
# -----------------------------
if [[ $# -ne 2 ]]; then
    echo "Usage: $0 <btrfs_image> <path_in_fs>"
    echo "Example: $0 xvdb1_btrfs.img /passwd"
    exit 1
fi

IMAGE="$1"
TARGET="$2"

# -----------------------------
# Check image is Btrfs
# -----------------------------
if ! file "$IMAGE" | grep -qi "btrfs"; then
    echo "Error: $IMAGE does not appear to be a Btrfs filesystem image."
    exit 1
fi

echo "[+] Image verified as Btrfs."

# -----------------------------
# Check file exists (dry-run restore)
# -----------------------------
if ! btrfs restore -s -D --path-regex "^${TARGET}$" "$IMAGE" /tmp >/dev/null 2>&1; then
    echo "Error: File '$TARGET' not found in image."
    exit 1
fi

echo "[+] File exists in image: $TARGET"

# -----------------------------
# Extract inode number
# -----------------------------
BASENAME=$(basename "$TARGET")

INODE=$(btrfs inspect-internal dump-tree "$IMAGE" \
    | grep -B3 "name: ${BASENAME}$" \
    | grep "location key" \
    | head -n1 \
    | sed -E 's/.*\(([0-9]+) INODE_ITEM.*/\1/')

if [[ -z "$INODE" ]]; then
    echo "Error: Could not determine inode for $TARGET"
    exit 1
fi

echo "[+] Inode: $INODE"

# -----------------------------
# Extract timestamps
# -----------------------------
META=$(btrfs inspect-internal dump-tree "$IMAGE" \
    | grep -A12 "[0-9] key (${INODE} INODE_ITEM 0)")

extract_ts() {
    echo "$META" | grep "$1" | awk '{print $2}'
}

ATIME=$(extract_ts atime)
MTIME=$(extract_ts mtime)
CTIME=$(extract_ts ctime)
OTIME=$(extract_ts otime)

echo "[+] atime: $ATIME"
echo "[+] mtime: $MTIME"
echo "[+] ctime: $CTIME"
echo "[+] otime: $OTIME (creation time)"

# -----------------------------
# Restore file
# -----------------------------
TS=$(date +%s)
OUTDIR="/tmp/restore_${TS}"
mkdir -p "$OUTDIR"

btrfs restore -s --path-regex "^${TARGET}$" "$IMAGE" "$OUTDIR" >/dev/null

echo "[+] File restored to: $OUTDIR/$BASENAME"
echo "[+] Done."
