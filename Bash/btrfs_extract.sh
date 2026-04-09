#!/usr/bin/env bash
# btrfs_extract.sh
# Extract inode, timestamps, and file content from a btrfs image without mounting.
# Usage: ./btrfs_extract.sh <filename> <image>

set -euo pipefail

# ─── Colour codes ────────────────────────────────────────────────────────────
RED='\033[0;31m'
GRN='\033[0;32m'
YLW='\033[1;33m'
CYN='\033[0;36m'
BLD='\033[1m'
RST='\033[0m'

# ─── Usage ───────────────────────────────────────────────────────────────────
usage() {
    echo -e "${BLD}Usage:${RST} $0 <filename> <btrfs_image>"
    echo -e "  filename    : name of the file to locate (not a path, root directory only)"
    echo -e "  btrfs_image : path to the btrfs disk image"
    exit 1
}

# ─── Argument checks ─────────────────────────────────────────────────────────
[[ $# -ne 2 ]] && { echo -e "${RED}[ERROR]${RST} Incorrect number of arguments."; usage; }

TARGET_FILE="$1"
IMAGE="$2"

[[ -z "$TARGET_FILE" ]] && { echo -e "${RED}[ERROR]${RST} Filename argument is empty."; usage; }
[[ -f "$IMAGE" ]] || { echo -e "${RED}[ERROR]${RST} Image file not found: $IMAGE"; exit 1; }
[[ -r "$IMAGE" ]] || { echo -e "${RED}[ERROR]${RST} Image file is not readable: $IMAGE"; exit 1; }

# ─── Dependency checks ───────────────────────────────────────────────────────
for cmd in btrfs file awk grep; do
    command -v "$cmd" &>/dev/null || { echo -e "${RED}[ERROR]${RST} Required command not found: $cmd"; exit 1; }
done

# ─── Verify btrfs image ──────────────────────────────────────────────────────
echo -e "\n${CYN}[*]${RST} Verifying image type..."
FILE_TYPE=$(file "$IMAGE")
if ! echo "$FILE_TYPE" | grep -qi "btrfs"; then
    # file(1) doesn't always detect btrfs — fall back to btrfs check
    if ! btrfs inspect-internal dump-super "$IMAGE" &>/dev/null; then
        echo -e "${RED}[ERROR]${RST} Image does not appear to be a valid btrfs filesystem: $IMAGE"
        exit 1
    fi
fi
echo -e "${GRN}[+]${RST} Image verified as btrfs."

# ─── Dump the tree once and cache it ─────────────────────────────────────────
echo -e "${CYN}[*]${RST} Parsing btrfs tree (this may take a moment)..."
TREE_DUMP=$(btrfs inspect-internal dump-tree "$IMAGE" 2>/dev/null)

# ─── Locate inode via DIR_ITEM only ──────────────────────────────────────────
INODE=$(echo "$TREE_DUMP" | awk '
    /key \([0-9]+ DIR_ITEM [0-9]+\)/ { block=$0; found=1; next }
    found && /key \([0-9]+ DIR_/     { found=0 }
    found                            { block=block"\n"$0 }
    found && /name: '"$TARGET_FILE"'$/ {
        found=0
        match(block,/\(([0-9]+) INODE_ITEM/,a)
        print a[1]
    }
')

if [[ -z "$INODE" ]]; then
    echo -e "${RED}[ERROR]${RST} File '${TARGET_FILE}' not found in the btrfs image root directory."
    exit 1
fi

echo -e "${GRN}[+]${RST} File located."

# ─── Extract timestamps from INODE_ITEM ──────────────────────────────────────
INODE_BLOCK=$(echo "$TREE_DUMP" | grep -A12 "key (${INODE} INODE_ITEM 0)")

extract_ts() {
    echo "$INODE_BLOCK" | grep "$1" | awk '{print $2, $3}' | tr -d '()'
}

ATIME=$(echo "$INODE_BLOCK" | grep 'atime' | sed 's/.*(\(.*\))/\1/')
CTIME=$(echo "$INODE_BLOCK" | grep 'ctime' | sed 's/.*(\(.*\))/\1/')
MTIME=$(echo "$INODE_BLOCK" | grep 'mtime' | sed 's/.*(\(.*\))/\1/')
OTIME=$(echo "$INODE_BLOCK" | grep 'otime' | sed 's/.*(\(.*\))/\1/')

FILESIZE=$(echo "$INODE_BLOCK" | grep 'size' | awk '{print $4}')
FILEMODE=$(echo "$INODE_BLOCK" | grep 'mode' | awk '{print $5}')
FILEUID=$(echo "$INODE_BLOCK"  | grep 'uid'  | awk '{print $7}')
FILEGID=$(echo "$INODE_BLOCK"  | grep 'gid'  | awk '{print $9}')

# ─── Output results ──────────────────────────────────────────────────────────
echo ""
echo -e "${BLD}════════════════════════════════════════════════════${RST}"
echo -e "${BLD}  btrfs File Extraction Report${RST}"
echo -e "${BLD}════════════════════════════════════════════════════${RST}"
echo -e "  ${BLD}Image   :${RST} $IMAGE"
echo -e "  ${BLD}File    :${RST} $TARGET_FILE"
echo -e "  ${BLD}Inode   :${RST} ${YLW}${INODE}${RST}"
echo -e "  ${BLD}Size    :${RST} ${FILESIZE} bytes"
echo -e "  ${BLD}Mode    :${RST} ${FILEMODE}  UID: ${FILEUID}  GID: ${FILEGID}"
echo -e "${BLD}────────────────────────────────────────────────────${RST}"
echo -e "  ${BLD}Timestamps${RST}"
echo -e "  atime (last access)          : ${ATIME}"
echo -e "  mtime (last modification)    : ${MTIME}"
echo -e "  ctime (last metadata change) : ${CTIME}"
echo -e "  otime (inode creation)       : ${OTIME}"
echo -e "${BLD}════════════════════════════════════════════════════${RST}"

# ─── Restore file ────────────────────────────────────────────────────────────
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
RESTORE_DIR="/tmp/restore_${TIMESTAMP}"
mkdir -p "$RESTORE_DIR"

echo -e "\n${CYN}[*]${RST} Restoring '${TARGET_FILE}' to ${RESTORE_DIR}..."

if btrfs restore -s --path-regex "^/(${TARGET_FILE})$" "$IMAGE" "$RESTORE_DIR" &>/dev/null; then
    RESTORED_PATH="${RESTORE_DIR}/${TARGET_FILE}"
    if [[ -f "$RESTORED_PATH" ]]; then
        echo -e "${GRN}[+]${RST} File restored to: ${BLD}${RESTORED_PATH}${RST}"

        # Safety check before displaying content
        MIME=$(file --mime-type -b "$RESTORED_PATH")
        echo -e "  ${BLD}MIME type:${RST} ${MIME}"

        if echo "$MIME" | grep -q "^text/"; then
            LINE_COUNT=$(wc -l < "$RESTORED_PATH")
            if [[ $LINE_COUNT -le 50 ]]; then
                echo -e "\n${BLD}────────────────────────────────────────────────────${RST}"
                echo -e "${YLW}[!] File content (${LINE_COUNT} lines):${RST}"
                echo -e "${BLD}────────────────────────────────────────────────────${RST}"
                cat "$RESTORED_PATH"
                echo -e "${BLD}────────────────────────────────────────────────────${RST}"
            else
                echo -e "${YLW}[!]${RST} File is text but ${LINE_COUNT} lines — content not printed automatically."
                echo -e "    View with: ${BLD}cat ${RESTORED_PATH}${RST}"
            fi
        else
            echo -e "${YLW}[!]${RST} File is not plain text (${MIME}) — content not printed."
            echo -e "    Inspect with: ${BLD}xxd ${RESTORED_PATH} | head -20${RST}"
        fi
    else
        echo -e "${RED}[ERROR]${RST} Restore completed but file not found at expected path."
        echo -e "    Check restore directory: ${RESTORE_DIR}"
    fi
else
    echo -e "${RED}[ERROR]${RST} btrfs restore failed for '${TARGET_FILE}'."
    rmdir "$RESTORE_DIR" 2>/dev/null
    exit 1
fi

echo -e "\n${GRN}[+]${RST} Done.\n"
