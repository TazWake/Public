#!/usr/bin/env bash

# lvm_automount.sh
#
# Usage: sudo ./lvm_automount.sh /path/to/image_or_E01 /mount/point
#
# - If given an E01/E0* file and ewfmount is available,  this script will:
#   * mount the EWF to /mnt/ewf$$
#   * use /mnt/ewf$$/ewf1 as the raw image for the rest of the logic
#
# - If given a raw image, the script should use it directly.

set -euo pipefail

usage() {
    echo "Usage: $0 /path/to/image.raw_or_E01 /mount/point" >&2
    exit 1
}

if [[ $# -ne 2 ]]; then
    usage
fi

ORIG_IMAGE="$1"
MOUNTPOINT="$2"

if [[ ! -f "$ORIG_IMAGE" ]]; then
    echo "[-] Image file not found: $ORIG_IMAGE" >&2
    exit 1
fi

if [[ $EUID -ne 0 ]]; then
    echo "[-] This script must be run as root." >&2
    exit 1
fi

for bin in mmls losetup pvdisplay vgchange blkid mount; do
    if ! command -v "$bin" >/dev/null 2>&1; then
        echo "[-] Required tool not found in PATH: $bin" >&2
        exit 1
    fi
done

RAW_IMAGE="$ORIG_IMAGE"
EWF_MOUNT_DIR=""

# --- E01/EWF handling --------------------------------------------------
case "${ORIG_IMAGE##*.}" in
    E01|E02|E0[0-9])
        if command -v ewfmount >/dev/null 2>&1; then
            EWF_MOUNT_DIR="/mnt/ewf$$"
            echo "[*] Detected EWF/E01 image. Using ewfmount -> $EWF_MOUNT_DIR"
            mkdir -p "$EWF_MOUNT_DIR"
            ewfmount "$ORIG_IMAGE" "$EWF_MOUNT_DIR"
            RAW_IMAGE="$EWF_MOUNT_DIR/ewf1"
            if [[ ! -e "$RAW_IMAGE" ]]; then
                echo "[-] ewfmount did not produce $RAW_IMAGE" >&2
                exit 1
            fi
        else
            echo "[-] Image looks like EWF/E01 but ewfmount is not available." >&2
            echo "    Install libewf-tools or mount manually, then re-run using the raw device." >&2
            exit 1
        fi
        ;;
esac

echo "[*] Using raw image: $RAW_IMAGE"

# Clean up function (loop + optional EWF dir)
LOOPDEV=""
cleanup() {
    if [[ -n "$LOOPDEV" ]]; then
        echo "[*] Cleaning up loop device: $LOOPDEV"
        losetup -d "$LOOPDEV" 2>/dev/null || true
    fi
    if [[ -n "$EWF_MOUNT_DIR" ]]; then
        echo "[*] Unmounting EWF: $EWF_MOUNT_DIR"
        umount "$EWF_MOUNT_DIR" 2>/dev/null || true
        rmdir "$EWF_MOUNT_DIR" 2>/dev/null || true
    fi
}
trap cleanup EXIT

# --- Step 1: Sector size via mmls ----------------------------------------------

echo "[*] Running mmls on image: $RAW_IMAGE"

SECTOR_SIZE=$(mmls "$RAW_IMAGE" 2>/dev/null | awk '
/^Units are in/ {
    gsub(/-byte/, "", $4);
    print $4;
    exit
}')

if [[ -z "${SECTOR_SIZE:-}" ]]; then
    echo "[!] Could not determine sector size from mmls output, defaulting to 512." >&2
    SECTOR_SIZE=512
fi

echo "[+] Sector size detected: $SECTOR_SIZE bytes"

# --- Step 2: Find first LVM (0x8e) partition -----------------------------------
LVM_START_SECTOR=$(mmls "$RAW_IMAGE" 2>/dev/null | awk '
$0 ~ /\(0x8e\)/ && $3 ~ /^[0-9]+$/ {
    print $3;
    exit
}')
if [[ -z "${LVM_START_SECTOR:-}" ]]; then
    echo "[-] No LVM (0x8e) partition found in image." >&2
    exit 1
fi
echo "[+] LVM partition start sector: $LVM_START_SECTOR"
LVM_START_SECTOR_DEC=$((10#$LVM_START_SECTOR))
OFFSET=$(( LVM_START_SECTOR_DEC * SECTOR_SIZE ))

echo "[+] Computed byte offset: $OFFSET"

# --- Step 3: Attach loop device -------------------------------------------------
LOOPDEV=$(losetup -f) || {
    echo "[-] Could not obtain a free loop device." >&2
    exit 1
}

echo "[*] Attaching image to loop device: $LOOPDEV (read-only, offset=$OFFSET)"
losetup -r -o "$OFFSET" "$LOOPDEV" "$RAW_IMAGE"

# --- Step 4: Identify VG name via pvdisplay (robust to failure) -----------------
echo "[*] Running pvdisplay on $LOOPDEV"

PVINFO="$(pvdisplay "$LOOPDEV" 2>/dev/null || true)"

VGNAME=$(awk '/VG Name/ {print $3; exit}' <<< "$PVINFO")

if [[ -z "${VGNAME:-}" ]]; then
    echo "[-] Could not determine VG Name from pvdisplay for $LOOPDEV" >&2
    echo "    Is this really an LVM physical volume?" >&2
    exit 1
fi

echo "[+] Volume Group detected: $VGNAME"

# --- Step 5: Activate VG -------------------------------------------------------
echo "[*] Activating VG: $VGNAME"
vgchange -ay "$VGNAME" >/dev/null

# --- Step 6: Determine LV to mount ---------------------------------------------
LV_PATH="/dev/${VGNAME}/root"

if [[ ! -e "$LV_PATH" ]]; then
    echo "[!] Expected LV $LV_PATH not found. Attempting to locate a likely root LV..." >&2
    LV_PATH=$(lvs --noheadings -o lv_path 2>/dev/null | awk -v vg="$VGNAME" '
        $1 ~ "^/dev/"vg"/" && $1 ~ /root/ {print $1; exit}
    ') || true
fi

if [[ -z "${LV_PATH:-}" || ! -e "$LV_PATH" ]]; then
    echo "[-] Could not locate a root logical volume in VG '$VGNAME'." >&2
    exit 1
fi

echo "[+] Using LV for mount: $LV_PATH"

# --- Step 7: Prepare mountpoint -------------------------------------------------
if [[ ! -d "$MOUNTPOINT" ]]; then
    echo "[*] Mountpoint does not exist, creating: $MOUNTPOINT"
    mkdir -p "$MOUNTPOINT"
fi

# --- Step 8: Determine filesystem type & mount options -------------------------
FSTYPE=$(blkid -o value -s TYPE "$LV_PATH" 2>/dev/null || echo "")

MOUNT_OPTS="ro,noexec,nodev,nosuid"

case "$FSTYPE" in
    xfs)
        MOUNT_OPTS="ro,norecovery,noexec,nodev,nosuid"
        ;;
    ext2|ext3|ext4)
        MOUNT_OPTS="ro,noload,noexec,nodev,nosuid"
        ;;
esac

echo "[*] Filesystem type detected: ${FSTYPE:-unknown}"
echo "[*] Mount options: $MOUNT_OPTS"

echo "[*] Mounting $LV_PATH -> $MOUNTPOINT"
mount -o "$MOUNT_OPTS" "$LV_PATH" "$MOUNTPOINT"

# We *want* to keep loop/VG alive now, so stop auto-cleanup
trap - EXIT

echo "[+] Success."
echo "    Original image: $ORIG_IMAGE"
echo "    Raw image:      $RAW_IMAGE"
echo "    Loop dev:       $LOOPDEV"
echo "    VG:             $VGNAME"
echo "    LV:             $LV_PATH"
echo "    Mounted at:     $MOUNTPOINT"
echo
echo "Remember to clean up afterwards:"
echo "  umount \"$MOUNTPOINT\""
echo "  vgchange -an \"$VGNAME\""
echo "  losetup -d \"$LOOPDEV\""
[[ -n "$EWF_MOUNT_DIR" ]] && echo "  umount \"$EWF_MOUNT_DIR\" && rmdir \"$EWF_MOUNT_DIR\""
