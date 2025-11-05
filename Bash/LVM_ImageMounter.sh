#!/usr/bin/env bash
#
# Given a full-disk image that contains an LVM2 partition, this script:
#   1) Finds the LVM partition and its offset (mmls if available, else fdisk)
#   2) Attaches it to a loop device (read-only) at that offset
#   3) Identifies and activates the volume group
#   4) Finds logical volumes in that VG
#   5) Mounts them read-only under /mnt/lvmevidenceN
#
# Forensic-friendly:
#   - losetup is read-only
#   - LVs are mounted read-only with noexec,nodev,nosuid
#   - For ext* and xfs, we avoid journal replay where possible
#
# REQUIREMENTS:
#   - fdisk
#   - losetup
#   - LVM2 tools: pvs, vgchange, lvs
#   - blkid
#   - mount
#   - Optional: mmls (Sleuth Kit) for nicer partition parsing
#
# Run as root.

set -euo pipefail

script_name="$(basename "$0")"

error() {
    echo "[-] ERROR: $*" >&2
    exit 1
}

usage() {
    cat <<EOF
Usage: sudo $script_name DISK_IMAGE

Example:
  sudo $script_name /cases/images/disk001.dd
EOF
    exit 1
}

[ "${1:-}" ] || usage
IMAGE="$1"

[ -f "$IMAGE" ] || error "File not found: $IMAGE"

if [ "$(id -u)" -ne 0 ]; then
    error "This script must be run as root."
fi

SECTOR_SIZE=""
START_SECTOR=""

echo "[*] Locating LVM partition in image: $IMAGE"

if command -v mmls >/dev/null 2>&1; then
    echo "[*] Using mmls (Sleuth Kit) to identify LVM partition..."
    # mmls typically uses 512-byte sectors by default for raw images.
    SECTOR_SIZE=512
    START_SECTOR=$(mmls "$IMAGE" | awk '/Linux Logical Volume Manager|Linux LVM/ {print $3; exit}')
else
    echo "[*] mmls not available, falling back to fdisk..."
    command -v fdisk >/dev/null 2>&1 || error "fdisk not found."

    # Get logical sector size for this image
    SECTOR_SIZE=$(fdisk -l "$IMAGE" | awk -F'[ ,]+' '/Sector size/ {print $4; exit}')
    [ -z "$SECTOR_SIZE" ] && SECTOR_SIZE=512

    # Find the start sector of the Linux LVM partition
    # Example fdisk line:
    # disk001.img2      411648 1953523711 ... Linux LVM
    START_SECTOR=$(fdisk -l "$IMAGE" | awk '/Linux LVM/ {print $2; exit}')
fi

# After we’ve populated START_SECTOR and SECTOR_SIZE

[ -n "${START_SECTOR:-}" ] || error "Could not find an LVM partition in $IMAGE."

case "$START_SECTOR" in
    ''|*[!0-9]*) error "Non-numeric start sector detected: '$START_SECTOR'";;
esac
case "$SECTOR_SIZE" in
    ''|*[!0-9]*) error "Non-numeric sector size detected: '$SECTOR_SIZE'";;
esac

# Force decimal to avoid octal interpretation of leading zeros
START_SECTOR=$((10#$START_SECTOR))
SECTOR_SIZE=$((10#$SECTOR_SIZE))

OFFSET_BYTES=$(( START_SECTOR * SECTOR_SIZE ))

echo "[*] LVM partition start sector : $START_SECTOR"
echo "[*] Sector size                : $SECTOR_SIZE bytes"
echo "[*] Byte offset                : $OFFSET_BYTES"

command -v losetup >/dev/null 2>&1 || error "losetup not found."

echo "[*] Attaching image at offset to a loop device (read-only)..."

# --find picks the first free /dev/loopX, --show prints the device name
LOOPDEV=$(losetup --find --show --read-only -o "$OFFSET_BYTES" "$IMAGE") || \
    error "losetup failed."

echo "[+] Image attached as: $LOOPDEV"

for cmd in pvs vgchange lvs blkid mount; do
    command -v "$cmd" >/dev/null 2>&1 || error "Required command '$cmd' not found in PATH."
done

echo "[*] Identifying volume group on $LOOPDEV..."

VGNAME=$(pvs --noheadings -o vg_name "$LOOPDEV" 2>/dev/null | awk '{$1=$1; print}')
[ -n "${VGNAME:-}" ] || error "No volume group found on $LOOPDEV (no LVM metadata or corrupted)."

echo "[+] Volume Group detected: $VGNAME"

echo "[*] Activating volume group $VGNAME..."
vgchange -ay "$VGNAME" >/dev/null

echo "[*] Enumerating logical volumes in VG $VGNAME..."

LV_PATHS=()
while IFS= read -r line; do
    [ -n "$line" ] && LV_PATHS+=( "$line" )
done < <(lvs --noheadings -o lv_path "$VGNAME" | awk '{$1=$1; print}')

if [ "${#LV_PATHS[@]}" -eq 0 ]; then
    error "No logical volumes found in VG $VGNAME."
fi

echo "[+] Found ${#LV_PATHS[@]} logical volume(s):"
for lv in "${LV_PATHS[@]}"; do
    echo "    $lv"
done

MOUNT_BASE="/mnt/lvmevidence"

i=1
for LV in "${LV_PATHS[@]}"; do
    MNT="${MOUNT_BASE}${i}"

    # Detect filesystem type
    FSTYPE=$(blkid -o value -s TYPE "$LV" 2>/dev/null || echo "")

    # Swap volumes are not mountable as filesystems – skip them cleanly
    if [ "$FSTYPE" = "swap" ]; then
        echo "[*] Skipping $LV: filesystem type 'swap' (not a mountable filesystem)."
        i=$((i + 1))
        continue
    fi

    case "$FSTYPE" in
        xfs)
            MNT_OPTS="ro,norecovery,noexec,nodev,nosuid"
            ;;
        ext2|ext3|ext4)
            MNT_OPTS="ro,noload,noexec,nodev,nosuid"
            ;;
        btrfs)
            MNT_OPTS="ro,noexec,nodev,nosuid"
            ;;
        ntfs|ntfs-3g)
            MNT_OPTS="ro,noexec,nodev,nosuid"
            ;;
        vfat|fat|fat16|fat32|exfat)
            MNT_OPTS="ro,noexec,nodev,nosuid"
            ;;
        f2fs|reiserfs|jfs)
            MNT_OPTS="ro,noexec,nodev,nosuid"
            ;;
        *)
            MNT_OPTS="ro,noexec,nodev,nosuid"
            ;;
    esac

    echo "[*] Mounting $LV (type: ${FSTYPE:-unknown}) -> $MNT with options: $MNT_OPTS"

    mkdir -p "$MNT"

    # Don't let a failed mount kill the whole script (set -e is on)
    if ! mount -o "$MNT_OPTS" "$LV" "$MNT"; then
        echo "[-] WARNING: Failed to mount $LV (type: ${FSTYPE:-unknown}) on $MNT. Skipping." >&2
        rmdir "$MNT" 2>/dev/null || true
    else
        echo "[+] Mounted $LV on $MNT"
    fi

    i=$((i + 1))
done

echo
echo "[✓] Done."
echo "    Image:     $IMAGE"
echo "    Loop dev:  $LOOPDEV"
echo "    VG:        $VGNAME"
echo "    Mounts:"
i=1
for LV in "${LV_PATHS[@]}"; do
    echo "      - $LV -> ${MOUNT_BASE}${i}"
    i=$((i + 1))
done
echo
echo "Teardown sequence (manual):"
echo "  1) umount /mnt/lvmevidence*"
echo "  2) vgchange -an $VGNAME"
echo "  3) losetup -d $LOOPDEV"
