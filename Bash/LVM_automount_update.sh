#!/usr/bin/env bash

# LVM_automount_update.sh
#
# Comprehensive LVM image mounting tool combining the best features from
# lvm_automount.sh and LVM_ImageMounter.sh
#
# Features:
#   - E01/EWF image support via ewfmount
#   - Mount single LV or all LVs in a volume group
#   - Comprehensive filesystem support (ext*, XFS, btrfs, NTFS, FAT, etc.)
#   - Automatic cleanup with trap mechanism (optional keep-mounted)
#   - Forensically sound: read-only mounts with noexec,nodev,nosuid
#   - Robust error handling and validation
#
# Usage:
#   Single LV mode:  sudo ./LVM_automount_update.sh [OPTIONS] IMAGE MOUNTPOINT
#   All LVs mode:    sudo ./LVM_automount_update.sh [OPTIONS] --all IMAGE
#
# Options:
#   --all                Mount all logical volumes (to /mnt/lvmevidenceN)
#   --keep-mounted       Skip automatic cleanup on exit (for forensic work)
#   --base-mount PATH    Base path for --all mode (default: /mnt/lvmevidence)
#   --lv-name NAME       Specific LV name to mount (default: root)
#   --help               Show this help message
#
# Examples:
#   # Mount single root LV from E01 image
#   sudo ./LVM_automount_update.sh case001.E01 /mnt/evidence
#
#   # Mount all LVs from raw image
#   sudo ./LVM_automount_update.sh --all disk.dd
#
#   # Mount all LVs and keep them mounted
#   sudo ./LVM_automount_update.sh --all --keep-mounted disk.raw

set -euo pipefail

# ============================================================================
# CONFIGURATION
# ============================================================================

MOUNT_ALL=false
KEEP_MOUNTED=false
BASE_MOUNT="/mnt/lvmevidence"
LV_NAME="root"
ORIG_IMAGE=""
MOUNTPOINT=""

# Cleanup tracking
RAW_IMAGE=""
EWF_MOUNT_DIR=""
LOOPDEV=""
VGNAME=""
MOUNTED_LVS=()

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

usage() {
    cat <<'EOF'
Usage:
  Single LV:  sudo ./LVM_automount_update.sh [OPTIONS] IMAGE MOUNTPOINT
  All LVs:    sudo ./LVM_automount_update.sh [OPTIONS] --all IMAGE

Options:
  --all                Mount all logical volumes
  --keep-mounted       Skip automatic cleanup on exit
  --base-mount PATH    Base mount path for --all mode (default: /mnt/lvmevidence)
  --lv-name NAME       Specific LV name to mount in single mode (default: root)
  --help               Show this help message

Arguments:
  IMAGE                Path to disk image (.raw, .dd, .E01, etc.)
  MOUNTPOINT           Where to mount (single LV mode only)

Examples:
  # Mount single root LV from E01
  sudo ./LVM_automount_update.sh case001.E01 /mnt/case001

  # Mount all LVs from raw image
  sudo ./LVM_automount_update.sh --all evidence.dd

  # Keep all LVs mounted for analysis
  sudo ./LVM_automount_update.sh --all --keep-mounted disk.raw

EOF
    exit 0
}

error_exit() {
    echo "[-] ERROR: $*" >&2
    exit 1
}

info() {
    echo "[*] $*"
}

success() {
    echo "[+] $*"
}

# ============================================================================
# CLEANUP FUNCTION
# ============================================================================

cleanup() {
    if [[ "$KEEP_MOUNTED" == "true" ]]; then
        info "Keep-mounted flag set, skipping automatic cleanup"
        return 0
    fi

    info "Performing cleanup..."

    # Unmount all mounted LVs
    if [[ ${#MOUNTED_LVS[@]} -gt 0 ]]; then
        for mnt in "${MOUNTED_LVS[@]}"; do
            if mountpoint -q "$mnt" 2>/dev/null; then
                info "Unmounting $mnt"
                umount "$mnt" 2>/dev/null || true
                rmdir "$mnt" 2>/dev/null || true
            fi
        done
    fi

    # Deactivate volume group
    if [[ -n "$VGNAME" ]]; then
        info "Deactivating volume group: $VGNAME"
        vgchange -an "$VGNAME" 2>/dev/null || true
    fi

    # Detach loop device
    if [[ -n "$LOOPDEV" ]]; then
        info "Detaching loop device: $LOOPDEV"
        losetup -d "$LOOPDEV" 2>/dev/null || true
    fi

    # Unmount EWF
    if [[ -n "$EWF_MOUNT_DIR" ]]; then
        info "Unmounting EWF: $EWF_MOUNT_DIR"
        umount "$EWF_MOUNT_DIR" 2>/dev/null || true
        rmdir "$EWF_MOUNT_DIR" 2>/dev/null || true
    fi

    success "Cleanup completed"
}

# ============================================================================
# ARGUMENT PARSING
# ============================================================================

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --all)
                MOUNT_ALL=true
                shift
                ;;
            --keep-mounted)
                KEEP_MOUNTED=true
                shift
                ;;
            --base-mount)
                BASE_MOUNT="$2"
                shift 2
                ;;
            --lv-name)
                LV_NAME="$2"
                shift 2
                ;;
            --help|-h)
                usage
                ;;
            -*)
                error_exit "Unknown option: $1"
                ;;
            *)
                if [[ -z "$ORIG_IMAGE" ]]; then
                    ORIG_IMAGE="$1"
                elif [[ -z "$MOUNTPOINT" ]]; then
                    MOUNTPOINT="$1"
                else
                    error_exit "Too many arguments"
                fi
                shift
                ;;
        esac
    done

    # Validate arguments
    if [[ -z "$ORIG_IMAGE" ]]; then
        error_exit "No image file specified. Use --help for usage information."
    fi

    if [[ "$MOUNT_ALL" == "false" && -z "$MOUNTPOINT" ]]; then
        error_exit "MOUNTPOINT required in single LV mode. Use --all to mount all LVs."
    fi

    if [[ "$MOUNT_ALL" == "true" && -n "$MOUNTPOINT" ]]; then
        error_exit "MOUNTPOINT not allowed with --all flag"
    fi
}

# ============================================================================
# PREREQUISITE CHECKS
# ============================================================================

check_requirements() {
    if [[ $EUID -ne 0 ]]; then
        error_exit "This script must be run as root"
    fi

    if [[ ! -f "$ORIG_IMAGE" ]]; then
        error_exit "Image file not found: $ORIG_IMAGE"
    fi

    local required_tools=(mmls losetup pvdisplay vgchange lvs blkid mount)
    for bin in "${required_tools[@]}"; do
        if ! command -v "$bin" >/dev/null 2>&1; then
            error_exit "Required tool not found in PATH: $bin"
        fi
    done
}

# ============================================================================
# E01/EWF IMAGE HANDLING
# ============================================================================

handle_ewf_image() {
    local ext="${ORIG_IMAGE##*.}"

    case "$ext" in
        E01|E02|E0[0-9]|e01|e02|e0[0-9])
            if command -v ewfmount >/dev/null 2>&1; then
                EWF_MOUNT_DIR="/mnt/ewf$$"
                info "Detected EWF/E01 image. Using ewfmount -> $EWF_MOUNT_DIR"

                mkdir -p "$EWF_MOUNT_DIR"
                ewfmount "$ORIG_IMAGE" "$EWF_MOUNT_DIR"

                RAW_IMAGE="$EWF_MOUNT_DIR/ewf1"
                if [[ ! -e "$RAW_IMAGE" ]]; then
                    error_exit "ewfmount did not produce $RAW_IMAGE"
                fi
            else
                error_exit "Image looks like EWF/E01 but ewfmount is not available. Install libewf-tools."
            fi
            ;;
        *)
            RAW_IMAGE="$ORIG_IMAGE"
            ;;
    esac

    info "Using raw image: $RAW_IMAGE"
}

# ============================================================================
# LVM PARTITION DETECTION
# ============================================================================

detect_lvm_partition() {
    info "Running mmls on image: $RAW_IMAGE"

    # Extract sector size
    local sector_size
    sector_size=$(mmls "$RAW_IMAGE" 2>/dev/null | awk '
        /^Units are in/ {
            gsub(/-byte/, "", $4);
            print $4;
            exit
        }
    ')

    if [[ -z "${sector_size:-}" ]]; then
        info "Could not determine sector size from mmls, defaulting to 512"
        sector_size=512
    fi

    success "Sector size detected: $sector_size bytes"

    # Find first LVM (0x8e) partition
    local lvm_start_sector
    lvm_start_sector=$(mmls "$RAW_IMAGE" 2>/dev/null | awk '
        $0 ~ /\(0x8e\)/ && $3 ~ /^[0-9]+$/ {
            print $3;
            exit
        }
    ')

    if [[ -z "${lvm_start_sector:-}" ]]; then
        error_exit "No LVM (0x8e) partition found in image"
    fi

    success "LVM partition start sector: $lvm_start_sector"

    # Calculate byte offset (force decimal interpretation)
    local lvm_start_decimal=$((10#$lvm_start_sector))
    local offset=$(( lvm_start_decimal * sector_size ))

    success "Computed byte offset: $offset"

    echo "$offset"
}

# ============================================================================
# LOOP DEVICE SETUP
# ============================================================================

setup_loop_device() {
    local offset=$1

    LOOPDEV=$(losetup -f) || error_exit "Could not obtain a free loop device"

    info "Attaching image to loop device: $LOOPDEV (read-only, offset=$offset)"
    losetup -r -o "$offset" "$LOOPDEV" "$RAW_IMAGE"

    success "Loop device attached: $LOOPDEV"
}

# ============================================================================
# VOLUME GROUP DETECTION AND ACTIVATION
# ============================================================================

activate_volume_group() {
    info "Running pvdisplay on $LOOPDEV"

    local pvinfo
    pvinfo=$(pvdisplay "$LOOPDEV" 2>/dev/null || true)

    VGNAME=$(awk '/VG Name/ {print $3; exit}' <<< "$pvinfo")

    if [[ -z "${VGNAME:-}" ]]; then
        error_exit "Could not determine VG Name from pvdisplay for $LOOPDEV. Is this really an LVM physical volume?"
    fi

    success "Volume Group detected: $VGNAME"

    info "Activating volume group: $VGNAME"
    vgchange -ay "$VGNAME" >/dev/null

    success "Volume group activated"
}

# ============================================================================
# FILESYSTEM DETECTION AND MOUNT OPTIONS
# ============================================================================

get_mount_options() {
    local lv_path=$1
    local fstype

    fstype=$(blkid -o value -s TYPE "$lv_path" 2>/dev/null || echo "")

    local mount_opts="ro,noexec,nodev,nosuid"

    case "$fstype" in
        xfs)
            mount_opts="ro,norecovery,noexec,nodev,nosuid"
            ;;
        ext2|ext3|ext4)
            mount_opts="ro,noload,noexec,nodev,nosuid"
            ;;
        btrfs|ntfs|ntfs-3g|vfat|fat|fat16|fat32|exfat|f2fs|reiserfs|jfs)
            mount_opts="ro,noexec,nodev,nosuid"
            ;;
    esac

    echo "$fstype|$mount_opts"
}

# ============================================================================
# MOUNT SINGLE LV
# ============================================================================

mount_single_lv() {
    local lv_path="/dev/${VGNAME}/${LV_NAME}"

    if [[ ! -e "$lv_path" ]]; then
        info "Expected LV $lv_path not found. Attempting to locate a likely ${LV_NAME} LV..."
        lv_path=$(lvs --noheadings -o lv_path 2>/dev/null | awk -v vg="$VGNAME" -v lv="$LV_NAME" '
            $1 ~ "^/dev/"vg"/" && $1 ~ lv {print $1; exit}
        ') || true
    fi

    if [[ -z "${lv_path:-}" || ! -e "$lv_path" ]]; then
        error_exit "Could not locate logical volume '${LV_NAME}' in VG '$VGNAME'"
    fi

    success "Using LV for mount: $lv_path"

    # Prepare mountpoint
    if [[ ! -d "$MOUNTPOINT" ]]; then
        info "Mountpoint does not exist, creating: $MOUNTPOINT"
        mkdir -p "$MOUNTPOINT"
    fi

    # Get filesystem type and mount options
    local fs_info
    fs_info=$(get_mount_options "$lv_path")
    local fstype="${fs_info%%|*}"
    local mount_opts="${fs_info##*|}"

    info "Filesystem type detected: ${fstype:-unknown}"
    info "Mount options: $mount_opts"

    info "Mounting $lv_path -> $MOUNTPOINT"
    mount -o "$mount_opts" "$lv_path" "$MOUNTPOINT"

    MOUNTED_LVS+=("$MOUNTPOINT")

    success "Successfully mounted $lv_path to $MOUNTPOINT"
}

# ============================================================================
# MOUNT ALL LVS
# ============================================================================

mount_all_lvs() {
    info "Enumerating logical volumes in VG $VGNAME..."

    local lv_paths=()
    while IFS= read -r line; do
        [[ -n "$line" ]] && lv_paths+=("$line")
    done < <(lvs --noheadings -o lv_path "$VGNAME" 2>/dev/null | awk '{$1=$1; print}')

    if [[ ${#lv_paths[@]} -eq 0 ]]; then
        error_exit "No logical volumes found in VG $VGNAME"
    fi

    success "Found ${#lv_paths[@]} logical volume(s):"
    for lv in "${lv_paths[@]}"; do
        echo "    $lv"
    done

    local counter=1
    for lv_path in "${lv_paths[@]}"; do
        local mnt="${BASE_MOUNT}${counter}"

        # Get filesystem type
        local fs_info
        fs_info=$(get_mount_options "$lv_path")
        local fstype="${fs_info%%|*}"
        local mount_opts="${fs_info##*|}"

        # Skip swap volumes
        if [[ "$fstype" == "swap" ]]; then
            info "Skipping $lv_path: filesystem type 'swap' (not mountable)"
            counter=$((counter + 1))
            continue
        fi

        info "Mounting $lv_path (type: ${fstype:-unknown}) -> $mnt"
        info "Mount options: $mount_opts"

        mkdir -p "$mnt"

        if mount -o "$mount_opts" "$lv_path" "$mnt"; then
            success "Mounted $lv_path on $mnt"
            MOUNTED_LVS+=("$mnt")
        else
            echo "[-] WARNING: Failed to mount $lv_path (type: ${fstype:-unknown}) on $mnt. Skipping." >&2
            rmdir "$mnt" 2>/dev/null || true
        fi

        counter=$((counter + 1))
    done
}

# ============================================================================
# DISPLAY SUMMARY
# ============================================================================

display_summary() {
    echo
    success "Mounting operation completed successfully"
    echo
    echo "    Original image: $ORIG_IMAGE"
    echo "    Raw image:      $RAW_IMAGE"
    echo "    Loop device:    $LOOPDEV"
    echo "    Volume Group:   $VGNAME"
    echo

    if [[ "$MOUNT_ALL" == "true" ]]; then
        echo "    Mounted volumes:"
        for mnt in "${MOUNTED_LVS[@]}"; do
            echo "      - $mnt"
        done
    else
        echo "    Mounted at:     $MOUNTPOINT"
    fi

    echo

    if [[ "$KEEP_MOUNTED" == "false" ]]; then
        echo "To unmount and clean up, run:"
        if [[ "$MOUNT_ALL" == "true" ]]; then
            echo "  umount ${BASE_MOUNT}*"
        else
            echo "  umount \"$MOUNTPOINT\""
        fi
        echo "  vgchange -an \"$VGNAME\""
        echo "  losetup -d \"$LOOPDEV\""
        [[ -n "$EWF_MOUNT_DIR" ]] && echo "  umount \"$EWF_MOUNT_DIR\" && rmdir \"$EWF_MOUNT_DIR\""
    else
        echo "Volumes remain mounted for analysis (--keep-mounted flag set)"
        echo
        echo "Manual cleanup commands:"
        if [[ "$MOUNT_ALL" == "true" ]]; then
            echo "  umount ${BASE_MOUNT}*"
        else
            echo "  umount \"$MOUNTPOINT\""
        fi
        echo "  vgchange -an \"$VGNAME\""
        echo "  losetup -d \"$LOOPDEV\""
        [[ -n "$EWF_MOUNT_DIR" ]] && echo "  umount \"$EWF_MOUNT_DIR\" && rmdir \"$EWF_MOUNT_DIR\""
    fi
    echo
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

main() {
    parse_args "$@"
    check_requirements

    # Set trap for cleanup (will check KEEP_MOUNTED flag)
    trap cleanup EXIT

    handle_ewf_image
    local offset
    offset=$(detect_lvm_partition)
    setup_loop_device "$offset"
    activate_volume_group

    if [[ "$MOUNT_ALL" == "true" ]]; then
        mount_all_lvs
    else
        mount_single_lv
    fi

    # Disable trap if keeping mounted
    if [[ "$KEEP_MOUNTED" == "true" ]]; then
        trap - EXIT
    fi

    display_summary
}

# Run main function with all arguments
main "$@"
