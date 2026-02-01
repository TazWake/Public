#!/usr/bin/env bash
set -euo pipefail

# evidence_collect.sh: Mount evidence image and run initial collection scripts.

SCRIPT_NAME="$(/usr/bin/basename "$0")"
LOG_DIR="/var/log/triage_tooling"
LOG_FILE="${LOG_DIR}/evidence_collect_$(/usr/bin/date +%Y%m%d_%H%M%S).log"

IMAGE_PATH=""
IMAGE_TYPE="auto"  # auto|e01|raw
MOUNT_DIR="/mnt/case1"
EWF_MOUNT_DIR="/mnt/ewf"
OFFSET_BYTES=""
PARTITION_NUM=""
AUTO_DETECT=true

LOOP_DEV=""

usage() {
  /usr/bin/cat <<EOF
Usage: ${SCRIPT_NAME} --image <path> [options]

Options:
  --image <path>           Path to E01 or raw image (required)
  --type <auto|e01|raw>    Image type (default: auto)
  --mount-dir <dir>        Mount point for evidence (default: /mnt/case1)
  --ewf-mount <dir>        E01 mount point (default: /mnt/ewf)
  --offset <bytes>         Byte offset for partition mount
  --partition <num>        Partition number to mount (uses losetup -P)
  --no-auto                Disable auto-detection prompts
  -h, --help               Show help
EOF
}

log() {
  /usr/bin/printf '%s %s\n' "$(/usr/bin/date -u +%Y-%m-%dT%H:%M:%SZ)" "$1" | /usr/bin/tee -a "$LOG_FILE" >/dev/null
}

fatal() {
  log "ERROR: $1"
  /usr/bin/printf 'ERROR: %s\n' "$1" >&2
  exit 1
}

cleanup() {
  if [[ -n "${LOOP_DEV}" ]]; then
    /sbin/umount "${MOUNT_DIR}" >/dev/null 2>&1 || true
    /sbin/losetup -d "${LOOP_DEV}" >/dev/null 2>&1 || true
  fi
}

trap cleanup EXIT

if [[ "$(/usr/bin/id -u)" -ne 0 ]]; then
  fatal "This script must be run as root."
fi

if [[ $# -eq 0 ]]; then
  usage
  exit 1
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    --image)
      IMAGE_PATH="$2"
      shift 2
      ;;
    --type)
      IMAGE_TYPE="$2"
      shift 2
      ;;
    --mount-dir)
      MOUNT_DIR="$2"
      shift 2
      ;;
    --ewf-mount)
      EWF_MOUNT_DIR="$2"
      shift 2
      ;;
    --offset)
      OFFSET_BYTES="$2"
      shift 2
      ;;
    --partition)
      PARTITION_NUM="$2"
      shift 2
      ;;
    --no-auto)
      AUTO_DETECT=false
      shift 1
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fatal "Unknown option: $1"
      ;;
  esac
done

[[ -n "$IMAGE_PATH" ]] || fatal "--image is required."
[[ -f "$IMAGE_PATH" ]] || fatal "Image not found: $IMAGE_PATH"

/usr/bin/mkdir -p "$LOG_DIR"
/usr/bin/touch "$LOG_FILE"

log "Starting ${SCRIPT_NAME}"
log "Image: ${IMAGE_PATH}"
log "Type: ${IMAGE_TYPE}"
log "Mount dir: ${MOUNT_DIR}"
log "EWF mount dir: ${EWF_MOUNT_DIR}"

if [[ "$IMAGE_TYPE" == "auto" ]]; then
  case "${IMAGE_PATH}" in
    *.E01|*.e01)
      IMAGE_TYPE="e01"
      ;;
    *)
      IMAGE_TYPE="raw"
      ;;
  esac
fi

/usr/bin/mkdir -p "$MOUNT_DIR"

mount_raw_image() {
  local raw_path="$1"

  if [[ -n "$OFFSET_BYTES" ]]; then
    log "Mounting raw image with offset ${OFFSET_BYTES}"
    /bin/mount -o ro,loop,offset="${OFFSET_BYTES}" "$raw_path" "$MOUNT_DIR"
    return
  fi

  if [[ -n "$PARTITION_NUM" ]]; then
    log "Setting up loop device with partitions"
    LOOP_DEV="$(/sbin/losetup -f --show -P "$raw_path")"
    log "Loop device: ${LOOP_DEV}"
    /bin/mount -o ro "${LOOP_DEV}p${PARTITION_NUM}" "$MOUNT_DIR"
    return
  fi

  if $AUTO_DETECT; then
    log "Attempting partition discovery via fdisk"
    /sbin/fdisk -l "$raw_path" | /usr/bin/tee -a "$LOG_FILE" >/dev/null || true
    /usr/bin/printf 'This appears to be a full disk image. Specify partition number or offset.\n' >&2
    /usr/bin/read -r -p "Partition number (e.g., 1) or leave blank to specify offset: " PARTITION_NUM
    if [[ -n "$PARTITION_NUM" ]]; then
      LOOP_DEV="$(/sbin/losetup -f --show -P "$raw_path")"
      log "Loop device: ${LOOP_DEV}"
      /bin/mount -o ro "${LOOP_DEV}p${PARTITION_NUM}" "$MOUNT_DIR"
      return
    fi
    /usr/bin/read -r -p "Offset in bytes: " OFFSET_BYTES
    if [[ -n "$OFFSET_BYTES" ]]; then
      /bin/mount -o ro,loop,offset="${OFFSET_BYTES}" "$raw_path" "$MOUNT_DIR"
      return
    fi
  fi

  fatal "Full disk image requires --partition or --offset."
}

if [[ "$IMAGE_TYPE" == "e01" ]]; then
  /usr/bin/mkdir -p "$EWF_MOUNT_DIR"
  log "Mounting E01 with ewfmount"
  /usr/bin/ewfmount "$IMAGE_PATH" "$EWF_MOUNT_DIR"
  RAW_FROM_EWF="${EWF_MOUNT_DIR}/ewf1"
  [[ -f "$RAW_FROM_EWF" ]] || fatal "EWF raw image not found at ${RAW_FROM_EWF}"
  mount_raw_image "$RAW_FROM_EWF"
else
  mount_raw_image "$IMAGE_PATH"
fi

log "Mounted evidence to ${MOUNT_DIR}"

INITIAL_SCRIPT="$(/usr/bin/dirname "$0")/initial_collection.sh"
if [[ -x "$INITIAL_SCRIPT" ]]; then
  log "Running initial collection script: ${INITIAL_SCRIPT}"
  "$INITIAL_SCRIPT" --mount "$MOUNT_DIR" --log "$LOG_FILE"
else
  log "No initial collection script found at ${INITIAL_SCRIPT}; skipping."
fi

log "Completed ${SCRIPT_NAME}"
