#!/usr/bin/env bash
set -euo pipefail

# evidence_collect.sh: Mount evidence image and run initial collection commands.

SCRIPT_NAME="$(/usr/bin/basename "$0")"
RUN_TS="$(/usr/bin/date +%Y%m%d_%H%M%S)"
LOG_DIR=""
LOG_FILE=""

IMAGE_PATH=""
IMAGE_TYPE="auto"  # auto|e01|raw
MOUNT_DIR="/mnt/case1"
EWF_MOUNT_DIR="/mnt/ewf"
OFFSET_BYTES=""
PARTITION_NUM=""
AUTO_DETECT=true
INCLUDE_LIVE=false
INCLUDE_LIVE_REQUESTED=false
OUTPUT_DIR="/var/tmp/triage_${RUN_TS}"
MOUNT_OPTS="ro,loop,noatime,noexec,noload,norecovery"
REPORT_JSON=false
LIVE_SYSTEM=false
MOUNT_ALL_PARTITIONS=false
LVM_DEVICES_FILE=""

LOOP_DEV=""
MOUNT_POINTS=()
MOUNT_TARGETS=()

usage() {
  /usr/bin/cat <<EOF
Usage: ${SCRIPT_NAME} --image <path> [options]

Options:
  --image <path>           Path to E01 or raw image (required)
  --type <auto|e01|raw>    Image type (default: auto)
  --mount-dir <dir>        Mount point for evidence (default: /mnt/case1)
  --ewf-mount <dir>        E01 mount point (default: /mnt/ewf)
  --offset <n[s|b]>        Offset for partition mount (default: sectors; use 'b' for bytes)
  --partition <num>        Partition number to mount (uses losetup -P)
  --out-dir <dir>          Output directory for triage artifacts
  --live-system            Run on live system (no image); enables live collection
  --include-live           Deprecated: only honored with --live-system
  --report-json            Also output report.json
  --mount-all-partitions   Mount all partitions from a full disk image
  --no-auto                Disable auto-detection prompts
  -h, --help               Show help
EOF
}

log() {
  /usr/bin/printf '%s %s\n' "$(/usr/bin/date -u +%Y-%m-%dT%H:%M:%SZ)" "$1" | /usr/bin/tee -a "$LOG_FILE" >/dev/null
}

warn() {
  log "WARN: $1"
}

fatal() {
  log "ERROR: $1"
  /usr/bin/printf 'ERROR: %s\n' "$1" >&2
  exit 1
}

have_cmd() {
  command -v "$1" >/dev/null 2>&1
}

ensure_dir() {
  /usr/bin/mkdir -p "$1"
}

add_mountpoint() {
  MOUNT_POINTS+=("$1")
}

run_cmd() {
  local desc="$1"
  shift
  log "RUN: ${desc}"
  if "$@" >>"$LOG_FILE" 2>&1; then
    return 0
  fi
  warn "Command failed: ${desc}"
  return 1
}

cleanup() {
  if ((${#MOUNT_POINTS[@]} > 0)); then
    for ((i=${#MOUNT_POINTS[@]}-1; i>=0; i--)); do
      /bin/umount "${MOUNT_POINTS[$i]}" >/dev/null 2>&1 || true
    done
  fi
  if [[ -n "${LOOP_DEV}" ]]; then
    /sbin/losetup -d "${LOOP_DEV}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${LVM_DEVICES_FILE}" && -f "${LVM_DEVICES_FILE}" ]]; then
    /bin/rm -f "${LVM_DEVICES_FILE}" >/dev/null 2>&1 || true
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
    --out-dir)
      OUTPUT_DIR="$2"
      shift 2
      ;;
    --live-system)
      LIVE_SYSTEM=true
      shift 1
      ;;
    --include-live)
      INCLUDE_LIVE=true
      INCLUDE_LIVE_REQUESTED=true
      shift 1
      ;;
    --report-json)
      REPORT_JSON=true
      shift 1
      ;;
    --mount-all-partitions)
      MOUNT_ALL_PARTITIONS=true
      shift 1
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

if $LIVE_SYSTEM; then
  if [[ -n "$IMAGE_PATH" ]]; then
    fatal "--live-system cannot be used with --image."
  fi
  INCLUDE_LIVE=true
else
  [[ -n "$IMAGE_PATH" ]] || fatal "--image is required unless --live-system is specified."
  [[ -f "$IMAGE_PATH" ]] || fatal "Image not found: $IMAGE_PATH"
  INCLUDE_LIVE=false
fi

LOG_DIR="$OUTPUT_DIR"
LOG_FILE="${LOG_DIR}/evidence_collect_${RUN_TS}.log"
ensure_dir "$LOG_DIR"
/usr/bin/touch "$LOG_FILE"

log "Starting ${SCRIPT_NAME}"
log "Image: ${IMAGE_PATH:-<live>}"
log "Type: ${IMAGE_TYPE}"
log "EWF mount dir: ${EWF_MOUNT_DIR}"
log "Output dir: ${OUTPUT_DIR}"
log "Live system: ${LIVE_SYSTEM}"
if ! $LIVE_SYSTEM && $INCLUDE_LIVE_REQUESTED; then
  warn "--include-live ignored for image-based collection (mounted-only mode)."
fi

if $LIVE_SYSTEM; then
  MOUNT_DIR="/"
else
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
  ensure_dir "$MOUNT_DIR"
fi

log "Mount dir: ${MOUNT_DIR}"

ensure_dir "$OUTPUT_DIR"

OUT_META="${OUTPUT_DIR}/metadata"
OUT_VOL="${OUTPUT_DIR}/volatile"
OUT_SYS="${OUTPUT_DIR}/system"
OUT_PERSIST="${OUTPUT_DIR}/persistence"
OUT_LOGS="${OUTPUT_DIR}/logs"
OUT_FS="${OUTPUT_DIR}/filesystem"
OUT_PROC="${OUTPUT_DIR}/proc_maps"
OUT_CSV="${OUTPUT_DIR}/csv"
OUT_REPORT="${OUTPUT_DIR}/report.txt"
OUT_HASHES="${OUTPUT_DIR}/hashes.sha256"
OUT_TARGETS="${OUTPUT_DIR}/targets"

ensure_dir "$OUT_META"
ensure_dir "$OUT_VOL"
ensure_dir "$OUT_SYS"
ensure_dir "$OUT_PERSIST"
ensure_dir "$OUT_LOGS"
ensure_dir "$OUT_FS"
ensure_dir "$OUT_PROC"
ensure_dir "$OUT_CSV"
ensure_dir "$OUT_TARGETS"

json_escape() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\n'/\\n}"
  s="${s//$'\r'/\\r}"
  s="${s//$'\t'/\\t}"
  /usr/bin/printf '%s' "$s"
}

mount_device_ro() {
  local dev="$1"
  local mnt="$2"
  if ! /bin/mount -o "ro,noatime,noexec,noload,norecovery" "$dev" "$mnt"; then
    warn "Mount with safe options failed; retrying with ro only"
    /bin/mount -o ro "$dev" "$mnt"
  fi
  add_mountpoint "$mnt"
  MOUNT_TARGETS+=("$mnt")
}

is_lvm_member() {
  local dev="$1"
  if have_cmd blkid; then
    local fstype=""
    fstype="$(/sbin/blkid -o value -s TYPE "$dev" 2>/dev/null || true)"
    [[ "$fstype" == "LVM2_member" ]]
    return
  fi
  return 1
}

activate_lvm_from_device() {
  local dev="$1"
  if ! have_cmd lvm; then
    warn "lvm command not found; cannot activate LVM volumes"
    return 1
  fi
  local cfg="devices{ filter=[\"a|${dev}|\",\"r|.*|\"] }"
  local lvm_args=("--config" "$cfg")
  if have_cmd lvmdevices; then
    if [[ -z "$LVM_DEVICES_FILE" ]]; then
      LVM_DEVICES_FILE="${OUTPUT_DIR}/lvm_devices_${RUN_TS}.devices"
    fi
    /sbin/lvmdevices --devicesfile "$LVM_DEVICES_FILE" --adddev "$dev" >>"$LOG_FILE" 2>&1 || true
    lvm_args=("--devicesfile" "$LVM_DEVICES_FILE")
  fi

  /sbin/lvm pvscan --cache "${lvm_args[@]}" >>"$LOG_FILE" 2>&1 || true
  /sbin/lvm vgscan --mknodes "${lvm_args[@]}" >>"$LOG_FILE" 2>&1 || true
  /sbin/lvm vgchange -ay "${lvm_args[@]}" >>"$LOG_FILE" 2>&1 || true

  local lv_paths=()
  while IFS= read -r lv; do
    [[ -n "$lv" ]] || continue
    lv_paths+=("$lv")
  done < <(/sbin/lvm lvs --noheadings -o lv_path "${lvm_args[@]}" 2>>"$LOG_FILE" | /usr/bin/tr -d ' ')

  if ((${#lv_paths[@]} == 0)); then
    warn "No logical volumes found for ${dev}"
    return 1
  fi

  ensure_dir "${MOUNT_DIR}/vols"
  for lv in "${lv_paths[@]}"; do
    local base=""
    base="$(/usr/bin/basename "$lv")"
    local lv_mnt="${MOUNT_DIR}/vols/${base}"
    ensure_dir "$lv_mnt"
    log "Mounting LVM logical volume ${lv} to ${lv_mnt}"
    mount_device_ro "$lv" "$lv_mnt"
  done
  return 0
}

mount_raw_image() {
  local raw_path="$1"
  local opts="${MOUNT_OPTS}"
  local offset_val="${OFFSET_BYTES}"
  local offset_bytes=""

  if [[ -n "$offset_val" ]]; then
    if [[ "$offset_val" =~ b$ ]]; then
      offset_val="${offset_val%b}"
      offset_bytes="$offset_val"
    else
      if [[ "$offset_val" =~ s$ ]]; then
        offset_val="${offset_val%s}"
      fi
      offset_bytes="$((offset_val * 512))"
    fi
  fi

  if [[ -n "$offset_bytes" ]]; then
    log "Setting up loop device with offset ${offset_bytes} bytes"
    LOOP_DEV="$(/sbin/losetup -f --show --offset "${offset_bytes}" "$raw_path")"
    log "Loop device: ${LOOP_DEV}"
    if is_lvm_member "$LOOP_DEV"; then
      log "Detected LVM2 member at ${LOOP_DEV}"
      activate_lvm_from_device "$LOOP_DEV" && return 0
    fi
    mount_device_ro "$LOOP_DEV" "$MOUNT_DIR"
    return
  fi

  if [[ -n "$PARTITION_NUM" ]]; then
    log "Setting up loop device with partitions"
    LOOP_DEV="$(/sbin/losetup -f --show -P "$raw_path")"
    log "Loop device: ${LOOP_DEV}"
    local part_dev="${LOOP_DEV}p${PARTITION_NUM}"
    if is_lvm_member "$part_dev"; then
      log "Detected LVM2 member at ${part_dev}"
      activate_lvm_from_device "$part_dev" && return 0
    fi
    mount_device_ro "$part_dev" "$MOUNT_DIR"
    return
  fi

  if $AUTO_DETECT; then
    if $MOUNT_ALL_PARTITIONS; then
      log "Mounting all partitions from full disk image"
      LOOP_DEV="$(/sbin/losetup -f --show -P "$raw_path")"
      log "Loop device: ${LOOP_DEV}"
      if have_cmd lsblk; then
        while IFS= read -r part_dev; do
          [[ -n "$part_dev" ]] || continue
          local part_name=""
          part_name="$(/usr/bin/basename "$part_dev")"
          local part_mnt="${MOUNT_DIR}/parts/${part_name}"
          ensure_dir "$part_mnt"
          if is_lvm_member "$part_dev"; then
            log "Detected LVM2 member at ${part_dev}"
            activate_lvm_from_device "$part_dev" || true
            continue
          fi
          log "Mounting partition ${part_dev} to ${part_mnt}"
          mount_device_ro "$part_dev" "$part_mnt"
        done < <(/bin/lsblk -ln -o PATH,TYPE "$LOOP_DEV" 2>>"$LOG_FILE" | /usr/bin/awk '$2 == "part" {print $1}')
      else
        warn "lsblk not available; cannot auto-mount all partitions"
      fi
      if ((${#MOUNT_TARGETS[@]} > 0)); then
        return
      fi
    fi
    log "Attempting partition discovery (fdisk/lsblk)"
    /sbin/fdisk -l "$raw_path" | /usr/bin/tee -a "$LOG_FILE" >/dev/null || true
    if have_cmd mmls; then
      /usr/bin/mmls "$raw_path" | /usr/bin/tee -a "$LOG_FILE" >/dev/null || true
    fi
    if have_cmd lsblk; then
      local tmp_loop=""
      tmp_loop="$(/sbin/losetup -f --show -P "$raw_path")"
      /bin/lsblk -o NAME,TYPE,SIZE,FSTYPE,PTTYPE,PTUUID,PARTLABEL,PARTUUID "$tmp_loop" 2>>"$LOG_FILE" || true
      /sbin/losetup -d "$tmp_loop" >/dev/null 2>&1 || true
    fi
    /usr/bin/printf 'This appears to be a full disk image. Specify partition number or offset.\n' >&2
    /usr/bin/read -r -p "Partition number (e.g., 1) or leave blank to specify offset: " PARTITION_NUM
    if [[ -n "$PARTITION_NUM" ]]; then
      LOOP_DEV="$(/sbin/losetup -f --show -P "$raw_path")"
      log "Loop device: ${LOOP_DEV}"
      local part_dev="${LOOP_DEV}p${PARTITION_NUM}"
      if is_lvm_member "$part_dev"; then
        log "Detected LVM2 member at ${part_dev}"
        activate_lvm_from_device "$part_dev" && return 0
      fi
      mount_device_ro "$part_dev" "$MOUNT_DIR"
      return
    fi
    /usr/bin/read -r -p "Offset (sectors by default; use 'b' for bytes, e.g., 2048s or 1048576b): " OFFSET_BYTES
    offset_val="${OFFSET_BYTES}"
    offset_bytes=""
    if [[ -n "$offset_val" ]]; then
      if [[ "$offset_val" =~ b$ ]]; then
        offset_val="${offset_val%b}"
        offset_bytes="$offset_val"
      else
        if [[ "$offset_val" =~ s$ ]]; then
          offset_val="${offset_val%s}"
        fi
        offset_bytes="$((offset_val * 512))"
      fi
    fi
    if [[ -n "$OFFSET_BYTES" ]]; then
      LOOP_DEV="$(/sbin/losetup -f --show --offset "${offset_bytes}" "$raw_path")"
      log "Loop device: ${LOOP_DEV}"
      if is_lvm_member "$LOOP_DEV"; then
        log "Detected LVM2 member at ${LOOP_DEV}"
        activate_lvm_from_device "$LOOP_DEV" && return 0
      fi
      mount_device_ro "$LOOP_DEV" "$MOUNT_DIR"
      return
    fi
  fi

  fatal "Full disk image requires --partition or --offset."
}

if ! $LIVE_SYSTEM; then
  if [[ "$IMAGE_TYPE" == "e01" ]]; then
    have_cmd ewfmount || fatal "ewfmount is required for E01 images."
    ensure_dir "$EWF_MOUNT_DIR"
    log "Mounting E01 with ewfmount"
    /usr/bin/ewfmount "$IMAGE_PATH" "$EWF_MOUNT_DIR"
    RAW_FROM_EWF="${EWF_MOUNT_DIR}/ewf1"
    [[ -f "$RAW_FROM_EWF" ]] || fatal "EWF raw image not found at ${RAW_FROM_EWF}"
    mount_raw_image "$RAW_FROM_EWF"
  else
    mount_raw_image "$IMAGE_PATH"
  fi

  if ((${#MOUNT_TARGETS[@]} > 0)); then
    log "Mount targets: ${MOUNT_TARGETS[*]}"
  else
    log "Mounted evidence to ${MOUNT_DIR}"
  fi
fi

hash_file() {
  local src="$1"
  if have_cmd sha256sum; then
    /usr/bin/sha256sum "$src" >>"$OUT_HASHES" 2>>"$LOG_FILE" || true
  fi
}

hash_path_list() {
  local list_file="$1"
  if have_cmd sha256sum && [[ -f "$list_file" ]]; then
    while IFS= read -r line; do
      [[ -n "$line" ]] || continue
      /usr/bin/sha256sum "$line" >>"$OUT_HASHES" 2>>"$LOG_FILE" || true
    done < "$list_file"
  fi
}

copy_dir_preserve() {
  local src="$1"
  local dst="$2"
  if have_cmd rsync; then
    /usr/bin/rsync -a "$src" "$dst" >>"$LOG_FILE" 2>&1 || true
  else
    /bin/cp -a "$src" "$dst" >>"$LOG_FILE" 2>&1 || true
  fi
}

collect_live_volatile() {
  log "Collecting live volatile data (RFC3227 order)"
  run_cmd "date -u" /usr/bin/date -u
  run_cmd "uptime" /usr/bin/uptime
  run_cmd "who" /usr/bin/who
  run_cmd "w" /usr/bin/w
  run_cmd "last" /usr/bin/last
  run_cmd "lastlog" /usr/bin/lastlog
  run_cmd "ps auxf" /bin/ps auxf
  if have_cmd pstree; then
    run_cmd "pstree" /usr/bin/pstree -ap
  fi
  if have_cmd top; then
    /usr/bin/top -b -n1 >"${OUT_VOL}/top.txt" 2>>"$LOG_FILE" || true
  fi
  if have_cmd ss; then
    run_cmd "ss -apn" /usr/bin/ss -apn
    run_cmd "ss -lntup" /usr/bin/ss -lntup
  fi
  if have_cmd lsof; then
    /usr/bin/lsof -nP >"${OUT_VOL}/lsof.txt" 2>>"$LOG_FILE" || true
    /usr/bin/lsof -nP -i >"${OUT_VOL}/lsof_i.txt" 2>>"$LOG_FILE" || true
  fi
  if have_cmd ip; then
    run_cmd "ip a" /usr/sbin/ip a
    run_cmd "ip r" /usr/sbin/ip r
  fi
  if have_cmd arp; then
    run_cmd "arp -n" /usr/sbin/arp -n
  fi
  if have_cmd lsmod; then
    run_cmd "lsmod" /usr/sbin/lsmod
  fi
  if have_cmd dmesg; then
    /usr/bin/dmesg >"${OUT_VOL}/dmesg.txt" 2>>"$LOG_FILE" || true
  fi

  if [[ -d /proc ]]; then
    for maps in /proc/[0-9]*/maps; do
      [[ -r "$maps" ]] || continue
      /bin/cp -a "$maps" "${OUT_PROC}/$(/usr/bin/basename "$(/usr/bin/dirname "$maps")")_maps" 2>>"$LOG_FILE" || true
    done
  fi
}

collect_live_system() {
  log "Collecting live system configuration"
  /usr/bin/uname -a >"${OUT_SYS}/uname.txt" 2>>"$LOG_FILE" || true
  if [[ -f /etc/os-release ]]; then
    /bin/cp -a /etc/os-release "${OUT_SYS}/" 2>>"$LOG_FILE" || true
  fi
  if have_cmd hostnamectl; then
    /usr/bin/hostnamectl >"${OUT_SYS}/hostnamectl.txt" 2>>"$LOG_FILE" || true
  fi
  if have_cmd timedatectl; then
    /usr/bin/timedatectl >"${OUT_SYS}/timedatectl.txt" 2>>"$LOG_FILE" || true
  fi
  if have_cmd systemctl; then
    /usr/bin/systemctl list-units --type=service --all >"${OUT_SYS}/systemctl_services.txt" 2>>"$LOG_FILE" || true
    /usr/bin/systemctl list-timers --all >"${OUT_SYS}/systemctl_timers.txt" 2>>"$LOG_FILE" || true
  fi
  if have_cmd crontab; then
    /usr/bin/crontab -l >"${OUT_SYS}/crontab_root.txt" 2>>"$LOG_FILE" || true
  fi
  if have_cmd dpkg; then
    /usr/bin/dpkg -l >"${OUT_SYS}/packages.txt" 2>>"$LOG_FILE" || true
  elif have_cmd rpm; then
    /usr/bin/rpm -qa >"${OUT_SYS}/packages.txt" 2>>"$LOG_FILE" || true
  fi
}

collect_mounted_filesystem() {
  local root="$1"
  local tag="$2"
  local tgt_base="${OUT_TARGETS}/${tag}"
  local tgt_sys="${tgt_base}/system"
  local tgt_persist="${tgt_base}/persistence"
  local tgt_logs="${tgt_base}/logs"
  local tgt_fs="${tgt_base}/filesystem"
  local tgt_csv="${tgt_base}/csv"

  ensure_dir "$tgt_sys"
  ensure_dir "$tgt_persist"
  ensure_dir "$tgt_logs"
  ensure_dir "$tgt_fs"
  ensure_dir "$tgt_csv"

  log "Collecting artifacts from ${root} into ${tgt_base}"

  # Users and groups
  if [[ -f "$root/etc/passwd" ]]; then
    /bin/cp -a "$root/etc/passwd" "${tgt_sys}/passwd" 2>>"$LOG_FILE" || true
  fi
  if [[ -f "$root/etc/shadow" ]]; then
    /bin/cp -a "$root/etc/shadow" "${tgt_sys}/shadow" 2>>"$LOG_FILE" || true
  fi
  if [[ -f "$root/etc/group" ]]; then
    /bin/cp -a "$root/etc/group" "${tgt_sys}/group" 2>>"$LOG_FILE" || true
  fi
  if [[ -f "$root/etc/os-release" ]]; then
    /bin/cp -a "$root/etc/os-release" "${tgt_sys}/os-release" 2>>"$LOG_FILE" || true
  fi

  # Services and timers
  if [[ -d "$root/etc/systemd" ]]; then
    copy_dir_preserve "$root/etc/systemd" "${tgt_sys}/"
  fi
  if [[ -d "$root/etc/init.d" ]]; then
    copy_dir_preserve "$root/etc/init.d" "${tgt_sys}/"
  fi

  # Cron
  if [[ -d "$root/etc/cron.d" ]]; then
    copy_dir_preserve "$root/etc/cron.d" "${tgt_sys}/"
  fi
  if [[ -d "$root/var/spool/cron" ]]; then
    copy_dir_preserve "$root/var/spool/cron" "${tgt_sys}/"
  fi

  # Logs
  if [[ -d "$root/var/log" ]]; then
    copy_dir_preserve "$root/var/log" "${tgt_logs}/"
  fi

  # Key configs
  if [[ -d "$root/etc" ]]; then
    ensure_dir "${tgt_persist}/etc"
    for f in ssh/sshd_config ssh/ssh_config sudoers sudoers.d passwd shadow group hosts resolv.conf crontab; do
      if [[ -e "$root/etc/$f" ]]; then
        /bin/cp -a "$root/etc/$f" "${tgt_persist}/etc/" 2>>"$LOG_FILE" || true
      fi
    done
  fi

  # Shell history from users
  if [[ -d "$root/home" ]]; then
    /usr/bin/find "$root/home" -maxdepth 2 -type f \( -name ".bash_history" -o -name ".zsh_history" -o -name ".history" -o -name ".bashrc" -o -name ".profile" \) -print >"${tgt_fs}/user_history_files.txt" 2>>"$LOG_FILE" || true
    if [[ -s "${tgt_fs}/user_history_files.txt" ]]; then
      ensure_dir "${tgt_fs}/user_history"
      while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        /bin/cp -a "$f" "${tgt_fs}/user_history/" 2>>"$LOG_FILE" || true
      done < "${tgt_fs}/user_history_files.txt"
    fi
  fi

  # Login records
  for lf in wtmp btmp lastlog; do
    if [[ -f "$root/var/log/$lf" ]]; then
      /bin/cp -a "$root/var/log/$lf" "${tgt_logs}/" 2>>"$LOG_FILE" || true
    fi
  done

  # Bodyfile generation (best effort)
  if have_cmd statx; then
    /usr/bin/find "$root" -xdev -type f -print0 | /usr/bin/xargs -0 /usr/bin/statx --format '%n|%s|%b|%X|%Y|%Z' >"${tgt_fs}/bodyfile_statx.txt" 2>>"$LOG_FILE" || true
  elif have_cmd fls; then
    /usr/bin/fls -r -m / "$root" >"${tgt_fs}/bodyfile.txt" 2>>"$LOG_FILE" || true
  else
    /usr/bin/find "$root" -xdev -type f -printf '%p|%s|%A@|%T@|%C@\n' >"${tgt_fs}/bodyfile_fallback.txt" 2>>"$LOG_FILE" || true
  fi

  # Users and last password change times
  if [[ -f "$root/etc/shadow" ]]; then
    /usr/bin/printf 'user,last_change_days,last_change_date_utc\n' >"${tgt_csv}/users_last_change.csv"
    while IFS=: read -r user _ last_change _; do
      [[ -n "$user" ]] || continue
      if [[ -n "$last_change" && "$last_change" != "0" ]]; then
        /usr/bin/printf '%s,%s,%s\n' "$user" "$last_change" "$(/usr/bin/date -u -d \"@$(($last_change*86400))\" +%Y-%m-%d 2>/dev/null || /usr/bin/printf 'unknown')" >>"${tgt_csv}/users_last_change.csv"
      else
        /usr/bin/printf '%s,%s,%s\n' "$user" "$last_change" "unknown" >>"${tgt_csv}/users_last_change.csv"
      fi
    done < "$root/etc/shadow"
  fi

  # Service files and modification times
  /usr/bin/printf 'path,mtime_utc\n' >"${tgt_csv}/service_files.csv"
  for svc_root in "$root/etc/systemd/system" "$root/lib/systemd/system" "$root/usr/lib/systemd/system"; do
    if [[ -d "$svc_root" ]]; then
      /usr/bin/find "$svc_root" -type f -name '*.service' -printf '%p\n' 2>>"$LOG_FILE" | while IFS= read -r f; do
        /usr/bin/printf '%s,%s\n' "$f" "$(/usr/bin/stat -c %y "$f" 2>/dev/null || /usr/bin/printf 'unknown')" >>"${tgt_csv}/service_files.csv"
      done
    fi
  done

  # Login events CSV (best effort)
  if have_cmd last && [[ -f "$root/var/log/wtmp" ]]; then
    /usr/bin/printf 'raw\n' >"${tgt_csv}/login_events.csv"
    /usr/bin/last -f "$root/var/log/wtmp" -w --time-format iso 2>>"$LOG_FILE" | /usr/bin/sed 's/\"/\"\"/g' | /usr/bin/awk '{print \"\\\"\"$0\"\\\"\"}' >>"${tgt_csv}/login_events.csv" || true
  fi

  # Cron jobs CSV (best effort)
  /usr/bin/printf 'source,raw\n' >"${tgt_csv}/cron_jobs.csv"
  for cron_file in "$root/etc/crontab" "$root/etc/cron.d"/* "$root/var/spool/cron"/*; do
    [[ -f "$cron_file" ]] || continue
    /usr/bin/awk -v src="$cron_file" 'NF && $1 !~ /^#/ { gsub(/\"/, \"\"\"\", $0); printf(\"\\\"%s\\\",\\\"%s\\\"\\n\", src, $0); }' "$cron_file" >>"${tgt_csv}/cron_jobs.csv" || true
  done

  # Shell history CSV (best effort)
  /usr/bin/printf 'file,timestamp_utc,command\n' >"${tgt_csv}/shell_history.csv"
  if [[ -s "${tgt_fs}/user_history_files.txt" ]]; then
    while IFS= read -r hist_file; do
      [[ -n "$hist_file" ]] || continue
      /usr/bin/awk -v src="$hist_file" '
        BEGIN { ts=\"\" }
        /^#[0-9]+$/ { ts=$0; sub(/^#/, \"\", ts); next }
        NF {
          gsub(/\"/, \"\"\"\", $0);
          if (ts != \"\") {
            cmd_ts=strftime(\"%Y-%m-%dT%H:%M:%SZ\", ts);
          } else {
            cmd_ts=\"\";
          }
          printf(\"\\\"%s\\\",\\\"%s\\\",\\\"%s\\\"\\n\", src, cmd_ts, $0);
          ts=\"\";
        }
      ' "$hist_file" >>"${tgt_csv}/shell_history.csv" || true
    done < "${tgt_fs}/user_history_files.txt"
  fi
}

collect_all_targets() {
  local targets=()
  if $LIVE_SYSTEM; then
    targets=("/")
  elif ((${#MOUNT_TARGETS[@]} > 0)); then
    targets=("${MOUNT_TARGETS[@]}")
  else
    targets=("$MOUNT_DIR")
  fi

  local idx=0
  for t in "${targets[@]}"; do
    local tag=""
    if [[ "$t" == "/" ]]; then
      tag="root"
    else
      tag="$(/usr/bin/basename "$t")"
    fi
    if [[ -z "$tag" ]]; then
      tag="target${idx}"
    fi
    collect_mounted_filesystem "$t" "$tag"
    idx=$((idx+1))
  done
}

build_report() {
  log "Building report"
  local targets=()
  while IFS= read -r d; do
    targets+=("$(/usr/bin/basename "$d")")
  done < <(/usr/bin/find "$OUT_TARGETS" -mindepth 1 -maxdepth 1 -type d 2>/dev/null || true)

  {
    /usr/bin/printf 'Triage Report\n'
    /usr/bin/printf 'Run timestamp (UTC): %s\n' "$(/usr/bin/date -u +%Y-%m-%dT%H:%M:%SZ)"
    /usr/bin/printf 'Live system: %s\n' "$LIVE_SYSTEM"
    /usr/bin/printf 'Image: %s\n' "${IMAGE_PATH:-<live>}"
    /usr/bin/printf 'Mount: %s\n' "$MOUNT_DIR"
    /usr/bin/printf 'Output: %s\n\n' "$OUTPUT_DIR"

    if ((${#targets[@]} > 0)); then
      /usr/bin/printf 'Targets:\n'
      for t in "${targets[@]}"; do
        /usr/bin/printf '  - %s\n' "$t"
      done
    fi
  } >"$OUT_REPORT"

  if $REPORT_JSON; then
    local json_out="${OUTPUT_DIR}/report.json"
    {
      /usr/bin/printf '{\n'
      /usr/bin/printf '  "run_timestamp_utc": "%s",\n' "$(/usr/bin/date -u +%Y-%m-%dT%H:%M:%SZ)"
      /usr/bin/printf '  "live_system": %s,\n' "$([[ "$LIVE_SYSTEM" == "true" ]] && /usr/bin/printf 'true' || /usr/bin/printf 'false')"
      /usr/bin/printf '  "image": "%s",\n' "$(json_escape "${IMAGE_PATH:-<live>}")"
      /usr/bin/printf '  "mount": "%s",\n' "$(json_escape "$MOUNT_DIR")"
      /usr/bin/printf '  "output": "%s",\n' "$(json_escape "$OUTPUT_DIR")"
      /usr/bin/printf '  "targets": ['
      if ((${#targets[@]} > 0)); then
        /usr/bin/printf '\n'
        local i=0
        for t in "${targets[@]}"; do
          /usr/bin/printf '    "%s"' "$(json_escape "$t")"
          i=$((i+1))
          if ((i < ${#targets[@]})); then
            /usr/bin/printf ',\n'
          else
            /usr/bin/printf '\n'
          fi
        done
        /usr/bin/printf '  ]\n'
      else
        /usr/bin/printf ']\n'
      fi
      /usr/bin/printf '}\n'
    } >"$json_out"
  fi
}

hash_collected() {
  log "Hashing collected artifacts"
  : >"$OUT_HASHES"
  if have_cmd sha256sum; then
    /usr/bin/find "$OUTPUT_DIR" -type f -print0 | /usr/bin/xargs -0 /usr/bin/sha256sum >>"$OUT_HASHES" 2>>"$LOG_FILE" || true
  else
    warn "sha256sum not available; skipping hash manifest"
  fi
}

if $INCLUDE_LIVE; then
  collect_live_volatile
  collect_live_system
fi

collect_all_targets

build_report
hash_collected

OUT_TAR="${OUTPUT_DIR}.tar.gz"
log "Creating evidence archive ${OUT_TAR}"
/usr/bin/tar -C "$OUTPUT_DIR" -czf "$OUT_TAR" . >>"$LOG_FILE" 2>&1 || true
hash_file "$OUT_TAR"

log "Completed ${SCRIPT_NAME}"
