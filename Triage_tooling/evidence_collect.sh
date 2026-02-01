#!/usr/bin/env bash
set -euo pipefail

# evidence_collect.sh: Mount evidence image and run initial collection commands.

SCRIPT_NAME="$(/usr/bin/basename "$0")"
LOG_DIR="/var/log/triage_tooling"
RUN_TS="$(/usr/bin/date +%Y%m%d_%H%M%S)"
LOG_FILE="${LOG_DIR}/evidence_collect_${RUN_TS}.log"

IMAGE_PATH=""
IMAGE_TYPE="auto"  # auto|e01|raw
MOUNT_DIR="/mnt/case1"
EWF_MOUNT_DIR="/mnt/ewf"
OFFSET_BYTES=""
PARTITION_NUM=""
AUTO_DETECT=true
INCLUDE_LIVE=false
OUTPUT_DIR="/var/tmp/triage_${RUN_TS}"
MOUNT_OPTS="ro,loop,noatime,noexec,noload,norecovery"

LOOP_DEV=""

usage() {
  /usr/bin/cat <<EOF
Usage: ${SCRIPT_NAME} --image <path> [options]

Options:
  --image <path>           Path to E01 or raw image (required)
  --type <auto|e01|raw>    Image type (default: auto)
  --mount-dir <dir>        Mount point for evidence (default: /mnt/case1)
  --ewf-mount <dir>        E01 mount point (default: /mnt/ewf)
  --offset <bytes|sectors> Byte offset (or sectors with 's' suffix) for partition mount
  --partition <num>        Partition number to mount (uses losetup -P)
  --out-dir <dir>          Output directory for triage artifacts
  --include-live           Also collect local live system state
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
  if [[ -n "${LOOP_DEV}" ]]; then
    /bin/umount "${MOUNT_DIR}" >/dev/null 2>&1 || true
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
    --out-dir)
      OUTPUT_DIR="$2"
      shift 2
      ;;
    --include-live)
      INCLUDE_LIVE=true
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

[[ -n "$IMAGE_PATH" ]] || fatal "--image is required."
[[ -f "$IMAGE_PATH" ]] || fatal "Image not found: $IMAGE_PATH"

ensure_dir "$LOG_DIR"
/usr/bin/touch "$LOG_FILE"

log "Starting ${SCRIPT_NAME}"
log "Image: ${IMAGE_PATH}"
log "Type: ${IMAGE_TYPE}"
log "Mount dir: ${MOUNT_DIR}"
log "EWF mount dir: ${EWF_MOUNT_DIR}"
log "Output dir: ${OUTPUT_DIR}"

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

ensure_dir "$OUT_META"
ensure_dir "$OUT_VOL"
ensure_dir "$OUT_SYS"
ensure_dir "$OUT_PERSIST"
ensure_dir "$OUT_LOGS"
ensure_dir "$OUT_FS"
ensure_dir "$OUT_PROC"
ensure_dir "$OUT_CSV"

mount_raw_image() {
  local raw_path="$1"
  local opts="${MOUNT_OPTS}"
  local offset_val="${OFFSET_BYTES}"

  if [[ -n "$offset_val" && "$offset_val" =~ s$ ]]; then
    offset_val="${offset_val%s}"
    if [[ "$offset_val" =~ ^[0-9]+$ ]]; then
      offset_val="$((offset_val * 512))"
    fi
  fi

  if [[ -n "$offset_val" ]]; then
    log "Mounting raw image with offset ${offset_val} bytes"
    if ! /bin/mount -o "${opts},offset=${offset_val}" "$raw_path" "$MOUNT_DIR"; then
      warn "Mount with safe options failed; retrying with ro,loop only"
      /bin/mount -o "ro,loop,offset=${offset_val}" "$raw_path" "$MOUNT_DIR"
    fi
    return
  fi

  if [[ -n "$PARTITION_NUM" ]]; then
    log "Setting up loop device with partitions"
    LOOP_DEV="$(/sbin/losetup -f --show -P "$raw_path")"
    log "Loop device: ${LOOP_DEV}"
    if ! /bin/mount -o "ro,noatime,noexec,noload,norecovery" "${LOOP_DEV}p${PARTITION_NUM}" "$MOUNT_DIR"; then
      warn "Mount with safe options failed; retrying with ro only"
      /bin/mount -o ro "${LOOP_DEV}p${PARTITION_NUM}" "$MOUNT_DIR"
    fi
    return
  fi

  if $AUTO_DETECT; then
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
      if ! /bin/mount -o "ro,noatime,noexec,noload,norecovery" "${LOOP_DEV}p${PARTITION_NUM}" "$MOUNT_DIR"; then
        warn "Mount with safe options failed; retrying with ro only"
        /bin/mount -o ro "${LOOP_DEV}p${PARTITION_NUM}" "$MOUNT_DIR"
      fi
      return
    fi
    /usr/bin/read -r -p "Offset in bytes (or sectors with 's' suffix, e.g., 2048s): " OFFSET_BYTES
    offset_val="${OFFSET_BYTES}"
    if [[ -n "$offset_val" && "$offset_val" =~ s$ ]]; then
      offset_val="${offset_val%s}"
      if [[ "$offset_val" =~ ^[0-9]+$ ]]; then
        offset_val="$((offset_val * 512))"
      fi
    fi
    if [[ -n "$OFFSET_BYTES" ]]; then
      if ! /bin/mount -o "${opts},offset=${offset_val}" "$raw_path" "$MOUNT_DIR"; then
        warn "Mount with safe options failed; retrying with ro,loop only"
        /bin/mount -o "ro,loop,offset=${offset_val}" "$raw_path" "$MOUNT_DIR"
      fi
      return
    fi
  fi

  fatal "Full disk image requires --partition or --offset."
}

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

log "Mounted evidence to ${MOUNT_DIR}"

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
  log "Collecting artifacts from mounted evidence"

  # Users and groups
  if [[ -f "$MOUNT_DIR/etc/passwd" ]]; then
    /bin/cp -a "$MOUNT_DIR/etc/passwd" "${OUT_SYS}/passwd" 2>>"$LOG_FILE" || true
  fi
  if [[ -f "$MOUNT_DIR/etc/shadow" ]]; then
    /bin/cp -a "$MOUNT_DIR/etc/shadow" "${OUT_SYS}/shadow" 2>>"$LOG_FILE" || true
  fi
  if [[ -f "$MOUNT_DIR/etc/group" ]]; then
    /bin/cp -a "$MOUNT_DIR/etc/group" "${OUT_SYS}/group" 2>>"$LOG_FILE" || true
  fi
  if [[ -f "$MOUNT_DIR/etc/os-release" ]]; then
    /bin/cp -a "$MOUNT_DIR/etc/os-release" "${OUT_SYS}/os-release" 2>>"$LOG_FILE" || true
  fi

  # Services and timers
  if [[ -d "$MOUNT_DIR/etc/systemd" ]]; then
    copy_dir_preserve "$MOUNT_DIR/etc/systemd" "${OUT_SYS}/"
  fi
  if [[ -d "$MOUNT_DIR/etc/init.d" ]]; then
    copy_dir_preserve "$MOUNT_DIR/etc/init.d" "${OUT_SYS}/"
  fi

  # Cron
  if [[ -d "$MOUNT_DIR/etc/cron.d" ]]; then
    copy_dir_preserve "$MOUNT_DIR/etc/cron.d" "${OUT_SYS}/"
  fi
  if [[ -d "$MOUNT_DIR/var/spool/cron" ]]; then
    copy_dir_preserve "$MOUNT_DIR/var/spool/cron" "${OUT_SYS}/"
  fi

  # Logs
  if [[ -d "$MOUNT_DIR/var/log" ]]; then
    copy_dir_preserve "$MOUNT_DIR/var/log" "${OUT_LOGS}/"
  fi

  # Key configs
  if [[ -d "$MOUNT_DIR/etc" ]]; then
    ensure_dir "${OUT_PERSIST}/etc"
    for f in ssh/sshd_config ssh/ssh_config sudoers sudoers.d passwd shadow group hosts resolv.conf crontab; do
      if [[ -e "$MOUNT_DIR/etc/$f" ]]; then
        /bin/cp -a "$MOUNT_DIR/etc/$f" "${OUT_PERSIST}/etc/" 2>>"$LOG_FILE" || true
      fi
    done
  fi

  # Shell history from users
  if [[ -d "$MOUNT_DIR/home" ]]; then
    /usr/bin/find "$MOUNT_DIR/home" -maxdepth 2 -type f \( -name ".bash_history" -o -name ".zsh_history" -o -name ".history" -o -name ".bashrc" -o -name ".profile" \) -print >"${OUT_FS}/user_history_files.txt" 2>>"$LOG_FILE" || true
    if [[ -s "${OUT_FS}/user_history_files.txt" ]]; then
      ensure_dir "${OUT_FS}/user_history"
      while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        /bin/cp -a "$f" "${OUT_FS}/user_history/" 2>>"$LOG_FILE" || true
      done < "${OUT_FS}/user_history_files.txt"
    fi
  fi

  # Login records
  for lf in wtmp btmp lastlog; do
    if [[ -f "$MOUNT_DIR/var/log/$lf" ]]; then
      /bin/cp -a "$MOUNT_DIR/var/log/$lf" "${OUT_LOGS}/" 2>>"$LOG_FILE" || true
    fi
  done

  # Bodyfile generation (best effort)
  if have_cmd statx; then
    /usr/bin/find "$MOUNT_DIR" -xdev -type f -print0 | /usr/bin/xargs -0 /usr/bin/statx --format '%n|%s|%b|%X|%Y|%Z' >"${OUT_FS}/bodyfile_statx.txt" 2>>"$LOG_FILE" || true
  elif have_cmd fls; then
    /usr/bin/fls -r -m / "$MOUNT_DIR" >"${OUT_FS}/bodyfile.txt" 2>>"$LOG_FILE" || true
  else
    /usr/bin/find "$MOUNT_DIR" -xdev -type f -printf '%p|%s|%A@|%T@|%C@\n' >"${OUT_FS}/bodyfile_fallback.txt" 2>>"$LOG_FILE" || true
  fi

  # Users and last password change times
  if [[ -f "$MOUNT_DIR/etc/shadow" ]]; then
    /usr/bin/printf 'user,last_change_days,last_change_date_utc\n' >"${OUT_CSV}/users_last_change.csv"
    while IFS=: read -r user _ last_change _; do
      [[ -n "$user" ]] || continue
      if [[ -n "$last_change" && "$last_change" != "0" ]]; then
        /usr/bin/printf '%s,%s,%s\n' "$user" "$last_change" "$(/usr/bin/date -u -d \"@$(($last_change*86400))\" +%Y-%m-%d 2>/dev/null || /usr/bin/printf 'unknown')" >>"${OUT_CSV}/users_last_change.csv"
      else
        /usr/bin/printf '%s,%s,%s\n' "$user" "$last_change" "unknown" >>"${OUT_CSV}/users_last_change.csv"
      fi
    done < "$MOUNT_DIR/etc/shadow"
  fi

  # Service files and modification times
  /usr/bin/printf 'path,mtime_utc\n' >"${OUT_CSV}/service_files.csv"
  for svc_root in "$MOUNT_DIR/etc/systemd/system" "$MOUNT_DIR/lib/systemd/system" "$MOUNT_DIR/usr/lib/systemd/system"; do
    if [[ -d "$svc_root" ]]; then
      /usr/bin/find "$svc_root" -type f -name '*.service' -printf '%p\n' 2>>"$LOG_FILE" | while IFS= read -r f; do
        /usr/bin/printf '%s,%s\n' "$f" "$(/usr/bin/stat -c %y "$f" 2>/dev/null || /usr/bin/printf 'unknown')" >>"${OUT_CSV}/service_files.csv"
      done
    fi
  done

  # Login events CSV (best effort)
  if have_cmd last && [[ -f "$MOUNT_DIR/var/log/wtmp" ]]; then
    /usr/bin/printf 'raw\n' >"${OUT_CSV}/login_events.csv"
    /usr/bin/last -f "$MOUNT_DIR/var/log/wtmp" -w --time-format iso 2>>"$LOG_FILE" | /usr/bin/sed 's/\"/\"\"/g' | /usr/bin/awk '{print \"\\\"\"$0\"\\\"\"}' >>"${OUT_CSV}/login_events.csv" || true
  fi

  # Cron jobs CSV (best effort)
  /usr/bin/printf 'source,raw\n' >"${OUT_CSV}/cron_jobs.csv"
  for cron_file in "$MOUNT_DIR/etc/crontab" "$MOUNT_DIR/etc/cron.d"/* "$MOUNT_DIR/var/spool/cron"/*; do
    [[ -f "$cron_file" ]] || continue
    /usr/bin/awk -v src="$cron_file" 'NF && $1 !~ /^#/ { gsub(/\"/, \"\"\"\", $0); printf(\"\\\"%s\\\",\\\"%s\\\"\\n\", src, $0); }' "$cron_file" >>"${OUT_CSV}/cron_jobs.csv" || true
  done

  # Shell history CSV (best effort)
  /usr/bin/printf 'file,timestamp_utc,command\n' >"${OUT_CSV}/shell_history.csv"
  if [[ -s "${OUT_FS}/user_history_files.txt" ]]; then
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
      ' "$hist_file" >>"${OUT_CSV}/shell_history.csv" || true
    done < "${OUT_FS}/user_history_files.txt"
  fi
}

build_report() {
  log "Building report"
  {
    /usr/bin/printf 'Triage Report\n'
    /usr/bin/printf 'Run timestamp (UTC): %s\n' "$(/usr/bin/date -u +%Y-%m-%dT%H:%M:%SZ)"
    /usr/bin/printf 'Image: %s\n' "$IMAGE_PATH"
    /usr/bin/printf 'Mount: %s\n' "$MOUNT_DIR"
    /usr/bin/printf 'Output: %s\n\n' "$OUTPUT_DIR"

    if [[ -f "${OUT_SYS}/passwd" ]]; then
      /usr/bin/printf 'Users: %s\n' "$(/usr/bin/wc -l < "${OUT_SYS}/passwd" | /usr/bin/tr -d ' ')"
    fi
    if [[ -f "${OUT_LOGS}/wtmp" ]]; then
      /usr/bin/printf 'wtmp present: yes\n'
    fi
    if [[ -f "${OUT_LOGS}/btmp" ]]; then
      /usr/bin/printf 'btmp present: yes\n'
    fi
    if [[ -f "${OUT_LOGS}/lastlog" ]]; then
      /usr/bin/printf 'lastlog present: yes\n'
    fi
    if [[ -d "${OUT_LOGS}/var" || -d "${OUT_LOGS}/log" ]]; then
      /usr/bin/printf 'logs copied: yes\n'
    fi
  } >"$OUT_REPORT"
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

collect_mounted_filesystem

if $INCLUDE_LIVE; then
  collect_live_volatile
  collect_live_system
fi

build_report
hash_collected

OUT_TAR="${OUTPUT_DIR}.tar.gz"
log "Creating evidence archive ${OUT_TAR}"
/usr/bin/tar -C "$OUTPUT_DIR" -czf "$OUT_TAR" . >>"$LOG_FILE" 2>&1 || true
hash_file "$OUT_TAR"

log "Completed ${SCRIPT_NAME}"
