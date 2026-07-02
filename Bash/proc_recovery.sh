#!/usr/bin/env bash
#
# Forensic process artifact recovery tool.
# - Recovers via /proc/<pid>/exe when possible
# - Detects memfd-backed executables
# - Falls back to maps-based segment extraction
# - Logs actions
# - Supports PID, process name, evidence directory
# - Optional JSON and JSONL output modes

set -euo pipefail

usage() {
    cat <<EOF
Forensic Process Recovery Tool
------------------------------

Usage:
  $0 -p <pid> -d <dest> [options]
  $0 -n <name> -d <dest> [options]

Options:
  -p <pid>        Target PID
  -n <name>       Target process name (regex). First match used.
  -d <dir>        Destination evidence directory (required)
  -j              Output JSON summary file
  -J              Output JSONL event log
  -h              Show this help

Examples:
  sudo $0 -p 1234 -d /evidence/proc_1234
  sudo $0 -n nginx -d /evidence/nginx --json
  sudo $0 -n "python.*server" -d /evidence --jsonl

Notes:
  - Requires root privileges.
  - Attempts exe-based recovery first.
  - Detects memfd-backed executables.
  - Falls back to maps-based extraction.
  - Records metadata, hashes, timestamps.
  - JSON/JSONL outputs include process start time (Unix epoch).
EOF
    exit 1
}

log() {
    local msg="$1"
    echo "[$(date +%Y-%m-%dT%H:%M:%S%z)] $msg" | tee -a "$logfile"
}

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: This script must be run as root."
    exit 1
fi

pid=""
name=""
dest=""
json=0
jsonl=0

while getopts ":p:n:d:jJh" opt; do
    case "$opt" in
        p) pid="$OPTARG" ;;
        n) name="$OPTARG" ;;
        d) dest="$OPTARG" ;;
        j) json=1 ;;
        J) jsonl=1 ;;
        h) usage ;;
        *) usage ;;
    esac
done

if [[ -z "$dest" ]]; then
    echo "ERROR: Destination directory (-d) is required."
    usage
fi

mkdir -p "$dest"

timestamp="$(date +%Y%m%d_%H%M%S)"
logfile="${dest}/proc_recover_${timestamp}.log"

# Resolve PID from name if needed
if [[ -z "$pid" ]]; then
    if [[ -z "$name" ]]; then
        echo "ERROR: Either -p <pid> or -n <name> must be provided."
        usage
    fi

    # Use pgrep for reliable name matching
    pid=$(pgrep -f "$name" | head -n 1 || true)

    if [[ -z "$pid" ]]; then
        log "ERROR: No process found matching name '$name'."
        exit 1
    fi

    log "Resolved process name '$name' to PID $pid."
else
    log "Using provided PID $pid."
fi

if [[ ! -d "/proc/$pid" ]]; then
    log "ERROR: PID $pid does not exist."
    exit 1
fi

prefix="${dest}/${pid}_${timestamp}"

log "Starting forensic recovery for PID $pid."
log "Evidence prefix: ${prefix}"

# Collect metadata
cp "/proc/$pid/status" "${prefix}_status.txt"
tr '\0' ' ' < "/proc/$pid/cmdline" > "${prefix}_cmdline.txt" || true

# Process start time (Unix epoch)
start_time=$(stat -c %X "/proc/$pid")
log "Process start time (epoch): $start_time"

# JSON accumulator
json_file="${prefix}_summary.json"
jsonl_file="${prefix}_events.jsonl"

json_obj="{
  \"pid\": \"$pid\",
  \"timestamp\": \"$timestamp\",
  \"start_time_epoch\": \"$start_time\",
  \"evidence_prefix\": \"$prefix\",
  \"exe\": {},
  \"segments\": []
}"

# exe recovery
if [[ -e "/proc/$pid/exe" ]]; then
    exe_target=$(readlink "/proc/$pid/exe" || echo "[unreadable]")
    log "exe symlink target: ${exe_target}"
    echo "$exe_target" > "${prefix}_exe_link.txt"

    memfd_flag=0
    [[ "$exe_target" == memfd:* ]] && memfd_flag=1

    stat -Lc 'inode=%i links=%h size=%s mode=%a uid=%u gid=%g mtime=%y ctime=%z' \
        "/proc/$pid/exe" > "${prefix}_exe_stat.txt" || true

    log "Attempting recovery via /proc/$pid/exe..."
    dd if="/proc/$pid/exe" \
       of="${prefix}_exe_recovered" \
       bs=4M iflag=fullblock conv=fsync status=none || {
        log "ERROR: dd from /proc/$pid/exe failed."
    }

    if [[ -s "${prefix}_exe_recovered" ]]; then
        log "Recovered binary via exe symlink."
        sha256sum "/proc/$pid/exe" "${prefix}_exe_recovered" \
            > "${prefix}_exe_hashes.txt" || true
        file "${prefix}_exe_recovered" > "${prefix}_exe_filetype.txt" || true
    else
        log "WARNING: Recovered exe file is empty."
    fi

    # JSON update
    json_obj=$(jq \
      --arg exe_target "$exe_target" \
      --arg memfd "$memfd_flag" \
      '.exe = { "target": $exe_target, "memfd": ($memfd|tonumber) }' \
      <<< "$json_obj")
else
    log "WARNING: /proc/$pid/exe not present."
fi

# maps extraction
log "Recording /proc/$pid/maps and extracting segments."
cp "/proc/$pid/maps" "${prefix}_maps.txt"

if [[ ! -r "/proc/$pid/mem" ]]; then
    log "ERROR: Cannot read /proc/$pid/mem."
else
    segment_list="${prefix}_segments_layout.txt"
    : > "$segment_list"
    : > "${prefix}_segments_hashes.txt"

    while read -r line; do
        addr_range=$(awk '{print $1}' <<< "$line")
        perms=$(awk '{print $2}' <<< "$line")
        file_path=$(awk '{print $6}' <<< "$line")

        [[ "$perms" != *"x"* ]] && continue

        start_hex="${addr_range%-*}"
        end_hex="${addr_range#*-}"

        start=$((0x$start_hex))
        end=$((0x$end_hex))
        size=$((end - start))

        seg_file="${prefix}_seg_${start_hex}-${end_hex}.bin"

        echo "segment ${start_hex}-${end_hex} perms=${perms} file=${file_path:-[anon]} size=${size}" \
            | tee -a "$segment_list" >> "$logfile"

        dd if="/proc/$pid/mem" \
           of="$seg_file" \
           bs=1 skip="$start" count="$size" \
           status=none || {
            log "ERROR: dd failed for segment ${start_hex}-${end_hex}."
            continue
        }

        sha256sum "$seg_file" >> "${prefix}_segments_hashes.txt" || true

        # JSONL event
        if [[ $jsonl -eq 1 ]]; then
            jq -n \
              --arg start "$start_hex" \
              --arg end "$end_hex" \
              --arg perms "$perms" \
              --arg file "$file_path" \
              --arg seg "$seg_file" \
              '{type:"segment", start:$start, end:$end, perms:$perms, file:$file, output:$seg}' \
              >> "$jsonl_file"
        fi

        # JSON array append
        json_obj=$(jq \
          --arg start "$start_hex" \
          --arg end "$end_hex" \
          --arg perms "$perms" \
          --arg file "$file_path" \
          --arg seg "$seg_file" \
          '.segments += [{start:$start, end:$end, perms:$perms, file:$file, output:$seg}]' \
          <<< "$json_obj"

    done < "/proc/$pid/maps"
fi

# Write JSON summary
if [[ $json -eq 1 ]]; then
    jq <<< "$json_obj" > "$json_file"
    log "JSON summary written to $json_file"
fi

log "Forensic recovery completed for PID $pid."
echo "[+] Done. Log: ${logfile}"
echo "    Evidence prefix: ${prefix}_*"
