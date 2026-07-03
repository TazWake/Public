#!/usr/bin/env bash
#
# Forensic process artifact recovery tool.
# - Recovers via /proc/<pid>/exe when possible
# - Detects memfd-backed executables
# - Falls back to maps-based segment extraction
# - Logs actions
# - Supports PID, process name, evidence directory
# - Always produces a CSV manifest of recovered artifacts with SHA-256 hashes
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
  sudo $0 -n nginx -d /evidence/nginx -j
  sudo $0 -n "python.*server" -d /evidence -J

Notes:
  - Requires root privileges.
  - Attempts exe-based recovery first.
  - Detects memfd-backed and deleted-on-disk executables.
  - Falls back to maps-based extraction.
  - Records metadata, SHA-256 hashes, timestamps.
  - A CSV manifest (<prefix>_report.csv) is always produced and lists every
    recovered artifact (exe + segments) with source path, output file,
    size, SHA-256 hash and permissions, for direct import into case notes
    or a hash-verification workflow.
  - JSON/JSONL outputs include process start time (Unix epoch).
EOF
    exit 1
}

log() {
    local msg="$1"
    echo "[$(date +%Y-%m-%dT%H:%M:%S%z)] $msg" | tee -a "$logfile"
}

# Escape a single field for CSV (RFC4180-ish: wrap in quotes, double any quotes).
csv_escape() {
    local field="$1"
    field="${field//\"/\"\"}"
    printf '"%s"' "$field"
}

# Append one row to the CSV manifest. Columns are defined by csv_header below.
csv_row() {
    local out="" first=1
    for field in "$@"; do
        if [[ $first -eq 1 ]]; then
            out="$(csv_escape "$field")"
            first=0
        else
            out="${out},$(csv_escape "$field")"
        fi
    done
    printf '%s\n' "$out" >> "$csv_file"
}

# SHA-256 of a file, empty string if it can't be read/hashed.
sha256_of() {
    local target="$1"
    if [[ -r "$target" ]]; then
        sha256sum "$target" 2>/dev/null | awk '{print $1}'
    else
        echo ""
    fi
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

proc_name=$(cat "/proc/$pid/comm" 2>/dev/null || echo "unknown")
ppid=$(awk '/^PPid:/{print $2}' "/proc/$pid/status" 2>/dev/null || echo "")

# Process start time (Unix epoch)
start_time=$(stat -c %X "/proc/$pid")
log "Process start time (epoch): $start_time"
log "Process name: $proc_name (PPID: ${ppid:-unknown})"

# CSV manifest -- the primary investigator-facing artifact report.
csv_file="${prefix}_report.csv"
csv_row "timestamp_utc" "pid" "process_name" "ppid" "start_time_epoch" \
        "artifact_type" "status" "original_path" "extracted_file" \
        "size_bytes" "sha256" "permissions" "addr_start" "addr_end" \
        "deleted" "memfd" "filetype" "notes"

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

    deleted_flag=0
    [[ "$exe_target" == *" (deleted)" ]] && deleted_flag=1

    exe_perms=$(stat -Lc '%a' "/proc/$pid/exe" 2>/dev/null || echo "")
    stat -Lc 'inode=%i links=%h size=%s mode=%a uid=%u gid=%g mtime=%y ctime=%z' \
        "/proc/$pid/exe" > "${prefix}_exe_stat.txt" || true

    log "Attempting recovery via /proc/$pid/exe..."
    recovered_exe="${prefix}_exe_recovered"
    exe_status="recovered"
    if ! dd if="/proc/$pid/exe" \
       of="$recovered_exe" \
       bs=4M iflag=fullblock conv=fsync status=none; then
        log "ERROR: dd from /proc/$pid/exe failed."
        exe_status="dd_failed"
    fi

    exe_sha256=""
    exe_size=0
    exe_filetype=""
    exe_notes=""

    if [[ -s "$recovered_exe" ]]; then
        log "Recovered binary via exe symlink."
        {
            sha256sum "/proc/$pid/exe" 2>/dev/null || true
            sha256sum "$recovered_exe" 2>/dev/null || true
        } > "${prefix}_exe_hashes.txt"
        exe_sha256=$(sha256_of "$recovered_exe")
        exe_size=$(stat -c %s "$recovered_exe" 2>/dev/null || echo 0)
        file "$recovered_exe" > "${prefix}_exe_filetype.txt" 2>/dev/null || true
        exe_filetype=$(cut -d: -f2- "${prefix}_exe_filetype.txt" 2>/dev/null | sed -e 's/^ *//' -e 's/,.*$//')
        [[ "$memfd_flag" -eq 1 ]] && exe_notes="memfd-backed executable (fileless / in-memory only)"
        [[ "$deleted_flag" -eq 1 ]] && exe_notes="${exe_notes:+$exe_notes; }binary deleted from disk, recovered from open file handle"
        [[ -z "$exe_notes" ]] && exe_notes="recovered via /proc/$pid/exe"
    else
        log "WARNING: Recovered exe file is empty."
        exe_status="empty"
        exe_notes="recovered file was empty; exe handle may be inaccessible or already closed"
    fi

    csv_row "$(date +%Y-%m-%dT%H:%M:%S%z)" "$pid" "$proc_name" "$ppid" "$start_time" \
            "exe" "$exe_status" "$exe_target" "$recovered_exe" \
            "$exe_size" "$exe_sha256" "$exe_perms" "" "" \
            "$deleted_flag" "$memfd_flag" "$exe_filetype" "$exe_notes"

    # JSON update
    json_obj=$(jq \
      --arg exe_target "$exe_target" \
      --arg memfd "$memfd_flag" \
      --arg sha256 "$exe_sha256" \
      --arg size "$exe_size" \
      '.exe = { "target": $exe_target, "memfd": ($memfd|tonumber), "sha256": $sha256, "size": ($size|tonumber) }' \
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

        seg_status="recovered"
        seg_sha256=""
        seg_actual_size=0
        seg_filetype=""
        seg_notes=""

        if ! dd if="/proc/$pid/mem" \
           of="$seg_file" \
           bs=1 skip="$start" count="$size" \
           status=none; then
            log "ERROR: dd failed for segment ${start_hex}-${end_hex}."
            seg_status="dd_failed"
            seg_notes="extraction failed (region may be unmapped or inaccessible at read time)"
        else
            sha256sum "$seg_file" >> "${prefix}_segments_hashes.txt" || true
            seg_sha256=$(sha256_of "$seg_file")
            seg_actual_size=$(stat -c %s "$seg_file" 2>/dev/null || echo 0)
            seg_filetype=$(file -b "$seg_file" 2>/dev/null | sed -e 's/,.*$//')
            [[ -z "$file_path" ]] && seg_notes="anonymous executable mapping (no backing file; possible shellcode/injected code)"
        fi

        csv_row "$(date +%Y-%m-%dT%H:%M:%S%z)" "$pid" "$proc_name" "$ppid" "$start_time" \
                "segment" "$seg_status" "${file_path:-[anon]}" "$seg_file" \
                "$seg_actual_size" "$seg_sha256" "$perms" "$start_hex" "$end_hex" \
                "" "" "$seg_filetype" "$seg_notes"

        # JSONL event
        if [[ $jsonl -eq 1 ]]; then
            jq -n \
              --arg start "$start_hex" \
              --arg end "$end_hex" \
              --arg perms "$perms" \
              --arg file "$file_path" \
              --arg seg "$seg_file" \
              --arg sha256 "$seg_sha256" \
              --arg status "$seg_status" \
              '{type:"segment", start:$start, end:$end, perms:$perms, file:$file, output:$seg, sha256:$sha256, status:$status}' \
              >> "$jsonl_file"
        fi

        # JSON array append
        json_obj=$(jq \
          --arg start "$start_hex" \
          --arg end "$end_hex" \
          --arg perms "$perms" \
          --arg file "$file_path" \
          --arg seg "$seg_file" \
          --arg sha256 "$seg_sha256" \
          --arg status "$seg_status" \
          '.segments += [{start:$start, end:$end, perms:$perms, file:$file, output:$seg, sha256:$sha256, status:$status}]' \
          <<< "$json_obj")

    done < "/proc/$pid/maps"
fi

# Write JSON summary
if [[ $json -eq 1 ]]; then
    jq <<< "$json_obj" > "$json_file"
    log "JSON summary written to $json_file"
fi

artifact_count=$(( $(wc -l < "$csv_file") - 1 ))

log "Forensic recovery completed for PID $pid."
log "CSV manifest written to ${csv_file} (${artifact_count} artifact(s))."
echo "[+] Done. Log: ${logfile}"
echo "    CSV report: ${csv_file}"
echo "    Evidence prefix: ${prefix}_*"
