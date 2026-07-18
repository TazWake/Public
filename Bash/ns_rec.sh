#!/usr/bin/env bash
#
# ns_rec.sh - Namespace-aware executable recovery and triage for live Linux IR.
#
# Given a live PID, this records the process's namespace context, captures the
# mount table it can see, and recovers the backing executable using the most
# reliable source available:
#
#   1. /proc/<pid>/root/<exe-path>  - pivot into the process's own mount view
#   2. /proc/<pid>/exe              - the open file handle (works even if deleted)
#   3. /proc/<pid>/maps + mem       - carve executable segments when the binary
#                                     only exists in memory (e.g. memfd)
#
# It is deliberately read-only against the target and writes all evidence,
# hashes and metadata to a destination directory of your choosing.
#
# Companion to a LinkedIn article.
# For the wider methodology: https://sans.org/for577
#
# Usage:
#   sudo ./ns_rec.sh <PID> <destination_directory>
# Example:
#   sudo ./ns_rec.sh 2314 /evidence/ns_2314

set -euo pipefail

usage() {
    echo "Usage: $0 <PID> <destination_directory>"
    echo
    echo "Example:"
    echo "  sudo $0 2314 /evidence/ns_2314"
    exit 1
}

# --- Root check -------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
    echo "ERROR: This script must be run as root." >&2
    exit 1
fi

# --- Argument validation ----------------------------------------------------
if [[ $# -ne 2 ]]; then
    usage
fi

pid="$1"
dest="$2"

if ! [[ "$pid" =~ ^[0-9]+$ ]]; then
    echo "ERROR: PID must be numeric." >&2
    exit 1
fi

if [[ ! -d "/proc/$pid" ]]; then
    echo "ERROR: PID $pid does not exist (process may have exited)." >&2
    exit 1
fi

mkdir -p "$dest"
timestamp="$(date +%Y%m%d_%H%M%S)"
prefix="${dest}/${pid}_${timestamp}"

echo "[*] Recording namespace context for PID $pid..."
{
    echo "# Namespace inodes for PID $pid (compare against PID 1 = host)"
    for ns in /proc/"$pid"/ns/*; do
        printf '%-8s %s\n' "$(basename "$ns")" "$(readlink "$ns" 2>/dev/null || echo '[unreadable]')"
    done
    echo
    echo "# Host (PID 1) namespace inodes for reference"
    for ns in /proc/1/ns/*; do
        printf '%-8s %s\n' "$(basename "$ns")" "$(readlink "$ns" 2>/dev/null || echo '[unreadable]')"
    done
} | tee "${prefix}_namespaces.txt"

# Flag whether the mount namespace differs from the host
host_mnt="$(readlink /proc/1/ns/mnt 2>/dev/null || true)"
proc_mnt="$(readlink /proc/"$pid"/ns/mnt 2>/dev/null || true)"
if [[ -n "$proc_mnt" && "$proc_mnt" != "$host_mnt" ]]; then
    echo "[!] PID $pid is in a NON-HOST mount namespace ($proc_mnt) - files may be hidden from the host view."
else
    echo "[*] PID $pid shares the host mount namespace."
fi

echo "[*] Capturing process metadata..."
tr '\0' ' ' < "/proc/$pid/cmdline" > "${prefix}_cmdline.txt" 2>/dev/null || true
cp "/proc/$pid/status" "${prefix}_status.txt" 2>/dev/null || true

echo "[*] Capturing the mount table visible to the process..."
# mountinfo reflects the process's own mount namespace
cp "/proc/$pid/mountinfo" "${prefix}_mountinfo.txt" 2>/dev/null || true

echo "[*] Recording exe link target..."
exe_target="$(readlink "/proc/$pid/exe" 2>/dev/null || echo '[unreadable]')"
echo "$exe_target" | tee "${prefix}_exe_link.txt"

recovered="${prefix}_exe_recovered"
method=""

# --- Recovery strategy ------------------------------------------------------
# Strip a trailing " (deleted)" marker if present, for the root-pivot attempt.
clean_target="${exe_target% (deleted)}"

if [[ "$exe_target" == memfd:* || "$exe_target" == *"/memfd:"* ]]; then
    # Memory-only file: nothing on any filesystem to copy. Carve from memory.
    method="memfd/segment-carve"
elif [[ -n "$clean_target" && "$clean_target" == /* && -e "/proc/$pid/root${clean_target}" ]]; then
    # Best case: the real file is reachable through the process's own root.
    echo "[*] Recovering via /proc/$pid/root${clean_target} ..."
    cp -L --preserve=mode,timestamps "/proc/$pid/root${clean_target}" "$recovered"
    method="proc-root-pivot"
elif [[ -r "/proc/$pid/exe" ]]; then
    # Fall back to the open file handle - works even for deleted binaries.
    echo "[*] Recovering via /proc/$pid/exe (open handle) ..."
    dd if="/proc/$pid/exe" of="$recovered" bs=4M iflag=fullblock conv=fsync status=progress
    method="proc-exe-handle"
else
    method="memfd/segment-carve"
fi

# --- Memory carve fallback --------------------------------------------------
if [[ "$method" == "memfd/segment-carve" ]]; then
    echo "[!] No on-disk backing file - carving executable segments from memory."
    if [[ ! -r "/proc/$pid/mem" ]]; then
        echo "ERROR: Cannot read /proc/$pid/mem (permissions or kernel restrictions)." >&2
        exit 1
    fi
    cp "/proc/$pid/maps" "${prefix}_maps.txt" 2>/dev/null || true
    seg_index="${prefix}_segments_layout.txt"
    : > "$seg_index"
    while read -r line; do
        perms=$(awk '{print $2}' <<< "$line")
        [[ "$perms" == *x* ]] || continue
        range=$(awk '{print $1}' <<< "$line")
        start_hex="${range%-*}"; end_hex="${range#*-}"
        start=$((16#$start_hex)); end=$((16#$end_hex))
        size=$((end - start))
        seg="${prefix}_seg_${start_hex}-${end_hex}.bin"
        echo "segment ${start_hex}-${end_hex} perms=${perms} size=${size}" | tee -a "$seg_index"
        dd if="/proc/$pid/mem" of="$seg" bs=1 skip="$start" count="$size" status=none 2>/dev/null || \
            echo "    [!] could not read segment ${start_hex}-${end_hex}"
    done < "/proc/$pid/maps"
    echo "[*] Hashing carved segments..."
    ( cd "$dest" && sha256sum "${prefix##*/}"_seg_*.bin 2>/dev/null ) > "${prefix}_segment_hashes.txt" || true
    echo "[+] Segment carve complete. Recovery method: $method"
    echo "    Evidence stored under: ${prefix}_*"
    exit 0
fi

# --- Hash and identify a recovered single file ------------------------------
echo "[*] Hashing recovered binary..."
sha256sum "$recovered" | tee "${prefix}_exe_hash.txt"

echo "[*] Identifying recovered file type..."
file "$recovered" || true

echo "[+] Recovery complete. Method: $method"
echo "    Evidence stored under: ${prefix}_*"
