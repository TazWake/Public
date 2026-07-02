#!/usr/bin/env bash

set -euo pipefail

usage() {
    echo "Usage: $0 <PID> <destination_directory>"
    echo
    echo "Example:"
    echo "  sudo $0 1234 /evidence"
    exit 1
}

# --- Root check ---
if [[ $EUID -ne 0 ]]; then
    echo "ERROR: This script must be run as root."
    exit 1
fi

# --- Argument validation ---
if [[ $# -ne 2 ]]; then
    usage
fi

pid="$1"
dest="$2"

# --- PID validation ---
if [[ ! -d "/proc/$pid" ]]; then
    echo "ERROR: PID $pid does not exist."
    exit 1
fi

if [[ ! -e "/proc/$pid/exe" ]]; then
    echo "ERROR: /proc/$pid/exe is missing (kernel restrictions or zombie process)."
    exit 1
fi

mkdir -p "$dest"

timestamp="$(date +%Y%m%d_%H%M%S)"
prefix="${dest}/${pid}_${timestamp}"

echo "[*] Recording exe symlink target..."
readlink "/proc/$pid/exe" | tee "${prefix}_exe_link.txt"

echo "[*] Recording inode metadata..."
stat -Lc 'inode=%i links=%h size=%s mode=%a uid=%u gid=%g mtime=%y ctime=%z' \
    "/proc/$pid/exe" | tee "${prefix}_exe_stat.txt"

echo "[*] Recovering binary via /proc/$pid/exe..."
dd if="/proc/$pid/exe" \
   of="${prefix}_exe_recovered" \
   bs=4M iflag=fullblock conv=fsync status=progress

echo "[*] Hashing original and recovered content..."
sha256sum "/proc/$pid/exe" \
          "${prefix}_exe_recovered" \
    | tee "${prefix}_exe_hashes.txt"

echo "[*] Identifying recovered file type..."
file "${prefix}_exe_recovered"

echo "[+] Recovery complete."
echo "    Evidence stored under: ${prefix}_*"
