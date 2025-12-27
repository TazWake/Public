#!/usr/bin/env bash
set -euo pipefail

# ##################################### #
#           Rapid log grabber           #
# ##################################### #
#
# This is a bash script designed to allow rapid collection of key event logs
# from multiple Linux systems. It is provided as an example of what can be
# created and may not function correctly in your environment. It is important
# that you test this before use.
#
# Key Areas:
#  - The account used must have superuser access. If you block root from SSH
#    login, this will fail.
# ##################################### #

# --- Configuration & Defaults ---
USER_NAME="root"
OUTPUT_DIR="./collected_logs_$(date +%Y%m%d_%H%M%S)"
HOSTS=()
HOST_FILE=""

# The "Target List" - The script will check for these and only pull if they exist.
# Covers Debian/Ubuntu (syslog/auth.log) and RHEL/CentOS/Fedora (messages/secure)
LOG_FILES=(
  "/var/log/auth.log"         # Debian/Ubuntu Auth
  "/var/log/secure"           # RHEL/CentOS Auth
  "/var/log/syslog"           # Debian/Ubuntu Syslog
  "/var/log/messages"         # RHEL/CentOS Syslog
  "/var/log/audit/audit.log"  # Linux Audit Logs
)

SSH_OPTS=(
  -o BatchMode=yes
  -o ConnectTimeout=8
  -o ServerAliveInterval=5
  -o ServerAliveCountMax=2
  -o StrictHostKeyChecking=accept-new
)

# --- Functions ---

show_help() {
  cat << EOF
Usage: $(basename "$0") [OPTIONS] [HOST1 HOST2 ...]

Tactical IR Log Collector - Pulls auth, syslog, audit, and journalctl data.

Options:
  -h          Show this help message.
  -f FILE     Read hostnames/IPs from a file (one per line).
  -u USER     SSH username (default: $USER_NAME).
  -o DIR      Output directory (default: ./collected_logs_TIMESTAMP).

Example:
  $(basename "$0") -f servers.txt
  $(basename "$0") 10.0.0.1 10.0.0.2
EOF
}

# --- Argument Parsing ---

while getopts "hf:u:o:" opt; do
  case "$opt" in
    h) show_help; exit 0 ;;
    f) HOST_FILE="$OPTARG" ;;
    u) USER_NAME="$OPTARG" ;;
    o) OUTPUT_DIR="$OPTARG" ;;
    *) show_help; exit 1 ;;
  esac
done
shift $((OPTIND-1))

# Collect hosts from file if provided
if [[ -n "$HOST_FILE" ]]; then
  if [[ -f "$HOST_FILE" ]]; then
    while IFS= read -r line; do
      [[ -z "$line" || "$line" =~ ^# ]] && continue
      HOSTS+=("$line")
    done < "$HOST_FILE"
  else
    echo "Error: Host file '$HOST_FILE' not found."
    exit 1
  fi
fi

# Collect hosts from remaining CLI arguments
HOSTS+=("$@")

if [[ ${#HOSTS[@]} -eq 0 ]]; then
  echo "Error: No hosts provided."
  show_help
  exit 1
fi

# --- Execution ---

mkdir -p "$OUTPUT_DIR"

for endpoint in "${HOSTS[@]}"; do
  echo "----------------------------------------------------------"
  echo "Target: $endpoint"
  endpoint_dir="$OUTPUT_DIR/${endpoint}"
  mkdir -p "$endpoint_dir"

  # 1. Capture Journalctl (Last 24h)
  echo "  [+] Extracting journalctl (last 24h)..."
  ssh "${SSH_OPTS[@]}" "${USER_NAME}@${endpoint}" \
    "sudo -n journalctl --since '24 hours ago' -o short-iso" \
    > "${endpoint_dir}/journalctl_last24h.log" 2>/dev/null || echo "      ! Failed to collect journalctl (check sudo permissions)"

  # 2. Iterate through potential log files
  for log_file in "${LOG_FILES[@]}"; do
    # Check if the file exists and is readable before attempting SCP
    if ssh "${SSH_OPTS[@]}" "${USER_NAME}@${endpoint}" "test -r \"${log_file}\""; then
      echo "  [+] Collecting: $log_file"
      scp "${SSH_OPTS[@]}" -p "${USER_NAME}@${endpoint}:${log_file}" "$endpoint_dir/" 2>/dev/null
    else
      # Silent skip for cleaner output on mixed OS environments
      continue
    fi
  done
done

echo "----------------------------------------------------------"
echo "Log collection complete."
echo "Results saved to: $OUTPUT_DIR"
