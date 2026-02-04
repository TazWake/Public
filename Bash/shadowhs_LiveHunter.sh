#!/bin/bash

# ShadowHS LiveHunter - Fileless Linux Malware Detection Script
#
# This script detects traces of the ShadowHS fileless Linux post-exploitation
# framework on a live system. ShadowHS is known for:
#   - Memory-only execution via memfd_create()
#   - Argv spoofing to hide malicious processes
#   - GSocket tunneling for C2 communication
#   - Cryptomining payloads
#   - Kernel module (LKM) persistence
#
# Reference: https://cyble.com/blog/shadowhs-fileless-linux-post-exploitation-framework/
#
# REQUIREMENTS:
#   - Root privileges (required to read /proc data for all processes)
#   - Standard Linux utilities (readlink, awk, grep, netstat/ss)
#
# USE:
#   sudo ./shadowhs_LiveHunter.sh [output_directory]
#
#   If no output directory is specified, results are written to ./shadowhs_hunt_<timestamp>/
#
# EXIT CODES:
#   0 - No findings (system appears clean)
#   1 - Findings detected (potential compromise indicators)
#   2 - Error during execution

set -euo pipefail

# ============================================================================
# CONFIGURATION
# ============================================================================

VERSION="1.0.0"
SCRIPT_NAME="ShadowHS LiveHunter"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Known IOCs
declare -a KNOWN_C2_IPS=(
    "91.92.242.200"
    "62.171.153.47"
    "204.93.253.180"
)

declare -a SUSPICIOUS_PROCESS_NAMES=(
    "-bash-screen"
    "gs-dbus"
    "gs-netcat"
    "gs-sftp"
    "gs-mount"
    "spirit"
    "rustscan"
    "-bash"
)

declare -a SUSPICIOUS_FILE_PATHS=(
    "/tmp/health.sh"
    "/tmp/docker"
    "/tmp/fg"
    "/dev/shm/bootcfg"
    "/tmp/bootcfg"
)

declare -a MINER_PROCESSES=(
    "xmrig"
    "gminer"
    "lolminer"
    "t-rex"
    "nbminer"
    "phoenixminer"
)

declare -a MINING_POOL_DOMAINS=(
    "zergpool.com"
    "2miners.com"
    "nanopool.org"
    "f2pool.com"
    "hashvault.pro"
)

# ============================================================================
# COLOR DEFINITIONS
# ============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# ============================================================================
# GLOBAL VARIABLES
# ============================================================================

OUTPUT_DIR=""
LOGFILE=""
FINDINGS_DIR=""
FINDING_COUNT=0
SCAN_START_TIME=""

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

log_info() {
    local msg="$1"
    echo -e "${BLUE}[ ]${NC} $msg"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] $msg" >> "$LOGFILE"
}

log_success() {
    local msg="$1"
    echo -e "${GREEN}[+]${NC} $msg"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [OK] $msg" >> "$LOGFILE"
}

log_warning() {
    local msg="$1"
    echo -e "${YELLOW}[!]${NC} $msg"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [WARN] $msg" >> "$LOGFILE"
}

log_finding() {
    local msg="$1"
    echo -e "${RED}[*]${NC} ${RED}FINDING:${NC} $msg"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [FINDING] $msg" >> "$LOGFILE"
    ((FINDING_COUNT++)) || true
}

log_error() {
    local msg="$1"
    echo -e "${RED}[!]${NC} ERROR: $msg" >&2
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $msg" >> "$LOGFILE"
}

log_section() {
    local title="$1"
    local border=$(printf '=%.0s' {1..60})
    echo ""
    echo -e "${CYAN}${border}${NC}"
    echo -e "${CYAN}  $title${NC}"
    echo -e "${CYAN}${border}${NC}"
    echo "" >> "$LOGFILE"
    echo "$border" >> "$LOGFILE"
    echo "  $title" >> "$LOGFILE"
    echo "$border" >> "$LOGFILE"
}

hashfile() {
    local file="$1"
    if [[ -f "$file" ]]; then
        local hash
        hash=$(/usr/bin/sha1sum "$file" 2>/dev/null | /usr/bin/awk '{print $1}')
        echo "[#] SHA1: $hash  $file" >> "$LOGFILE"
    fi
}

show_help() {
    cat << EOF
$SCRIPT_NAME v$VERSION
Detect traces of ShadowHS fileless Linux malware on a live system.

USAGE:
    sudo $0 [OPTIONS] [OUTPUT_DIRECTORY]

OPTIONS:
    -h, --help      Show this help message
    -v, --version   Show version information

ARGUMENTS:
    OUTPUT_DIRECTORY    Directory to store scan results (default: ./shadowhs_hunt_<timestamp>/)

EXAMPLES:
    sudo $0                     # Scan with default output directory
    sudo $0 /mnt/usb/case001/   # Scan with custom output directory

EXIT CODES:
    0 - No findings (system appears clean)
    1 - Findings detected (potential compromise indicators)
    2 - Error during execution

REFERENCE:
    https://cyble.com/blog/shadowhs-fileless-linux-post-exploitation-framework/

EOF
}

# ============================================================================
# SETUP FUNCTIONS
# ============================================================================

check_privileges() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[!]${NC} This script must be run with root privileges!"
        echo -e "${RED}[!]${NC} Please run: sudo $0 $*"
        exit 2
    fi
}

setup_output_directory() {
    local base_dir="${1:-./shadowhs_hunt_${TIMESTAMP}}"

    OUTPUT_DIR="$base_dir"
    LOGFILE="${OUTPUT_DIR}/shadowhs_hunt_${TIMESTAMP}.log"
    FINDINGS_DIR="${OUTPUT_DIR}/findings"

    # Create directories
    if ! /bin/mkdir -p "$OUTPUT_DIR" "$FINDINGS_DIR" 2>/dev/null; then
        echo -e "${RED}[!]${NC} Unable to create output directory: $OUTPUT_DIR"
        exit 2
    fi

    # Test write access
    local tempfile="${OUTPUT_DIR}/.write_test_$$"
    if ! /usr/bin/touch "$tempfile" 2>/dev/null; then
        echo -e "${RED}[!]${NC} Unable to write to output directory: $OUTPUT_DIR"
        exit 2
    fi
    /bin/rm -f "$tempfile"

    # Initialize log file
    cat > "$LOGFILE" << EOF
================================================================================
                        $SCRIPT_NAME v$VERSION
                    Scan Report - $(date '+%Y-%m-%d %H:%M:%S')
================================================================================

Scan Started: $(date)
Hostname: $(hostname)
Kernel: $(uname -r)
Output Directory: $OUTPUT_DIR

EOF
}

# ============================================================================
# DETECTION FUNCTIONS
# ============================================================================

check_memfd_execution() {
    log_section "Checking for memfd/deleted binary execution"
    log_info "Scanning /proc/*/exe for memfd: or (deleted) indicators..."

    local findings_file="${FINDINGS_DIR}/memfd_processes.txt"
    local found=0

    echo "# Processes with memfd or deleted executables" > "$findings_file"
    echo "# Generated: $(date)" >> "$findings_file"
    echo "" >> "$findings_file"

    for exe in /proc/[0-9]*/exe; do
        local pid_dir
        pid_dir=$(dirname "$exe")
        local pid
        pid=$(basename "$pid_dir")

        local target
        target=$(/usr/bin/readlink "$exe" 2>/dev/null) || continue

        if [[ "$target" == *"(deleted)"* ]] || [[ "$target" == *"memfd:"* ]]; then
            local cmdline
            cmdline=$(/usr/bin/tr '\0' ' ' < "${pid_dir}/cmdline" 2>/dev/null) || cmdline="<unavailable>"
            local comm
            comm=$(/bin/cat "${pid_dir}/comm" 2>/dev/null) || comm="<unavailable>"

            log_finding "PID $pid: exe='$target' cmdline='$cmdline'"
            echo "PID: $pid" >> "$findings_file"
            echo "  Executable: $target" >> "$findings_file"
            echo "  Command: $comm" >> "$findings_file"
            echo "  Cmdline: $cmdline" >> "$findings_file"
            echo "" >> "$findings_file"
            found=1
        fi
    done

    if [[ $found -eq 0 ]]; then
        log_success "No memfd or deleted binary execution detected"
        echo "No findings." >> "$findings_file"
    fi

    hashfile "$findings_file"
}

check_fd_execution() {
    log_section "Checking for ELF execution from /proc/pid/fd/"
    log_info "Scanning for processes executing from file descriptors..."

    local findings_file="${FINDINGS_DIR}/fd_execution.txt"
    local found=0

    echo "# Processes executing from /proc/pid/fd/" > "$findings_file"
    echo "# Generated: $(date)" >> "$findings_file"
    echo "" >> "$findings_file"

    for exe in /proc/[0-9]*/exe; do
        local pid_dir
        pid_dir=$(dirname "$exe")
        local pid
        pid=$(basename "$pid_dir")

        local target
        target=$(/usr/bin/readlink "$exe" 2>/dev/null) || continue

        # Check if executable path points to /proc/*/fd/*
        if [[ "$target" =~ /proc/[0-9]+/fd/[0-9]+ ]]; then
            local cmdline
            cmdline=$(/usr/bin/tr '\0' ' ' < "${pid_dir}/cmdline" 2>/dev/null) || cmdline="<unavailable>"

            log_finding "PID $pid executing from fd: $target"
            echo "PID: $pid" >> "$findings_file"
            echo "  Executable: $target" >> "$findings_file"
            echo "  Cmdline: $cmdline" >> "$findings_file"
            echo "" >> "$findings_file"
            found=1
        fi
    done

    if [[ $found -eq 0 ]]; then
        log_success "No execution from /proc/pid/fd/ detected"
        echo "No findings." >> "$findings_file"
    fi

    hashfile "$findings_file"
}

check_argv_spoofing() {
    log_section "Checking for argv spoofing"
    log_info "Comparing /proc/pid/exe with /proc/pid/cmdline for mismatches..."

    local findings_file="${FINDINGS_DIR}/argv_spoofing.txt"
    local found=0

    echo "# Processes with potential argv spoofing" > "$findings_file"
    echo "# Generated: $(date)" >> "$findings_file"
    echo "" >> "$findings_file"

    for exe in /proc/[0-9]*/exe; do
        local pid_dir
        pid_dir=$(dirname "$exe")
        local pid
        pid=$(basename "$pid_dir")

        local exe_target
        exe_target=$(/usr/bin/readlink "$exe" 2>/dev/null) || continue

        # Skip if exe is deleted/memfd (handled elsewhere)
        [[ "$exe_target" == *"(deleted)"* ]] && continue
        [[ "$exe_target" == *"memfd:"* ]] && continue

        local cmdline
        cmdline=$(/usr/bin/tr '\0' ' ' < "${pid_dir}/cmdline" 2>/dev/null) || continue
        [[ -z "$cmdline" ]] && continue

        local exe_basename
        exe_basename=$(/usr/bin/basename "$exe_target" 2>/dev/null)

        # Get the first argument from cmdline
        local cmdline_arg0
        cmdline_arg0=$(echo "$cmdline" | /usr/bin/awk '{print $1}')
        local cmdline_basename
        cmdline_basename=$(/usr/bin/basename "$cmdline_arg0" 2>/dev/null)

        # Skip common legitimate patterns
        # Interpreters often show script name
        [[ "$exe_basename" == "python"* ]] && continue
        [[ "$exe_basename" == "perl"* ]] && continue
        [[ "$exe_basename" == "ruby"* ]] && continue
        [[ "$exe_basename" == "node"* ]] && continue
        [[ "$exe_basename" == "java"* ]] && continue
        # Busybox symlinks
        [[ "$exe_basename" == "busybox"* ]] && continue

        # Check for mismatch
        if [[ "$exe_basename" != "$cmdline_basename" ]]; then
            # Additional filter: common shell patterns
            if [[ "$exe_basename" == "bash" ]] && [[ "$cmdline_arg0" == "-bash" ]]; then
                continue  # Login shell
            fi
            if [[ "$exe_basename" == "zsh" ]] && [[ "$cmdline_arg0" == "-zsh" ]]; then
                continue  # Login shell
            fi

            log_finding "PID $pid: exe='$exe_basename' vs cmdline='$cmdline_basename'"
            echo "PID: $pid" >> "$findings_file"
            echo "  Actual Executable: $exe_target" >> "$findings_file"
            echo "  Claimed Command: $cmdline" >> "$findings_file"
            echo "" >> "$findings_file"
            found=1
        fi
    done

    if [[ $found -eq 0 ]]; then
        log_success "No argv spoofing detected"
        echo "No findings." >> "$findings_file"
    fi

    hashfile "$findings_file"
}

check_path_manipulation() {
    log_section "Checking for PATH manipulation (. prefix)"
    log_info "Scanning process environments for PATH=.: patterns..."

    local findings_file="${FINDINGS_DIR}/path_manipulation.txt"
    local found=0

    echo "# Processes with suspicious PATH manipulation" > "$findings_file"
    echo "# Generated: $(date)" >> "$findings_file"
    echo "" >> "$findings_file"

    for environ in /proc/[0-9]*/environ; do
        local pid_dir
        pid_dir=$(dirname "$environ")
        local pid
        pid=$(basename "$pid_dir")

        # Check if PATH starts with .: (current directory first)
        if /usr/bin/tr '\0' '\n' < "$environ" 2>/dev/null | /bin/grep -q '^PATH=\.:'; then
            local path_value
            path_value=$(/usr/bin/tr '\0' '\n' < "$environ" 2>/dev/null | /bin/grep '^PATH=')
            local cmdline
            cmdline=$(/usr/bin/tr '\0' ' ' < "${pid_dir}/cmdline" 2>/dev/null) || cmdline="<unavailable>"

            log_finding "PID $pid has PATH starting with .: (hijack risk)"
            echo "PID: $pid" >> "$findings_file"
            echo "  Cmdline: $cmdline" >> "$findings_file"
            echo "  $path_value" >> "$findings_file"
            echo "" >> "$findings_file"
            found=1
        fi
    done

    if [[ $found -eq 0 ]]; then
        log_success "No PATH manipulation detected"
        echo "No findings." >> "$findings_file"
    fi

    hashfile "$findings_file"
}

check_shells_without_exe() {
    log_section "Checking for shells without backing executables"
    log_info "Looking for interactive shells with deleted/memfd executables..."

    local findings_file="${FINDINGS_DIR}/orphan_shells.txt"
    local found=0

    echo "# Interactive shells without valid backing executables" > "$findings_file"
    echo "# Generated: $(date)" >> "$findings_file"
    echo "" >> "$findings_file"

    for exe in /proc/[0-9]*/exe; do
        local pid_dir
        pid_dir=$(dirname "$exe")
        local pid
        pid=$(basename "$pid_dir")

        local target
        target=$(/usr/bin/readlink "$exe" 2>/dev/null) || continue

        # Check if it's a shell
        local is_shell=0
        [[ "$target" == *"/bash"* ]] && is_shell=1
        [[ "$target" == *"/zsh"* ]] && is_shell=1
        [[ "$target" == *"/sh"* ]] && is_shell=1
        [[ "$target" == *"/dash"* ]] && is_shell=1
        [[ "$target" == *"/fish"* ]] && is_shell=1

        if [[ $is_shell -eq 1 ]]; then
            if [[ "$target" == *"(deleted)"* ]] || [[ "$target" == *"memfd:"* ]]; then
                local cmdline
                cmdline=$(/usr/bin/tr '\0' ' ' < "${pid_dir}/cmdline" 2>/dev/null) || cmdline="<unavailable>"

                log_finding "PID $pid: shell without valid executable: $target"
                echo "PID: $pid" >> "$findings_file"
                echo "  Executable: $target" >> "$findings_file"
                echo "  Cmdline: $cmdline" >> "$findings_file"
                echo "" >> "$findings_file"
                found=1
            fi
        fi
    done

    if [[ $found -eq 0 ]]; then
        log_success "No orphan shells detected"
        echo "No findings." >> "$findings_file"
    fi

    hashfile "$findings_file"
}

check_gdb_memory_dumping() {
    log_section "Checking for GDB memory dumping activity"
    log_info "Looking for gdb --batch --pid patterns..."

    local findings_file="${FINDINGS_DIR}/gdb_activity.txt"
    local found=0

    echo "# Suspicious GDB activity" > "$findings_file"
    echo "# Generated: $(date)" >> "$findings_file"
    echo "" >> "$findings_file"

    for cmdline_file in /proc/[0-9]*/cmdline; do
        local pid_dir
        pid_dir=$(dirname "$cmdline_file")
        local pid
        pid=$(basename "$pid_dir")

        local cmdline
        cmdline=$(/usr/bin/tr '\0' ' ' < "$cmdline_file" 2>/dev/null) || continue

        # Check for gdb with batch mode attaching to processes
        if [[ "$cmdline" == *"gdb"*"--batch"*"--pid"* ]] || \
           [[ "$cmdline" == *"gdb"*"-batch"*"-p"* ]] || \
           [[ "$cmdline" == *"gdb"*"attach"* ]]; then
            log_finding "PID $pid: GDB attached to process: $cmdline"
            echo "PID: $pid" >> "$findings_file"
            echo "  Cmdline: $cmdline" >> "$findings_file"
            echo "" >> "$findings_file"
            found=1
        fi
    done

    if [[ $found -eq 0 ]]; then
        log_success "No suspicious GDB activity detected"
        echo "No findings." >> "$findings_file"
    fi

    hashfile "$findings_file"
}

check_gsocket_tunnels() {
    log_section "Checking for GSocket tunneling tools"
    log_info "Scanning for gs-dbus, gs-netcat, and related processes..."

    local findings_file="${FINDINGS_DIR}/gsocket_tunnels.txt"
    local found=0

    echo "# GSocket tunneling processes" > "$findings_file"
    echo "# Generated: $(date)" >> "$findings_file"
    echo "" >> "$findings_file"

    for cmdline_file in /proc/[0-9]*/cmdline; do
        local pid_dir
        pid_dir=$(dirname "$cmdline_file")
        local pid
        pid=$(basename "$pid_dir")

        local cmdline
        cmdline=$(/usr/bin/tr '\0' ' ' < "$cmdline_file" 2>/dev/null) || continue
        local comm
        comm=$(/bin/cat "${pid_dir}/comm" 2>/dev/null) || comm=""

        # Check for GSocket tools
        for pattern in "gs-dbus" "gs-netcat" "gs-sftp" "gs-mount" "gsocket"; do
            if [[ "$cmdline" == *"$pattern"* ]] || [[ "$comm" == *"$pattern"* ]]; then
                log_finding "PID $pid: GSocket tool detected: $cmdline"
                echo "PID: $pid" >> "$findings_file"
                echo "  Process: $comm" >> "$findings_file"
                echo "  Cmdline: $cmdline" >> "$findings_file"
                echo "" >> "$findings_file"
                found=1
                break
            fi
        done
    done

    if [[ $found -eq 0 ]]; then
        log_success "No GSocket tunneling tools detected"
        echo "No findings." >> "$findings_file"
    fi

    hashfile "$findings_file"
}

check_suspicious_rsync() {
    log_section "Checking for suspicious rsync transport patterns"
    log_info "Looking for rsync -e with gs-* tools..."

    local findings_file="${FINDINGS_DIR}/suspicious_rsync.txt"
    local found=0

    echo "# Suspicious rsync transport configurations" > "$findings_file"
    echo "# Generated: $(date)" >> "$findings_file"
    echo "" >> "$findings_file"

    for cmdline_file in /proc/[0-9]*/cmdline; do
        local pid_dir
        pid_dir=$(dirname "$cmdline_file")
        local pid
        pid=$(basename "$pid_dir")

        local cmdline
        cmdline=$(/usr/bin/tr '\0' ' ' < "$cmdline_file" 2>/dev/null) || continue

        # Check for rsync with GSocket as transport
        if [[ "$cmdline" == *"rsync"*"-e"*"gs-"* ]] || \
           [[ "$cmdline" == *"rsync"*"--rsh"*"gs-"* ]]; then
            log_finding "PID $pid: rsync with GSocket transport: $cmdline"
            echo "PID: $pid" >> "$findings_file"
            echo "  Cmdline: $cmdline" >> "$findings_file"
            echo "" >> "$findings_file"
            found=1
        fi
    done

    if [[ $found -eq 0 ]]; then
        log_success "No suspicious rsync transport patterns detected"
        echo "No findings." >> "$findings_file"
    fi

    hashfile "$findings_file"
}

check_known_iocs() {
    log_section "Checking for known C2 IP addresses"
    log_info "Scanning network connections for known ShadowHS infrastructure..."

    local findings_file="${FINDINGS_DIR}/suspicious_network.txt"
    local found=0

    echo "# Network connections to known IOC addresses" > "$findings_file"
    echo "# Generated: $(date)" >> "$findings_file"
    echo "# Known C2 IPs: ${KNOWN_C2_IPS[*]}" >> "$findings_file"
    echo "" >> "$findings_file"

    # Get network connections
    local netstat_output=""
    if command -v ss &>/dev/null; then
        netstat_output=$(/usr/sbin/ss -tunap 2>/dev/null) || netstat_output=""
    elif command -v netstat &>/dev/null; then
        netstat_output=$(/usr/bin/netstat -tunap 2>/dev/null) || netstat_output=""
    fi

    if [[ -z "$netstat_output" ]]; then
        log_warning "Unable to retrieve network connections (ss/netstat unavailable)"
        echo "Unable to check network connections." >> "$findings_file"
        hashfile "$findings_file"
        return
    fi

    # Check for known C2 IPs
    for ip in "${KNOWN_C2_IPS[@]}"; do
        if echo "$netstat_output" | /bin/grep -q "$ip"; then
            local connections
            connections=$(echo "$netstat_output" | /bin/grep "$ip")
            log_finding "Connection to known C2 IP: $ip"
            echo "C2 IP: $ip" >> "$findings_file"
            echo "$connections" >> "$findings_file"
            echo "" >> "$findings_file"
            found=1
        fi
    done

    # Check for mining pool connections
    for domain in "${MINING_POOL_DOMAINS[@]}"; do
        if echo "$netstat_output" | /bin/grep -qi "$domain"; then
            local connections
            connections=$(echo "$netstat_output" | /bin/grep -i "$domain")
            log_finding "Connection to mining pool: $domain"
            echo "Mining Pool: $domain" >> "$findings_file"
            echo "$connections" >> "$findings_file"
            echo "" >> "$findings_file"
            found=1
        fi
    done

    # Save full network state for analysis
    echo "" >> "$findings_file"
    echo "=== Full Network Connection State ===" >> "$findings_file"
    echo "$netstat_output" >> "$findings_file"

    if [[ $found -eq 0 ]]; then
        log_success "No connections to known C2 infrastructure detected"
    fi

    hashfile "$findings_file"
}

check_kernel_taint() {
    log_section "Checking kernel taint flags"
    log_info "Reading /proc/sys/kernel/tainted..."

    local findings_file="${FINDINGS_DIR}/kernel_taint.txt"
    local found=0

    echo "# Kernel taint flags analysis" > "$findings_file"
    echo "# Generated: $(date)" >> "$findings_file"
    echo "" >> "$findings_file"

    local taint_value
    taint_value=$(/bin/cat /proc/sys/kernel/tainted 2>/dev/null) || taint_value="<unavailable>"

    echo "Taint value: $taint_value" >> "$findings_file"
    echo "" >> "$findings_file"

    if [[ "$taint_value" == "0" ]]; then
        log_success "Kernel is not tainted"
        echo "Kernel is not tainted." >> "$findings_file"
    elif [[ "$taint_value" == "<unavailable>" ]]; then
        log_warning "Unable to read kernel taint status"
    else
        log_finding "Kernel is tainted (value: $taint_value)"
        found=1

        # Decode taint flags
        echo "Taint flag breakdown:" >> "$findings_file"
        local val=$taint_value

        ((val & 1)) && echo "  G - Proprietary module loaded" >> "$findings_file"
        ((val & 2)) && echo "  F - Module force loaded" >> "$findings_file"
        ((val & 4)) && echo "  S - SMP kernel on non-SMP hardware" >> "$findings_file"
        ((val & 8)) && echo "  R - Module force unloaded" >> "$findings_file"
        ((val & 16)) && echo "  M - Machine check exception occurred" >> "$findings_file"
        ((val & 32)) && echo "  B - Bad page referenced" >> "$findings_file"
        ((val & 64)) && echo "  U - User requested taint" >> "$findings_file"
        ((val & 128)) && echo "  D - Kernel died recently (OOPS or BUG)" >> "$findings_file"
        ((val & 256)) && echo "  A - ACPI table overridden" >> "$findings_file"
        ((val & 512)) && echo "  W - Warning issued" >> "$findings_file"
        ((val & 1024)) && echo "  C - Staging driver loaded" >> "$findings_file"
        ((val & 2048)) && echo "  I - Working around firmware bug" >> "$findings_file"
        ((val & 4096)) && echo "  O - Out-of-tree module loaded" >> "$findings_file"
        ((val & 8192)) && echo "  E - Unsigned module loaded" >> "$findings_file"
        ((val & 16384)) && echo "  L - Soft lockup occurred" >> "$findings_file"
        ((val & 32768)) && echo "  K - Live-patched kernel" >> "$findings_file"
        ((val & 65536)) && echo "  X - Auxiliary taint (distro-specific)" >> "$findings_file"
        ((val & 131072)) && echo "  T - Kernel built with struct randomization" >> "$findings_file"
    fi

    hashfile "$findings_file"
}

check_suspicious_lkms() {
    log_section "Checking for suspicious kernel modules"
    log_info "Parsing /proc/modules for unsigned/out-of-tree modules..."

    local findings_file="${FINDINGS_DIR}/kernel_modules.txt"
    local found=0

    echo "# Kernel module analysis" > "$findings_file"
    echo "# Generated: $(date)" >> "$findings_file"
    echo "" >> "$findings_file"

    # Capture full module list
    echo "=== Loaded Kernel Modules ===" >> "$findings_file"
    /bin/cat /proc/modules >> "$findings_file" 2>/dev/null
    echo "" >> "$findings_file"

    # Check for out-of-tree and unsigned modules
    echo "=== Module Analysis ===" >> "$findings_file"

    while read -r line; do
        local module_name
        module_name=$(echo "$line" | /usr/bin/awk '{print $1}')

        # Get module info
        local modinfo_output
        modinfo_output=$(/usr/sbin/modinfo "$module_name" 2>/dev/null) || continue

        # Check for missing signature
        if ! echo "$modinfo_output" | /bin/grep -q "^sig_id:"; then
            log_finding "Unsigned kernel module: $module_name"
            echo "UNSIGNED MODULE: $module_name" >> "$findings_file"
            echo "$modinfo_output" >> "$findings_file"
            echo "" >> "$findings_file"
            found=1
        fi

        # Check for intree status
        local intree
        intree=$(echo "$modinfo_output" | /bin/grep "^intree:" | /usr/bin/awk '{print $2}')
        if [[ "$intree" == "N" ]]; then
            log_finding "Out-of-tree kernel module: $module_name"
            echo "OUT-OF-TREE MODULE: $module_name" >> "$findings_file"
            echo "$modinfo_output" >> "$findings_file"
            echo "" >> "$findings_file"
            found=1
        fi
    done < /proc/modules

    if [[ $found -eq 0 ]]; then
        log_success "No suspicious kernel modules detected"
        echo "No suspicious modules found." >> "$findings_file"
    fi

    hashfile "$findings_file"
}

check_cryptominer_artifacts() {
    log_section "Checking for cryptominer artifacts"
    log_info "Looking for miner processes and configuration files..."

    local findings_file="${FINDINGS_DIR}/cryptominer_artifacts.txt"
    local found=0

    echo "# Cryptominer artifact detection" > "$findings_file"
    echo "# Generated: $(date)" >> "$findings_file"
    echo "" >> "$findings_file"

    # Check for miner processes
    for cmdline_file in /proc/[0-9]*/cmdline; do
        local pid_dir
        pid_dir=$(dirname "$cmdline_file")
        local pid
        pid=$(basename "$pid_dir")

        local cmdline
        cmdline=$(/usr/bin/tr '\0' ' ' < "$cmdline_file" 2>/dev/null) || continue
        local cmdline_lower
        cmdline_lower=$(echo "$cmdline" | /usr/bin/tr '[:upper:]' '[:lower:]')

        local comm
        comm=$(/bin/cat "${pid_dir}/comm" 2>/dev/null) || comm=""
        local comm_lower
        comm_lower=$(echo "$comm" | /usr/bin/tr '[:upper:]' '[:lower:]')

        # Check for known miner processes
        for miner in "${MINER_PROCESSES[@]}"; do
            if [[ "$cmdline_lower" == *"$miner"* ]] || [[ "$comm_lower" == *"$miner"* ]]; then
                log_finding "PID $pid: Cryptominer detected: $miner"
                echo "MINER PROCESS - PID: $pid" >> "$findings_file"
                echo "  Type: $miner" >> "$findings_file"
                echo "  Comm: $comm" >> "$findings_file"
                echo "  Cmdline: $cmdline" >> "$findings_file"
                echo "" >> "$findings_file"
                found=1
                break
            fi
        done

        # Check for -bash-screen (ShadowHS miner wrapper)
        if [[ "$comm" == "-bash-screen" ]] || [[ "$cmdline" == *"-bash-screen"* ]]; then
            log_finding "PID $pid: ShadowHS miner wrapper detected: -bash-screen"
            echo "SHADOWHS MINER WRAPPER - PID: $pid" >> "$findings_file"
            echo "  Cmdline: $cmdline" >> "$findings_file"
            echo "" >> "$findings_file"
            found=1
        fi
    done

    # Check for bootcfg*.data files (miner configs)
    echo "=== Checking for miner config files ===" >> "$findings_file"

    for pattern in "/tmp/bootcfg*.data" "/dev/shm/bootcfg*.data" "/var/tmp/bootcfg*.data"; do
        for file in $pattern; do
            if [[ -f "$file" ]]; then
                log_finding "Miner config file found: $file"
                echo "MINER CONFIG: $file" >> "$findings_file"
                /bin/ls -la "$file" >> "$findings_file" 2>/dev/null
                echo "" >> "$findings_file"
                found=1
            fi
        done
    done

    if [[ $found -eq 0 ]]; then
        log_success "No cryptominer artifacts detected"
        echo "No cryptominer artifacts found." >> "$findings_file"
    fi

    hashfile "$findings_file"
}

check_lateral_movement() {
    log_section "Checking for lateral movement tools"
    log_info "Looking for spirit, rustscan, and other lateral movement indicators..."

    local findings_file="${FINDINGS_DIR}/lateral_movement.txt"
    local found=0

    echo "# Lateral movement tool detection" > "$findings_file"
    echo "# Generated: $(date)" >> "$findings_file"
    echo "" >> "$findings_file"

    for cmdline_file in /proc/[0-9]*/cmdline; do
        local pid_dir
        pid_dir=$(dirname "$cmdline_file")
        local pid
        pid=$(basename "$pid_dir")

        local cmdline
        cmdline=$(/usr/bin/tr '\0' ' ' < "$cmdline_file" 2>/dev/null) || continue
        local comm
        comm=$(/bin/cat "${pid_dir}/comm" 2>/dev/null) || comm=""

        # Check for lateral movement tools
        for tool in "spirit" "rustscan" "-bash"; do
            if [[ "$comm" == "$tool" ]] || [[ "$cmdline" == *"$tool"* ]]; then
                # Skip legitimate -bash (login shells)
                if [[ "$tool" == "-bash" ]]; then
                    local exe
                    exe=$(/usr/bin/readlink "${pid_dir}/exe" 2>/dev/null) || continue
                    # If it's actually bash, skip
                    [[ "$exe" == *"/bash"* ]] && [[ "$exe" != *"(deleted)"* ]] && continue
                fi

                log_finding "PID $pid: Lateral movement tool detected: $tool"
                echo "LATERAL MOVEMENT TOOL - PID: $pid" >> "$findings_file"
                echo "  Tool: $tool" >> "$findings_file"
                echo "  Comm: $comm" >> "$findings_file"
                echo "  Cmdline: $cmdline" >> "$findings_file"
                echo "" >> "$findings_file"
                found=1
                break
            fi
        done
    done

    if [[ $found -eq 0 ]]; then
        log_success "No lateral movement tools detected"
        echo "No lateral movement tools found." >> "$findings_file"
    fi

    hashfile "$findings_file"
}

check_openssl_patterns() {
    log_section "Checking for OpenSSL decryption patterns"
    log_info "Looking for openssl enc aes-cbc -nosalt patterns in cmdlines..."

    local findings_file="${FINDINGS_DIR}/openssl_patterns.txt"
    local found=0

    echo "# Suspicious OpenSSL encryption patterns" > "$findings_file"
    echo "# Generated: $(date)" >> "$findings_file"
    echo "" >> "$findings_file"

    for cmdline_file in /proc/[0-9]*/cmdline; do
        local pid_dir
        pid_dir=$(dirname "$cmdline_file")
        local pid
        pid=$(basename "$pid_dir")

        local cmdline
        cmdline=$(/usr/bin/tr '\0' ' ' < "$cmdline_file" 2>/dev/null) || continue

        # Check for suspicious OpenSSL patterns
        if [[ "$cmdline" == *"openssl"*"enc"*"aes"*"-nosalt"* ]] || \
           [[ "$cmdline" == *"openssl"*"aes-256-cbc"*"-d"* ]] || \
           [[ "$cmdline" == *"openssl"*"-base64"*"-d"* ]]; then
            log_finding "PID $pid: Suspicious OpenSSL decryption: $cmdline"
            echo "PID: $pid" >> "$findings_file"
            echo "  Cmdline: $cmdline" >> "$findings_file"
            echo "" >> "$findings_file"
            found=1
        fi
    done

    if [[ $found -eq 0 ]]; then
        log_success "No suspicious OpenSSL patterns detected"
        echo "No suspicious patterns found." >> "$findings_file"
    fi

    hashfile "$findings_file"
}

check_perl_exec_patterns() {
    log_section "Checking for Perl exec patterns"
    log_info "Looking for perl one-liners with exec{} and fd patterns..."

    local findings_file="${FINDINGS_DIR}/perl_exec_patterns.txt"
    local found=0

    echo "# Suspicious Perl execution patterns" > "$findings_file"
    echo "# Generated: $(date)" >> "$findings_file"
    echo "" >> "$findings_file"

    for cmdline_file in /proc/[0-9]*/cmdline; do
        local pid_dir
        pid_dir=$(dirname "$cmdline_file")
        local pid
        pid=$(basename "$pid_dir")

        local cmdline
        cmdline=$(/usr/bin/tr '\0' ' ' < "$cmdline_file" 2>/dev/null) || continue

        # Check for suspicious Perl patterns
        if [[ "$cmdline" == *"perl"*"-e"*"exec"* ]] || \
           [[ "$cmdline" == *"perl"*"syscall"* ]] || \
           [[ "$cmdline" == *"perl"*"/proc/"*"/fd/"* ]] || \
           [[ "$cmdline" == *"perl"*"memfd_create"* ]]; then
            log_finding "PID $pid: Suspicious Perl execution: $cmdline"
            echo "PID: $pid" >> "$findings_file"
            echo "  Cmdline: $cmdline" >> "$findings_file"
            echo "" >> "$findings_file"
            found=1
        fi
    done

    if [[ $found -eq 0 ]]; then
        log_success "No suspicious Perl exec patterns detected"
        echo "No suspicious patterns found." >> "$findings_file"
    fi

    hashfile "$findings_file"
}

check_suspicious_files() {
    log_section "Checking for suspicious file paths"
    log_info "Looking for known ShadowHS file artifacts..."

    local findings_file="${FINDINGS_DIR}/suspicious_files.txt"
    local found=0

    echo "# Suspicious file detection" > "$findings_file"
    echo "# Generated: $(date)" >> "$findings_file"
    echo "" >> "$findings_file"

    # Check for specific known files
    for pattern in "${SUSPICIOUS_FILE_PATHS[@]}"; do
        for file in $pattern*; do
            if [[ -e "$file" ]]; then
                log_finding "Suspicious file found: $file"
                echo "SUSPICIOUS FILE: $file" >> "$findings_file"
                /bin/ls -la "$file" >> "$findings_file" 2>/dev/null
                /usr/bin/file "$file" >> "$findings_file" 2>/dev/null
                echo "" >> "$findings_file"
                found=1
            fi
        done
    done

    # Check for suspicious files in /dev/shm
    log_info "Scanning /dev/shm for suspicious content..."
    if [[ -d "/dev/shm" ]]; then
        local shm_files
        shm_files=$(/usr/bin/find /dev/shm -type f 2>/dev/null) || shm_files=""

        if [[ -n "$shm_files" ]]; then
            echo "=== Files in /dev/shm ===" >> "$findings_file"
            while IFS= read -r file; do
                if [[ -n "$file" ]]; then
                    log_warning "File in /dev/shm: $file"
                    /bin/ls -la "$file" >> "$findings_file" 2>/dev/null
                    /usr/bin/file "$file" >> "$findings_file" 2>/dev/null
                    echo "" >> "$findings_file"
                fi
            done <<< "$shm_files"
        fi
    fi

    # Check for ELF files in /tmp
    log_info "Scanning /tmp for ELF executables..."
    if [[ -d "/tmp" ]]; then
        local tmp_elfs
        tmp_elfs=$(/usr/bin/find /tmp -maxdepth 2 -type f -executable 2>/dev/null) || tmp_elfs=""

        if [[ -n "$tmp_elfs" ]]; then
            echo "=== Executable files in /tmp ===" >> "$findings_file"
            while IFS= read -r file; do
                if [[ -n "$file" ]]; then
                    local file_type
                    file_type=$(/usr/bin/file "$file" 2>/dev/null)
                    if [[ "$file_type" == *"ELF"* ]]; then
                        log_finding "ELF executable in /tmp: $file"
                        echo "ELF IN TMP: $file" >> "$findings_file"
                        echo "  Type: $file_type" >> "$findings_file"
                        /bin/ls -la "$file" >> "$findings_file" 2>/dev/null
                        echo "" >> "$findings_file"
                        found=1
                    fi
                fi
            done <<< "$tmp_elfs"
        fi
    fi

    if [[ $found -eq 0 ]]; then
        log_success "No suspicious files detected"
        echo "No suspicious files found." >> "$findings_file"
    fi

    hashfile "$findings_file"
}

check_rwx_memory_regions() {
    log_section "Checking for suspicious RWX memory regions"
    log_info "Scanning /proc/*/maps for anonymous RWX regions..."

    local findings_file="${FINDINGS_DIR}/rwx_memory.txt"
    local found=0

    echo "# Suspicious RWX memory regions" > "$findings_file"
    echo "# Generated: $(date)" >> "$findings_file"
    echo "# Note: Some RWX regions are legitimate (JIT compilers, etc.)" >> "$findings_file"
    echo "" >> "$findings_file"

    for maps_file in /proc/[0-9]*/maps; do
        local pid_dir
        pid_dir=$(dirname "$maps_file")
        local pid
        pid=$(basename "$pid_dir")

        # Look for anonymous RWX regions
        local rwx_regions
        rwx_regions=$(/bin/grep -E 'rwxp.*00000000 00:00 0' "$maps_file" 2>/dev/null) || continue

        if [[ -n "$rwx_regions" ]]; then
            local cmdline
            cmdline=$(/usr/bin/tr '\0' ' ' < "${pid_dir}/cmdline" 2>/dev/null) || cmdline="<unavailable>"
            local exe
            exe=$(/usr/bin/readlink "${pid_dir}/exe" 2>/dev/null) || exe="<unavailable>"

            # Skip known legitimate processes
            [[ "$exe" == *"java"* ]] && continue
            [[ "$exe" == *"node"* ]] && continue
            [[ "$exe" == *"python"* ]] && continue
            [[ "$exe" == *"chrome"* ]] && continue
            [[ "$exe" == *"firefox"* ]] && continue

            local region_count
            region_count=$(echo "$rwx_regions" | /usr/bin/wc -l)

            log_warning "PID $pid: $region_count anonymous RWX region(s) - may be suspicious"
            echo "PID: $pid (RWX regions: $region_count)" >> "$findings_file"
            echo "  Executable: $exe" >> "$findings_file"
            echo "  Cmdline: $cmdline" >> "$findings_file"
            echo "  RWX Regions:" >> "$findings_file"
            echo "$rwx_regions" >> "$findings_file"
            echo "" >> "$findings_file"
            found=1
        fi
    done

    if [[ $found -eq 0 ]]; then
        log_success "No suspicious anonymous RWX memory regions detected"
        echo "No suspicious RWX regions found." >> "$findings_file"
    fi

    hashfile "$findings_file"
}

check_suspicious_process_names() {
    log_section "Checking for suspicious process names"
    log_info "Looking for known ShadowHS process naming patterns..."

    local findings_file="${FINDINGS_DIR}/suspicious_process_names.txt"
    local found=0

    echo "# Suspicious process name detection" > "$findings_file"
    echo "# Generated: $(date)" >> "$findings_file"
    echo "" >> "$findings_file"

    for comm_file in /proc/[0-9]*/comm; do
        local pid_dir
        pid_dir=$(dirname "$comm_file")
        local pid
        pid=$(basename "$pid_dir")

        local comm
        comm=$(/bin/cat "$comm_file" 2>/dev/null) || continue

        for suspicious_name in "${SUSPICIOUS_PROCESS_NAMES[@]}"; do
            if [[ "$comm" == "$suspicious_name" ]]; then
                local cmdline
                cmdline=$(/usr/bin/tr '\0' ' ' < "${pid_dir}/cmdline" 2>/dev/null) || cmdline="<unavailable>"
                local exe
                exe=$(/usr/bin/readlink "${pid_dir}/exe" 2>/dev/null) || exe="<unavailable>"

                log_finding "PID $pid: Suspicious process name: $comm"
                echo "PID: $pid" >> "$findings_file"
                echo "  Process Name: $comm" >> "$findings_file"
                echo "  Executable: $exe" >> "$findings_file"
                echo "  Cmdline: $cmdline" >> "$findings_file"
                echo "" >> "$findings_file"
                found=1
                break
            fi
        done
    done

    if [[ $found -eq 0 ]]; then
        log_success "No suspicious process names detected"
        echo "No suspicious process names found." >> "$findings_file"
    fi

    hashfile "$findings_file"
}

# ============================================================================
# SUMMARY AND REPORTING
# ============================================================================

generate_summary() {
    log_section "Generating Summary Report"

    local summary_file="${OUTPUT_DIR}/summary.txt"
    local scan_end_time
    scan_end_time=$(date '+%Y-%m-%d %H:%M:%S')

    cat > "$summary_file" << EOF
================================================================================
                    ShadowHS LiveHunter - Scan Summary
================================================================================

Scan Information:
  Start Time: $SCAN_START_TIME
  End Time:   $scan_end_time
  Hostname:   $(hostname)
  Kernel:     $(uname -r)

Results:
  Total Findings: $FINDING_COUNT

EOF

    if [[ $FINDING_COUNT -eq 0 ]]; then
        cat >> "$summary_file" << EOF
Status: CLEAN
  No indicators of ShadowHS compromise were detected on this system.

  Note: This does not guarantee the system is clean. ShadowHS is designed
  to be fileless and may leave minimal traces. Consider additional
  forensic analysis if compromise is suspected.
EOF
        log_success "Scan complete - No findings (system appears clean)"
    else
        cat >> "$summary_file" << EOF
Status: FINDINGS DETECTED
  $FINDING_COUNT potential indicator(s) of compromise were detected.

  RECOMMENDED ACTIONS:
  1. Review all findings in the ${FINDINGS_DIR}/ directory
  2. Capture memory dump for offline analysis
  3. Preserve network logs and connections
  4. Consider isolating the system from the network
  5. Engage incident response team

  Reference: https://cyble.com/blog/shadowhs-fileless-linux-post-exploitation-framework/
EOF
        log_finding "Scan complete - $FINDING_COUNT finding(s) detected"
    fi

    cat >> "$summary_file" << EOF

================================================================================
Output Files:
EOF
    /bin/ls -la "${FINDINGS_DIR}/" >> "$summary_file" 2>/dev/null

    echo "" >> "$summary_file"
    echo "Log file: $LOGFILE" >> "$summary_file"

    hashfile "$summary_file"

    # Also append summary to main log
    echo "" >> "$LOGFILE"
    echo "=================================================================================" >> "$LOGFILE"
    echo "SCAN SUMMARY" >> "$LOGFILE"
    echo "=================================================================================" >> "$LOGFILE"
    echo "Total Findings: $FINDING_COUNT" >> "$LOGFILE"
    echo "Output Directory: $OUTPUT_DIR" >> "$LOGFILE"
    echo "Scan Completed: $scan_end_time" >> "$LOGFILE"

    # Generate final hash of log file
    echo "" >> "$LOGFILE"
    echo "=== End of Log ===" >> "$LOGFILE"

    # Print summary location
    echo ""
    echo -e "${CYAN}=================================================================================${NC}"
    echo -e "${CYAN}  Scan Complete${NC}"
    echo -e "${CYAN}=================================================================================${NC}"
    echo -e "  Total Findings: ${FINDING_COUNT}"
    echo -e "  Output Directory: ${OUTPUT_DIR}"
    echo -e "  Summary: ${summary_file}"
    echo -e "  Log: ${LOGFILE}"
    echo -e "${CYAN}=================================================================================${NC}"
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

main() {
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                show_help
                exit 0
                ;;
            -v|--version)
                echo "$SCRIPT_NAME v$VERSION"
                exit 0
                ;;
            -*)
                echo -e "${RED}[!]${NC} Unknown option: $1"
                echo "Use -h or --help for usage information."
                exit 2
                ;;
            *)
                OUTPUT_DIR="$1"
                shift
                ;;
        esac
    done

    # Check privileges
    check_privileges "$@"

    # Setup output directory
    setup_output_directory "${OUTPUT_DIR:-}"

    # Record start time
    SCAN_START_TIME=$(date '+%Y-%m-%d %H:%M:%S')

    echo ""
    echo -e "${MAGENTA}=================================================================================${NC}"
    echo -e "${MAGENTA}  $SCRIPT_NAME v$VERSION${NC}"
    echo -e "${MAGENTA}  Detecting ShadowHS Fileless Linux Malware${NC}"
    echo -e "${MAGENTA}=================================================================================${NC}"
    echo ""
    log_info "Scan started at $SCAN_START_TIME"
    log_info "Output directory: $OUTPUT_DIR"
    echo ""

    # Run all detection functions
    # Category A: Highly Detectable
    check_memfd_execution
    check_fd_execution
    check_argv_spoofing
    check_path_manipulation
    check_shells_without_exe
    check_gdb_memory_dumping
    check_suspicious_process_names
    check_kernel_taint
    check_suspicious_lkms
    check_gsocket_tunnels
    check_known_iocs
    check_suspicious_rsync
    check_cryptominer_artifacts
    check_lateral_movement
    check_suspicious_files

    # Category B: Runtime Detection (Best Effort)
    check_openssl_patterns
    check_perl_exec_patterns
    check_rwx_memory_regions

    # Generate summary report
    generate_summary

    # Exit with appropriate code
    if [[ $FINDING_COUNT -gt 0 ]]; then
        exit 1
    else
        exit 0
    fi
}

# Run main function
main "$@"
