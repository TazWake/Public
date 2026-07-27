#!/usr/bin/env bash
#
# proc-hunter.sh - deleted-binary and masquerade process hunter
# =============================================================
#
# Hunt hypothesis
# ---------------
# Malware running on a host betrays itself through process anomalies. A running
# executable that has been unlinked from disk, a binary living in a
# world-writable temp directory, or a mismatch between what a process calls
# itself and what it actually is are all cheap to look for and expensive for an
# attacker to avoid. This tool reads /proc - the kernel's own view - and reports
# the discrepancies.
#
# It is a modern, dependency-free reimplementation of a very old idea: compare
# what a process claims (comm, argv[0]) against what the kernel records (exe,
# maps, fd) and against the state of the filesystem underneath it. No third-party
# code; the concept only.
#
# What it flags
# -------------
#   PROC-EXE-DELETED     HIGH    exe symlink ends in " (deleted)" - the running
#                                image has been unlinked from disk
#   PROC-EXE-TEMP        HIGH    backing binary lives in /tmp, /dev/shm,
#                                /var/tmp, /run or /var/run
#   PROC-EXE-WORLDWRITE  HIGH    backing binary, or its directory, is
#                                world-writable
#   PROC-EXE-NOBACKING   HIGH    a user process with no resolvable on-disk image
#   PROC-EXE-MISSING     HIGH    exe names a path that does not exist
#   PROC-MAPS-DELETED    HIGH    a deleted file is memory-mapped into the process
#   PROC-MAPS-MEMFD      HIGH    an anonymous memfd is mapped - fileless
#                                execution
#   PROC-NAME-MISMATCH   MEDIUM  comm disagrees with the basename of exe
#   PROC-ARGV-MISMATCH   MEDIUM  comm disagrees with the basename of argv[0]
#   PROC-CWD-TEMP        MEDIUM  working directory is temp or world-writable
#   PROC-EXE-OWNER       MEDIUM  running as root from a binary owned by a
#                                non-root user
#   PROC-FD-DELETED      MEDIUM  an open file descriptor points at a deleted file
#
# Scores are additive per PID: HIGH 5.0, MEDIUM 2.0, LOW 1.0, INFO 0.5.
#
# Inputs it understands
# ---------------------
# A live /proc, a mounted image's proc capture, or a collected /proc snapshot.
# In a snapshot the symlinks (exe, cwd, fd/*) are usually captured as plain text
# files holding the readlink output; this tool reads either form. Use --fs-root
# to tell it where the snapshot's filesystem is mounted so on-disk checks resolve
# against the evidence rather than the analysis host.
#
# Forensic notes
# --------------
#   * Read-only. Nothing under the proc root or the filesystem root is written,
#     renamed or executed. The only writes are to --output.
#   * Reading a backing binary to hash it updates that file's access time on a
#     live, writable mount. Access times are NOT restored, because restoring them
#     rewrites the change time and is itself an alteration of the evidence. Pass
#     --no-hash to avoid opening any target file at all.
#   * proc-hunter sees only what the kernel is willing to show. A kernel-module
#     rootkit can hide a PID from /proc entirely; pair this with a
#     cross-view checker (hidden-hunter) before drawing conclusions.
#   * Without root, other users' processes expose far less. Coverage gaps are
#     counted and reported in the summary rather than silently ignored.
#
# -------------------------------------------------------------------------------------------------- #
# NOTE: Any detections should be treated as investigative leads, not evidence of malicious activity. #
# -------------------------------------------------------------------------------------------------- #
#
# Author: Halkyn Consulting
# Licence: MIT. Original code; contains no third-party code.

set -euo pipefail

PROGRAM="proc-hunter"
VERSION="1.0.0"

# Locate the shared library beside this script.
PH_SELF_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
# shellcheck source=./hunterlib.sh
. "$PH_SELF_DIR/hunterlib.sh"

# --------------------------------------------------------------------------- #
# Defaults
# --------------------------------------------------------------------------- #

PROC_ROOT=""
FS_ROOT=""
declare -a EXCLUDE_PIDS=()
OUT_DIR=""
FORCE=0
CASE_REF=""
EXAMINER=""
SOURCE_ID=""
VERBOSE=0
QUIET=0
DO_HASH=1
MAX_SIZE=$((64 * 1024 * 1024))
MAX_FILES=200000
SHOW_KERNEL_THREADS=0
OWNER_CHECKS_MODE="auto"
OWNER_CHECKS=0
MODE_CHECKS_MODE="auto"
MODE_CHECKS=0

# Directories whose contents any local user can drop a binary into. A process
# running from one of these is not automatically malicious - but on a server it
# is almost never how software is meant to be deployed.
TEMP_PREFIXES="/tmp/ /var/tmp/ /dev/shm/ /run/ /var/run/ /dev/mqueue/"

# Counters
PIDS_SEEN=0
PIDS_SKIPPED=0
KTHREADS=0
COVERAGE_GAPS=0

declare -A PH_SCORE=()
declare -A PH_HITS=()

# --------------------------------------------------------------------------- #
# Help
# --------------------------------------------------------------------------- #

usage() {
    cat <<'EOF'
proc-hunter - deleted-binary and masquerade process hunter (Bash, read-only)

USAGE
    proc-hunter.sh -o DIR [--root /proc | --proc DIR | -p DIR] [options]

HUNT HYPOTHESIS
    Malware on a host betrays itself through process anomalies: a running image
    deleted from disk, a binary in a world-writable temp directory, or a
    mismatch between what a process calls itself (comm, argv[0]) and what the
    kernel says it is (exe). This tool reads /proc and reports the disagreements.

TARGET SELECTION
    -p, --path DIR        Proc directory to examine. Repeatable. Equivalent to
                          --proc; provided for consistency across the suite.
    --proc DIR            Alias for --path, clearer when reading a snapshot.
    --root DIR            Base to find proc under (default /). --root /mnt/img
                          examines /mnt/img/proc.
    --fs-root DIR         Where the examined system's filesystem is mounted.
                          On-disk checks (existence, ownership, permissions,
                          hashing) resolve exe/cwd paths under this prefix.
                          Default: empty, i.e. the paths are taken literally,
                          which is what you want on a live host.
    -x, --exclude PID     Skip this PID. Repeatable. A path ending in the PID
                          is also accepted.

OUTPUT AND CASE METADATA
    -o, --output DIR      Output directory (required). Refused if it sits inside
                          a scan root, or is non-empty without --force.
    --force               Permit writing into an existing non-empty directory.
    --case TEXT           Case or incident reference.
    --examiner TEXT       Examiner or operator name.
    --source-id TEXT      Evidence or host identifier.

BEHAVIOUR
    --no-hash             Do not open or hash backing binaries. Guarantees no
                          target file is read at all - only /proc metadata.
    --owner-checks MODE   auto (default), on, or off. Ownership rules only make
                          sense where the uids on disk are the examined
                          system's. A tree copied or extracted without root
                          carries the copier's uid on every file, which would
                          make PROC-EXE-OWNER fire host-wide. "auto" looks for a
                          root-owned path under --fs-root and disables the rule,
                          loudly, when it cannot find one.
    --mode-checks MODE    auto (default), on, or off. Same idea for permission
                          bits: a share, an exFAT volume or a Windows drive
                          under WSL reports mode 777 for every file, which would
                          make PROC-EXE-WORLDWRITE fire host-wide. "auto"
                          disables the rule when the system directories under
                          --fs-root claim to be world-writable.
    --max-size MIB        Largest binary to hash (default 64).
    --max-files N         Stop after examining N processes (default 200000).
    --kernel-threads      Include kernel threads in the inventory. They are
                          never scored; they are expected and are noise.
    -v, --verbose         Per-process detail on stderr.
    -q, --quiet           Suppress console output. Files are still written.
    -V, --version         Print version and exit.
    -h, --help            This help.

SNAPSHOT SUPPORT
    A collected /proc snapshot normally stores the exe, cwd and fd symlinks as
    plain text files containing the readlink output, because the real link
    targets cannot be preserved by a copy. proc-hunter reads a symlink or a text
    file interchangeably, so the same rules run against live and collected
    evidence. cmdline may be NUL-separated (as the kernel presents it) or
    newline-separated (as most collectors write it).

EVIDENCE PRACTICE
    * The target is read-only. No writes, no renames, no execution, no upload.
    * Point --output at a directory outside the target, ideally on separate
      media. When the scan root is /, containment cannot be checked and the
      log records that fact.
    * Hashing a backing binary reads it and therefore updates its access time on
      a live writable mount. Access times are NOT restored: doing so rewrites
      the change time and is itself tampering. Use --no-hash to avoid this.
    * PIDs come and go. A process that vanishes mid-walk is logged as a skip,
      not treated as an error.

OUTPUTS (in --output)
    proc-hunter.log   Timestamped audit/action log
    findings.tsv      score severity rule_id pid comm exe_path detail evidence sha256
    inventory.tsv     Every process examined, with metadata and score
    summary.txt       Counts, coverage, top-scoring processes, caveat
    SHA256SUMS        SHA-256 manifest of the output artefacts

EXIT STATUS
    0  completed, no findings        2  invalid use / unsafe path
    1  completed, findings recorded  130 interrupted

EXAMPLES
    # Live host, full visibility (run as root)
    sudo ./proc-hunter.sh --root / -o /cases/host01/proc --case IR-2026-041

    # A collected snapshot, with the image mounted read-only elsewhere
    ./proc-hunter.sh --proc /evidence/host01/proc --fs-root /mnt/host01 \
        -o /cases/host01/proc --examiner "A. Analyst"

    # Metadata only - never opens a single target file
    sudo ./proc-hunter.sh -o /cases/host01/proc --no-hash

LIMITS
    Linux-only by nature: it depends on the /proc filesystem. The Windows
    analogue of this hunt is parent/child and image-path anomaly analysis over
    Sysmon Event ID 1, which is a different data source and needs a different tool.

Findings are investigative leads, not proof of compromise.
EOF
}

# --------------------------------------------------------------------------- #
# Argument parsing
# --------------------------------------------------------------------------- #

declare -a PROC_PATHS=()

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            -p|--path|--proc)
                [ $# -ge 2 ] || hl_die "$1 requires a directory"
                PROC_PATHS+=("$2"); shift 2 ;;
            --root)
                [ $# -ge 2 ] || hl_die "--root requires a directory"
                PROC_ROOT="$2"; shift 2 ;;
            --fs-root)
                [ $# -ge 2 ] || hl_die "--fs-root requires a directory"
                FS_ROOT="$2"; shift 2 ;;
            -x|--exclude)
                [ $# -ge 2 ] || hl_die "--exclude requires a PID"
                EXCLUDE_PIDS+=("${2##*/}"); shift 2 ;;
            -o|--output)
                [ $# -ge 2 ] || hl_die "--output requires a directory"
                OUT_DIR="$2"; shift 2 ;;
            --force)   FORCE=1; shift ;;
            --case)
                [ $# -ge 2 ] || hl_die "--case requires text"
                CASE_REF="$2"; shift 2 ;;
            --examiner)
                [ $# -ge 2 ] || hl_die "--examiner requires text"
                EXAMINER="$2"; shift 2 ;;
            --source-id)
                [ $# -ge 2 ] || hl_die "--source-id requires text"
                SOURCE_ID="$2"; shift 2 ;;
            --no-hash) DO_HASH=0; shift ;;
            --owner-checks)
                [ $# -ge 2 ] || hl_die "--owner-checks requires auto, on or off"
                case "$2" in
                    auto|on|off) OWNER_CHECKS_MODE="$2" ;;
                    *) hl_die "--owner-checks must be auto, on or off" ;;
                esac
                shift 2 ;;
            --mode-checks)
                [ $# -ge 2 ] || hl_die "--mode-checks requires auto, on or off"
                case "$2" in
                    auto|on|off) MODE_CHECKS_MODE="$2" ;;
                    *) hl_die "--mode-checks must be auto, on or off" ;;
                esac
                shift 2 ;;
            --kernel-threads) SHOW_KERNEL_THREADS=1; shift ;;
            --max-size)
                [ $# -ge 2 ] || hl_die "--max-size requires a size in MiB"
                case "$2" in ''|*[!0-9]*) hl_die "--max-size must be a whole number of MiB" ;; esac
                MAX_SIZE=$(( $2 * 1024 * 1024 )); shift 2 ;;
            --max-files)
                [ $# -ge 2 ] || hl_die "--max-files requires a count"
                case "$2" in ''|*[!0-9]*) hl_die "--max-files must be a whole number" ;; esac
                MAX_FILES="$2"; shift 2 ;;
            -v|--verbose) VERBOSE=1; shift ;;
            -q|--quiet)   QUIET=1; shift ;;
            -V|--version) printf '%s %s\n' "$PROGRAM" "$VERSION"; exit 0 ;;
            -h|--help)    usage; exit 0 ;;
            --) shift; break ;;
            -*) hl_die "unknown option: $1 (use -h for help)" ;;
            *)  hl_die "unexpected argument: $1 (use -h for help)" ;;
        esac
    done
}

# --------------------------------------------------------------------------- #
# /proc readers
# --------------------------------------------------------------------------- #

# ph_link PATH - resolve a proc symlink, or read a snapshot's text stand-in.
# Prints the target, or nothing if it cannot be resolved.
ph_link() {
    local p="$1" line=""
    if [ -L "$p" ]; then
        readlink -- "$p" 2>/dev/null || printf ''
        return 0
    fi
    if [ -f "$p" ] && [ -r "$p" ]; then
        IFS= read -r line <"$p" 2>/dev/null || true
        printf '%s' "$line"
    fi
}

# ph_first_line PATH
ph_first_line() {
    local line=""
    [ -r "$1" ] || return 0
    IFS= read -r line <"$1" 2>/dev/null || true
    printf '%s' "$line"
}

# ph_cmdline PATH - NUL- or newline-separated argv, printed one arg per line.
ph_cmdline() {
    [ -r "$1" ] || return 0
    tr '\0' '\n' <"$1" 2>/dev/null || printf ''
}

# ph_strip_deleted TARGET - remove the kernel's " (deleted)" suffix.
ph_strip_deleted() {
    local t="$1"
    printf '%s' "${t% (deleted)}"
}

# ph_on_disk PATH - the analysis-host path for a path recorded inside the
# evidence. Empty input yields empty output.
ph_on_disk() {
    [ -n "$1" ] || return 0
    if [ -n "$FS_ROOT" ]; then
        printf '%s%s' "${FS_ROOT%/}" "$1"
    else
        printf '%s' "$1"
    fi
}

# ph_is_temp PATH - true when the path sits under a shared writable directory.
ph_is_temp() {
    local p="$1" pre
    [ -n "$p" ] || return 1
    for pre in $TEMP_PREFIXES; do
        # Match the directory itself as well as everything beneath it: a cwd of
        # "/dev/shm" is the same finding as "/dev/shm/x".
        if [ "$p" = "${pre%/}" ]; then return 0; fi
        case "$p" in "$pre"*) return 0 ;; esac
    done
    return 1
}

# ph_basename_token PATH - basename, cut at the first space or colon, with the
# conventional argv[0] prefix characters removed.
#
# Comparing a raw argv[0] against comm flags half a healthy host, because three
# conventions rewrite it legitimately:
#   * daemons replace it with a status string - "nginx: worker process",
#     "postgres: checkpointer" - so only the leading token is the real name;
#   * login shells prefix it with "-" ("-bash");
#   * systemd and D-Bus prefix it with "@", "+", "!" or "-" as a marker
#     ("@dbus-daemon"), which is not part of the name at all.
ph_basename_token() {
    local b="${1##*/}"
    b="${b%% *}"
    b="${b%%:*}"
    b="${b#[-@+!]}"
    printf '%s' "$b"
}

# ph_names_agree A B - compare two process names the way the kernel forces us
# to: comm is truncated to 15 characters, and interpreters legitimately carry a
# version suffix (exe python3.11 vs comm python3), so a prefix relationship on
# the truncated names counts as agreement.
ph_names_agree() {
    local a="${1:0:15}" b="${2:0:15}"
    [ -n "$a" ] && [ -n "$b" ] || return 0
    [ "$a" = "$b" ] && return 0
    case "$a" in "$b"*) return 0 ;; esac
    case "$b" in "$a"*) return 0 ;; esac
    return 1
}

# ph_metadata_probe - decide whether the ownership and permission bits in the
# tree under examination are the examined system's, by sampling directories
# that are root-owned and not world-writable on every Linux installation.
#
# This matters more than it sounds. An image extracted without root carries the
# extracting user's uid on every file; an image mounted through a translation
# layer (a network share, exFAT, or a Windows drive under WSL) reports uid 1000
# and mode 777 for everything on it. Trusting either would make the ownership
# and world-writable rules fire on every process on the host - thousands of
# findings, all wrong. So the probe runs once, the verdict is logged, and the
# affected rules are switched off rather than left to produce noise.
#
# Sets PROBE_OWNER_OK and PROBE_MODE_OK to 1 or 0.
ph_metadata_probe() {
    local base="${FS_ROOT%/}" p target fields uid mode
    local seen=0 any_ww=0
    PROBE_OWNER_OK=0
    PROBE_MODE_OK=0
    for p in / /usr /usr/bin /usr/sbin /etc /usr/lib; do
        target="$base$p"
        [ -e "$target" ] || continue
        seen=$((seen + 1))
        fields=$(hl_stat_fields "$target")
        mode=$(printf '%s' "$fields" | cut -f1)
        uid=$(printf '%s' "$fields" | cut -f2)
        if [ "$uid" = "0" ]; then
            PROBE_OWNER_OK=1
        fi
        if [ -n "$mode" ] && hl_world_writable "$mode"; then
            any_ww=1
        fi
    done
    # Every one of those directories is 755-or-tighter on a real Linux system.
    # If any is world-writable, the mount is inventing its mode bits.
    if [ "$seen" -gt 0 ] && [ "$any_ww" -eq 0 ]; then
        PROBE_MODE_OK=1
    fi
    return 0
}

# --------------------------------------------------------------------------- #
# Finding helper - records the finding and keeps the per-PID score for the
# inventory, so findings.tsv and inventory.tsv can never disagree.
# --------------------------------------------------------------------------- #

ph_finding() {
    local pid="$1" severity="$2" rule="$3" detail="$4" evidence="$5"
    local weight
    case "$severity" in
        HIGH)   weight=50 ;;
        MEDIUM) weight=20 ;;
        LOW)    weight=10 ;;
        *)      weight=5 ;;
    esac
    PH_SCORE["$pid"]=$(( ${PH_SCORE["$pid"]:-0} + weight ))
    PH_HITS["$pid"]=$(( ${PH_HITS["$pid"]:-0} + 1 ))
    hl_finding "$pid" "$severity" "$rule" \
        "$pid" "$P_COMM" "$P_EXE" "$detail" "$evidence" "$P_SHA256"
    hl_detail "pid $pid $severity $rule: $detail"
}

# --------------------------------------------------------------------------- #
# Per-process examination
# --------------------------------------------------------------------------- #

# Globals set by ph_examine, consumed by ph_finding and the inventory writer.
P_COMM=""; P_EXE=""; P_SHA256=""

ph_examine() {
    local pid="$1" d="$2"
    local exe_raw exe_path exe_deleted cwd_raw cwd_path
    local comm argv0 cmdline_disp cmdline_raw
    local stat_raw stat_rest state ppid flags start_ticks
    local uid euid gid
    local disk_exe fields mode f_uid f_gid f_size f_mtime
    local parent parent_mode
    local is_kthread=0

    P_COMM=""; P_EXE=""; P_SHA256=""

    comm=$(ph_first_line "$d/comm")
    exe_raw=$(ph_link "$d/exe")
    cwd_raw=$(ph_link "$d/cwd")

    cmdline_raw=$(ph_cmdline "$d/cmdline")
    argv0=""
    if [ -n "$cmdline_raw" ]; then
        argv0=${cmdline_raw%%$'\n'*}
    fi
    cmdline_disp=${cmdline_raw//$'\n'/ }
    cmdline_disp=${cmdline_disp% }

    # /proc/PID/stat: comm sits in parentheses and may itself contain spaces or
    # parentheses, so everything up to the LAST ')' is discarded before the
    # numeric fields are read. After that: 1=state 2=ppid 7=flags 20=starttime.
    state=""; ppid=""; flags=""; start_ticks=""
    stat_raw=$(ph_first_line "$d/stat")
    if [ -n "$stat_raw" ] && [ "${stat_raw}" != "${stat_raw#*)}" ]; then
        stat_rest="${stat_raw##*)}"
        # shellcheck disable=SC2086
        set -- $stat_rest
        state="${1:-}"; ppid="${2:-}"; flags="${7:-}"; start_ticks="${20:-}"
    fi

    uid=""; euid=""; gid=""
    if [ -r "$d/status" ]; then
        local uid_line gid_line
        uid_line=$(awk -F'[ \t]+' '$1=="Uid:"{print $2" "$3; exit}' "$d/status" 2>/dev/null) || uid_line=""
        gid_line=$(awk -F'[ \t]+' '$1=="Gid:"{print $2; exit}' "$d/status" 2>/dev/null) || gid_line=""
        uid="${uid_line%% *}"
        euid="${uid_line##* }"
        gid="$gid_line"
    fi

    # Kernel threads have no user-space image and no argv. They are expected,
    # they trip half the heuristics below, and they are never the finding you
    # are looking for - so they are filtered, counted, and (optionally) listed.
    # PF_KTHREAD is 0x00200000 in the stat flags field; the empty-exe and
    # empty-cmdline pair is the fallback when flags are unavailable.
    if [ -n "$flags" ] && [ -z "${flags//[0-9]/}" ]; then
        if [ $(( flags & 2097152 )) -ne 0 ]; then is_kthread=1; fi
    fi
    if [ "$is_kthread" -eq 0 ] && [ -z "$exe_raw" ] && [ -z "$cmdline_raw" ] \
       && [ "$state" != "Z" ]; then
        is_kthread=1
    fi
    case "$comm" in
        \[*\]) is_kthread=1 ;;
    esac

    exe_deleted=0
    case "$exe_raw" in
        *" (deleted)") exe_deleted=1 ;;
    esac
    exe_path=$(ph_strip_deleted "$exe_raw")
    cwd_path=$(ph_strip_deleted "$cwd_raw")

    P_COMM="$comm"
    P_EXE="$exe_raw"

    if [ "$is_kthread" -eq 1 ]; then
        KTHREADS=$((KTHREADS + 1))
        hl_detail "pid $pid is a kernel thread (comm=$comm) - not scored"
        if [ "$SHOW_KERNEL_THREADS" -eq 1 ]; then
            ph_inventory_row "$pid" "$ppid" "$uid" "$gid" "$comm" "$state" \
                "kernel-thread" "" "$start_ticks" ""
        fi
        return 0
    fi

    # A zombie has already released its image: no exe, no argv, by design.
    # Scoring it would produce a guaranteed false positive on every host.
    if [ "$state" = "Z" ]; then
        hl_detail "pid $pid is a zombie (comm=$comm) - not scored"
        ph_inventory_row "$pid" "$ppid" "$uid" "$gid" "$comm" "$state" \
            "zombie" "" "$start_ticks" "$cmdline_disp"
        return 0
    fi

    # --- on-disk state of the backing image ------------------------------- #
    # Only trustworthy when the paths recorded in /proc actually resolve to the
    # examined system: a live host, or a snapshot with --fs-root. Reading a
    # same-named path on the analysis host would attribute the wrong owner,
    # mode and hash to the evidence, so those checks are skipped instead.
    disk_exe=""
    mode=""; f_uid=""; f_gid=""; f_size=""; f_mtime=""
    if [ "$FS_CHECKS_VALID" -eq 1 ]; then
        disk_exe=$(ph_on_disk "$exe_path")
    fi
    if [ -n "$disk_exe" ] && [ -e "$disk_exe" ]; then
        fields=$(hl_stat_fields "$disk_exe")
        IFS=$'\t' read -r mode f_uid f_gid f_size f_mtime <<<"$fields" || true
    fi

    # Hash the backing image for the inventory and for IOC cross-reference.
    if [ "$DO_HASH" -eq 1 ] && [ -n "$disk_exe" ] && [ -f "$disk_exe" ] && [ -r "$disk_exe" ]; then
        if [ -n "$f_size" ] && [ "$f_size" -gt "$MAX_SIZE" ] 2>/dev/null; then
            hl_detail "pid $pid: exe $exe_path exceeds --max-size, not hashed"
        else
            P_SHA256=$(hl_sha256 "$disk_exe")
        fi
    fi

    # --- rules ------------------------------------------------------------- #

    # 1. A running image unlinked from disk. Legitimate during a package
    #    upgrade; classic for a dropper that removes its own payload.
    if [ "$exe_deleted" -eq 1 ]; then
        ph_finding "$pid" HIGH PROC-EXE-DELETED \
            "Running executable has been deleted from disk" "$exe_raw"
    fi

    # 2. Execution from a shared writable directory.
    if ph_is_temp "$exe_path"; then
        ph_finding "$pid" HIGH PROC-EXE-TEMP \
            "Backing binary lives in a shared writable directory" "$exe_path"
    fi

    # 3. World-writable image or image directory: anyone on the box could
    #    have replaced what this process is running. Only meaningful where the
    #    mount preserves permission bits - see MODE_CHECKS below.
    if [ "$MODE_CHECKS" -eq 0 ]; then
        :
    elif [ -n "$mode" ] && hl_world_writable "$mode"; then
        ph_finding "$pid" HIGH PROC-EXE-WORLDWRITE \
            "Backing binary is world-writable (mode $mode)" "$exe_path"
    elif [ -n "$disk_exe" ] && [ -e "$disk_exe" ]; then
        parent=$(dirname -- "$disk_exe")
        parent_mode=$(hl_stat_fields "$parent" | cut -f1)
        if [ -n "$parent_mode" ] && hl_world_writable "$parent_mode"; then
            ph_finding "$pid" HIGH PROC-EXE-WORLDWRITE \
                "Directory holding the backing binary is world-writable (mode $parent_mode)" \
                "$(dirname -- "$exe_path")"
        fi
    fi

    # 4. No on-disk backing at all, or a path that no longer exists.
    #
    #    "Could not read the exe link" and "there is no exe link" are entirely
    #    different statements and only the second is a finding. Every Linux user
    #    process has an exe link - even one whose binary was deleted, which is
    #    what makes rule 1 work - but reading it needs ptrace permission, and
    #    Ubuntu ships yama ptrace_scope=1, which denies it even for processes
    #    owned by the same user. Treating an unreadable link as "no on-disk
    #    image" would flag most of a healthy host.
    if [ -z "$exe_raw" ]; then
        if [ -L "$d/exe" ] || [ -e "$d/exe" ]; then
            COVERAGE_GAPS=$((COVERAGE_GAPS + 1))
            hl_detail "pid $pid: exe link present but unreadable (ptrace restrictions or insufficient privilege) - coverage gap, not a finding"
        else
            ph_finding "$pid" HIGH PROC-EXE-NOBACKING \
                "User process with no on-disk image at all" "comm=$comm cmdline=$cmdline_disp"
        fi
    elif [ "$exe_deleted" -eq 0 ] && [ -n "$disk_exe" ] && [ ! -e "$disk_exe" ]; then
        ph_finding "$pid" HIGH PROC-EXE-MISSING \
            "exe names a path that does not exist on disk" "$exe_path"
    fi

    # 5/6. Masquerade: the kernel's name for the process disagrees with the
    #      image it is running, or with the argv the process advertises.
    local exe_token="" argv_token="" exe_bad=0 argv_bad=0
    # A memfd image has no meaningful name to compare against, and
    # PROC-MAPS-MEMFD already describes that case precisely, so it is excluded
    # here rather than reported twice under a less accurate rule.
    if [ -n "$comm" ] && [ -n "$exe_path" ] && [ "${exe_path#/memfd:}" = "$exe_path" ]; then
        exe_token=$(ph_basename_token "$exe_path")
        ph_names_agree "$comm" "$exe_token" || exe_bad=1
    fi
    # PID 1 is exempt: init is conventionally exec'd from a path whose argv[0]
    # is /sbin/init while comm reports the real implementation (systemd),
    # so this rule would fire on every healthy Linux host.
    if [ -n "$comm" ] && [ -n "$argv0" ] && [ "$pid" != "1" ]; then
        argv_token=$(ph_basename_token "$argv0")
        ph_names_agree "$comm" "$argv_token" || argv_bad=1
    fi
    if [ "$exe_bad" -eq 1 ]; then
        # One underlying fact, one finding: when argv[0] agrees with the
        # executable and only comm differs, that is a single disagreement, and
        # scoring it twice would inflate the process above genuinely worse ones.
        ph_finding "$pid" MEDIUM PROC-NAME-MISMATCH \
            "Process name disagrees with its executable" \
            "comm=$comm exe=$exe_path${argv0:+ argv0=$argv0}"
    elif [ "$argv_bad" -eq 1 ]; then
        ph_finding "$pid" MEDIUM PROC-ARGV-MISMATCH \
            "Process name disagrees with argv[0]" \
            "comm=$comm argv0=$argv0"
    fi

    # 7. Working directory in a shared writable location.
    if ph_is_temp "$cwd_path"; then
        ph_finding "$pid" MEDIUM PROC-CWD-TEMP \
            "Working directory is a shared writable directory" "$cwd_path"
    fi

    # 8. Root running someone else's binary. Only meaningful where the recorded
    #    ownership is the examined system's - see OWNER_CHECKS below.
    if [ "$OWNER_CHECKS" -eq 1 ] && [ "${euid:-}" = "0" ] && [ -n "$f_uid" ] && [ "$f_uid" != "0" ]; then
        ph_finding "$pid" MEDIUM PROC-EXE-OWNER \
            "Process runs as root from a binary owned by uid $f_uid" "$exe_path"
    fi

    # 9. Open descriptors on deleted files - the process is holding evidence
    #    the filesystem no longer shows.
    ph_check_fds "$pid" "$d"

    # 10/11. Deleted or anonymous executable mappings: in-memory execution.
    ph_check_maps "$pid" "$d" "$exe_path"

    ph_inventory_row "$pid" "$ppid" "$uid" "$gid" "$comm" "$state" \
        "$exe_raw" "$cwd_raw" "$start_ticks" "$cmdline_disp"
}

ph_check_fds() {
    local pid="$1" d="$2" fd target n=0 evidence=""
    [ -d "$d/fd" ] || return 0
    for fd in "$d"/fd/*; do
        [ -e "$fd" ] || [ -L "$fd" ] || continue
        target=$(ph_link "$fd")
        case "$target" in
            *" (deleted)")
                n=$((n + 1))
                if [ "$n" -le 3 ]; then
                    evidence="$evidence fd/${fd##*/}=$target"
                fi
                ;;
        esac
    done
    if [ "$n" -gt 0 ]; then
        ph_finding "$pid" MEDIUM PROC-FD-DELETED \
            "$n open file descriptor(s) point at deleted files" "${evidence# }"
    fi
}

ph_check_maps() {
    local pid="$1" d="$2" exe_path="$3"
    local deleted memfd
    [ -r "$d/maps" ] || return 0
    # Field 6 of a maps line is the pathname. The process's own executable is
    # excluded here: when the exe is deleted it also appears in maps, and
    # counting the same fact twice would inflate the score.
    deleted=$(awk -v self="$exe_path" '
        { path = ""; for (i = 6; i <= NF; i++) path = (path == "" ? $i : path " " $i) }
        path ~ / \(deleted\)$/ {
            base = path; sub(/ \(deleted\)$/, "", base);
            if (base != self && base !~ /^\/memfd:/) seen[base] = 1
        }
        END { n = 0; out = ""; for (k in seen) { n++; if (n <= 3) out = out " " k }
              if (n > 0) printf "%d\t%s", n, substr(out, 2) }
    ' "$d/maps" 2>/dev/null) || deleted=""
    if [ -n "$deleted" ]; then
        ph_finding "$pid" HIGH PROC-MAPS-DELETED \
            "Deleted file(s) mapped into memory: ${deleted%%$'\t'*}" \
            "${deleted#*$'\t'}"
    fi

    memfd=$(awk '
        { path = ""; for (i = 6; i <= NF; i++) path = (path == "" ? $i : path " " $i) }
        path ~ /^\/memfd:/ { seen[path] = 1 }
        END { n = 0; out = ""; for (k in seen) { n++; if (n <= 3) out = out " " k }
              if (n > 0) printf "%d\t%s", n, substr(out, 2) }
    ' "$d/maps" 2>/dev/null) || memfd=""
    if [ -n "$memfd" ]; then
        ph_finding "$pid" HIGH PROC-MAPS-MEMFD \
            "Anonymous memfd mapping - possible fileless execution" \
            "${memfd#*$'\t'}"
    fi
}

# --------------------------------------------------------------------------- #
# Inventory
# --------------------------------------------------------------------------- #

INVENTORY_RAW=""

ph_inventory_row() {
    local pid="$1" ppid="$2" uid="$3" gid="$4" comm="$5" state="$6"
    local exe="$7" cwd="$8" ticks="$9" cmdline="${10}"
    local start_utc=""
    if [ -n "$ticks" ] && [ -n "$BOOT_EPOCH" ] && [ -z "${ticks//[0-9]/}" ]; then
        start_utc=$(hl_iso $(( BOOT_EPOCH + ticks / CLK_TCK )))
    fi
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$pid" "$ppid" "$uid" "$gid" "$(hl_scrub "$comm" 64)" "$state" \
        "$(hl_scrub "$exe" 512)" "$(hl_scrub "$cwd" 512)" \
        "$start_utc" "$ticks" "$(hl_scrub "$cmdline" 512)" \
        "$P_SHA256" >>"$INVENTORY_RAW"
}

# The per-PID scores are joined in with awk rather than a shell read loop:
# with IFS set to tab, `read` collapses runs of tabs (tab is IFS whitespace),
# which silently shifts every column after the first empty field.
ph_write_inventory() {
    local out="$1" scores sorted pid
    scores="${INVENTORY_RAW}.scores"
    sorted="${INVENTORY_RAW}.sorted"
    : >"$scores"
    if [ "${#PH_SCORE[@]}" -gt 0 ]; then
        for pid in "${!PH_SCORE[@]}"; do
            printf '%s\t%s\t%s\n' "$pid" "${PH_HITS[$pid]:-0}" \
                "$(ph_score_string "${PH_SCORE[$pid]}")" >>"$scores"
        done
    fi
    LC_ALL=C sort -t'	' -k1,1n "$INVENTORY_RAW" >"$sorted" 2>/dev/null || : >"$sorted"
    {
        printf 'pid\tppid\tuid\tgid\tcomm\tstate\texe\tcwd\tstart_utc\tstart_ticks\tcmdline\tsha256\tfinding_count\tscore\n'
        awk -F'\t' -v OFS='\t' '
            NR == FNR { hits[$1] = $2; score[$1] = $3; next }
            { print $0, ($1 in hits ? hits[$1] : 0), ($1 in score ? score[$1] : "0.0") }
        ' "$scores" "$sorted"
    } >"$out"
    rm -f -- "$scores" "$sorted"
}

# Scores are held as integers (tenths x10) to keep the arithmetic in Bash;
# they are printed in the same one-decimal form the rest of the suite uses.
ph_score_string() {
    printf '%d.%d' $(( $1 / 10 )) $(( $1 % 10 ))
}

# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #

main() {
    local raw_args="" outdir procdir
    raw_args=$(hl_command_line "$0" "$@")
    parse_args "$@"

    [ -n "$OUT_DIR" ] || hl_die "--output is required (use -h for help)"

    hl_date_init
    hl_stat_init
    hl_hash_init || hl_die "no SHA-256 implementation found (need sha256sum, shasum or openssl). Evidence hashing is not optional."

    # Resolve the proc directory: explicit --path/--proc wins, else --root/proc.
    declare -a roots=()
    if [ "${#PROC_PATHS[@]}" -gt 0 ]; then
        for procdir in "${PROC_PATHS[@]}"; do
            [ -d "$procdir" ] || hl_die "proc path is not a directory: $procdir"
            roots+=("$(hl_abspath "$procdir")")
        done
    else
        local base="${PROC_ROOT:-/}"
        [ -d "$base" ] || hl_die "--root is not a directory: $base"
        # Strip the trailing slash before joining: "/" + "/proc" would give
        # "//proc", which POSIX leaves implementation-defined and which bash
        # preserves through pwd -P, breaking the live-/proc comparison below.
        base="${base%/}"
        if [ -d "$base/proc" ]; then
            roots+=("$(hl_abspath "$base/proc")")
        elif [ -e "$base/1/stat" ]; then
            roots+=("$(hl_abspath "$base")")
        else
            hl_die "no proc directory found under $base. Pass --proc explicitly. This tool needs /proc; it is Linux-only."
        fi
    fi

    if [ -n "$FS_ROOT" ]; then
        [ -d "$FS_ROOT" ] || hl_die "--fs-root is not a directory: $FS_ROOT"
        FS_ROOT=$(hl_abspath "$FS_ROOT")
    fi

    # On-disk checks are only meaningful when the paths recorded in /proc
    # resolve to the examined system: a live /proc, or a snapshot plus
    # --fs-root. Anything else and we would be describing the analysis host.
    FS_CHECKS_VALID=0
    if [ -n "$FS_ROOT" ]; then
        FS_CHECKS_VALID=1
    else
        for procdir in "${roots[@]}"; do
            if [ "$procdir" = "/proc" ]; then FS_CHECKS_VALID=1; fi
        done
    fi

    outdir=$(hl_resolve_output "$OUT_DIR" "$FORCE" "${roots[@]}" ${FS_ROOT:+"$FS_ROOT"})
    hl_log_open "$outdir/$PROGRAM.log" "$([ "$QUIET" -eq 1 ] && echo 0 || echo 1)" "$VERBOSE"
    hl_install_signals

    hl_ctx_set tool "$PROGRAM $VERSION"
    hl_ctx_set hunterlib "$HUNTERLIB_VERSION"
    hl_ctx_set started_utc "$(hl_utc_now)"
    hl_ctx_set host "$(uname -n 2>/dev/null || echo unknown)"
    hl_ctx_set platform "$(uname -srm 2>/dev/null || echo unknown)"
    hl_ctx_set shell "bash ${BASH_VERSION:-unknown}"
    hl_ctx_set operator_user "$(id -un 2>/dev/null || echo "${USER:-unknown}")"
    hl_ctx_set privileged "$([ "$(id -u 2>/dev/null || echo 1)" = "0" ] && echo yes || echo no)"
    hl_ctx_set case "$CASE_REF"
    hl_ctx_set examiner "$EXAMINER"
    hl_ctx_set source_id "$SOURCE_ID"
    hl_ctx_set proc_roots "$(printf '%s ; ' "${roots[@]}" | sed 's/ ; $//')"
    hl_ctx_set fs_root "${FS_ROOT:-(literal paths)}"
    hl_ctx_set output_dir "$outdir"
    hl_ctx_set command "$raw_args"
    hl_log_header

    [ -n "$HL_OUTPUT_NOTE" ] && hl_warning "$HL_OUTPUT_NOTE" || true
    if [ "$(id -u 2>/dev/null || echo 1)" != "0" ]; then
        hl_warning "running unprivileged: other users' processes will expose less. Coverage gaps are counted in the summary."
    fi
    if [ "$FS_CHECKS_VALID" -eq 0 ]; then
        hl_warning "reading a proc snapshot without --fs-root: on-disk checks (existence, ownership, permissions, hashing) are disabled so the analysis host is not mistaken for the evidence"
    fi

    # Ownership rules are only worth running where the recorded uids are the
    # examined system's. A tree copied or extracted without root carries the
    # copier's uid on every file, which would make PROC-EXE-OWNER fire on the
    # whole host. "auto" therefore looks for evidence that root ownership
    # survived, and says so either way rather than reporting quietly wrong
    # findings.
    PROBE_OWNER_OK=0; PROBE_MODE_OK=0
    if [ "$FS_CHECKS_VALID" -eq 1 ]; then
        ph_metadata_probe
    fi
    case "$OWNER_CHECKS_MODE" in
        on)  OWNER_CHECKS=1
             hl_info "ownership rules forced on (--owner-checks on)" ;;
        off) OWNER_CHECKS=0
             hl_info "ownership rules disabled (--owner-checks off)" ;;
        *)   if [ "$PROBE_OWNER_OK" -eq 1 ]; then
                 OWNER_CHECKS=1
             elif [ "$FS_CHECKS_VALID" -eq 0 ]; then
                 OWNER_CHECKS=0
                 hl_info "ownership rules disabled along with the other on-disk checks"
             else
                 OWNER_CHECKS=0
                 hl_warning "ownership rules disabled: no root-owned system directory found under ${FS_ROOT:-/}, so the uids in this tree are probably not the examined system's. Override with --owner-checks on."
             fi ;;
    esac
    case "$MODE_CHECKS_MODE" in
        on)  MODE_CHECKS=1
             hl_info "permission rules forced on (--mode-checks on)" ;;
        off) MODE_CHECKS=0
             hl_info "permission rules disabled (--mode-checks off)" ;;
        *)   if [ "$PROBE_MODE_OK" -eq 1 ]; then
                 MODE_CHECKS=1
             elif [ "$FS_CHECKS_VALID" -eq 0 ]; then
                 MODE_CHECKS=0
                 hl_info "permission rules disabled along with the other on-disk checks"
             else
                 MODE_CHECKS=0
                 hl_warning "permission rules disabled: system directories under ${FS_ROOT:-/} report world-writable modes, so this mount is not preserving permission bits. Override with --mode-checks on."
             fi ;;
    esac
    if [ "$DO_HASH" -eq 0 ]; then
        hl_info "--no-hash: no target file will be opened; only /proc metadata is read"
    fi

    INVENTORY_RAW="$outdir/.inventory.raw"
    : >"$INVENTORY_RAW"
    hl_findings_init "$outdir/.findings.raw" \
        "score	severity	rule_id	pid	comm	exe_path	detail	evidence	sha256"

    # Boot time and clock tick, for turning starttime into a wall-clock time.
    BOOT_EPOCH=""
    CLK_TCK=100
    if hl_have getconf; then
        CLK_TCK=$(getconf CLK_TCK 2>/dev/null || echo 100)
        case "$CLK_TCK" in ''|*[!0-9]*) CLK_TCK=100 ;; esac
    fi

    hl_section "process walk"
    local root pid d
    for root in "${roots[@]}"; do
        hl_info "proc root: $root"
        BOOT_EPOCH=""
        if [ -r "$root/stat" ]; then
            BOOT_EPOCH=$(awk '$1=="btime"{print $2; exit}' "$root/stat" 2>/dev/null) || BOOT_EPOCH=""
            case "$BOOT_EPOCH" in ''|*[!0-9]*) BOOT_EPOCH="" ;; esac
        fi
        [ -n "$BOOT_EPOCH" ] || hl_info "boot time unavailable under $root - start times reported as raw ticks only"

        while IFS= read -r pid; do
            if hl_interrupted; then
                hl_warning "interrupt received - finalising partial output"
                break
            fi
            if [ "$PIDS_SEEN" -ge "$MAX_FILES" ]; then
                hl_warning "--max-files ($MAX_FILES) reached - stopping the walk"
                break
            fi
            d="$root/$pid"
            local skip=0 ex
            for ex in ${EXCLUDE_PIDS[@]+"${EXCLUDE_PIDS[@]}"}; do
                if [ "$ex" = "$pid" ]; then skip=1; break; fi
            done
            if [ "$skip" -eq 1 ]; then
                PIDS_SKIPPED=$((PIDS_SKIPPED + 1))
                hl_detail "pid $pid excluded by --exclude"
                continue
            fi
            if [ ! -d "$d" ]; then
                PIDS_SKIPPED=$((PIDS_SKIPPED + 1))
                hl_detail "pid $pid vanished before it could be read"
                continue
            fi
            PIDS_SEEN=$((PIDS_SEEN + 1))
            if ! ph_examine "$pid" "$d"; then
                hl_error "pid $pid: examination failed (process may have exited)"
            fi
        done < <(ls -1 -- "$root" 2>/dev/null | grep -E '^[0-9]+$' | LC_ALL=C sort -n || true)
    done

    hl_section "writing reports"
    hl_findings_write "$outdir/findings.tsv"
    ph_write_inventory "$outdir/inventory.tsv"
    rm -f -- "$INVENTORY_RAW" "$outdir/.findings.raw"

    hl_ctx_set completed_utc "$(hl_utc_now)"
    hl_ctx_set completion "$(hl_interrupted && echo interrupted || echo complete)"
    ph_write_summary "$outdir/summary.txt" "$outdir"

    for f in findings.tsv inventory.tsv summary.txt; do
        hl_info "wrote $outdir/$f"
    done

    hl_section "run end"
    hl_info "processes_examined=$PIDS_SEEN kernel_threads=$KTHREADS flagged=$HL_FLAGGED_COUNT findings=$HL_FINDING_COUNT errors=$HL_ERROR_COUNT"
    # The manifest is genuinely the last write of the run, so it can cover this
    # log file too. Nothing may be appended to the log after this point, or
    # SHA256SUMS would no longer verify.
    hl_info "writing SHA256SUMS last; it covers this log, so this is the final log line"
    hl_log_close
    hl_write_manifest "$outdir" >/dev/null

    if [ "$QUIET" -ne 1 ]; then
        printf '\n%s complete. %d process(es) examined, %d flagged, %d finding(s).\n' \
            "$PROGRAM" "$PIDS_SEEN" "$HL_FLAGGED_COUNT" "$HL_FINDING_COUNT"
        printf 'Reports in: %s\n' "$outdir"
    fi

    if hl_interrupted; then
        return "$HL_EXIT_INTERRUPT"
    fi
    [ "$HL_FINDING_COUNT" -gt 0 ] && return "$HL_EXIT_FINDINGS"
    return "$HL_EXIT_OK"
}

ph_write_summary() {
    local file="$1" outdir="$2"
    hl_summary_open "$file" "$PROGRAM" "$VERSION"
    hl_summary_kv "$file" "processes examined" "$PIDS_SEEN"
    hl_summary_kv "$file" "kernel threads" "$KTHREADS (filtered, not scored)"
    hl_summary_kv "$file" "processes skipped" "$PIDS_SKIPPED"
    hl_summary_kv "$file" "coverage gaps" "$COVERAGE_GAPS (unreadable without root)"
    hl_summary_kv "$file" "processes flagged" "$HL_FLAGGED_COUNT"
    hl_summary_kv "$file" "findings" "$HL_FINDING_COUNT"
    hl_summary_kv "$file" "high" "$HL_HIGH_COUNT"
    hl_summary_kv "$file" "medium" "$HL_MEDIUM_COUNT"
    hl_summary_kv "$file" "low/info" "$HL_LOW_COUNT"
    hl_summary_kv "$file" "read errors" "$HL_ERROR_COUNT"
    hl_summary_kv "$file" "on-disk checks" \
        "$([ "$FS_CHECKS_VALID" -eq 1 ] && echo enabled || echo "disabled (snapshot without --fs-root)")"
    hl_summary_kv "$file" "ownership rules" \
        "$([ "$OWNER_CHECKS" -eq 1 ] && echo enabled || echo "disabled (uids in this tree are not the examined system's)")"
    hl_summary_kv "$file" "permission rules" \
        "$([ "$MODE_CHECKS" -eq 1 ] && echo enabled || echo "disabled (this mount does not preserve permission bits)")"
    {
        printf '\nTop scoring processes:\n'
        if [ -s "$outdir/findings.tsv" ]; then
            awk -F'\t' 'NR>1 && !seen[$4]++ {printf "  %6s  pid %-7s %-16s %s\n", $1, $4, $5, $6}' \
                "$outdir/findings.tsv" | head -n 20 || true
        fi
        printf '\nRule reference:\n'
        if [ -s "$outdir/findings.tsv" ]; then
            awk -F'\t' 'NR>1 {c[$3"\t"$2]++} END {for (k in c) {split(k, p, "\t"); printf "  %-8s %-22s %d\n", p[2], p[1], c[k]}}' \
                "$outdir/findings.tsv" | LC_ALL=C sort
        fi
        printf '\nCoverage note: proc-hunter sees only what the kernel exposes. A\n'
        printf 'kernel-module rootkit can hide a PID from /proc entirely; a clean\n'
        printf 'result here does not clear a host.\n'
    } >>"$file"
    hl_summary_caveat "$file"
    if [ "$QUIET" -ne 1 ]; then
        cat "$file"
    fi
}

# main returns the documented exit code (0 none, 1 findings, 130 interrupted).
# errexit propagates a non-zero return as the script's exit status, which is
# exactly what the contract wants; the explicit exit keeps that obvious.
main "$@"
exit $?
