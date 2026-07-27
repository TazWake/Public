#!/usr/bin/env bash
#
# persist-hunter.sh - Linux persistence enumerator, baseline and diff
# ===================================================================
#
# Hunt hypothesis
# ---------------
# Persistence lives in a finite, enumerable set of locations. An attacker who
# wants to survive a reboot has to write into one of them. Dumping them all,
# scoring the contents against a handful of behavioural rules, and diffing the
# result against a known-good baseline surfaces attacker-added autostarts
# without needing to know what the malware is.
#
# The enumeration is the point. There is no clever detection here that a careful
# analyst could not do by hand - there is simply no chance of the tool forgetting
# to look in /etc/update-motd.d at three in the morning.
#
# Locations enumerated (each is a location_type in the output)
# ------------------------------------------------------------
#   cron.system  cron.d  cron.periodic  cron.user  at.jobs
#   systemd.system  systemd.vendor  systemd.runtime  systemd.user
#   init.rc  init.d  init.tab
#   shell.init  shell.user
#   ld.preload  ld.conf  env.file
#   pam
#   ssh.authorized_keys  ssh.config
#   udev  xdg.autostart  motd.d
#
# Three ways to run it
# --------------------
#   1. Straight dump      persist-hunter.sh --root / -o OUT
#      Enumerate everything, apply the heuristic rules, report.
#   2. Capture a baseline persist-hunter.sh --root / -o OUT --baseline FILE
#      The same, plus a portable snapshot written to FILE. Capture this on a
#      trusted host at a known-good time. A baseline taken after a compromise
#      records the compromise as normal and is worth nothing.
#   3. Diff                persist-hunter.sh --root / -o OUT --compare FILE
#      Everything above, plus NEW / CHANGED / REMOVED findings against the
#      snapshot. This is where the tool earns its keep.
#
# The baseline record schema
# --------------------------
# One tab-separated record per line, sorted, with a commented header:
#
#   category  subject  entry  mtime_utc  size  mode  owner  sha256
#
#   category  the location_type above
#   subject   the path, relative to --root, so a baseline is portable between
#             a live host and a mounted image of it
#   entry     empty for a whole-file record; otherwise the significant line
#             (a crontab entry, an ExecStart=, an authorized_keys line)
#   sha256    for a file record, the hash of the file, so edits show up as
#             CHANGED; for an entry record, the hash of the entry text, so an
#             edited entry shows up as REMOVED plus NEW - which is what an
#             analyst actually wants to see for a crontab line
#
# This is the canonical schema for the whole tool suite: webroot-baseline and
# hunt-baseline conform to it, so one baseline format serves every tool.
#
# Forensic notes
# --------------
#   * Read-only. Nothing under --root is written, renamed, or executed. No
#     collected script or unit is ever run. The only writes are to --output and
#     to an explicitly named --baseline file.
#   * Reading a file to hash it updates its access time on a live writable
#     mount. Access times are NOT restored: doing so rewrites the change time
#     and is itself an alteration of the evidence.
#   * Symlinks are recorded as symlinks and never traversed. In systemd that is
#     a feature, not a limitation: an enabled unit IS a symlink, and the link
#     itself is the evidence of enablement.
#   * Full coverage needs root - every user's crontab, every home directory,
#     every authorized_keys. Run unprivileged and the gaps are counted and
#     reported rather than quietly skipped.
#
# Every result is an investigative lead, not proof of compromise.
#
# Author: Halkyn Consulting.
# Licence: MIT. Original code; contains no third-party code.

set -euo pipefail

PROGRAM="persist-hunter"
VERSION="1.0.0"
BASELINE_FORMAT="hunterkit-baseline 1"

PH_SELF_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
# shellcheck source=./hunterlib.sh
. "$PH_SELF_DIR/hunterlib.sh"

# --------------------------------------------------------------------------- #
# Defaults
# --------------------------------------------------------------------------- #

SCAN_ROOT=""
declare -a EXPLICIT_PATHS=()
declare -a EXCLUDES=()
OUT_DIR=""
FORCE=0
CASE_REF=""
EXAMINER=""
SOURCE_ID=""
VERBOSE=0
QUIET=0
BASELINE_OUT=""
COMPARE_IN=""
CROSS_FS=0
MAX_SIZE=$((8 * 1024 * 1024))
MAX_FILES=200000
RECENT_DAYS=14
NOW_EPOCH=""

FILES_SEEN=0
FILES_SKIPPED=0
LOCATIONS_ABSENT=0
COVERAGE_GAPS=0
ENTRIES=0

BASE_DEV=""

# --------------------------------------------------------------------------- #
# Help
# --------------------------------------------------------------------------- #

usage() {
    cat <<'EOF'
persist-hunter - Linux persistence enumerator, baseline and diff (Bash, read-only)

USAGE
    persist-hunter.sh -o DIR [--root /] [--baseline FILE | --compare FILE] [options]

HUNT HYPOTHESIS
    Persistence lives in a finite, enumerable set of locations. Dump them all,
    score them, and diff against a known-good baseline, and attacker-added
    autostarts have nowhere left to hide.

TARGET SELECTION
    --root DIR            Root of the system to examine (default /). Point this
                          at a mounted image to work offline.
    -p, --path PATH       Examine only this path (file or directory).
                          Repeatable. Suppresses the built-in location list.
    -x, --exclude PATH    Prune this path from the walk. Repeatable.
    --cross-filesystems   Permit descent across mount boundaries (default off).

MODES
    (default)             Enumerate and score the current state.
    --baseline FILE       Also write a portable snapshot to FILE. Capture this
                          on a trusted host, at a known-good time.
    --compare FILE        Diff the current state against a prior snapshot and
                          report NEW, CHANGED and REMOVED entries.

OUTPUT AND CASE METADATA
    -o, --output DIR      Output directory (required). Refused if it sits inside
                          the scan root, or is non-empty without --force.
    --force               Permit a non-empty output directory, and permit
                          overwriting an existing --baseline file.
    --case TEXT           Case or incident reference.
    --examiner TEXT       Examiner or operator name.
    --source-id TEXT      Evidence or host identifier.

BEHAVIOUR
    --recent-days N       Treat a persistence file modified within N days as
                          worth a look (default 14). Set 0 to disable.
    --now EPOCH           Treat this Unix time as "now" when applying
                          --recent-days. For reproducible runs and testing.
    --max-size MIB        Largest file to read and hash (default 8).
    --max-files N         Stop after collecting N files (default 200000).
    -v, --verbose         Per-file detail on stderr.
    -q, --quiet           Suppress console output. Files are still written.
    -V, --version         Print version and exit.
    -h, --help            This help.

WHAT IT LOOKS FOR, INDEPENDENT OF ANY BASELINE
    PERSIST-DOWNLOAD-PIPE  HIGH    a download piped straight into a shell
    PERSIST-ENCODED        HIGH    base64/openssl decoding in an autostart
    PERSIST-EVAL           HIGH    eval of decoded or downloaded content
    PERSIST-REVSHELL       HIGH    /dev/tcp, nc -e, bash -i, socat exec
    PERSIST-TEMP-EXEC      HIGH    execution from /tmp, /var/tmp, /dev/shm, /run
    PERSIST-PRELOAD-FILE   HIGH    /etc/ld.so.preload exists and is populated
    PERSIST-PRELOAD-LIB    HIGH    a preloaded library outside the standard dirs
    PERSIST-LDPRELOAD-ENV  HIGH    LD_PRELOAD/LD_AUDIT exported from a profile
    PERSIST-PAM-NONSTD     HIGH    a PAM module loaded from a non-standard path
    PERSIST-SYMLINK-TEMP   HIGH    a persistence file symlinked into temp space
    PERSIST-HIDDEN-PATH    MEDIUM  execution from a dot-path in shared space
    PERSIST-INLINE-INTERP  MEDIUM  inline python/perl/ruby/php -c or -e
    PERSIST-OBFUSCATED     MEDIUM  a long unbroken encoded-looking token
    PERSIST-CRON-REBOOT    MEDIUM  an @reboot crontab entry
    PERSIST-PAM-EXEC       MEDIUM  pam_exec.so runs a program on authentication
    PERSIST-SSH-FORCED-CMD MEDIUM  an authorized_keys line with command=
    PERSIST-SSH-SYSTEM-KEY MEDIUM  an SSH key on a service or root account
    PERSIST-RECENT         MEDIUM  a persistence file modified in the last N days

WITH --compare
    PERSIST-NEW      HIGH or MEDIUM   absent from the baseline
    PERSIST-CHANGED  HIGH or MEDIUM   present, but the contents differ
    PERSIST-REMOVED  LOW              in the baseline, gone now

EVIDENCE PRACTICE
    * The target is read-only. No collected script or unit is ever executed.
    * Point --output at a directory outside the target, ideally on separate
      media. When the scan root is /, containment cannot be checked and the
      log records that fact.
    * Reading a file updates its access time on a live writable mount. Access
      times are NOT restored: doing so rewrites the change time.
    * A baseline captured after a compromise records the compromise as normal.
      Capture on a trusted host, at a known-good time, and store it elsewhere.

OUTPUTS (in --output)
    persist-hunter.log        Timestamped audit/action log
    findings.tsv              score severity rule_id location_type path detail evidence sha256
    persistence-inventory.tsv The snapshot, in the canonical baseline schema
    inventory.tsv             Coverage: every location examined, present or not
    summary.txt               Counts, coverage, top findings, caveat
    SHA256SUMS                SHA-256 manifest of the output artefacts

EXIT STATUS
    0  completed, no findings        2  invalid use / unsafe path
    1  completed, findings recorded  130 interrupted

EXAMPLES
    # Capture a baseline on a freshly built host, and keep it somewhere else
    sudo ./persist-hunter.sh --root / -o /tmp/pb --baseline /media/usb/web01.tsv

    # Months later, on the suspect host
    sudo ./persist-hunter.sh --root / -o /cases/web01/persist \
        --compare /media/usb/web01.tsv --case IR-2026-041

    # Offline, against a mounted image
    ./persist-hunter.sh --root /mnt/image -o /cases/web01/persist

Findings are investigative leads, not proof of compromise.
EOF
}

# --------------------------------------------------------------------------- #
# Argument parsing
# --------------------------------------------------------------------------- #

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --root)
                [ $# -ge 2 ] || hl_die "--root requires a directory"
                SCAN_ROOT="$2"; shift 2 ;;
            -p|--path)
                [ $# -ge 2 ] || hl_die "--path requires a path"
                EXPLICIT_PATHS+=("$2"); shift 2 ;;
            -x|--exclude)
                [ $# -ge 2 ] || hl_die "--exclude requires a path"
                EXCLUDES+=("$2"); shift 2 ;;
            --cross-filesystems) CROSS_FS=1; shift ;;
            -o|--output)
                [ $# -ge 2 ] || hl_die "--output requires a directory"
                OUT_DIR="$2"; shift 2 ;;
            --force) FORCE=1; shift ;;
            --case)
                [ $# -ge 2 ] || hl_die "--case requires text"
                CASE_REF="$2"; shift 2 ;;
            --examiner)
                [ $# -ge 2 ] || hl_die "--examiner requires text"
                EXAMINER="$2"; shift 2 ;;
            --source-id)
                [ $# -ge 2 ] || hl_die "--source-id requires text"
                SOURCE_ID="$2"; shift 2 ;;
            --baseline)
                [ $# -ge 2 ] || hl_die "--baseline requires a file path"
                BASELINE_OUT="$2"; shift 2 ;;
            --compare)
                [ $# -ge 2 ] || hl_die "--compare requires a file path"
                COMPARE_IN="$2"; shift 2 ;;
            --recent-days)
                [ $# -ge 2 ] || hl_die "--recent-days requires a number"
                case "$2" in ''|*[!0-9]*) hl_die "--recent-days must be a whole number" ;; esac
                RECENT_DAYS="$2"; shift 2 ;;
            --now)
                [ $# -ge 2 ] || hl_die "--now requires a Unix timestamp"
                case "$2" in ''|*[!0-9]*) hl_die "--now must be a Unix timestamp" ;; esac
                NOW_EPOCH="$2"; shift 2 ;;
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
# Path helpers
# --------------------------------------------------------------------------- #

# pc_rel ABSPATH - the path as it appears on the examined system, i.e. with the
# scan root stripped. Baselines are stored this way so a snapshot taken on a
# live host still matches when the same system is examined as a mounted image.
pc_rel() {
    local p="$1"
    if [ "$SCAN_ROOT" = "/" ]; then
        printf '%s' "$p"
        return 0
    fi
    case "$p" in
        "$SCAN_ROOT") printf '/' ;;
        "$SCAN_ROOT"/*) printf '%s' "${p#"$SCAN_ROOT"}" ;;
        *) printf '%s' "$p" ;;
    esac
}

# pc_abs RELPATH - the reverse: a path on the examined system to a path here.
pc_abs() {
    local p="$1"
    if [ "$SCAN_ROOT" = "/" ]; then
        printf '%s' "$p"
    else
        printf '%s%s' "${SCAN_ROOT%/}" "$p"
    fi
}

pc_excluded() {
    local p="$1" ex
    for ex in ${EXCLUDES[@]+"${EXCLUDES[@]}"}; do
        [ -n "$ex" ] || continue
        if [ "$p" = "$ex" ]; then return 0; fi
        case "$p" in "$ex"/*) return 0 ;; esac
    done
    return 1
}

# pc_same_fs PATH - false when the path sits on a different mount than the scan
# root and --cross-filesystems was not given.
pc_same_fs() {
    local dev
    [ "$CROSS_FS" -eq 1 ] && return 0
    [ -n "$BASE_DEV" ] || return 0
    dev=$(hl_stat_dev "$1")
    [ -z "$dev" ] && return 0
    [ "$dev" = "$BASE_DEV" ]
}

# --------------------------------------------------------------------------- #
# Snapshot records
# --------------------------------------------------------------------------- #

SNAPSHOT_RAW=""
COVERAGE_RAW=""

# pc_record CATEGORY SUBJECT ENTRY MTIME SIZE MODE OWNER SHA256
pc_record() {
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$1" "$(hl_scrub "$2" 512)" "$(hl_scrub "$3" 512)" "$4" "$5" "$6" "$7" "$8" \
        >>"$SNAPSHOT_RAW"
}

pc_coverage() {
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$1" "$(hl_scrub "$2" 512)" "$3" "$4" "$5" "$6" "$7" "$8" >>"$COVERAGE_RAW"
}

# --------------------------------------------------------------------------- #
# Heuristic rules
# --------------------------------------------------------------------------- #
#
# One awk pass per file applies every content rule. The rules are deliberately
# tight: a stock Debian ~/.bashrc contains `eval "$(dircolors -b)"`, so a bare
# "eval" rule would fire on every healthy host and be switched off within a day.
# PERSIST-EVAL therefore only fires when what is being eval'd is itself decoded
# or downloaded.

pc_scan_content() {
    local path="$1" category="$2" rel="$3" sha="$4"
    local line rule sev evidence lineno

    while IFS=$'\t' read -r lineno rule sev evidence; do
        [ -n "$rule" ] || continue
        pc_finding "$rel" "$sev" "$rule" "$category" "$rel" \
            "$(pc_rule_detail "$rule") (line $lineno)" "$evidence" "$sha"
    done < <(awk -v cat="$category" '
        function longest_token(s,   best, t) {
            best = 0
            while (match(s, /[A-Za-z0-9+\/=]+/)) {
                t = RLENGTH
                if (t > best) best = t
                s = substr(s, RSTART + RLENGTH)
            }
            return best
        }
        # Decide what a mention of a shared writable directory actually is.
        # An init script that says [ -d "/tmp/.X11-unix" ] or DIR="/tmp/$1" is
        # not executing anything from /tmp, and reporting it at HIGH teaches the
        # reader to ignore the rule. Only a path in command position earns HIGH.
        function temp_context(s,   pre) {
            if (!match(s, /\/(tmp|var\/tmp|dev\/shm|run\/shm)\//)) return "none"
            pre = substr(s, 1, RSTART - 1)
            sub(/["'"'"']$/, "", pre)
            # A shell test operator: [ -d /tmp/x ], [ -f "/tmp/y" ]
            if (pre ~ /(^|[ \t])-[a-zA-Z][ \t]*$/) return "test"
            # A plain variable assignment, but NOT the assignment forms that
            # exist precisely to name a command (ExecStart=, RUN+=, Exec=).
            if (pre ~ /[A-Za-z_][A-Za-z0-9_]*=[ \t]*$/ &&
                pre !~ /(Exec[A-Za-z]*|TryExec|RUN\+?|PROGRAM|IMPORT|CMD|COMMAND|command)=[ \t]*$/)
                return "assign"
            # Housekeeping and inspection commands.
            if (pre ~ /(mktemp|mkdir|touch|rm|find|ls|du|df|stat|mount|umount|chmod|chown|cat|echo|printf|test|\[|tmpwatch|tmpreaper|systemd-tmpfiles)[^;|&]*$/)
                return "housekeeping"
            return "exec"
        }
        function emit(rule, sev,   ev) {
            ev = $0
            gsub(/^[ \t]+/, "", ev)
            printf "%d\t%s\t%s\t%s\n", FNR, rule, sev, substr(ev, 1, 240)
        }
        # Comments and blank lines carry no behaviour.
        /^[ \t]*#/ { next }
        /^[ \t]*;/ { next }
        /^[ \t]*$/ { next }
        {
            line = $0

            # A download piped straight into an interpreter. The single most
            # recognisable line in a Linux intrusion.
            if (line ~ /(curl|wget|fetch)[^|]*\|[ \t]*(sudo[ \t]+)?[a-z\/]*(sh|bash|zsh|dash|python[0-9.]*|perl|ruby)([ \t]|$|")/)
                emit("PERSIST-DOWNLOAD-PIPE", "HIGH")

            # Decoding in an autostart. Legitimate scripts encode data; they
            # very rarely decode a blob and hand it to a shell.
            if (line ~ /base64[ \t]*(-{1,2}[a-zA-Z]*d)/ || line ~ /openssl[ \t]+enc[ \t][^|]*-d/ || line ~ /uudecode|xxd[ \t]+-r/)
                emit("PERSIST-ENCODED", "HIGH")

            # eval, but only of something decoded or fetched. A bare eval rule
            # would fire on the stock Debian .bashrc, which contains
            # eval "$(dircolors -b)", and would be switched off within a day.
            if (line ~ /(^|[ \t;|&(])eval([ \t]|$)/ &&
                line ~ /(base64|curl|wget|gzip|gunzip|zcat|xxd|openssl|\/dev\/tcp)/)
                emit("PERSIST-EVAL", "HIGH")

            # Reverse shells, in their usual costumes.
            if (line ~ /\/dev\/(tcp|udp)\// ||
                line ~ /(^|[ \t;|&])(nc|ncat|netcat)([ \t]+-[a-zA-Z]*e|[ \t][^|;]*-e[ \t])/ ||
                line ~ /(bash|sh)[ \t]+-i[ \t]*(>|<)/ ||
                line ~ /mkfifo[^;]*;[^;]*(nc|ncat|telnet)/ ||
                line ~ /socat[ \t][^;]*exec/)
                emit("PERSIST-REVSHELL", "HIGH")

            # Execution out of shared writable space. Housekeeping jobs
            # legitimately name /tmp all day long - Debian ships init scripts
            # and cron jobs that test for and clean it - so anything that is
            # plainly not an invocation is reported at MEDIUM under its own
            # rule rather than crying wolf at HIGH.
            ctx = temp_context(line)
            if (ctx == "exec")
                emit("PERSIST-TEMP-EXEC", "HIGH")
            else if (ctx != "none")
                emit("PERSIST-TEMP-REF", "MEDIUM")

            # A dot-path in shared writable space: hiding in plain sight.
            if (line ~ /(^|[ \t"'"'"'=:])\/(tmp|var\/tmp|dev\/shm|opt|srv|run)(\/[^ \t"'"'"']*)?\/\.[^ \t"'"'"'\/]+/)
                emit("PERSIST-HIDDEN-PATH", "MEDIUM")

            # Inline interpreter code in an autostart.
            if (line ~ /(python[0-9.]*|perl|ruby|php|node)[ \t]+-[ce][ \t]/)
                emit("PERSIST-INLINE-INTERP", "MEDIUM")

            # A long unbroken encoded-looking token. Excluded for SSH key files,
            # where a 372-character base64 blob is the entire point of the file.
            if (cat !~ /^ssh\./ && longest_token(line) >= 80)
                emit("PERSIST-OBFUSCATED", "MEDIUM")

            # An environment file or profile that injects a library into every
            # process started from it - the userland rootkit trick.
            if (line ~ /LD_PRELOAD|LD_AUDIT/)
                emit("PERSIST-LDPRELOAD-ENV", "HIGH")

            if (cat ~ /^cron/ && line ~ /^[ \t]*@reboot/)
                emit("PERSIST-CRON-REBOOT", "MEDIUM")

            if (cat == "pam") {
                if (line ~ /pam_exec\.so/)
                    emit("PERSIST-PAM-EXEC", "MEDIUM")
                # A module given as an absolute path outside the usual security
                # directories is how a PAM backdoor gets loaded. So is a path
                # that starts inside a standard directory and then walks out of
                # it with .., which is why the traversal is checked separately.
                if (line ~ /[ \t]\/[^ \t]*\.so/ &&
                    (line ~ /[ \t]\/[^ \t]*\/\.\.\// ||
                     line !~ /[ \t]\/(lib|lib64|usr\/lib|usr\/lib64|usr\/local\/lib)([^ \t]*)?\/security\//))
                    emit("PERSIST-PAM-NONSTD", "HIGH")
            }

            if (cat == "ssh.authorized_keys") {
                if (line ~ /(^|,)command="/)
                    emit("PERSIST-SSH-FORCED-CMD", "MEDIUM")
            }
        }
    ' "$path" 2>/dev/null || true)
}

pc_rule_detail() {
    case "$1" in
        PERSIST-DOWNLOAD-PIPE)  printf 'Downloads and pipes content straight into an interpreter' ;;
        PERSIST-ENCODED)        printf 'Decodes an encoded payload at start-up' ;;
        PERSIST-EVAL)           printf 'Evaluates decoded or downloaded content' ;;
        PERSIST-REVSHELL)       printf 'Reverse-shell construct' ;;
        PERSIST-TEMP-EXEC)      printf 'Executes from shared writable space' ;;
        PERSIST-TEMP-REF)       printf 'References shared writable space (looks like housekeeping)' ;;
        PERSIST-HIDDEN-PATH)    printf 'References a dot-path in shared writable space' ;;
        PERSIST-INLINE-INTERP)  printf 'Runs inline interpreter code' ;;
        PERSIST-OBFUSCATED)     printf 'Contains a long unbroken encoded-looking token' ;;
        PERSIST-LDPRELOAD-ENV)  printf 'Injects a library into every process via the environment' ;;
        PERSIST-CRON-REBOOT)    printf 'Runs at every boot (@reboot)' ;;
        PERSIST-PAM-EXEC)       printf 'PAM runs an external program on authentication' ;;
        PERSIST-PAM-NONSTD)     printf 'PAM module loaded from a non-standard path' ;;
        PERSIST-SSH-FORCED-CMD) printf 'SSH key carries a forced command' ;;
        *)                      printf 'Heuristic match' ;;
    esac
}

# --------------------------------------------------------------------------- #
# Findings
# --------------------------------------------------------------------------- #

declare -A PC_SCORE=()
declare -A PC_HITS=()

# pc_finding SUBJECT SEVERITY RULE LOCATION_TYPE PATH DETAIL EVIDENCE SHA256
pc_finding() {
    local subject="$1" severity="$2" rule="$3"
    local weight
    case "$severity" in
        HIGH)   weight=50 ;;
        MEDIUM) weight=20 ;;
        LOW)    weight=10 ;;
        *)      weight=5 ;;
    esac
    PC_SCORE["$subject"]=$(( ${PC_SCORE["$subject"]:-0} + weight ))
    PC_HITS["$subject"]=$(( ${PC_HITS["$subject"]:-0} + 1 ))
    hl_finding "$subject" "$severity" "$rule" "$4" "$5" "$6" "$7" "$8"
    hl_detail "$severity $rule: $5"
}

# --------------------------------------------------------------------------- #
# Collection
# --------------------------------------------------------------------------- #

# pc_entry_filter MODE - the awk program that pulls the significant lines out of
# a file for entry-level baselining.
pc_entry_filter() {
    case "$1" in
        cron)    printf '%s' '!/^[ \t]*#/ && !/^[ \t]*$/ {print}' ;;
        exec)    printf '%s' '/^[ \t]*(ExecStart|ExecStartPre|ExecStartPost|ExecStop|ExecReload|ExecCondition)[ \t]*=/ {print}' ;;
        keys)    printf '%s' '!/^[ \t]*#/ && !/^[ \t]*$/ {print}' ;;
        preload) printf '%s' '!/^[ \t]*#/ && !/^[ \t]*$/ {print}' ;;
        pam)     printf '%s' '!/^[ \t]*#/ && !/^[ \t]*$/ {print}' ;;
        desktop) printf '%s' '/^[ \t]*(Exec|TryExec)[ \t]*=/ {print}' ;;
        udev)    printf '%s' '/RUN|PROGRAM|IMPORT\{program\}/ && !/^[ \t]*#/ {print}' ;;
        *)       printf '%s' '' ;;
    esac
}

# pc_collect_file CATEGORY MODE PATH
pc_collect_file() {
    local category="$1" mode="$2" path="$3"
    local rel fields fmode fuid fgid fsize fmtime mtime_iso sha target filt
    local entry n_entries=0

    if pc_excluded "$path"; then
        hl_detail "excluded: $path"
        return 0
    fi
    if [ "$FILES_SEEN" -ge "$MAX_FILES" ]; then
        return 0
    fi

    rel=$(pc_rel "$path")

    # A symlink is described, never followed. In systemd the link is itself the
    # evidence: /etc/systemd/system/*.wants/x.service -> the unit that enabled it.
    if [ -L "$path" ]; then
        target=$(readlink -- "$path" 2>/dev/null || printf '')
        fields=$(hl_stat_fields "$path")
        IFS=$'\t' read -r fmode fuid fgid fsize fmtime <<<"$fields" || true
        mtime_iso=$(hl_iso "$fmtime")
        sha=$(hl_sha256_string "symlink:$target")
        FILES_SEEN=$((FILES_SEEN + 1))
        pc_record "$category" "$rel" "-> $target" "$mtime_iso" "$fsize" "$fmode" "$fuid:$fgid" "$sha"
        pc_coverage "$category" "$rel" "symlink" "$fsize" "$mtime_iso" "$fmode" "$fuid:$fgid" "$sha"
        case "$target" in
            # /run/systemd is where systemd itself stages generated runtime
            # units; its symlinks are the normal state of a booted host.
            /run/systemd/*) ;;
            /tmp/*|/var/tmp/*|/dev/shm/*|/run/*)
                pc_finding "$rel" HIGH PERSIST-SYMLINK-TEMP "$category" "$rel" \
                    "Persistence file is a symlink into shared writable space" \
                    "-> $target" "$sha" ;;
        esac
        pc_check_recent "$category" "$rel" "$fmtime" "$sha"
        return 0
    fi

    if [ ! -f "$path" ]; then
        return 0
    fi
    if ! pc_same_fs "$path"; then
        FILES_SKIPPED=$((FILES_SKIPPED + 1))
        hl_detail "skipped (other filesystem): $path"
        return 0
    fi
    if [ ! -r "$path" ]; then
        COVERAGE_GAPS=$((COVERAGE_GAPS + 1))
        hl_error "unreadable (needs root?): $path"
        pc_coverage "$category" "$rel" "unreadable" "" "" "" "" ""
        return 0
    fi

    fields=$(hl_stat_fields "$path")
    IFS=$'\t' read -r fmode fuid fgid fsize fmtime <<<"$fields" || true
    mtime_iso=$(hl_iso "$fmtime")

    if [ -n "$fsize" ] && [ "$fsize" -gt "$MAX_SIZE" ] 2>/dev/null; then
        FILES_SKIPPED=$((FILES_SKIPPED + 1))
        hl_info "skipped (over --max-size): $path ($fsize bytes)"
        pc_coverage "$category" "$rel" "oversize" "$fsize" "$mtime_iso" "$fmode" "$fuid:$fgid" ""
        return 0
    fi

    FILES_SEEN=$((FILES_SEEN + 1))
    sha=$(hl_sha256 "$path")

    # The whole-file record: this is what turns into a CHANGED finding.
    pc_record "$category" "$rel" "" "$mtime_iso" "$fsize" "$fmode" "$fuid:$fgid" "$sha"

    # Entry records, for the location types where a single line is the unit of
    # persistence and an analyst wants line-level NEW/REMOVED.
    filt=$(pc_entry_filter "$mode")
    if [ -n "$filt" ]; then
        while IFS= read -r entry; do
            [ -n "$entry" ] || continue
            n_entries=$((n_entries + 1))
            ENTRIES=$((ENTRIES + 1))
            pc_record "$category" "$rel" "$entry" "$mtime_iso" "" "" "" \
                "$(hl_sha256_string "$entry")"
        done < <(awk "$filt" "$path" 2>/dev/null || true)
    fi

    pc_coverage "$category" "$rel" "file" "$fsize" "$mtime_iso" "$fmode" "$fuid:$fgid" "$sha"

    pc_scan_content "$path" "$category" "$rel" "$sha"
    pc_check_recent "$category" "$rel" "$fmtime" "$sha"
    pc_check_location "$category" "$path" "$rel" "$sha" "$fmode" "$fuid"
}

# Files that changed recently, relative to the run time. Persistence that
# appeared last Tuesday deserves a look; persistence installed with the OS
# usually does not.
pc_check_recent() {
    local category="$1" rel="$2" mtime="$3" sha="$4" age
    [ "$RECENT_DAYS" -gt 0 ] || return 0
    case "$mtime" in ''|*[!0-9]*) return 0 ;; esac
    # /run is a tmpfs rebuilt at every boot, so everything in it is always
    # "recent". Saying so on every reboot is noise, not a lead.
    case "$rel" in /run/*) return 0 ;; esac
    age=$(( (NOW_EPOCH - mtime) / 86400 ))
    if [ "$age" -ge 0 ] && [ "$age" -lt "$RECENT_DAYS" ]; then
        pc_finding "$rel" MEDIUM PERSIST-RECENT "$category" "$rel" \
            "Persistence file modified within the last $RECENT_DAYS days" \
            "mtime $(hl_iso "$mtime") (${age}d ago)" "$sha"
    fi
}

# Location-specific rules that need more than a line of text to decide.
pc_check_location() {
    local category="$1" path="$2" rel="$3" sha="$4" fmode="$5" fuid="$6"
    local lib libpath libfields libmode libuid

    case "$category" in
        ld.preload)
            # /etc/ld.so.preload should not normally exist at all, and should
            # certainly not be populated. Everything it names is injected into
            # every dynamically linked process on the host.
            if [ -s "$path" ]; then
                pc_finding "$rel" HIGH PERSIST-PRELOAD-FILE "$category" "$rel" \
                    "ld.so.preload exists and is populated - libraries here load into every process" \
                    "$(head -c 200 "$path" 2>/dev/null | tr '\n' ' ')" "$sha"
                while IFS= read -r lib; do
                    case "$lib" in ''|\#*) continue ;; esac
                    case "$lib" in
                        /lib/*|/lib64/*|/usr/lib/*|/usr/lib64/*|/usr/local/lib/*) ;;
                        *) pc_finding "$rel" HIGH PERSIST-PRELOAD-LIB "$category" "$rel" \
                               "Preloaded library outside the standard library directories" \
                               "$lib" "$sha"
                           continue ;;
                    esac
                    libpath=$(pc_abs "$lib")
                    if [ -e "$libpath" ]; then
                        libfields=$(hl_stat_fields "$libpath")
                        IFS=$'\t' read -r libmode libuid _ _ _ <<<"$libfields" || true
                        if [ -n "$libmode" ] && hl_world_writable "$libmode"; then
                            pc_finding "$rel" HIGH PERSIST-PRELOAD-LIB "$category" "$rel" \
                                "Preloaded library is world-writable (mode $libmode)" \
                                "$lib" "$sha"
                        fi
                    else
                        pc_finding "$rel" MEDIUM PERSIST-PRELOAD-LIB "$category" "$rel" \
                            "Preloaded library is not present on disk" "$lib" "$sha"
                    fi
                done <"$path"
            fi ;;
        ssh.authorized_keys)
            # An SSH key on an account that is never meant to log in
            # interactively is a backdoor until proven otherwise.
            local owner_user shell_of
            owner_user=$(pc_user_for_home "$rel")
            shell_of=$(pc_shell_for_user "$owner_user")
            case "$shell_of" in
                */nologin|*/false|"")
                    if [ -n "$owner_user" ]; then
                        pc_finding "$rel" MEDIUM PERSIST-SSH-SYSTEM-KEY "$category" "$rel" \
                            "SSH key present on a service account with shell ${shell_of:-unknown}" \
                            "user=$owner_user" "$sha"
                    fi ;;
            esac
            if [ "$owner_user" = "root" ]; then
                pc_finding "$rel" MEDIUM PERSIST-SSH-SYSTEM-KEY "$category" "$rel" \
                    "SSH key present on the root account" "user=root" "$sha"
            fi ;;
    esac
}

# --------------------------------------------------------------------------- #
# User enumeration (all users, not just the invoker)
# --------------------------------------------------------------------------- #

declare -a USER_NAMES=()
declare -a USER_HOMES=()
declare -A USER_SHELL=()
declare -A HOME_USER=()

pc_load_users() {
    local passwd name home shell
    passwd=$(pc_abs /etc/passwd)
    if [ -r "$passwd" ]; then
        while IFS=: read -r name _ _ _ _ home shell; do
            [ -n "$name" ] || continue
            [ -n "$home" ] || continue
            case "$home" in /*) ;; *) continue ;; esac
            USER_NAMES+=("$name")
            USER_HOMES+=("$home")
            USER_SHELL["$name"]="$shell"
            [ -n "${HOME_USER[$home]+set}" ] || HOME_USER["$home"]="$name"
        done <"$passwd"
        hl_info "enumerated ${#USER_NAMES[@]} account(s) from /etc/passwd"
    else
        # No passwd file (or no permission): fall back to the obvious homes so
        # the run still covers something, and say so.
        COVERAGE_GAPS=$((COVERAGE_GAPS + 1))
        hl_warning "cannot read /etc/passwd under the scan root - falling back to /root and /home/*"
        local d
        for d in "$(pc_abs /root)" "$(pc_abs /home)"/*; do
            [ -d "$d" ] || continue
            home=$(pc_rel "$d")
            USER_NAMES+=("${home##*/}")
            USER_HOMES+=("$home")
            HOME_USER["$home"]="${home##*/}"
        done
    fi
}

pc_user_for_home() {
    # Given /home/alice/.ssh/authorized_keys, work back to the account.
    local rel="$1" home
    for home in ${USER_HOMES[@]+"${USER_HOMES[@]}"}; do
        case "$rel" in "$home"/*) printf '%s' "${HOME_USER[$home]-}"; return 0 ;; esac
    done
    printf ''
}

pc_shell_for_user() {
    [ -n "${1:-}" ] || return 0
    printf '%s' "${USER_SHELL[$1]-}"
}

# --------------------------------------------------------------------------- #
# The location list
# --------------------------------------------------------------------------- #

# pc_glob CATEGORY MODE PATTERN... - collect each existing match, in a stable
# order, recording absent locations for the coverage inventory.
pc_glob() {
    local category="$1" mode="$2"; shift 2
    local pattern hit path found
    for pattern in "$@"; do
        found=0
        while IFS= read -r path; do
            [ -n "$path" ] || continue
            found=1
            pc_collect_file "$category" "$mode" "$path"
        done < <(pc_expand "$pattern")
        if [ "$found" -eq 0 ]; then
            LOCATIONS_ABSENT=$((LOCATIONS_ABSENT + 1))
            pc_coverage "$category" "$(pc_rel "$pattern")" "absent" "" "" "" "" ""
            hl_detail "absent: $pattern"
        fi
    done
}

# pc_expand PATTERN - stable, sorted expansion of a glob, one match per line,
# and nothing at all when it matches nothing. compgen -G is used rather than
# an array assignment because the latter word-splits, which would break any
# scan root containing a space.
pc_expand() {
    compgen -G "$1" 2>/dev/null | LC_ALL=C sort || true
}

# pc_tree CATEGORY MODE DIR - every file and symlink under a directory.
pc_tree() {
    local category="$1" mode="$2" dir="$3" path
    if [ ! -d "$dir" ]; then
        LOCATIONS_ABSENT=$((LOCATIONS_ABSENT + 1))
        pc_coverage "$category" "$(pc_rel "$dir")" "absent" "" "" "" "" ""
        return 0
    fi
    if pc_excluded "$dir"; then
        hl_detail "excluded: $dir"
        return 0
    fi
    local xdev="-xdev"
    [ "$CROSS_FS" -eq 1 ] && xdev=""
    while IFS= read -r path; do
        [ -n "$path" ] || continue
        pc_collect_file "$category" "$mode" "$path"
    done < <(find "$dir" $xdev \( -type f -o -type l \) -print 2>/dev/null | LC_ALL=C sort || true)
}

pc_enumerate() {
    local u home i

    hl_section "cron"
    pc_glob cron.system  cron "$(pc_abs /etc/crontab)" "$(pc_abs /etc/anacrontab)"
    pc_tree cron.d       cron "$(pc_abs /etc/cron.d)"
    for i in hourly daily weekly monthly; do
        pc_tree cron.periodic none "$(pc_abs "/etc/cron.$i")"
    done
    pc_tree cron.user    cron "$(pc_abs /var/spool/cron)"
    pc_tree at.jobs      none "$(pc_abs /var/spool/at)"

    hl_section "systemd"
    pc_tree systemd.system  exec "$(pc_abs /etc/systemd/system)"
    pc_tree systemd.vendor  exec "$(pc_abs /usr/lib/systemd/system)"
    pc_tree systemd.vendor  exec "$(pc_abs /lib/systemd/system)"
    pc_tree systemd.runtime exec "$(pc_abs /run/systemd/system)"
    pc_tree systemd.user    exec "$(pc_abs /etc/systemd/user)"
    pc_tree systemd.user    exec "$(pc_abs /usr/lib/systemd/user)"

    hl_section "init scripts"
    pc_glob init.rc  none "$(pc_abs /etc/rc.local)" "$(pc_abs /etc/rc.d/rc.local)"
    pc_glob init.tab none "$(pc_abs /etc/inittab)"
    pc_tree init.d   none "$(pc_abs /etc/init.d)"

    hl_section "shell initialisation"
    pc_glob shell.init none \
        "$(pc_abs /etc/profile)" "$(pc_abs /etc/bash.bashrc)" \
        "$(pc_abs /etc/bashrc)" "$(pc_abs /etc/csh.cshrc)" \
        "$(pc_abs /etc/zsh/zshrc)" "$(pc_abs /etc/zsh/zshenv)" \
        "$(pc_abs /etc/zprofile)"
    pc_tree shell.init none "$(pc_abs /etc/profile.d)"

    hl_section "library preload and environment"
    pc_glob ld.preload preload "$(pc_abs /etc/ld.so.preload)"
    pc_glob ld.conf    none    "$(pc_abs /etc/ld.so.conf)"
    pc_tree ld.conf    none    "$(pc_abs /etc/ld.so.conf.d)"
    pc_glob env.file   none    "$(pc_abs /etc/environment)"
    pc_tree env.file   none    "$(pc_abs /etc/default)"
    pc_tree env.file   none    "$(pc_abs /etc/sysconfig)"

    hl_section "PAM"
    pc_tree pam pam "$(pc_abs /etc/pam.d)"

    hl_section "SSH"
    pc_glob ssh.config none "$(pc_abs /etc/ssh/sshd_config)"
    pc_tree ssh.config none "$(pc_abs /etc/ssh/sshd_config.d)"

    hl_section "udev"
    pc_tree udev udev "$(pc_abs /etc/udev/rules.d)"
    pc_tree udev udev "$(pc_abs /lib/udev/rules.d)"
    pc_tree udev udev "$(pc_abs /usr/lib/udev/rules.d)"

    hl_section "desktop autostart and motd"
    pc_tree xdg.autostart desktop "$(pc_abs /etc/xdg/autostart)"
    pc_tree motd.d        none    "$(pc_abs /etc/update-motd.d)"

    hl_section "per-user locations"
    i=0
    for home in ${USER_HOMES[@]+"${USER_HOMES[@]}"}; do
        u="${USER_NAMES[$i]}"
        i=$((i + 1))
        local habs
        habs=$(pc_abs "$home")
        [ -d "$habs" ] || continue
        pc_glob shell.user none \
            "$habs/.bashrc" "$habs/.bash_profile" "$habs/.bash_login" \
            "$habs/.bash_logout" "$habs/.profile" "$habs/.zshrc" \
            "$habs/.zshenv" "$habs/.zlogin" "$habs/.zprofile" \
            "$habs/.kshrc" "$habs/.cshrc" "$habs/.tcshrc"
        pc_glob ssh.authorized_keys keys \
            "$habs/.ssh/authorized_keys" "$habs/.ssh/authorized_keys2"
        pc_tree xdg.autostart desktop "$habs/.config/autostart"
        pc_tree systemd.user  exec    "$habs/.config/systemd/user"
    done
    hl_info "examined per-user locations for ${#USER_HOMES[@]} account(s)"
}

# --------------------------------------------------------------------------- #
# Baseline comparison
# --------------------------------------------------------------------------- #

# Which categories represent code that runs on its own. A new entry in one of
# these is a materially different event from a new line in sshd_config.
pc_is_autostart() {
    case "$1" in
        cron.*|at.jobs|systemd.*|init.*|shell.*|ld.preload|udev|xdg.autostart|motd.d|pam|ssh.authorized_keys)
            return 0 ;;
        *) return 1 ;;
    esac
}

pc_compare() {
    local baseline="$1" current="$2"
    local change category subject entry old new sev

    if ! head -1 "$baseline" | grep -q "^# $BASELINE_FORMAT"; then
        hl_die "not a $PROGRAM baseline (missing '# $BASELINE_FORMAT' header): $baseline"
    fi

    hl_section "baseline comparison"
    hl_info "baseline: $baseline"
    hl_info "$(grep -m1 '^# created_utc:' "$baseline" 2>/dev/null || printf '# created_utc: unknown')"

    # Fields are separated by US (0x1f), not TAB: with IFS set to a whitespace
    # character, `read` collapses runs of delimiters, so an empty `entry` field
    # would silently shift every column after it.
    while IFS=$'\x1f' read -r change category subject entry old new; do
        [ -n "$change" ] || continue
        case "$change" in
            NEW)
                if pc_is_autostart "$category"; then sev=HIGH; else sev=MEDIUM; fi
                pc_finding "$subject" "$sev" PERSIST-NEW "$category" "$subject" \
                    "Not present in the baseline${entry:+ (new entry)}" \
                    "${entry:-<file> sha256=$new}" "$new" ;;
            CHANGED)
                case "$category" in
                    ld.preload|pam|ssh.authorized_keys|systemd.*|cron.*|init.*) sev=HIGH ;;
                    *) sev=MEDIUM ;;
                esac
                pc_finding "$subject" "$sev" PERSIST-CHANGED "$category" "$subject" \
                    "Contents differ from the baseline" \
                    "baseline=$old current=$new" "$new" ;;
            REMOVED)
                pc_finding "$subject" LOW PERSIST-REMOVED "$category" "$subject" \
                    "Present in the baseline, absent now${entry:+ (entry removed)}" \
                    "${entry:-<file> sha256=$old}" "$old" ;;
        esac
    done < <(awk -F'\t' '
        BEGIN { OFS = sprintf("%c", 31) }
        /^#/ { next }
        $1 == "category" && $2 == "subject" { next }
        NR == FNR { key = $1 SUBSEP $2 SUBSEP $3; base[key] = $8; bcat[key] = $1;
                    bsub[key] = $2; bent[key] = $3; next }
        {
            key = $1 SUBSEP $2 SUBSEP $3
            if (!(key in base)) {
                print "NEW", $1, $2, $3, "", $8
            } else {
                if ($8 != base[key]) print "CHANGED", $1, $2, $3, base[key], $8
                delete base[key]
            }
        }
        END {
            n = 0
            for (k in base) {
                print "REMOVED", bcat[k], bsub[k], bent[k], base[k], ""
                n++
            }
        }
    ' "$baseline" "$current" | LC_ALL=C sort || true)
}

# --------------------------------------------------------------------------- #
# Output writers
# --------------------------------------------------------------------------- #

pc_write_snapshot() {
    local out="$1" root_label="$2"
    {
        printf '# %s\n' "$BASELINE_FORMAT"
        printf '# tool: %s %s\n' "$PROGRAM" "$VERSION"
        printf '# created_utc: %s\n' "$(hl_utc_now)"
        printf '# root: %s\n' "$root_label"
        printf '# collected_from: %s\n' "$SCAN_ROOT"
        printf '# host: %s\n' "$(uname -n 2>/dev/null || echo unknown)"
        printf '# case: %s\n' "$CASE_REF"
        printf '# source_id: %s\n' "$SOURCE_ID"
        printf '# schema: category<TAB>subject<TAB>entry<TAB>mtime_utc<TAB>size<TAB>mode<TAB>owner<TAB>sha256\n'
        printf '# NOTE: a baseline captured after a compromise records the compromise as normal.\n'
        printf 'category\tsubject\tentry\tmtime_utc\tsize\tmode\towner\tsha256\n'
        LC_ALL=C sort -u "$SNAPSHOT_RAW" 2>/dev/null || true
    } >"$out"
}

pc_write_coverage() {
    local out="$1" scores sorted subject
    scores="${COVERAGE_RAW}.scores"
    sorted="${COVERAGE_RAW}.sorted"
    : >"$scores"
    if [ "${#PC_SCORE[@]}" -gt 0 ]; then
        for subject in "${!PC_SCORE[@]}"; do
            printf '%s\t%s\t%d.%d\n' "$subject" "${PC_HITS[$subject]:-0}" \
                $(( PC_SCORE["$subject"] / 10 )) $(( PC_SCORE["$subject"] % 10 )) >>"$scores"
        done
    fi
    LC_ALL=C sort -u "$COVERAGE_RAW" >"$sorted" 2>/dev/null || : >"$sorted"
    {
        printf 'location_type\tpath\tstatus\tsize\tmtime_utc\tmode\towner\tsha256\tfinding_count\tscore\n'
        awk -F'\t' -v OFS='\t' '
            NR == FNR { hits[$1] = $2; score[$1] = $3; next }
            { print $0, ($2 in hits ? hits[$2] : 0), ($2 in score ? score[$2] : "0.0") }
        ' "$scores" "$sorted"
    } >"$out"
    rm -f -- "$scores" "$sorted"
}

pc_write_summary() {
    local file="$1" outdir="$2"
    hl_summary_open "$file" "$PROGRAM" "$VERSION"
    hl_summary_kv "$file" "files collected" "$FILES_SEEN"
    hl_summary_kv "$file" "entries recorded" "$ENTRIES"
    hl_summary_kv "$file" "locations absent" "$LOCATIONS_ABSENT"
    hl_summary_kv "$file" "files skipped" "$FILES_SKIPPED"
    hl_summary_kv "$file" "coverage gaps" "$COVERAGE_GAPS (unreadable without root)"
    hl_summary_kv "$file" "subjects flagged" "$HL_FLAGGED_COUNT"
    hl_summary_kv "$file" "findings" "$HL_FINDING_COUNT"
    hl_summary_kv "$file" "high" "$HL_HIGH_COUNT"
    hl_summary_kv "$file" "medium" "$HL_MEDIUM_COUNT"
    hl_summary_kv "$file" "low/info" "$HL_LOW_COUNT"
    hl_summary_kv "$file" "read errors" "$HL_ERROR_COUNT"
    hl_summary_kv "$file" "mode" \
        "$([ -n "$COMPARE_IN" ] && echo "compare against $COMPARE_IN" || echo "enumerate")"
    hl_summary_kv "$file" "baseline written" "${BASELINE_OUT:-(none)}"
    {
        printf '\nTop findings:\n'
        if [ -s "$outdir/findings.tsv" ]; then
            awk -F'\t' 'NR>1 {printf "  %6s  %-8s %-22s %s\n", $1, $2, $3, $5}' \
                "$outdir/findings.tsv" | head -n 25 || true
        else
            printf '  (none)\n'
        fi
        printf '\nFindings by location type:\n'
        if [ -s "$outdir/findings.tsv" ]; then
            awk -F'\t' 'NR>1 {c[$4]++} END {for (k in c) printf "  %-22s %d\n", k, c[k]}' \
                "$outdir/findings.tsv" | LC_ALL=C sort || true
        fi
        if [ "$COVERAGE_GAPS" -gt 0 ]; then
            printf '\nCoverage: %d location(s) could not be read. Full enumeration of\n' "$COVERAGE_GAPS"
            printf 'every user crontab, home directory and authorized_keys needs root.\n'
        fi
        if [ -z "$COMPARE_IN" ]; then
            printf '\nNo baseline was compared. Most persistence hunts reduce to "what\n'
            printf 'changed?" - capture a baseline on a trusted host with --baseline and\n'
            printf 'diff against it with --compare.\n'
        fi
    } >>"$file"
    hl_summary_caveat "$file"
    if [ "$QUIET" -ne 1 ]; then
        cat "$file"
    fi
}

# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #

main() {
    local raw_args outdir
    raw_args=$(hl_command_line "$0" "$@")
    parse_args "$@"

    [ -n "$OUT_DIR" ] || hl_die "--output is required (use -h for help)"

    hl_date_init
    hl_stat_init
    hl_hash_init || hl_die "no SHA-256 implementation found (need sha256sum, shasum or openssl). Evidence hashing is not optional."

    if [ -n "$COMPARE_IN" ]; then
        [ -r "$COMPARE_IN" ] || hl_die "--compare file is not readable: $COMPARE_IN"
    fi

    SCAN_ROOT="${SCAN_ROOT:-/}"
    [ -d "$SCAN_ROOT" ] || hl_die "--root is not a directory: $SCAN_ROOT"
    SCAN_ROOT=$(hl_abspath "$SCAN_ROOT")

    if [ -z "$NOW_EPOCH" ]; then
        NOW_EPOCH=$(date -u +%s)
    fi

    outdir=$(hl_resolve_output "$OUT_DIR" "$FORCE" "$SCAN_ROOT")

    if [ -n "$BASELINE_OUT" ]; then
        if [ -e "$BASELINE_OUT" ] && [ "$FORCE" -ne 1 ]; then
            hl_die "--baseline file already exists: $BASELINE_OUT (pass --force to overwrite)"
        fi
        local bdir
        bdir=$(dirname -- "$BASELINE_OUT")
        [ -d "$bdir" ] || hl_die "--baseline directory does not exist: $bdir"
    fi

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
    hl_ctx_set scan_root "$SCAN_ROOT"
    hl_ctx_set output_dir "$outdir"
    hl_ctx_set command "$raw_args"
    hl_log_header

    [ -n "$HL_OUTPUT_NOTE" ] && hl_warning "$HL_OUTPUT_NOTE" || true
    if [ "$(id -u 2>/dev/null || echo 1)" != "0" ] && [ "$SCAN_ROOT" = "/" ]; then
        hl_warning "running unprivileged against a live root: other users' crontabs, home directories and authorized_keys will not be readable. Coverage gaps are counted in the summary."
    fi

    SNAPSHOT_RAW="$outdir/.snapshot.raw"
    COVERAGE_RAW="$outdir/.coverage.raw"
    : >"$SNAPSHOT_RAW"
    : >"$COVERAGE_RAW"
    hl_findings_init "$outdir/.findings.raw" \
        "score	severity	rule_id	location_type	path	detail	evidence	sha256"

    BASE_DEV=$(hl_stat_dev "$SCAN_ROOT")
    if [ "$CROSS_FS" -eq 0 ] && [ -n "$BASE_DEV" ]; then
        hl_info "staying on the scan root's filesystem (device $BASE_DEV); pass --cross-filesystems to descend into others"
    fi

    pc_load_users

    if [ "${#EXPLICIT_PATHS[@]}" -gt 0 ]; then
        hl_section "explicit paths"
        local p
        for p in "${EXPLICIT_PATHS[@]}"; do
            if [ -d "$p" ]; then
                pc_tree explicit none "$p"
            elif [ -e "$p" ]; then
                pc_collect_file explicit none "$p"
            else
                hl_error "path does not exist: $p"
            fi
        done
    else
        pc_enumerate
    fi

    if hl_interrupted; then
        hl_warning "interrupt received - finalising partial output"
    fi

    hl_section "writing reports"
    pc_write_snapshot "$outdir/persistence-inventory.tsv" "$(pc_rel "$SCAN_ROOT")"

    if [ -n "$BASELINE_OUT" ]; then
        cp -- "$outdir/persistence-inventory.tsv" "$BASELINE_OUT" \
            || hl_die "could not write baseline: $BASELINE_OUT"
        hl_info "wrote baseline $BASELINE_OUT ($(wc -l <"$BASELINE_OUT" | tr -d ' ') lines)"
    fi

    if [ -n "$COMPARE_IN" ]; then
        pc_compare "$COMPARE_IN" "$outdir/persistence-inventory.tsv"
    fi

    hl_findings_write "$outdir/findings.tsv"
    pc_write_coverage "$outdir/inventory.tsv"
    rm -f -- "$SNAPSHOT_RAW" "$COVERAGE_RAW" "$outdir/.findings.raw"

    hl_ctx_set completed_utc "$(hl_utc_now)"
    hl_ctx_set completion "$(hl_interrupted && echo interrupted || echo complete)"
    pc_write_summary "$outdir/summary.txt" "$outdir"

    local f
    for f in findings.tsv persistence-inventory.tsv inventory.tsv summary.txt; do
        hl_info "wrote $outdir/$f"
    done

    hl_section "run end"
    hl_info "files=$FILES_SEEN entries=$ENTRIES flagged=$HL_FLAGGED_COUNT findings=$HL_FINDING_COUNT errors=$HL_ERROR_COUNT"
    # The manifest is the last write of the run so that it can cover this log
    # too. Nothing may be appended to the log after this point.
    hl_info "writing SHA256SUMS last; it covers this log, so this is the final log line"
    hl_log_close
    hl_write_manifest "$outdir" >/dev/null

    if [ "$QUIET" -ne 1 ]; then
        printf '\n%s complete. %d file(s) collected, %d subject(s) flagged, %d finding(s).\n' \
            "$PROGRAM" "$FILES_SEEN" "$HL_FLAGGED_COUNT" "$HL_FINDING_COUNT"
        printf 'Reports in: %s\n' "$outdir"
    fi

    if hl_interrupted; then
        return "$HL_EXIT_INTERRUPT"
    fi
    [ "$HL_FINDING_COUNT" -gt 0 ] && return "$HL_EXIT_FINDINGS"
    return "$HL_EXIT_OK"
}

main "$@"
exit $?
