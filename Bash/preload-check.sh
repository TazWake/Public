#!/usr/bin/env bash
# shellcheck shell=bash
#
# preload-check.sh - LD_PRELOAD / ld.so.preload userland rootkit detector
# =======================================================================
#
# Hunt hypothesis
# ---------------
# The commonest userland rootkit technique on Linux is library injection through
# the dynamic linker: an attacker names a malicious shared object in
# /etc/ld.so.preload, or exports LD_PRELOAD, and the loader maps their code into
# every dynamically-linked program that starts. That code then hooks libc calls
# to hide files, processes and connections. The injection point is small and
# enumerable, so it is cheap to hunt: look at the preload file, the environment
# of running processes, and the libraries actually mapped into them, and judge
# whether any preloaded object is where it should not be.
#
# This is a focused, single-technique companion to persist-hunter (which also
# records ld.so.preload as one persistence location among many). Its checks are
# exposed as functions so persist-hunter, or a responder at a shell, can reuse
# them. No third-party code; the concept only.
#
# What it flags
# -------------
#   PRE-LDSO-PRESENT     MEDIUM  /etc/ld.so.preload exists at all - it is absent
#                                on most healthy systems, so its mere presence
#                                is worth a look
#   PRE-LDSO-BADLIB      HIGH    a library named in ld.so.preload is missing,
#                                world-writable, not root-owned, or lives outside
#                                a standard library directory
#   PRE-ENV-PRELOAD      MEDIUM  LD_PRELOAD is set in a running process's
#                                environment
#   PRE-ENV-BADLIB       HIGH    a library named in a process's LD_PRELOAD is
#                                world-writable, not root-owned, or outside a
#                                standard library directory
#   PRE-CONFIG-PRELOAD   MEDIUM  LD_PRELOAD exported from a shell profile, an
#                                environment file, or a systemd drop-in
#   PRE-MAPPED-TEMP      HIGH    a shared object mapped into a running process is
#                                loaded from a temp or world-writable directory
#
# Scores are additive per subject, using the suite weights HIGH=5.0, MEDIUM=2.0,
# LOW=1.0, INFO=0.5.
#
# Forensic notes
# --------------
#   * Read-only. Nothing under the target is written, renamed or executed. The
#     only writes are to --output. Preloaded objects are described from metadata
#     and hashed for the record; they are never loaded or run by this tool.
#   * Requires root to read other processes' environ and maps. Unprivileged, the
#     environment and mapping checks see only your own processes; the summary
#     records the coverage gap.
#   * A rootkit already resident can lie to this tool as it lies to others. A
#     clean result narrows the field; it does not clear the host.
#
# Author: Halkyn Consulting - Friday Threat Hunting series.
# Licence: MIT. Original code; no third-party code included.

set -u

PROGRAM="preload-check"
VERSION="1.0.0"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
if [ -r "$SCRIPT_DIR/hunterlib.sh" ]; then
    . "$SCRIPT_DIR/hunterlib.sh"
elif [ -r "$SCRIPT_DIR/hunterlib/hunterlib.sh" ]; then
    . "$SCRIPT_DIR/hunterlib/hunterlib.sh"
else
    printf 'ERROR: hunterlib.sh not found next to %s\n' "$PROGRAM" >&2
    exit 2
fi

OUT_DIR=""
FORCE=0
CASE_REF=""; EXAMINER=""; SOURCE_ID=""
VERBOSE=0; QUIET=0
FS_ROOT=""          # examine a mounted image rooted here (files only; no live procs)
PROC_ROOT="/proc"

# Directories from which a preloaded library is legitimate. Anything outside
# these is suspicious for a preload target.
STD_LIB_DIRS="/lib /lib64 /usr/lib /usr/lib64 /usr/local/lib /usr/local/lib64 /lib/x86_64-linux-gnu /usr/lib/x86_64-linux-gnu /lib/aarch64-linux-gnu /usr/lib/aarch64-linux-gnu"
TEMP_PREFIXES="/tmp /dev/shm /var/tmp /run /var/run /home"

# Files that legitimately (and illegitimately) export environment for shells and
# services. Relative to the filesystem root.
ENV_CONFIG_FILES="etc/environment etc/profile etc/bash.bashrc etc/zsh/zshenv"
ENV_CONFIG_GLOBS="etc/profile.d etc/ld.so.conf.d"

usage() {
    cat <<'EOF'
preload-check - LD_PRELOAD / ld.so.preload rootkit detector (Bash, read-only)

USAGE
    preload-check.sh -o DIR [--fs-root DIR] [--proc DIR] [options]

HUNT HYPOTHESIS
    Userland rootkits most often inject through the dynamic linker: a library
    named in /etc/ld.so.preload or exported via LD_PRELOAD is mapped into every
    program that starts. This tool inspects the preload file, process
    environments, shell/service config, and the libraries actually mapped into
    running processes, and flags any preloaded object that is not where a
    legitimate one would be.

TARGET SELECTION
    --fs-root DIR         Examine a mounted image rooted here (reads files such
                          as etc/ld.so.preload and shell profiles under it).
                          Live process checks are skipped for an image.
    --proc DIR            Proc directory for the live process checks
                          (default /proc).

OUTPUT AND CASE METADATA
    -o, --output DIR      Output directory (required). Refused if inside a scan
                          root, or non-empty without --force.
    --force               Permit writing into an existing non-empty directory.
    --case TEXT           Case or incident reference.
    --examiner TEXT       Examiner or operator name.
    --source-id TEXT      Evidence or host identifier.

BEHAVIOUR
    -v, --verbose         Per-item detail on stderr.
    -q, --quiet           Suppress console output. Files are still written.
    -V, --version         Print version and exit.
    -h, --help            This help.

OUTPUTS (in --output)
    preload-check.log   Timestamped audit/action log
    findings.tsv        score severity rule_id subject source detail evidence sha256
    summary.txt         Counts, coverage, caveat
    SHA256SUMS          SHA-256 manifest of the output artefacts

EXIT STATUS
    0  nothing flagged               2  invalid use / unsafe path
    1  findings recorded             130 interrupted

EXAMPLES
    sudo ./preload-check.sh -o /cases/host01/preload --case IR-2026-041
    ./preload-check.sh --fs-root /mnt/image -o /cases/host01/preload

LIMITS
    Linux-only. A resident rootkit can hide from this tool. A clean result
    narrows the field; it does not clear the host.

Findings are investigative leads, not proof of compromise.
EOF
}

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            -o|--output) [ $# -ge 2 ] || hl_die "--output requires a directory"
                OUT_DIR="$2"; shift 2 ;;
            --force) FORCE=1; shift ;;
            --fs-root) [ $# -ge 2 ] || hl_die "--fs-root requires a directory"
                FS_ROOT="$2"; shift 2 ;;
            --proc) [ $# -ge 2 ] || hl_die "--proc requires a directory"
                PROC_ROOT="$2"; shift 2 ;;
            --case) [ $# -ge 2 ] || hl_die "--case requires text"
                CASE_REF="$2"; shift 2 ;;
            --examiner) [ $# -ge 2 ] || hl_die "--examiner requires text"
                EXAMINER="$2"; shift 2 ;;
            --source-id) [ $# -ge 2 ] || hl_die "--source-id requires text"
                SOURCE_ID="$2"; shift 2 ;;
            -v|--verbose) VERBOSE=1; shift ;;
            -q|--quiet) QUIET=1; shift ;;
            -V|--version) printf '%s %s\n' "$PROGRAM" "$VERSION"; exit 0 ;;
            -h|--help) usage; exit 0 ;;
            --) shift; break ;;
            -*) hl_die "unknown option: $1 (use -h for help)" ;;
            *) hl_die "unexpected argument: $1 (use -h for help)" ;;
        esac
    done
}

# --------------------------------------------------------------------------- #
# Reusable judgement: is a library path a legitimate preload target?
# Prints one of: ok | outside | temp | missing | worldwrite | nonroot
# These functions are the reusable core other tools can source.
# --------------------------------------------------------------------------- #

pc_on_disk() {  # map an in-evidence path to the analysis-host path
    [ -n "$1" ] || return 0
    if [ -n "$FS_ROOT" ]; then printf '%s%s' "${FS_ROOT%/}" "$1"; else printf '%s' "$1"; fi
}

pc_in_std_dir() {
    local lib="$1" d
    for d in $STD_LIB_DIRS; do
        case "$lib" in "$d"/*) return 0 ;; esac
    done
    return 1
}

pc_in_temp() {
    local lib="$1" d
    for d in $TEMP_PREFIXES; do
        case "$lib" in "$d"/*) return 0 ;; esac
    done
    return 1
}

# pc_judge_lib LIBPATH - classify a preload target. LIBPATH is as written in the
# preload file / environment (an absolute path, or a bare soname).
pc_judge_lib() {
    local lib="$1" disk fields uid mode
    # A bare soname (no slash) is resolved by the loader's search path and is the
    # normal, legitimate form; only a path tells us where it really is.
    case "$lib" in
        */*) : ;;
        *)   printf 'soname'; return 0 ;;
    esac
    if pc_in_temp "$lib"; then printf 'temp'; return 0; fi
    disk=$(pc_on_disk "$lib")
    if [ ! -e "$disk" ]; then printf 'missing'; return 0; fi
    fields=$(hl_stat_fields "$disk")
    mode=$(printf '%s' "$fields" | cut -f1)
    uid=$(printf '%s' "$fields" | cut -f2)
    if [ -n "$mode" ] && hl_world_writable "$mode"; then printf 'worldwrite'; return 0; fi
    if [ -n "$uid" ] && [ "$uid" != "0" ]; then printf 'nonroot'; return 0; fi
    if ! pc_in_std_dir "$lib"; then printf 'outside'; return 0; fi
    printf 'ok'
}

pc_lib_sha() {
    local disk; disk=$(pc_on_disk "$1")
    [ -f "$disk" ] && hl_sha256 "$disk" || printf ''
}

# Emit a finding for a bad library verdict; shared by the file and env checks.
pc_flag_lib() {  # subject rule_base source lib verdict
    local subject="$1" rule="$2" source="$3" lib="$4" verdict="$5" sha
    sha=$(pc_lib_sha "$lib")
    case "$verdict" in
        temp)       hl_finding "$subject" "HIGH" "$rule" "$subject" "$source" \
                        "preload library '$lib' loads from a temp/world-writable path" "$lib" "$sha" ;;
        missing)    hl_finding "$subject" "HIGH" "$rule" "$subject" "$source" \
                        "preload library '$lib' does not exist on disk" "$lib" "$sha" ;;
        worldwrite) hl_finding "$subject" "HIGH" "$rule" "$subject" "$source" \
                        "preload library '$lib' is world-writable" "$lib" "$sha" ;;
        nonroot)    hl_finding "$subject" "HIGH" "$rule" "$subject" "$source" \
                        "preload library '$lib' is not owned by root" "$lib" "$sha" ;;
        outside)    hl_finding "$subject" "HIGH" "$rule" "$subject" "$source" \
                        "preload library '$lib' is outside the standard library directories" "$lib" "$sha" ;;
        *) return 0 ;;
    esac
}

# --------------------------------------------------------------------------- #
# Checks
# --------------------------------------------------------------------------- #

# /etc/ld.so.preload
check_ldso_preload() {
    local f disk line lib verdict
    f="/etc/ld.so.preload"
    disk=$(pc_on_disk "$f")
    if [ ! -e "$disk" ]; then
        hl_info "ld.so.preload absent (normal)"
        return 0
    fi
    local sha; sha=$(hl_sha256 "$disk")
    hl_finding "$f" "MEDIUM" "PRE-LDSO-PRESENT" "$f" "ld.so.preload" \
        "$f exists; it is absent on most healthy hosts" "$(pc_on_disk "$f")" "$sha"
    # Each whitespace/newline-separated entry is a library the loader injects.
    while IFS= read -r line || [ -n "$line" ]; do
        for lib in $line; do
            [ -n "$lib" ] || continue
            case "$lib" in \#*) continue ;; esac
            verdict=$(pc_judge_lib "$lib")
            [ "$verdict" = "ok" ] || [ "$verdict" = "soname" ] && \
                hl_detail "ld.so.preload lib $lib: $verdict" || true
            if [ "$verdict" != "ok" ] && [ "$verdict" != "soname" ]; then
                pc_flag_lib "$f" "PRE-LDSO-BADLIB" "ld.so.preload" "$lib" "$verdict"
            fi
        done
    done <"$disk"
}

# LD_PRELOAD in shell/service configuration files.
check_config_preload() {
    local base="${FS_ROOT%/}" rel f d
    for rel in $ENV_CONFIG_FILES; do
        f="$base/$rel"
        [ -r "$f" ] || continue
        if grep -Eq 'LD_PRELOAD[[:space:]]*=' "$f" 2>/dev/null; then
            local ev; ev=$(grep -E 'LD_PRELOAD[[:space:]]*=' "$f" | head -n1)
            hl_finding "/$rel" "MEDIUM" "PRE-CONFIG-PRELOAD" "/$rel" "config" \
                "LD_PRELOAD is exported from /$rel" "$(hl_scrub "$ev" 200)" ""
        fi
    done
    for rel in $ENV_CONFIG_GLOBS; do
        d="$base/$rel"
        [ -d "$d" ] || continue
        while IFS= read -r f; do
            [ -r "$f" ] || continue
            if grep -Eq 'LD_PRELOAD[[:space:]]*=' "$f" 2>/dev/null; then
                local rp="${f#"$base"/}"
                hl_finding "/$rp" "MEDIUM" "PRE-CONFIG-PRELOAD" "/$rp" "config" \
                    "LD_PRELOAD is exported from /$rp" \
                    "$(grep -E 'LD_PRELOAD[[:space:]]*=' "$f" | head -n1 | (read -r l; hl_scrub "$l" 200))" ""
            fi
        done < <(find "$d" -maxdepth 1 -type f 2>/dev/null)
    done
    # systemd drop-ins occasionally carry Environment=LD_PRELOAD=...
    local sd="$base/etc/systemd/system"
    if [ -d "$sd" ]; then
        while IFS= read -r f; do
            grep -Eq 'Environment=.*LD_PRELOAD' "$f" 2>/dev/null || continue
            local rp="${f#"$base"/}"
            hl_finding "/$rp" "MEDIUM" "PRE-CONFIG-PRELOAD" "/$rp" "config" \
                "LD_PRELOAD set in systemd unit /$rp" \
                "$(grep -E 'Environment=.*LD_PRELOAD' "$f" | head -n1 | (read -r l; hl_scrub "$l" 200))" ""
        done < <(find "$sd" -type f -name '*.conf' -o -type f -name '*.service' 2>/dev/null)
    fi
}

# LD_PRELOAD in the environment of running processes, and suspicious mapped libs.
check_live_processes() {
    if [ -n "$FS_ROOT" ]; then
        hl_info "--fs-root given: live process environment/maps checks skipped (image has no live processes)"
        return 0
    fi
    local pid environ preload lib verdict comm maps
    for pid in $(ls -1 -- "$PROC_ROOT" 2>/dev/null | grep -E '^[0-9]+$' | LC_ALL=C sort -n); do
        hl_interrupted && break
        environ="$PROC_ROOT/$pid/environ"
        if [ -r "$environ" ]; then
            preload=$(tr '\0' '\n' <"$environ" 2>/dev/null | grep -E '^LD_PRELOAD=' | head -n1 | cut -d= -f2-)
            if [ -n "$preload" ]; then
                comm=$([ -r "$PROC_ROOT/$pid/comm" ] && tr -d '\n' <"$PROC_ROOT/$pid/comm" || printf '?')
                hl_finding "pid:$pid" "MEDIUM" "PRE-ENV-PRELOAD" "pid:$pid" "env" \
                    "pid $pid ($comm) has LD_PRELOAD set in its environment" "$preload" ""
                for lib in $preload; do
                    [ -n "$lib" ] || continue
                    verdict=$(pc_judge_lib "$lib")
                    if [ "$verdict" != "ok" ] && [ "$verdict" != "soname" ]; then
                        pc_flag_lib "pid:$pid" "PRE-ENV-BADLIB" "env" "$lib" "$verdict"
                    fi
                done
            fi
        fi
        # Shared objects mapped from temp/world-writable directories.
        maps="$PROC_ROOT/$pid/maps"
        if [ -r "$maps" ]; then
            while IFS= read -r lib; do
                [ -n "$lib" ] || continue
                if pc_in_temp "$lib"; then
                    comm=$([ -r "$PROC_ROOT/$pid/comm" ] && tr -d '\n' <"$PROC_ROOT/$pid/comm" || printf '?')
                    hl_finding "pid:$pid" "HIGH" "PRE-MAPPED-TEMP" "pid:$pid" "maps" \
                        "pid $pid ($comm) has a shared object mapped from a temp/world-writable path" \
                        "$lib" "$(pc_lib_sha "$lib")"
                fi
            done < <(awk '$0 ~ /\.so/ && $6 ~ /^\// {print $6}' "$maps" 2>/dev/null \
                     | LC_ALL=C sort -u)
        fi
    done
}

main() {
    local raw_args
    raw_args=$(hl_command_line "$0" "$@")
    parse_args "$@"
    [ -n "$OUT_DIR" ] || hl_die "--output is required (use -h for help)"

    hl_date_init; hl_stat_init
    hl_hash_init || hl_die "no SHA-256 implementation found (need sha256sum, shasum or openssl)."

    if [ -n "$FS_ROOT" ]; then
        [ -d "$FS_ROOT" ] || hl_die "--fs-root is not a directory: $FS_ROOT"
        FS_ROOT=$(hl_abspath "$FS_ROOT")
    fi

    local outdir
    outdir=$(hl_resolve_output "$OUT_DIR" "$FORCE" ${FS_ROOT:+"$FS_ROOT"} "$PROC_ROOT")
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
    hl_ctx_set fs_root "${FS_ROOT:-(live host)}"
    hl_ctx_set proc_root "$PROC_ROOT"
    hl_ctx_set output_dir "$outdir"
    hl_ctx_set command "$raw_args"
    hl_log_header
    [ -n "$HL_OUTPUT_NOTE" ] && hl_warning "$HL_OUTPUT_NOTE" || true
    if [ -z "$FS_ROOT" ] && [ "$(id -u 2>/dev/null || echo 1)" != "0" ]; then
        hl_warning "running unprivileged: only your own processes' environ and maps are readable. Run as root for full coverage."
    fi

    hl_findings_init "$outdir/.findings.raw" \
        "score	severity	rule_id	subject	source	detail	evidence	sha256"

    hl_section "ld.so.preload"
    check_ldso_preload
    hl_section "shell and service configuration"
    check_config_preload
    hl_section "live processes"
    check_live_processes

    hl_section "writing reports"
    hl_findings_write "$outdir/findings.tsv"
    rm -f -- "$outdir/.findings.raw"

    hl_ctx_set completed_utc "$(hl_utc_now)"
    hl_ctx_set completion "$(hl_interrupted && echo interrupted || echo complete)"
    hl_summary_open "$outdir/summary.txt" "$PROGRAM" "$VERSION"
    hl_summary_kv "$outdir/summary.txt" "subjects flagged" "$HL_FLAGGED_COUNT"
    hl_summary_kv "$outdir/summary.txt" "findings" "$HL_FINDING_COUNT"
    hl_summary_kv "$outdir/summary.txt" "high" "$HL_HIGH_COUNT"
    hl_summary_kv "$outdir/summary.txt" "medium" "$HL_MEDIUM_COUNT"
    hl_summary_kv "$outdir/summary.txt" "low/info" "$HL_LOW_COUNT"
    {
        printf '\nRule reference:\n'
        if [ -s "$outdir/findings.tsv" ]; then
            awk -F'\t' 'NR>1{c[$3]++} END{for(k in c) printf "  %-20s %d\n", k, c[k]}' \
                "$outdir/findings.tsv" | LC_ALL=C sort
        fi
        printf '\nCoverage note: a resident rootkit can hide from this tool as it\n'
        printf 'hides from others. A clean result narrows the field; it does not\n'
        printf 'clear the host.\n'
    } >>"$outdir/summary.txt"
    hl_summary_caveat "$outdir/summary.txt"
    [ "$QUIET" -ne 1 ] && cat "$outdir/summary.txt" || true

    hl_section "run end"
    hl_info "flagged=$HL_FLAGGED_COUNT findings=$HL_FINDING_COUNT errors=$HL_ERROR_COUNT"
    hl_info "writing SHA256SUMS last; it covers this log, so this is the final log line"
    hl_log_close
    hl_write_manifest "$outdir" >/dev/null

    if [ "$QUIET" -ne 1 ]; then
        printf '\n%s complete. %d subject(s) flagged, %d finding(s).\n' \
            "$PROGRAM" "$HL_FLAGGED_COUNT" "$HL_FINDING_COUNT"
        printf 'Reports in: %s\n' "$outdir"
    fi

    if hl_interrupted; then return "$HL_EXIT_INTERRUPT"; fi
    [ "$HL_FINDING_COUNT" -gt 0 ] && return "$HL_EXIT_FINDINGS"
    return "$HL_EXIT_OK"
}

# Sourcing guard, so persist-hunter or a test can reuse the judgement functions
# without running a full hunt.
if [ "${PRELOAD_CHECK_LIB:-0}" != "1" ]; then
    main "$@"
    exit $?
fi
