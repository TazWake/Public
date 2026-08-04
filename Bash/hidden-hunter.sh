#!/usr/bin/env bash
# shellcheck shell=bash
#
# hidden-hunter.sh - cross-view process and port visibility checker
# =================================================================
#
# Hunt hypothesis
# ---------------
# A rootkit that hides a process or a port has to lie consistently to every tool
# that might reveal it - and consistency is hard. If `ps` and a direct /proc
# walk disagree about which PIDs exist, or if `ss` reports fewer listening
# sockets than the kernel's own /proc/net tables contain, then something is
# filtering one of those views. This tool does not trust any single source; it
# compares independent enumerations of the same truth and reports the gaps.
#
# It is a modern, dependency-free reimplementation of the idea behind unhide:
# take two ways of listing the same thing and diff them. No third-party code;
# the concept only. It reads only what the system exposes and writes nothing to
# the target.
#
# What it flags
# -------------
#   HID-PROC-PS-GAP      HIGH    a PID present in the /proc readdir listing but
#                                absent from `ps` output (a userland ps filtered it)
#   HID-PROC-HIDDEN      HIGH    a PID reachable by direct /proc/<pid> access or
#                                kill -0 but absent from the /proc readdir
#                                listing - the readdir of /proc is being filtered
#   HID-PORT-SS-GAP      HIGH    a listening socket in /proc/net that `ss`/
#                                `netstat` does not report (a userland filter)
#
# Where a cross-check cannot run because a tool (ps, ss) is missing, that is
# logged as a WARNING and noted in the summary as a coverage gap, rather than
# emitted as a finding - a gap in visibility is not a detection.
#
# Every discrepancy is re-checked after a short settle, because processes and
# sockets legitimately come and go between two enumerations. Only differences
# that persist across the re-check are reported, which removes the benign race
# that makes naive versions of this hunt unusable.
#
# Scores are additive per subject, using the suite weights HIGH=5.0, MEDIUM=2.0,
# LOW=1.0, INFO=0.5.
#
# Forensic notes
# --------------
#   * Read-only. The target is never written, and no process is signalled with
#     anything other than signal 0 (kill -0), which only tests for existence and
#     delivers nothing.
#   * Requires root for complete visibility: unprivileged, other users' PIDs and
#     some sockets are invisible to every view equally, so gaps there are not
#     reliable. The summary records whether the run was privileged.
#   * This hunt raises suspicion; it cannot clear a host. A kernel-module rootkit
#     can hide a PID from /proc AND from kill -0 at once, defeating the process
#     cross-check. Pair a clean result with other evidence.
#
# Author: Halkyn Consulting - Friday Threat Hunting series.
# Licence: MIT. Original code; no third-party code included.

set -u

PROGRAM="hidden-hunter"
VERSION="1.0.0"

# Locate and source the vendored shared library.
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
SETTLE=2
PROC_ROOT="/proc"

usage() {
    cat <<'EOF'
hidden-hunter - cross-view process and port visibility checker (Bash, read-only)

USAGE
    hidden-hunter.sh -o DIR [options]

HUNT HYPOTHESIS
    A rootkit that hides a PID or a port must fool every tool that could reveal
    it. This checker compares independent views of the same truth - ps versus a
    /proc walk, ss versus /proc/net - and reports what one view hides from
    another. Discrepancies are re-checked to drop benign races.

OUTPUT AND CASE METADATA
    -o, --output DIR      Output directory (required). Refused if it sits inside
                          a scan root, or is non-empty without --force.
    --force               Permit writing into an existing non-empty directory.
    --case TEXT           Case or incident reference.
    --examiner TEXT       Examiner or operator name.
    --source-id TEXT      Evidence or host identifier.

BEHAVIOUR
    --settle SECS         Seconds to wait before re-checking a discrepancy
                          (default 2). Higher is slower but drops more races.
    -v, --verbose         Per-item detail on stderr.
    -q, --quiet           Suppress console output. Files are still written.
    -V, --version         Print version and exit.
    -h, --help            This help.

OUTPUTS (in --output)
    hidden-hunter.log   Timestamped audit/action log
    findings.tsv        score severity rule_id subject kind detail evidence
    inventory.tsv       Each view's counts, for coverage
    summary.txt         Counts, coverage, caveat
    SHA256SUMS          SHA-256 manifest of the output artefacts

EXIT STATUS
    0  no discrepancies              2  invalid use / unsafe path
    1  discrepancies recorded        130 interrupted

EXAMPLE
    sudo ./hidden-hunter.sh -o /cases/host01/hidden --case IR-2026-041

LIMITS
    Linux-only: it depends on /proc and /proc/net. It raises suspicion; it does
    not clear a host. A kernel-module rootkit can hide from more than one view
    at once.

Findings are investigative leads, not proof of compromise.
EOF
}

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            -o|--output) [ $# -ge 2 ] || hl_die "--output requires a directory"
                OUT_DIR="$2"; shift 2 ;;
            --force) FORCE=1; shift ;;
            --case) [ $# -ge 2 ] || hl_die "--case requires text"
                CASE_REF="$2"; shift 2 ;;
            --examiner) [ $# -ge 2 ] || hl_die "--examiner requires text"
                EXAMINER="$2"; shift 2 ;;
            --source-id) [ $# -ge 2 ] || hl_die "--source-id requires text"
                SOURCE_ID="$2"; shift 2 ;;
            --settle) [ $# -ge 2 ] || hl_die "--settle requires seconds"
                case "$2" in ''|*[!0-9]*) hl_die "--settle must be a whole number" ;; esac
                SETTLE="$2"; shift 2 ;;
            --proc) [ $# -ge 2 ] || hl_die "--proc requires a directory"
                PROC_ROOT="$2"; shift 2 ;;
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
# Enumerators - each returns a sorted list on stdout
# --------------------------------------------------------------------------- #

# PIDs visible under /proc.
list_proc_pids() {
    ls -1 -- "$PROC_ROOT" 2>/dev/null | grep -E '^[0-9]+$' | LC_ALL=C sort -n
}

# PIDs visible to ps.
list_ps_pids() {
    ps -eo pid= 2>/dev/null | tr -d ' ' | grep -E '^[0-9]+$' | LC_ALL=C sort -n
}

# PIDs reachable by DIRECT access, probed across the plausible range: a pid
# counts if /proc/<pid> can be stat'd directly, or (on a live host) if it
# answers kill -0. This is the crux of the hunt. A rootkit that filters the
# readdir() of /proc, or hooks a userland ps, still leaves the process
# reachable by its exact path or by a signal - so a pid reachable this way but
# absent from the readdir listing has been deliberately hidden. Honest kernels
# make direct access and readdir agree, so this is silent on a clean host.
probe_pids() {
    local maxpid=32768 pid
    [ -r "$PROC_ROOT/sys/kernel/pid_max" ] && \
        maxpid=$(cat "$PROC_ROOT/sys/kernel/pid_max" 2>/dev/null || echo 32768)
    case "$maxpid" in ''|*[!0-9]*) maxpid=32768 ;; esac
    # Cap the probe so this stays fast on hosts with a huge pid_max.
    [ "$maxpid" -gt 200000 ] && maxpid=200000
    local live=0
    [ "$(hl_abspath "$PROC_ROOT")" = "/proc" ] && live=1
    for pid in $(seq 1 "$maxpid"); do
        if [ -e "$PROC_ROOT/$pid/stat" ]; then
            printf '%s\n' "$pid"
        elif [ "$live" -eq 1 ] && kill -0 "$pid" 2>/dev/null; then
            printf '%s\n' "$pid"
        fi
    done | LC_ALL=C sort -n
}

# Listening TCP/UDP local ports from ss or netstat (userland view).
list_ss_ports() {
    if hl_have ss; then
        ss -H -ltun 2>/dev/null | awk '{print $5}' | sed -E 's/.*:([0-9]+)$/\1/' \
            | grep -E '^[0-9]+$' | LC_ALL=C sort -n | uniq
    elif hl_have netstat; then
        netstat -ltun 2>/dev/null | awk 'NR>2{print $4}' | sed -E 's/.*:([0-9]+)$/\1/' \
            | grep -E '^[0-9]+$' | LC_ALL=C sort -n | uniq
    fi
}

# Listening ports directly from the kernel tables in /proc/net (kernel view).
# Column 2 is local_address as HEX_IP:HEX_PORT; state 0A is LISTEN for tcp, and
# udp entries are all "listening" in the sense of bound local ports.
list_procnet_ports() {
    local f
    for f in tcp tcp6; do
        [ -r "$PROC_ROOT/net/$f" ] || continue
        awk 'NR>1 && $4=="0A"{split($2,a,":"); print strtonum("0x" a[2])}' \
            "$PROC_ROOT/net/$f" 2>/dev/null
    done
    for f in udp udp6; do
        [ -r "$PROC_ROOT/net/$f" ] || continue
        awk 'NR>1{split($2,a,":"); print strtonum("0x" a[2])}' \
            "$PROC_ROOT/net/$f" 2>/dev/null
    done | grep -E '^[0-9]+$' | LC_ALL=C sort -n | uniq
}

# comm for a pid, for context in a finding.
pid_comm() {
    local p="$1"
    [ -r "$PROC_ROOT/$p/comm" ] && tr -d '\n' <"$PROC_ROOT/$p/comm" 2>/dev/null || printf '?'
}

# --------------------------------------------------------------------------- #
# Set difference: lines in $1 not in $2 (both numeric, C-collated, unique).
# --------------------------------------------------------------------------- #
only_in_first() {
    LC_ALL=C comm -23 <(printf '%s\n' "$1" | grep -E '^[0-9]+$' | LC_ALL=C sort -u) \
                       <(printf '%s\n' "$2" | grep -E '^[0-9]+$' | LC_ALL=C sort -u)
}

# persistent_gap A1 B1 A2 B2 - items in (A1 minus B1) that are ALSO in
# (A2 minus B2). Two enumerations are taken a settle apart; only discrepancies
# that survive both passes are real. Transient processes and sockets that come
# or go between the passes cancel out, which removes the benign race that makes
# a naive cross-check unusable on a live host.
persistent_gap() {
    LC_ALL=C comm -12 \
        <(only_in_first "$1" "$2") \
        <(only_in_first "$3" "$4")
}

HH_PS_COUNT=0; HH_PROC_COUNT=0; HH_SS_COUNT=0; HH_PROCNET_COUNT=0
HH_PROBE_DONE=0

main() {
    local raw_args
    raw_args=$(hl_command_line "$0" "$@")
    parse_args "$@"
    [ -n "$OUT_DIR" ] || hl_die "--output is required (use -h for help)"

    hl_date_init; hl_stat_init
    hl_hash_init || hl_die "no SHA-256 implementation found (need sha256sum, shasum or openssl)."

    [ -d "$PROC_ROOT" ] || hl_die "--proc directory not found: $PROC_ROOT"
    local live=0
    [ "$(hl_abspath "$PROC_ROOT")" = "/proc" ] && live=1

    local outdir
    outdir=$(hl_resolve_output "$OUT_DIR" "$FORCE" "$PROC_ROOT")
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
    hl_ctx_set proc_root "$PROC_ROOT"
    hl_ctx_set output_dir "$outdir"
    hl_ctx_set command "$raw_args"
    hl_log_header
    [ -n "$HL_OUTPUT_NOTE" ] && hl_warning "$HL_OUTPUT_NOTE" || true
    if [ "$(id -u 2>/dev/null || echo 1)" != "0" ]; then
        hl_warning "running unprivileged: process and socket views are equally incomplete, so gaps may be unreliable. Run as root for a trustworthy cross-check."
    fi

    hl_findings_init "$outdir/.findings.raw" \
        "score	severity	rule_id	subject	kind	detail	evidence"

    # Two enumerations of every view, a settle apart. Only discrepancies that
    # persist across both passes are reported (see persistent_gap): this is what
    # separates a hidden PID from a process that merely started or exited while
    # we were looking.
    hl_section "process visibility (two-pass)"
    local proc1 ps1 probe1 proc2 ps2 probe2 pid comm
    proc1=$(list_proc_pids)
    ps1=$(hl_have ps && list_ps_pids || printf '')
    probe1=$(probe_pids)
    if [ "$SETTLE" -gt 0 ]; then sleep "$SETTLE"; fi
    proc2=$(list_proc_pids)
    ps2=$(hl_have ps && list_ps_pids || printf '')
    probe2=$(probe_pids)
    HH_PROBE_DONE=1

    HH_PROC_COUNT=$(printf '%s\n' "$proc2" | grep -cE '^[0-9]+$' || true)
    HH_PS_COUNT=$(printf '%s\n' "$ps2" | grep -cE '^[0-9]+$' || true)

    if hl_have ps; then
        # PIDs present in /proc in BOTH passes but hidden from ps in BOTH.
        for pid in $(persistent_gap "$proc1" "$ps1" "$proc2" "$ps2"); do
            comm=$(pid_comm "$pid")
            hl_finding "pid:$pid" "HIGH" "HID-PROC-PS-GAP" \
                "pid:$pid" "process" \
                "pid $pid ($comm) is in $PROC_ROOT but persistently hidden from ps" \
                "present:/proc absent:ps (2 passes)"
        done
    else
        hl_warning "ps not available - the /proc-vs-ps cross-check did not run (coverage gap)"
    fi

    # PIDs reachable by direct /proc/<pid> access or kill -0 in BOTH passes, but
    # absent from the /proc readdir listing in BOTH: the readdir has been hooked.
    for pid in $(persistent_gap "$probe1" "$proc1" "$probe2" "$proc2"); do
        comm=$(pid_comm "$pid")
        hl_finding "pid:$pid" "HIGH" "HID-PROC-HIDDEN" \
            "pid:$pid" "process" \
            "pid $pid ($comm) is reachable by direct access but hidden from the $PROC_ROOT listing - readdir is being filtered" \
            "present:direct/kill-0 absent:readdir (2 passes)"
    done

    # ------------------------------------------------------------------- #
    # Port cross-checks (two-pass)
    # ------------------------------------------------------------------- #
    hl_section "port visibility (two-pass)"
    local pn1 ssp1 pn2 ssp2 port
    pn1=$(list_procnet_ports)
    ssp1=$( { hl_have ss || hl_have netstat; } && list_ss_ports || printf '')
    if [ "$SETTLE" -gt 0 ]; then sleep "$SETTLE"; fi
    pn2=$(list_procnet_ports)
    ssp2=$( { hl_have ss || hl_have netstat; } && list_ss_ports || printf '')
    HH_PROCNET_COUNT=$(printf '%s\n' "$pn2" | grep -cE '^[0-9]+$' || true)
    HH_SS_COUNT=$(printf '%s\n' "$ssp2" | grep -cE '^[0-9]+$' || true)
    if hl_have ss || hl_have netstat; then
        # ports LISTEN/bound in /proc/net in BOTH passes but hidden from ss in BOTH.
        for port in $(persistent_gap "$pn1" "$ssp1" "$pn2" "$ssp2"); do
            hl_finding "port:$port" "HIGH" "HID-PORT-SS-GAP" \
                "port:$port" "port" \
                "local port $port is LISTEN/bound in /proc/net but persistently hidden from ss/netstat" \
                "present:/proc/net absent:ss (2 passes)"
        done
    else
        hl_warning "neither ss nor netstat available - the port cross-check did not run (coverage gap)"
    fi

    # ------------------------------------------------------------------- #
    hl_section "writing reports"
    hl_findings_write "$outdir/findings.tsv"
    {
        printf 'view\tcount\n'
        printf 'proc_pids\t%s\n' "$HH_PROC_COUNT"
        printf 'ps_pids\t%s\n' "$HH_PS_COUNT"
        printf 'procnet_ports\t%s\n' "$HH_PROCNET_COUNT"
        printf 'ss_ports\t%s\n' "$HH_SS_COUNT"
        printf 'pid_probe_run\t%s\n' "$HH_PROBE_DONE"
    } >"$outdir/inventory.tsv"
    rm -f -- "$outdir/.findings.raw"

    hl_ctx_set completed_utc "$(hl_utc_now)"
    hl_ctx_set completion "$(hl_interrupted && echo interrupted || echo complete)"

    hl_summary_open "$outdir/summary.txt" "$PROGRAM" "$VERSION"
    hl_summary_kv "$outdir/summary.txt" "proc PIDs" "$HH_PROC_COUNT"
    hl_summary_kv "$outdir/summary.txt" "ps PIDs" "$HH_PS_COUNT"
    hl_summary_kv "$outdir/summary.txt" "procnet ports" "$HH_PROCNET_COUNT"
    hl_summary_kv "$outdir/summary.txt" "ss ports" "$HH_SS_COUNT"
    hl_summary_kv "$outdir/summary.txt" "subjects flagged" "$HL_FLAGGED_COUNT"
    hl_summary_kv "$outdir/summary.txt" "findings" "$HL_FINDING_COUNT"
    hl_summary_kv "$outdir/summary.txt" "high" "$HL_HIGH_COUNT"
    hl_summary_kv "$outdir/summary.txt" "medium" "$HL_MEDIUM_COUNT"
    hl_summary_kv "$outdir/summary.txt" "low/info" "$HL_LOW_COUNT"
    {
        printf '\nRule reference:\n'
        if [ -s "$outdir/findings.tsv" ]; then
            awk -F'\t' 'NR>1{c[$3]++} END{for(k in c) printf "  %-22s %d\n", k, c[k]}' \
                "$outdir/findings.tsv" | LC_ALL=C sort
        fi
        printf '\nCoverage note: this hunt raises suspicion, it does not clear a\n'
        printf 'host. A kernel-module rootkit can hide a PID from /proc AND from\n'
        printf 'kill -0 simultaneously, defeating the process cross-check.\n'
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

# Sourcing guard: when sourced with HIDDEN_HUNTER_LIB=1 the functions load but
# main does not run, so the detection helpers can be unit-tested directly. An
# honest live filesystem cannot manufacture a hidden PID, so testing the
# set-difference and parsing logic in isolation is the only reliable way to
# prove the positive path.
if [ "${HIDDEN_HUNTER_LIB:-0}" != "1" ]; then
    main "$@"
    exit $?
fi
