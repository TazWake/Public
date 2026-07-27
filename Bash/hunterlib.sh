#!/usr/bin/env bash
# shellcheck shell=bash
#
# hunterlib.sh - shared helpers 
# ==============================
#
# This is the Bash half of `hunterlib`. It is the
# feature-aligned sibling of the Python helpers inside webshell-hunter.py, and
# it exists so every shell tool in the suite produces byte-comparable evidence:
# the same audit-log header, the same TSV findings contract, the same output
# safety rules, the same exit codes.
#
# It is VENDORED - copied into each tool's directory - rather than installed.
# A hunting tool must run on a locked-down IR host with nothing added, so there
# is no package to install and no import path to get wrong. The canonical copy
# lives in BuiltTools/hunterlib/; the copies beside each tool must stay
# identical to it (the test runners verify this).
#
# What it provides
# ----------------
#   Logging      hl_log_open, hl_info, hl_detail, hl_section, hl_warning,
#                hl_error, hl_log_header, hl_log_close
#   Context      hl_ctx_set, hl_ctx_get, hl_ctx_keys  (the case metadata that
#                appears in the log header and the summary)
#   Safety       hl_die, hl_resolve_output, hl_install_signals, hl_interrupted
#   Hashing      hl_hash_init, hl_sha256
#   Metadata     hl_stat_init, hl_stat_fields, hl_iso, hl_world_writable
#   Findings     hl_findings_init, hl_finding, hl_findings_write
#   Output       hl_write_manifest, hl_scrub, hl_summary_open, hl_summary_kv,
#                hl_summary_caveat
#
# Conventions it enforces
# -----------------------
#   * All timestamps UTC, ISO-8601 with a trailing Z.
#   * Findings are TSV with a fixed leading column order:
#         score  severity  rule_id  <subject columns...>  detail  evidence  sha256
#     `score` is the SUBJECT's total, additive across every rule that hit it,
#     using the weights HIGH=5.0, MEDIUM=2.0, LOW=1.0, INFO=0.5 - the same
#     weights webshell-hunter.py uses.
#   * Tabs, carriage returns and newlines are stripped from every field value,
#     and evidence is truncated, so one bad line can never break the table.
#   * Deterministic ordering: findings sort by score desc, then severity, then
#     subject. Same input, same bytes out.
#
# Exit codes (shared by every tool in the suite):
#   0 completed, no findings   1 completed, findings   2 usage/unsafe/incomplete
#   130 interrupted
#
# Author: Halkyn Consulting.
# Licence: MIT. Original code; no third-party code included.

HUNTERLIB_VERSION="1.0.0"

HL_EXIT_OK=0
HL_EXIT_FINDINGS=1
HL_EXIT_USAGE=2
HL_EXIT_INTERRUPT=130

# --------------------------------------------------------------------------- #
# Basics
# --------------------------------------------------------------------------- #

# hl_die MESSAGE - usage/safety error. Always exit 2, per the shared contract.
hl_die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit "$HL_EXIT_USAGE"
}

hl_have() { command -v "$1" >/dev/null 2>&1; }

hl_utc_now() { date -u +%Y-%m-%dT%H:%M:%SZ; }

# hl_iso EPOCH - epoch seconds to ISO-8601 UTC. Empty on failure, never fatal.
hl_iso() {
    local e="${1:-}"
    case "$e" in
        ''|*[!0-9-]*) printf '' ; return 0 ;;
    esac
    if [ "${HL_DATE_STYLE:-}" = "bsd" ]; then
        date -u -r "$e" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || printf ''
    else
        date -u -d "@$e" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || printf ''
    fi
}

hl_date_init() {
    if date -u -d @0 +%Y >/dev/null 2>&1; then
        HL_DATE_STYLE="gnu"
    elif date -u -r 0 +%Y >/dev/null 2>&1; then
        HL_DATE_STYLE="bsd"
    else
        HL_DATE_STYLE="none"
    fi
}

# hl_abspath PATH - absolute, symlink-resolved-for-directories path. No
# dependency on realpath(1), which is absent on several target userlands.
hl_abspath() {
    local p="$1" d b
    if [ -d "$p" ]; then
        ( cd -- "$p" 2>/dev/null && pwd -P ) || printf '%s\n' "$p"
        return 0
    fi
    d=$(dirname -- "$p")
    b=$(basename -- "$p")
    if [ -d "$d" ]; then
        d=$( cd -- "$d" 2>/dev/null && pwd -P ) || d=$(dirname -- "$p")
        case "$d" in
            /) printf '/%s\n' "$b" ;;
            *) printf '%s/%s\n' "$d" "$b" ;;
        esac
    else
        case "$p" in
            /*) printf '%s\n' "$p" ;;
            *)  printf '%s/%s\n' "$PWD" "$p" ;;
        esac
    fi
}

# hl_scrub VALUE [MAXLEN] - make a string safe to place in a TSV cell.
# Tabs and line breaks become spaces; the result is truncated. No forks.
hl_scrub() {
    local v="${1-}" max="${2:-400}"
    v=${v//$'\t'/ }
    v=${v//$'\r'/ }
    v=${v//$'\n'/ }
    if [ "${#v}" -gt "$max" ]; then
        v="${v:0:$max}..."
    fi
    printf '%s' "$v"
}

# --------------------------------------------------------------------------- #
# Hashing
# --------------------------------------------------------------------------- #

# hl_hash_init - pick a SHA-256 implementation. Returns 1 if none is available;
# the caller decides whether that is fatal (for evidence tools, it is).
hl_hash_init() {
    if hl_have sha256sum; then
        HL_HASH_STYLE="sha256sum"
    elif hl_have shasum; then
        HL_HASH_STYLE="shasum"
    elif hl_have openssl; then
        HL_HASH_STYLE="openssl"
    else
        HL_HASH_STYLE="none"
        return 1
    fi
    return 0
}

# hl_sha256 FILE - print the hex digest, or nothing if it cannot be read.
# Never fatal: an unreadable file is a logged skip, not the end of the run.
hl_sha256() {
    local f="$1" out=""
    [ -f "$f" ] || return 0
    [ -r "$f" ] || return 0
    case "${HL_HASH_STYLE:-none}" in
        sha256sum) out=$(sha256sum -- "$f" 2>/dev/null) || return 0 ;;
        shasum)    out=$(shasum -a 256 -- "$f" 2>/dev/null) || return 0 ;;
        openssl)   out=$(openssl dgst -sha256 -- "$f" 2>/dev/null) || return 0
                   out="${out##*= }" ; printf '%s' "$out" ; return 0 ;;
        *)         return 0 ;;
    esac
    printf '%s' "${out%% *}"
}

# hl_sha256_string STRING - digest of a literal string (used for entry keys).
hl_sha256_string() {
    local out=""
    case "${HL_HASH_STYLE:-none}" in
        sha256sum) out=$(printf '%s' "$1" | sha256sum 2>/dev/null) || return 0 ;;
        shasum)    out=$(printf '%s' "$1" | shasum -a 256 2>/dev/null) || return 0 ;;
        openssl)   out=$(printf '%s' "$1" | openssl dgst -sha256 2>/dev/null) || return 0
                   out="${out##*= }" ; printf '%s' "$out" ; return 0 ;;
        *)         return 0 ;;
    esac
    printf '%s' "${out%% *}"
}

# --------------------------------------------------------------------------- #
# Metadata (lstat semantics - symlinks are described, never followed)
# --------------------------------------------------------------------------- #

hl_stat_init() {
    if stat -c '%s' . >/dev/null 2>&1; then
        HL_STAT_STYLE="gnu"
    elif stat -f '%z' . >/dev/null 2>&1; then
        HL_STAT_STYLE="bsd"
    else
        HL_STAT_STYLE="none"
    fi
}

# hl_stat_fields PATH - print "mode<TAB>uid<TAB>gid<TAB>size<TAB>mtime_epoch".
# Empty fields where the platform does not expose the value. Does not follow
# symlinks, so a symlink is recorded as a symlink.
hl_stat_fields() {
    local p="$1"
    case "${HL_STAT_STYLE:-none}" in
        gnu) stat -c '%a	%u	%g	%s	%Y' -- "$p" 2>/dev/null || printf '\t\t\t\t' ;;
        bsd) stat -f '%Lp	%u	%g	%z	%m' -- "$p" 2>/dev/null || printf '\t\t\t\t' ;;
        *)   printf '\t\t\t\t' ;;
    esac
}

# hl_stat_dev PATH - filesystem device id, for mount-boundary checks. Empty if
# unavailable, which callers must treat as "cannot tell" (do not cross).
hl_stat_dev() {
    local p="$1"
    case "${HL_STAT_STYLE:-none}" in
        gnu) stat -c '%d' -- "$p" 2>/dev/null || printf '' ;;
        bsd) stat -f '%d' -- "$p" 2>/dev/null || printf '' ;;
        *)   printf '' ;;
    esac
}

# hl_world_writable MODE - true when the octal mode grants write to "other".
# Accepts 3- or 4-digit octal ("755", "1777"). Unknown input is not writable.
hl_world_writable() {
    local mode="${1:-}" last
    case "$mode" in
        ''|*[!0-7]*) return 1 ;;
    esac
    last="${mode: -1}"
    case "$last" in
        2|3|6|7) return 0 ;;
        *)       return 1 ;;
    esac
}

# --------------------------------------------------------------------------- #
# Case context (log header + summary)
# --------------------------------------------------------------------------- #

declare -a HL_CTX_ORDER=()
declare -A HL_CTX_VALUE=()

hl_ctx_set() {
    local k="$1" v="${2-}"
    if [ -z "${HL_CTX_VALUE[$k]+set}" ]; then
        HL_CTX_ORDER+=("$k")
    fi
    HL_CTX_VALUE["$k"]="$v"
}

hl_ctx_get() { printf '%s' "${HL_CTX_VALUE[$1]-}"; }

hl_ctx_keys() { printf '%s\n' "${HL_CTX_ORDER[@]}"; }

# --------------------------------------------------------------------------- #
# Audit log
# --------------------------------------------------------------------------- #
#
# Append-only within a run, UTC-timestamped, one line per significant action.
# Severity tags: INFO, DETAIL, SECTION, WARNING, ERROR. DETAIL is written to
# the file always but echoed only with -v; ERROR/WARNING echo to stderr.

HL_LOG_PATH=""
HL_LOG_ECHO=1
HL_LOG_VERBOSE=0
HL_ERROR_COUNT=0

hl_log_open() {
    HL_LOG_PATH="$1"
    HL_LOG_ECHO="${2:-1}"
    HL_LOG_VERBOSE="${3:-0}"
    : >>"$HL_LOG_PATH" || hl_die "cannot write audit log: $HL_LOG_PATH"
}

hl_log_write() {
    local level="$1"; shift
    local line
    line="$(hl_utc_now)	$level	$*"
    if [ -n "$HL_LOG_PATH" ]; then
        printf '%s\n' "$line" >>"$HL_LOG_PATH"
    fi
    if [ "$HL_LOG_ECHO" = "1" ]; then
        case "$level" in
            DETAIL) [ "$HL_LOG_VERBOSE" = "1" ] && printf '%s\n' "$line" >&2 || true ;;
            ERROR|WARNING) printf '%s\n' "$line" >&2 ;;
            *) printf '%s\n' "$line" ;;
        esac
    fi
}

hl_info()    { hl_log_write INFO "$@"; }
hl_detail()  { hl_log_write DETAIL "$@"; }
hl_warning() { hl_log_write WARNING "$@"; }
hl_error()   { HL_ERROR_COUNT=$((HL_ERROR_COUNT + 1)); hl_log_write ERROR "$@"; }
hl_section() { hl_log_write SECTION "--- $* ---"; }

# hl_log_header - the standard header block: who ran what, where, when.
hl_log_header() {
    local k
    hl_section "run start"
    for k in "${HL_CTX_ORDER[@]}"; do
        hl_info "$k = ${HL_CTX_VALUE[$k]}"
    done
}

hl_log_close() { HL_LOG_PATH=""; }

# hl_quote ARG - shell-ish quoting for recording the command line.
hl_quote() {
    case "$1" in
        *[[:space:]]*) printf '"%s"' "$1" ;;
        *) printf '%s' "$1" ;;
    esac
}

hl_command_line() {
    local out="" a
    for a in "$@"; do
        out="$out $(hl_quote "$a")"
    done
    printf '%s' "${out# }"
}

# --------------------------------------------------------------------------- #
# Interrupt handling
# --------------------------------------------------------------------------- #

HL_INTERRUPTED=0

hl_install_signals() {
    trap 'HL_INTERRUPTED=1' INT TERM
}

hl_interrupted() { [ "$HL_INTERRUPTED" = "1" ]; }

# --------------------------------------------------------------------------- #
# Output directory safety
# --------------------------------------------------------------------------- #

HL_OUTPUT_NOTE=""

# hl_resolve_output OUTDIR FORCE ROOT... - validate and create the output dir.
# Refuses to sit inside a scan root (self-ingestion and evidence contamination)
# and refuses a non-empty directory unless FORCE is 1. Prints the absolute path.
#
# A scan root of "/" is the one unavoidable exception: every path is inside it.
# In that case the containment check is skipped and a note is recorded, which
# the caller writes to the log so the compromise is visible in the evidence.
hl_resolve_output() {
    local outdir="$1" force="$2"; shift 2
    local root abs_root
    outdir=$(hl_abspath "$outdir")
    HL_OUTPUT_NOTE=""
    for root in "$@"; do
        [ -n "$root" ] || continue
        abs_root=$(hl_abspath "$root")
        if [ "$abs_root" = "/" ]; then
            HL_OUTPUT_NOTE="scan root is / - output directory containment check skipped; keep output on separate media where possible"
            continue
        fi
        if [ "$outdir" = "$abs_root" ] || case "$outdir" in "$abs_root"/*) true ;; *) false ;; esac; then
            hl_die "output directory $outdir is inside scan root $abs_root. Choose a location outside the target."
        fi
    done
    if [ -e "$outdir" ]; then
        [ -d "$outdir" ] || hl_die "output path exists and is not a directory: $outdir"
        if [ -n "$(ls -A -- "$outdir" 2>/dev/null)" ] && [ "$force" != "1" ]; then
            hl_die "output directory $outdir exists and is not empty. Choose a new directory or pass --force."
        fi
    else
        mkdir -p -- "$outdir" || hl_die "cannot create output directory: $outdir"
    fi
    printf '%s' "$outdir"
}

# --------------------------------------------------------------------------- #
# Findings
# --------------------------------------------------------------------------- #
#
# Findings accumulate in a raw spool keyed by SUBJECT (the thing being scored -
# a PID, a path, a persistence entry). At write time the per-subject score is
# summed across every rule that hit it, and rows are emitted in deterministic
# order. This mirrors webshell-hunter.py, where each finding row carries its
# candidate's total score.

HL_FINDINGS_RAW=""
HL_FINDINGS_HEADER=""
HL_FINDING_COUNT=0
HL_FLAGGED_COUNT=0
HL_HIGH_COUNT=0
HL_MEDIUM_COUNT=0
HL_LOW_COUNT=0

# hl_findings_init RAWFILE HEADER_TSV
hl_findings_init() {
    HL_FINDINGS_RAW="$1"
    HL_FINDINGS_HEADER="$2"
    : >"$HL_FINDINGS_RAW" || hl_die "cannot create findings spool: $HL_FINDINGS_RAW"
    HL_FINDING_COUNT=0
    HL_HIGH_COUNT=0; HL_MEDIUM_COUNT=0; HL_LOW_COUNT=0
}

# hl_finding SUBJECT SEVERITY RULE_ID FIELD... - record one finding.
# SUBJECT is the scoring key; the FIELDs are the tool's own columns, in the
# order declared in its findings header (after score/severity/rule_id).
hl_finding() {
    local subject="$1" severity="$2" rule="$3"; shift 3
    local line f
    line="$(hl_scrub "$subject" 512)	$severity	$rule"
    for f in "$@"; do
        line="$line	$(hl_scrub "$f")"
    done
    printf '%s\n' "$line" >>"$HL_FINDINGS_RAW"
    case "$severity" in
        HIGH)   HL_HIGH_COUNT=$((HL_HIGH_COUNT + 1)) ;;
        MEDIUM) HL_MEDIUM_COUNT=$((HL_MEDIUM_COUNT + 1)) ;;
        *)      HL_LOW_COUNT=$((HL_LOW_COUNT + 1)) ;;
    esac
    HL_FINDING_COUNT=$((HL_FINDING_COUNT + 1))
}

# hl_findings_write OUTFILE - sum scores, sort, and write the findings table.
# Sets HL_FINDING_COUNT (rows) and HL_FLAGGED_COUNT (distinct subjects).
hl_findings_write() {
    local out="$1" tmp
    tmp="${out}.tmp.$$"
    printf '%s\n' "$HL_FINDINGS_HEADER" >"$out"
    if [ ! -s "$HL_FINDINGS_RAW" ]; then
        HL_FINDING_COUNT=0
        HL_FLAGGED_COUNT=0
        return 0
    fi
    # Pass 1 sums the severity weights per subject; pass 2 emits sortable rows.
    awk -F'\t' -v OFS='\t' '
        BEGIN {
            w["HIGH"] = 5.0; w["MEDIUM"] = 2.0; w["LOW"] = 1.0; w["INFO"] = 0.5;
            o["HIGH"] = 0;   o["MEDIUM"] = 1;   o["LOW"] = 2;   o["INFO"] = 3;
        }
        NR == FNR { score[$1] += w[$2]; next }
        {
            s = score[$1];
            row = sprintf("%.1f\t%s\t%s", s, $2, $3);
            for (i = 4; i <= NF; i++) row = row OFS $i;
            # sort keys: score descending, then severity, then subject
            printf "%012.1f\t%d\t%s\t%s\n", (100000 - s), o[$2] + 0, $1, row;
        }
    ' "$HL_FINDINGS_RAW" "$HL_FINDINGS_RAW" \
        | LC_ALL=C sort -t'	' -k1,1 -k2,2n -k3,3 \
        | cut -f4- >"$tmp"
    cat "$tmp" >>"$out"
    rm -f -- "$tmp"
    HL_FINDING_COUNT=$(wc -l <"$HL_FINDINGS_RAW" | tr -d ' ')
    HL_FLAGGED_COUNT=$(cut -f1 "$HL_FINDINGS_RAW" | LC_ALL=C sort -u | wc -l | tr -d ' ')
    return 0
}

# --------------------------------------------------------------------------- #
# Summary and manifest
# --------------------------------------------------------------------------- #

hl_summary_open() {
    local file="$1" program="$2" version="$3" k
    {
        printf '%s %s - hunt summary\n' "$program" "$version"
        printf '%s\n' "================================================"
        for k in "${HL_CTX_ORDER[@]}"; do
            printf '%-18s %s\n' "$k:" "${HL_CTX_VALUE[$k]}"
        done
        printf '\n'
    } >"$file"
}

hl_summary_kv() {
    printf '%-18s %s\n' "$2:" "$3" >>"$1"
}

hl_summary_caveat() {
    {
        printf '\n'
        printf 'Reminder: findings are investigative leads, not proof of compromise.\n'
        printf 'Validate provenance and known-good state before acting.\n'
    } >>"$1"
}

# hl_write_manifest OUTDIR - SHA-256 of every artefact except the manifest.
# Written last, so the output set is tamper-evident. Format matches
# `sha256sum -c` so verification needs no special tooling.
hl_write_manifest() {
    local outdir="$1" f base digest manifest
    manifest="$outdir/SHA256SUMS"
    : >"$manifest"
    while IFS= read -r base; do
        f="$outdir/$base"
        [ -f "$f" ] || continue
        [ "$base" = "SHA256SUMS" ] && continue
        digest=$(hl_sha256 "$f")
        [ -n "$digest" ] || continue
        printf '%s  %s\n' "$digest" "$base" >>"$manifest"
    done < <(ls -A -- "$outdir" 2>/dev/null | LC_ALL=C sort)
    printf '%s' "$manifest"
}
