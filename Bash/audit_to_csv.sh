#!/bin/bash
#
# Exports Linux audit records to CSV via ausearch, either from the host's live
# audit logs or from extracted logs supplied as a file or directory.
# Always requests --extra-keys, --extra-labels and --extra-time so the CSV
# carries the key, MAC label and broken-down time columns.
#
# Usage: audit_to_csv.sh [-i PATH] [-o FILE] [-m TYPES] [--auth] [-ts D T] [-te D T]

set -euo pipefail
shopt -s extglob

# Authentication and account-management record types, used by --auth.
AUTH_TYPES="USER_AUTH,USER_ACCT,USER_MGMT,USER_LOGIN,USER_LOGOUT,USER_START,USER_END,USER_CMD,USER_ERR,USER_CHAUTHTOK,CRED_ACQ,CRED_DISP,CRED_REFR,LOGIN,ACCT_LOCK,ACCT_UNLOCK,ANOM_LOGIN_FAILURES,ANOM_LOGIN_SESSIONS,GRP_AUTH,ADD_USER,DEL_USER,ADD_GROUP,DEL_GROUP,ROLE_ASSIGN,ROLE_REMOVE"

INPUT=""
OUTPUT=""
TYPES=""
declare -a EXTRA=()

usage() {
    cat >&2 <<EOF
Usage: $0 [options]

  -i, --input PATH     audit log file, or directory of extracted logs
                       (default: the host's own audit logs)
  -o, --output FILE    write CSV here (default: stdout)
  -m, --message TYPES  comma-separated record types, e.g. USER_AUTH,AVC
      --auth           shorthand for the authentication record types
  -ts, --start D [T]   start date/time, as accepted by ausearch
  -te, --end D [T]     end date/time, as accepted by ausearch
  -h, --help           this message

Exports all record types unless -m or --auth is given.
EOF
    exit "${1:-2}"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -i|--input)   INPUT="${2:?path required}"; shift 2 ;;
        -o|--output)  OUTPUT="${2:?file required}"; shift 2 ;;
        -m|--message) TYPES="${2:?types required}"; shift 2 ;;
        --auth)       TYPES="$AUTH_TYPES"; shift ;;
        # ausearch takes date and time as separate words; accept either form.
        -ts|--start|-te|--end)
            opt="$1"; shift
            [[ $# -gt 0 ]] || usage
            EXTRA+=("$opt" "$1"); shift
            # A bare HH:MM[:SS] following the date is a time, not the next flag.
            if [[ $# -gt 0 && "$1" =~ ^[0-9]{1,2}:[0-9]{2}(:[0-9]{2})?$ ]]; then
                EXTRA+=("$1"); shift
            fi
            ;;
        -h|--help)    usage 0 ;;
        *)            echo "Unknown option: $1" >&2; usage ;;
    esac
done

command -v ausearch >/dev/null || { echo "ausearch not found - install the audit/auditd package" >&2; exit 1; }

args=(--format csv --extra-keys --extra-labels --extra-time)
if [[ -n "$TYPES" ]]; then args+=(-m "$TYPES"); fi

# Decompress on the fly so gzipped/xz'd extracted evidence works untouched.
emit() {
    local f
    for f in "$@"; do
        case "$f" in
            *.gz) gzip -dc -- "$f" ;;
            *.xz) xz -dc -- "$f" ;;
            *.bz2) bzip2 -dc -- "$f" ;;
            *) cat -- "$f" ;;
        esac
    done
}

declare -a FILES=()
if [[ -z "$INPUT" ]]; then
    # Host logs. These are mode 0600 root-only, so check before ausearch does.
    [[ -r /var/log/audit/audit.log ]] || {
        echo "Cannot read /var/log/audit/audit.log - re-run with sudo, or use -i for extracted logs" >&2
        exit 1
    }
    args+=(--input-logs)
elif [[ -d "$INPUT" ]]; then
    # Rotated logs sort newest-first by number, so reverse for chronological order.
    mapfile -t FILES < <(find "$INPUT" -maxdepth 1 -type f -name 'audit.log*' | sort -V -r)
    (( ${#FILES[@]} )) || { echo "No audit.log* files in $INPUT" >&2; exit 1; }
elif [[ -f "$INPUT" ]]; then
    FILES=("$INPUT")
else
    echo "No such file or directory: $INPUT" >&2; exit 1
fi

for f in "${FILES[@]}"; do
    [[ -r "$f" ]] || { echo "Cannot read $f" >&2; exit 1; }
done

# A single uncompressed file goes straight to ausearch; anything else is streamed.
run() {
    if (( ${#FILES[@]} == 1 )) && [[ "${FILES[0]}" != *.@(gz|xz|bz2) ]]; then
        ausearch "${args[@]}" "${EXTRA[@]}" -if "${FILES[0]}"
    elif (( ${#FILES[@]} )); then
        emit "${FILES[@]}" | ausearch "${args[@]}" "${EXTRA[@]}"
    else
        ausearch "${args[@]}" "${EXTRA[@]}"
    fi
}

# ausearch exits 1 when nothing matches, which is not an error here.
set +e
if [[ -n "$OUTPUT" ]]; then
    run > "$OUTPUT"
else
    run
fi
status=$?
set -e

case $status in
    0)  if [[ -n "$OUTPUT" ]]; then
            lines=$(wc -l < "$OUTPUT")
            echo "Wrote $(( lines > 0 ? lines - 1 : 0 )) records to $OUTPUT" >&2
        fi ;;
    1)  # ausearch prints "<no matches>" on stdout; keep it out of the CSV.
        if [[ -n "$OUTPUT" ]]; then : > "$OUTPUT"; fi
        echo "No matching audit records found." >&2 ;;
    *)  echo "ausearch failed (exit $status)" >&2; exit "$status" ;;
esac
