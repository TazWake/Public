#!/bin/bash
#
# Converts a directory of systemd journal files into a merged plain text log
# and a CSV, optionally compressing both afterwards.
#
# Usage: systemdJournalConverter.sh <journal_dir> <output_dir> [gzip|xz]

set -euo pipefail

usage() { echo "Usage: $0 <journal_dir> <output_dir> [gzip|xz]" >&2; exit 2; }

[[ $# -ge 2 && $# -le 3 ]] || usage

JOURNALS="$1"
OUTPUT="$2"
COMPRESS="${3:-}"

[[ -z "$COMPRESS" || "$COMPRESS" == gzip || "$COMPRESS" == xz ]] || usage

for tool in journalctl python3 ${COMPRESS:+$COMPRESS}; do
    command -v "$tool" >/dev/null || { echo "Missing required tool: $tool" >&2; exit 1; }
done

# Journals are usually root/systemd-journal only, so fail early rather than
# part way through a long conversion.
[[ -d "$JOURNALS" && -r "$JOURNALS" && -x "$JOURNALS" ]] || { echo "Cannot read directory: $JOURNALS" >&2; exit 1; }
[[ -d "$OUTPUT" && -w "$OUTPUT" ]] || { echo "Cannot write to directory: $OUTPUT" >&2; exit 1; }

mapfile -t files < <(find "$JOURNALS" -maxdepth 1 -name '*.journal*' -type f)
(( ${#files[@]} )) || { echo "No journal files found in $JOURNALS" >&2; exit 1; }
for f in "${files[@]}"; do
    [[ -r "$f" ]] || { echo "Cannot read $f - re-run as root or a member of systemd-journal" >&2; exit 1; }
done
echo "Found ${#files[@]} journal file(s)."

# journalctl merges the whole directory in one pass, so there is no need to
# spawn a process per file. The text and CSV passes run concurrently.
echo "Converting to text and CSV..."
journalctl --no-pager -D "$JOURNALS" -o short-iso > "$OUTPUT/journal.txt" &
text_pid=$!

journalctl --no-pager -D "$JOURNALS" -o json | python3 -c '
import csv, json, sys
from datetime import datetime, timezone
fields = ["_HOSTNAME", "SYSLOG_IDENTIFIER", "_PID", "PRIORITY", "_SYSTEMD_UNIT"]
w = csv.writer(sys.stdout)
w.writerow(["timestamp", "hostname", "identifier", "pid", "priority", "unit", "message"])
for line in sys.stdin:
    try:
        e = json.loads(line)
    except ValueError:
        continue
    ts = e.get("__REALTIME_TIMESTAMP")
    ts = datetime.fromtimestamp(int(ts) / 1e6, timezone.utc).isoformat() if ts else ""
    msg = e.get("MESSAGE", "")
    if isinstance(msg, list):  # non-UTF8 messages arrive as byte arrays
        msg = bytes(msg).decode("utf-8", "replace")
    w.writerow([ts] + [e.get(f, "") for f in fields] + [msg])
' > "$OUTPUT/journal.csv"

wait "$text_pid"

if [[ -n "$COMPRESS" ]]; then
    echo "Compressing with $COMPRESS..."
    opts=(-f)
    if [[ "$COMPRESS" == xz ]]; then opts+=(-T0); fi  # parallel compression
    "$COMPRESS" "${opts[@]}" "$OUTPUT/journal.txt" &
    "$COMPRESS" "${opts[@]}" "$OUTPUT/journal.csv" &
    wait
fi

echo "Done. Output written to $OUTPUT"
