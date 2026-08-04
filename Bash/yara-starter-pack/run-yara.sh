#!/usr/bin/env bash
# run-yara.sh - runner for the Halkyn YARA starter pack
# =====================================================
# Applies the bundled rules to a target tree and produces the standard suite
# output contract (findings.tsv, inventory.tsv, summary.txt, log, SHA256SUMS).
#
# It does the sensible thing depending on what is installed:
#   * If mini-ioc-scan.py is available, it drives that (so YARA hits land in the
#     same findings.tsv format as every other tool, and hash/filename IOCs can
#     be added in the same run). This is the preferred path.
#   * Otherwise, if the `yara` command-line tool is installed, it runs that
#     directly and writes a simple findings.tsv.
#
# Usage:
#   ./run-yara.sh -o OUTDIR TARGET [extra mini-ioc-scan args...]
#   ./run-yara.sh --rules DIR -o OUTDIR TARGET
#
# Read-only: the target is never modified.

set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RULES_DIR="$HERE/rules"
OUT=""
TARGET=""
EXTRA=()

usage() {
    cat <<EOF
run-yara.sh - apply the Halkyn YARA starter pack to a tree (read-only)

USAGE
    run-yara.sh -o OUTDIR TARGET [--rules DIR] [extra args...]

OPTIONS
    -o, --output DIR   Output directory (required).
    --rules DIR        Rules directory (default: the bundled rules/).
    -h, --help         This help.

The target is scanned with the bundled rules. Extra arguments are passed
through to mini-ioc-scan.py when it is the engine (e.g. --hash-list FILE).
Findings are investigative leads, not proof of compromise.
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        -o|--output) OUT="$2"; shift 2 ;;
        --rules) RULES_DIR="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        --) shift; while [ $# -gt 0 ]; do EXTRA+=("$1"); shift; done ;;
        -*) EXTRA+=("$1"); shift ;;
        *) if [ -z "$TARGET" ]; then TARGET="$1"; else EXTRA+=("$1"); fi; shift ;;
    esac
done

[ -n "$OUT" ] || { printf 'ERROR: -o/--output is required\n' >&2; exit 2; }
[ -n "$TARGET" ] || { printf 'ERROR: a TARGET directory is required\n' >&2; exit 2; }
[ -d "$RULES_DIR" ] || { printf 'ERROR: rules directory not found: %s\n' "$RULES_DIR" >&2; exit 2; }

# Preferred path: drive mini-ioc-scan.py so output matches the rest of the suite.
SCANNER=""
for cand in "$HERE/mini-ioc-scan.py" "$HERE/../mini-ioc-scan.py"; do
    [ -r "$cand" ] && SCANNER="$cand" && break
done

if [ -n "$SCANNER" ] && python3 -c "import yara" 2>/dev/null; then
    exec python3 "$SCANNER" --root "$TARGET" --yara-rules "$RULES_DIR" -o "$OUT" \
        ${EXTRA[@]+"${EXTRA[@]}"}
fi

# Fallback path: the yara(1) CLI, if present.
if command -v yara >/dev/null 2>&1; then
    mkdir -p "$OUT" || { printf 'ERROR: cannot create %s\n' "$OUT" >&2; exit 2; }
    findings="$OUT/findings.tsv"
    printf 'severity\trule_id\tpath\n' >"$findings"
    hits=0
    while IFS= read -r rf; do
        # yara -r: recurse; -w: no warnings; prints "RULE path" per match.
        while IFS= read -r line; do
            [ -n "$line" ] || continue
            rule="${line%% *}"; path="${line#* }"
            printf 'HIGH\t%s\t%s\n' "$rule" "$path" >>"$findings"
            hits=$((hits + 1))
        done < <(yara -r -w "$rf" "$TARGET" 2>/dev/null)
    done < <(find "$RULES_DIR" -type f \( -name '*.yar' -o -name '*.yara' \))
    printf 'yara CLI run complete: %d match(es). Findings in %s\n' "$hits" "$findings"
    [ "$hits" -gt 0 ] && exit 1 || exit 0
fi

printf 'ERROR: no YARA engine available. Install yara-python (preferred, used\n' >&2
printf 'with mini-ioc-scan.py) or the yara command-line tool.\n' >&2
exit 2
