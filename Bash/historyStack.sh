#!/usr/bin/env bash

set -uo pipefail

usage() {
    cat <<'EOF'
Usage:
  stack_bashhistory.sh [OPTIONS] [IMAGE_DIR]

Description:
  Loops through supported disk images in IMAGE_DIR and runs:

    target-query -q -j -f hostname,bashhistory IMAGE

  It extracts bash history command strings from the JSON output and produces
  a stack-ranked list showing how many times each command appears across all
  processed images.

Supported image extensions:
  .E01
  .Ex01
  .raw
  .dd
  .img

Arguments:
  IMAGE_DIR
      Directory containing disk images.
      Defaults to the current directory if omitted.

Options:
  --clean
      Skip command entries that do not begin with one of:

        A-Z
        a-z
        0-9
        [

      This is useful for removing malformed, empty, or odd artefact entries.

  --strict
      Implies --clean.

      Only records the first term from each command line before stack ranking.

      Examples:
        "nano file.txt"       becomes "nano"
        "cat /etc/passwd"     becomes "cat"
        "[ -f /tmp/test ]"    becomes "["

  -h, --help
      Show this help message.

Examples:
  ./stack_bashhistory.sh /cases/images

  ./stack_bashhistory.sh --clean /cases/images

  ./stack_bashhistory.sh --strict /cases/images

Output:
  Prints two columns:

    TOTAL      COMMAND

Requirements:
  target-query
  jq

Notes:
  The script uses target-query JSON output because it is safer and less brittle
  than parsing the rendered record format.
EOF
}

CLEAN=0
STRICT=0
IMAGE_DIR="."

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)
            usage
            exit 0
            ;;
        --clean)
            CLEAN=1
            shift
            ;;
        --strict)
            STRICT=1
            CLEAN=1
            shift
            ;;
        --)
            shift
            break
            ;;
        -*)
            echo "ERROR: Unknown option: $1" >&2
            echo >&2
            usage >&2
            exit 1
            ;;
        *)
            IMAGE_DIR="$1"
            shift
            ;;
    esac
done

if [[ $# -gt 0 ]]; then
    echo "ERROR: Too many positional arguments." >&2
    echo >&2
    usage >&2
    exit 1
fi

if [[ ! -d "$IMAGE_DIR" ]]; then
    echo "ERROR: Not a directory: $IMAGE_DIR" >&2
    exit 1
fi

if ! command -v target-query >/dev/null 2>&1; then
    echo "ERROR: target-query not found in PATH" >&2
    exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
    echo "ERROR: jq not found in PATH" >&2
    exit 1
fi

TMPDIR="$(mktemp -d)"
COMMANDS_FILE="$TMPDIR/bashhistory_commands.txt"
ERRORS_FILE="$TMPDIR/target-query_errors.log"

trap 'rm -rf "$TMPDIR"' EXIT

: > "$COMMANDS_FILE"
: > "$ERRORS_FILE"

found=0

process_command() {
    local cmd="$1"

    # Escape carriage returns and embedded newlines defensively.
    cmd="${cmd//$'\r'/\\r}"
    cmd="${cmd//$'\n'/\\n}"

    if [[ "$CLEAN" -eq 1 ]]; then
        # Keep only entries beginning with a plausible shell command character.
        [[ "$cmd" =~ ^[A-Za-z0-9\[] ]] || return 0

        # Drop entries containing the literal characters: \040
        case "$cmd" in
            *\\040*) return 0 ;;
        esac
    fi

    if [[ "$STRICT" -eq 1 ]]; then
        # Keep only the first whitespace-delimited term.
        cmd="${cmd%%[[:space:]]*}"
    fi

    [[ -n "$cmd" ]] || return 0

    printf '%s\n' "$cmd" >> "$COMMANDS_FILE"
}

while IFS= read -r -d '' image; do
    found=$((found + 1))

    echo "[*] Processing: $image" >&2

    while IFS= read -r cmd; do
        process_command "$cmd"
    done < <(
        target-query -q -j -f hostname,bashhistory "$image" 2>>"$ERRORS_FILE" \
            | jq -r '
                select(._type == "record")
                | select(.command? != null)
                | .command
            '
    )

done < <(
    find "$IMAGE_DIR" -maxdepth 1 -type f \
        \( \
            -iname '*.E01' -o \
            -iname '*.Ex01' -o \
            -iname '*.raw' -o \
            -iname '*.dd' -o \
            -iname '*.img' \
        \) \
        -print0
)

if [[ "$found" -eq 0 ]]; then
    echo "ERROR: No supported disk images found in: $IMAGE_DIR" >&2
    echo "Supported extensions: .E01, .Ex01, .raw, .dd, .img" >&2
    exit 1
fi

if [[ ! -s "$COMMANDS_FILE" ]]; then
    echo "No bash history commands were extracted." >&2

    if [[ -s "$ERRORS_FILE" ]]; then
        echo
        echo "target-query errors:"
        cat "$ERRORS_FILE"
    fi

    exit 0
fi

printf "%10s  %s\n" "TOTAL" "COMMAND"
printf "%10s  %s\n" "-----" "-------"

LC_ALL=C sort "$COMMANDS_FILE" \
    | uniq -c \
    | sort -rn \
    | awk '
        {
            count=$1
            $1=""
            sub(/^ /, "")
            printf "%10d  %s\n", count, $0
        }
    '

if [[ -s "$ERRORS_FILE" ]]; then
    echo >&2
    echo "[!] Some target-query errors were captured during processing." >&2
fi
