#!/usr/bin/env bash
# mini-ioc-scan.tests.sh - self-contained test runner for mini-ioc-scan.py
# ========================================================================
# Tests filename and hash indicators (stdlib, always available), the no-YARA
# degrade path or a real YARA match (depending on whether yara-python is
# installed), a clean tree, and the guards.
# Usage:  ./mini-ioc-scan.tests.sh [path-to-mini-ioc-scan.py]

set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
TOOL="${1:-$HERE/mini-ioc-scan.py}"
WORK="$(mktemp -d)"
PASS=0; FAIL=0
trap 'rm -rf "$WORK"' EXIT
ok()  { PASS=$((PASS + 1)); printf '  ok   - %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf '  FAIL - %s\n' "$1"; }
eq()  { [ "$2" = "$3" ] && ok "$1" || bad "$1 (got '$2', want '$3')"; }
has_rule() { cut -f3 "$1" | grep -qx "$2" && ok "$2 present" || bad "$2 missing"; }

# Fixture
mkdir -p "$WORK/web/uploads"
echo "malicious-payload" > "$WORK/web/uploads/shell.php"
echo "benign application code" > "$WORK/web/app.js"
echo "dropper bytes" > "$WORK/web/c99.php"
BADSHA=$(sha256sum "$WORK/web/uploads/shell.php" | cut -d' ' -f1)
BADMD5=$(md5sum "$WORK/web/c99.php" | cut -d' ' -f1)
printf '%s webshell\n%s dropper\n' "$BADSHA" "$BADMD5" > "$WORK/hashes.txt"
printf '*c99*.php\nshell.php\n' > "$WORK/names.txt"

printf 'Test 1: hash + filename indicators\n'
python3 "$TOOL" --root "$WORK/web" --hash-list "$WORK/hashes.txt" \
    --filename-ioc "$WORK/names.txt" -o "$WORK/o1" --quiet >/dev/null 2>&1
eq "exit 1 (findings)" "$?" "1"
has_rule "$WORK/o1/findings.tsv" "IOC-HASH"
has_rule "$WORK/o1/findings.tsv" "IOC-FILENAME"
grep -q "app.js" "$WORK/o1/findings.tsv" && bad "benign app.js wrongly flagged" \
    || ok "benign file not flagged"
# both bad files caught by hash
c=$(awk -F'\t' 'NR>1 && $3=="IOC-HASH"{print $4}' "$WORK/o1/findings.tsv" | sort -u | wc -l)
eq "both hash indicators matched" "$c" "2"
( cd "$WORK/o1" && sha256sum -c SHA256SUMS >/dev/null 2>&1 ) && ok "SHA256SUMS verifies" \
    || bad "SHA256SUMS does not verify"

printf 'Test 2: YARA path\n'
echo 'rule t { strings: $a = "malicious-payload" condition: $a }' > "$WORK/t.yar"
if python3 -c "import yara" 2>/dev/null; then
    python3 "$TOOL" --root "$WORK/web" --yara-rules "$WORK/t.yar" -o "$WORK/o2" \
        --quiet >/dev/null 2>&1
    eq "YARA match exits 1" "$?" "1"
    has_rule "$WORK/o2/findings.tsv" "IOC-YARA"
else
    # degrade path: warns and skips, does not crash
    out=$(python3 "$TOOL" --root "$WORK/web" --yara-rules "$WORK/t.yar" \
        -o "$WORK/o2" 2>&1)
    echo "$out" | grep -qi "yara.*not installed" && ok "degrades with clear warning" \
        || bad "degrade warning missing"
fi

printf 'Test 3: clean tree and usage guards\n'
mkdir -p "$WORK/clean"; echo hi > "$WORK/clean/ok.txt"
python3 "$TOOL" --root "$WORK/clean" --hash-list "$WORK/hashes.txt" \
    -o "$WORK/o3" --quiet >/dev/null 2>&1
eq "clean tree exits 0" "$?" "0"
python3 "$TOOL" --root "$WORK/clean" -o "$WORK/o4" >/dev/null 2>&1
eq "no indicators is a usage error" "$?" "2"
python3 "$TOOL" --root "$WORK/web" --hash-list "$WORK/hashes.txt" \
    -o "$WORK/o1" --quiet >/dev/null 2>&1
eq "refuses non-empty output" "$?" "2"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
