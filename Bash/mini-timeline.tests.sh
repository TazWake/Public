#!/usr/bin/env bash
# mini-timeline.tests.sh - self-contained test runner for mini-timeline.py
# ========================================================================
# Builds a subtree with timestomped and normal files, runs mini-timeline, and
# asserts the anomalies are flagged, the MACB timeline is well-formed, access
# times are preserved, exit codes are correct, and SHA256SUMS verifies.
# Usage:  ./mini-timeline.tests.sh [path-to-mini-timeline.py]

set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
TOOL="${1:-$HERE/mini-timeline.py}"
WORK="$(mktemp -d)"
PASS=0; FAIL=0
trap 'rm -rf "$WORK"' EXIT
ok()  { PASS=$((PASS + 1)); printf '  ok   - %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf '  FAIL - %s\n' "$1"; }
has_rule() { cut -f3 "$1" | grep -qx "$2" && ok "$2 present" || bad "$2 missing"; }

# Fixture
mkdir -p "$WORK/web"
cd "$WORK/web"
echo aaa > a.txt; echo bbb > b.txt        # normal, with sub-second mtimes
sleep 1
echo "<?php eval(\$_POST[0]); ?>" > shell.php
touch -m -t 201901010000.00 shell.php     # backdated: zero ns among ns siblings
echo future > future.txt
touch -m -t 202901010000.00 future.txt    # future mtime -> ctime<mtime + future
cd "$WORK"

OUT="$WORK/out"
before=$(stat -c '%X' "$WORK/web/a.txt" 2>/dev/null || stat -f '%a' "$WORK/web/a.txt")
python3 "$TOOL" --root "$WORK/web" -o "$OUT" --not-before 2020-01-01 --quiet
rc=$?
F="$OUT/findings.tsv"
printf 'Test 1: timeline the fixture (exit %d)\n' "$rc"
[ "$rc" -eq 1 ] && ok "exit 1 (findings)" || bad "exit $rc, want 1"
has_rule "$F" "MT-FUTURE-STAMP"
has_rule "$F" "MT-CTIME-BEFORE-MTIME"
has_rule "$F" "MT-SUBSECOND-ZERO"
has_rule "$F" "MT-PREDATES-REFERENCE"
# backdated shell.php must be flagged (zeroed sub-second)
grep -q "shell.php" "$F" && ok "backdated shell.php flagged" || bad "shell.php not flagged"
# timeline well-formed: exploded MACB flags appear
awk -F'\t' 'NR>1 && $3 ~ /^[M.][A.][C.][B.]$/' "$OUT/timeline.tsv" | grep -q . \
    && ok "timeline has MACB flag column" || bad "timeline MACB column malformed"
# access time preserved by the walk (metadata-only)
after=$(stat -c '%X' "$WORK/web/a.txt" 2>/dev/null || stat -f '%a' "$WORK/web/a.txt")
[ "$before" = "$after" ] && ok "access time preserved (metadata-only walk)" \
    || bad "access time changed ($before -> $after)"
( cd "$OUT" && sha256sum -c SHA256SUMS >/dev/null 2>&1 ) && ok "SHA256SUMS verifies" \
    || bad "SHA256SUMS does not verify"

# Test 2: a clean subtree exits 0
mkdir -p "$WORK/clean/d"; echo x > "$WORK/clean/d/f"
python3 "$TOOL" --root "$WORK/clean" -o "$WORK/cout" --quiet
[ "$?" -eq 0 ] && ok "clean subtree exits 0" || bad "clean subtree did not exit 0"

# Test 3: safety guards
python3 "$TOOL" --root "$WORK/web" -o "$WORK/web/inside" -q >/dev/null 2>&1
[ "$?" -eq 2 ] && ok "refuses output inside scan root" || bad "did not refuse inside-root"
python3 "$TOOL" --root "$WORK/web" -o "$OUT" -q >/dev/null 2>&1
[ "$?" -eq 2 ] && ok "refuses non-empty output" || bad "did not refuse non-empty output"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
