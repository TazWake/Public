#!/usr/bin/env bash
# hidden-hunter.tests.sh - self-contained test runner for hidden-hunter.sh
# ========================================================================
# An honest live filesystem cannot manufacture a hidden PID (direct access and
# readdir always agree), so the positive path is proven by unit-testing the
# detection helpers in isolation via the sourcing guard, plus a clean live run
# and the safety guards.
# Usage:  ./hidden-hunter.tests.sh [path-to-hidden-hunter.sh]

set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
TOOL="${1:-$HERE/hidden-hunter.sh}"
WORK="$(mktemp -d)"
PASS=0; FAIL=0
trap 'rm -rf "$WORK"' EXIT
ok()  { PASS=$((PASS + 1)); printf '  ok   - %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf '  FAIL - %s\n' "$1"; }
eq()  { [ "$2" = "$3" ] && ok "$1" || bad "$1 (got '$2', want '$3')"; }

printf 'Test 1: detection helpers (sourced)\n'
# shellcheck source=/dev/null
HIDDEN_HUNTER_LIB=1 . "$TOOL" 2>/dev/null
# a pid reachable (A) in both passes but absent from readdir (B) in both -> hidden
A1=$'100\n200\n4242'; B=$'100\n200'
eq "persistent hidden pid detected" "$(persistent_gap "$A1" "$B" "$A1" "$B")" "4242"
# a pid present in only one pass is a race and must be dropped
eq "transient pid filtered out" "$(persistent_gap "$A1" "$B" "$B" "$B")" ""
# port hex parsing: LISTEN (0A) on 0x1F90 = 8080, ignore ESTABLISHED (01)
mkdir -p "$WORK/fp/net"
printf '  sl local_address rem st\n  0: 0100007F:1F90 0:0 0A 0\n  1: 0100007F:0050 0:0 01 0\n' \
    > "$WORK/fp/net/tcp"
: > "$WORK/fp/net/tcp6"; : > "$WORK/fp/net/udp"; : > "$WORK/fp/net/udp6"
eq "procnet LISTEN port parsed" "$(PROC_ROOT="$WORK/fp" list_procnet_ports | tr '\n' ' ')" "8080 "

printf 'Test 2: clean live run exits 0\n'
( "$TOOL" -o "$WORK/out" --settle 1 --quiet >/dev/null 2>&1 )
rc=$?
[ "$rc" -eq 0 ] && ok "clean host exits 0 (no persistent gaps)" \
    || bad "clean host exit $rc, want 0 (residual race?)"
[ -f "$WORK/out/findings.tsv" ] && ok "findings.tsv written" || bad "no findings.tsv"
( cd "$WORK/out" && sha256sum -c SHA256SUMS >/dev/null 2>&1 ) && ok "SHA256SUMS verifies" \
    || bad "SHA256SUMS does not verify"

printf 'Test 3: safety guards\n'
( "$TOOL" -o "$WORK/out" --quiet >/dev/null 2>&1 )
[ "$?" -eq 2 ] && ok "refuses non-empty output (exit 2)" || bad "did not refuse non-empty output"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
