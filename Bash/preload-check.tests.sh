#!/usr/bin/env bash
# preload-check.tests.sh - self-contained test runner for preload-check.sh
# ========================================================================
# Exercises the image (fs-root) path, the live-process path with a planted
# LD_PRELOAD, the reusable judgement functions, a clean host, and the guards.
# Usage:  ./preload-check.tests.sh [path-to-preload-check.sh]

set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
TOOL="${1:-$HERE/preload-check.sh}"
WORK="$(mktemp -d)"
PASS=0; FAIL=0
CLEANUP_PID=""
trap '[ -n "$CLEANUP_PID" ] && kill "$CLEANUP_PID" 2>/dev/null; rm -rf "$WORK"' EXIT
ok()  { PASS=$((PASS + 1)); printf '  ok   - %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf '  FAIL - %s\n' "$1"; }
eq()  { [ "$2" = "$3" ] && ok "$1" || bad "$1 (got '$2', want '$3')"; }
has_rule() { cut -f3 "$1" | grep -qx "$2" && ok "$2 present" || bad "$2 missing"; }

# --- Test 1: mounted-image path -------------------------------------------
mkdir -p "$WORK/img/etc/profile.d" "$WORK/img/tmp"
echo evil > "$WORK/img/tmp/evil.so"
printf '/tmp/evil.so\nlibfake.so\n' > "$WORK/img/etc/ld.so.preload"   # bad path + benign soname
printf 'export LD_PRELOAD=/tmp/evil.so\n' > "$WORK/img/etc/profile.d/bad.sh"
printf 'Test 1: mounted image\n'
"$TOOL" --fs-root "$WORK/img" -o "$WORK/o1" --quiet >/dev/null 2>&1
eq "image with malicious preload exits 1" "$?" "1"
has_rule "$WORK/o1/findings.tsv" "PRE-LDSO-PRESENT"
has_rule "$WORK/o1/findings.tsv" "PRE-LDSO-BADLIB"
has_rule "$WORK/o1/findings.tsv" "PRE-CONFIG-PRELOAD"
grep -q "libfake.so" "$WORK/o1/findings.tsv" && bad "benign soname wrongly flagged" \
    || ok "benign bare soname not flagged"
( cd "$WORK/o1" && sha256sum -c SHA256SUMS >/dev/null 2>&1 ) && ok "SHA256SUMS verifies" \
    || bad "SHA256SUMS does not verify"

# --- Test 2: live process with LD_PRELOAD ---------------------------------
printf 'Test 2: live process LD_PRELOAD\n'
echo notelf > "$WORK/evil2.so"
LD_PRELOAD="$WORK/evil2.so" sleep 30 &
CLEANUP_PID=$!
sleep 0.5
"$TOOL" -o "$WORK/o2" --quiet >/dev/null 2>&1
rc=$?
[ "$rc" -eq 1 ] && ok "live LD_PRELOAD process exits 1" || bad "live path exit $rc, want 1"
grep -q "pid:$CLEANUP_PID" "$WORK/o2/findings.tsv" && ok "planted LD_PRELOAD process detected" \
    || bad "planted process not detected"
has_rule "$WORK/o2/findings.tsv" "PRE-ENV-PRELOAD"
kill "$CLEANUP_PID" 2>/dev/null; CLEANUP_PID=""

# --- Test 3: reusable judgement (sourced) ---------------------------------
printf 'Test 3: reusable judgement functions\n'
# shellcheck source=/dev/null
PRELOAD_CHECK_LIB=1 . "$TOOL" 2>/dev/null
eq "bare soname is legitimate" "$(pc_judge_lib libc.so.6)" "soname"
eq "temp-path library flagged" "$(pc_judge_lib /tmp/x.so)" "temp"

# --- Test 4: clean host / image exits 0 -----------------------------------
printf 'Test 4: clean image\n'
mkdir -p "$WORK/clean/etc/profile.d"
echo 'export PATH=/usr/bin' > "$WORK/clean/etc/profile.d/ok.sh"
"$TOOL" --fs-root "$WORK/clean" -o "$WORK/o4" --quiet >/dev/null 2>&1
eq "clean image exits 0" "$?" "0"

# --- Test 5: guards --------------------------------------------------------
printf 'Test 5: safety guards\n'
"$TOOL" --fs-root "$WORK/img" -o "$WORK/o1" --quiet >/dev/null 2>&1
eq "refuses non-empty output" "$?" "2"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
