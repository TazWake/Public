#!/usr/bin/env bash
# auth-hunter.tests.sh - self-contained test runner for auth-hunter.py
# ====================================================================
#
# Builds a fixture tree of benign and deliberately suspicious authentication
# logs, runs auth-hunter against it, and asserts that the known-bad events are
# flagged, the known-good ones are not, the exit codes are correct, and the
# SHA256SUMS manifest verifies. No live-host dependency; runs anywhere Python 3
# and a POSIX shell do.
#
# Usage:  ./auth-hunter.tests.sh [path-to-auth-hunter.py]
# Exit:   0 all tests passed, 1 a test failed.

set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
TOOL="${1:-$HERE/auth-hunter.py}"
WORK="$(mktemp -d)"
PASS=0
FAIL=0

trap 'rm -rf "$WORK"' EXIT

ok()   { PASS=$((PASS + 1)); printf '  ok   - %s\n' "$1"; }
bad()  { FAIL=$((FAIL + 1)); printf '  FAIL - %s\n' "$1"; }
check_rule() {  # check_rule FINDINGS_FILE RULE_ID
    if cut -f3 "$1" | grep -qx "$2"; then ok "$2 present"; else bad "$2 missing"; fi
}
refute() {      # refute FINDINGS_FILE PATTERN DESC
    if grep -q "$2" "$1"; then bad "$3 (unexpected match: $2)"; else ok "$3"; fi
}

# --------------------------------------------------------------------------- #
# Fixture: a mounted-image-style tree under $WORK/img
# --------------------------------------------------------------------------- #
mkdir -p "$WORK/img/var/log"
LOG="$WORK/img/var/log/auth.log"
{
    echo "Aug  4 09:01:11 web01 sshd[1010]: Accepted publickey for taz from 10.0.0.5 port 51000 ssh2"
    echo "Aug  4 09:02:01 web01 sudo:     taz : TTY=pts/0 ; PWD=/home/taz ; USER=root ; COMMAND=/usr/bin/apt update"
    echo "Aug  4 10:15:00 web01 sshd[1044]: Accepted password for taz from 10.0.0.5 port 51044 ssh2"
    for i in 1 2 3 4 5 6; do
        printf 'Aug  4 23:%02d:%02d web01 sshd[20%02d]: Failed password for invalid user admin from 45.61.7.9 port 40%02d ssh2\n' \
            $((10 + i)) $((i * 3)) "$i" "$i"
    done
    echo "Aug  4 23:17:40 web01 sshd[2077]: Accepted password for admin from 45.61.7.9 port 4099 ssh2"
    echo "Aug  5 03:12:05 web01 sshd[2500]: Accepted password for root from 203.0.113.9 port 33001 ssh2"
    echo "Aug  5 03:13:01 web01 useradd[2530]: new user: name=svc, UID=0, GID=0, home=/home/svc, shell=/bin/bash"
    echo "Aug  5 03:13:02 web01 usermod[2531]: add 'svc' to group 'sudo'"
    echo "Aug  5 03:14:00 web01 su[2600]: pam_unix(su:session): session opened for user root(uid=0) by taz(uid=1000)"
    echo "Aug  4 08:00:00 web01 sshd[9999]: Accepted password for taz from 10.0.0.5 port 51999 ssh2"
} > "$LOG"
: > "$WORK/img/var/log/secure"            # empty log -> truncation signal
echo "10.0.0.0/24" > "$WORK/known.txt"    # known-good source network

# --------------------------------------------------------------------------- #
# Test 1: full hunt against the fixture
# --------------------------------------------------------------------------- #
OUT="$WORK/out"
python3 "$TOOL" --root "$WORK/img" -o "$OUT" --known-ips "$WORK/known.txt" \
    --no-wtmp --no-journal --year 2026 --quiet
rc=$?
F="$OUT/findings.tsv"
printf 'Test 1: hunt the fixture (exit %d)\n' "$rc"
[ "$rc" -eq 1 ] && ok "exit 1 (findings)" || bad "exit code $rc, want 1"
for r in AUTH-BRUTE-FORCE AUTH-BRUTE-SUCCESS AUTH-NEW-SOURCE-IP AUTH-ROOT-LOGIN \
         AUTH-ODD-HOURS AUTH-NEW-ACCOUNT AUTH-NEW-SUDOER AUTH-SU-ROOT \
         AUTH-TIME-REVERSAL AUTH-LOG-EMPTY; do
    check_rule "$F" "$r"
done
# The brute-success line must be HIGH and name the attacker IP.
if awk -F'\t' '$3=="AUTH-BRUTE-SUCCESS" && $2=="HIGH" && $4=="45.61.7.9"{f=1} END{exit !f}' "$F"; then
    ok "AUTH-BRUTE-SUCCESS is HIGH for 45.61.7.9"; else bad "AUTH-BRUTE-SUCCESS not HIGH/attacker"; fi
# Benign taz from the known host must never be flagged.
refute "$F" "10.0.0.5" "benign known-host logins not flagged"
# Manifest integrity.
( cd "$OUT" && sha256sum -c SHA256SUMS >/dev/null 2>&1 ) && ok "SHA256SUMS verifies" \
    || bad "SHA256SUMS does not verify"

# --------------------------------------------------------------------------- #
# Test 2: a clean log exits 0 with no findings
# --------------------------------------------------------------------------- #
mkdir -p "$WORK/clean/var/log"
echo "Aug  4 09:00:01 h sshd[1]: Accepted publickey for taz from 10.0.0.5 port 5 ssh2" \
    > "$WORK/clean/var/log/auth.log"
python3 "$TOOL" --root "$WORK/clean" -o "$WORK/cout" --known-ips "$WORK/known.txt" \
    --no-wtmp --no-journal --year 2026 --quiet
rc=$?
printf 'Test 2: clean log (exit %d)\n' "$rc"
[ "$rc" -eq 0 ] && ok "exit 0 (no findings)" || bad "exit code $rc, want 0"

# --------------------------------------------------------------------------- #
# Test 3: safety guards - inside-root refusal and non-empty refusal
# --------------------------------------------------------------------------- #
printf 'Test 3: output-directory safety\n'
python3 "$TOOL" --root "$WORK/img" -o "$WORK/img/inside" --no-wtmp --no-journal -q >/dev/null 2>&1
[ "$?" -eq 2 ] && ok "refuses output inside scan root (exit 2)" || bad "did not refuse inside-root output"
python3 "$TOOL" --root "$WORK/img" -o "$OUT" --no-wtmp --no-journal -q >/dev/null 2>&1
[ "$?" -eq 2 ] && ok "refuses non-empty output (exit 2)" || bad "did not refuse non-empty output"

# --------------------------------------------------------------------------- #
printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
