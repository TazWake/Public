#!/usr/bin/env bash
# mvp_audit_check.sh - confirm the minimum viable audit ruleset is actually working.
#
# Run this AFTER loading audit_mvp.rules. It checks the daemon is up, the rules
# are loaded, and - the part people skip - that events are genuinely reaching
# the log by generating a harmless one and reading it back.
#
# Read-only apart from one benign command execution and one temp file.
# Needs root to read /var/log/audit and query auditctl.

set -uo pipefail

pass=0; fail=0
ok()   { printf '  [ OK ] %s\n' "$1"; pass=$((pass+1)); }
bad()  { printf '  [FAIL] %s\n' "$1"; fail=$((fail+1)); }
note() { printf '  [ .. ] %s\n' "$1"; }

if [[ $EUID -ne 0 ]]; then
    echo "Run as root - auditctl and /var/log/audit need privileges." >&2
    exit 1
fi

echo
echo "1. Daemon"
if command -v auditctl >/dev/null 2>&1; then
    ok "audit tools installed ($(auditctl -v 2>/dev/null || echo 'version unknown'))"
else
    bad "auditctl not found - install the audit package first"; exit 1
fi

if auditctl -s 2>/dev/null | grep -qE '^enabled [12]'; then
    ok "auditing enabled"
    auditctl -s 2>/dev/null | grep -E '^(enabled|backlog|lost)' | sed 's/^/         /'
else
    bad "auditing not enabled (auditctl -s)"
fi

echo
echo "2. Rules loaded"
loaded=$(auditctl -l 2>/dev/null)
if [[ "$loaded" == "No rules" || -z "$loaded" ]]; then
    bad "no rules loaded - did augenrules --load run?"
else
    ok "$(printf '%s\n' "$loaded" | wc -l) rules loaded"
fi

for k in exec identity persistence modules netconn; do
    if printf '%s\n' "$loaded" | grep -q -- "-k $k\|key=$k"; then
        ok "key present: $k"
    else
        note "key absent: $k  (expected if you did not enable that section)"
    fi
done

echo
echo "3. Immutability"
if printf '%s\n' "$loaded" | grep -q -- '-e 2' || [[ "$(auditctl -s 2>/dev/null | awk '/^enabled/{print $2}')" == "2" ]]; then
    ok "ruleset is immutable (-e 2) - auditctl -D cannot silently disable it"
else
    note "ruleset is mutable - root can run 'auditctl -D'. Consider -e 2 once tuned."
fi

echo
echo "4. End-to-end: are events actually landing?"
marker="audit-selftest-$$-$RANDOM"
tmp="/tmp/$marker"
: > "$tmp"                      # touch, to exercise nothing special
/bin/echo "$marker" >/dev/null  # a real execve of /bin/echo
sleep 2

if command -v ausearch >/dev/null 2>&1; then
    if ausearch -k exec -ts recent -i 2>/dev/null | grep -q 'echo'; then
        ok "execve events are reaching the audit log"
    else
        bad "no recent execve events found - rules loaded but nothing logged"
        note "check: dmesg | grep -i audit    and    auditctl -s | grep lost"
    fi
else
    bad "ausearch not found"
fi
rm -f "$tmp"

echo
echo "5. Volume sanity check (last hour)"
if command -v ausearch >/dev/null 2>&1; then
    for k in exec netconn; do
        n=$(ausearch -k "$k" -ts recent 2>/dev/null | grep -c '^type=SYSCALL' || true)
        printf '  %-10s %s events in the last 10 minutes\n' "$k" "${n:-0}"
    done
    note "if exec is in the thousands, add 'never' rules before the always rules"
fi

echo
printf 'Result: %d passed, %d failed\n\n' "$pass" "$fail"
[[ $fail -eq 0 ]]
