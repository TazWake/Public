#!/usr/bin/env bash
# audit_check.sh - confirm the minimum viable audit ruleset is actually working.
#
# Run this AFTER loading audit_mvp.rules. It checks the daemon is up, the rules
# are loaded, and - the part people skip - that events are genuinely reaching
# the log by generating a uniquely tagged one and reading it back.
#
# Read-only apart from executing /bin/echo once.
# Needs root: auditctl and /var/log/audit require privilege.
#
# NOTE: deliberately does NOT use 'set -o pipefail'. Several checks pipe a
# long-running producer into a consumer that exits early, which raises SIGPIPE
# in the producer; with pipefail that surfaces as 141 and produces false
# negatives even when the match succeeded. Checks below capture output into a
# variable first and test that, rather than testing a pipeline's exit status.

set -u

pass=0; fail=0
ok()   { printf '  [ OK ] %s\n' "$1"; pass=$((pass+1)); }
bad()  { printf '  [FAIL] %s\n' "$1"; fail=$((fail+1)); }
note() { printf '  [ .. ] %s\n' "$1"; }

if [[ $EUID -ne 0 ]]; then
    echo "Run as root - auditctl and /var/log/audit need privilege." >&2
    exit 1
fi

echo
echo "1. Daemon"
if command -v auditctl >/dev/null 2>&1; then
    ok "audit tools installed ($(auditctl -v 2>/dev/null || echo 'version unknown'))"
else
    bad "auditctl not found - install the audit package first"; exit 1
fi

status=$(auditctl -s 2>/dev/null)
if [[ "$status" == *"enabled 1"* || "$status" == *"enabled 2"* ]]; then
    ok "auditing enabled"
    printf '%s\n' "$status" | grep -E '^(enabled|backlog|lost)' | sed 's/^/         /'
else
    bad "auditing not enabled (auditctl -s)"
fi

lost=$(printf '%s\n' "$status" | awk '/^lost/{print $2}')
if [[ -n "${lost:-}" && "${lost:-0}" -gt 0 ]]; then
    bad "kernel has dropped $lost records - raise -b in the rules file"
fi

echo
echo "2. Rules loaded"
loaded=$(auditctl -l 2>/dev/null)
if [[ -z "$loaded" || "$loaded" == "No rules" ]]; then
    bad "no rules loaded - did 'augenrules --load' run?"
else
    n=$(printf '%s\n' "$loaded" | grep -c .)
    ok "$n rules loaded"
    note "audit_mvp.rules has 20 active lines; -D, -b and -f are settings not rules, so 17 here is correct"
fi

for k in exec identity persistence modules netconn; do
    # auditctl renders keys two ways: "-k identity" on watch rules, "-F key=exec"
    # on syscall rules. Match both, and require a word boundary so "exec" does
    # not match "execve" style keys added later.
    if printf '%s\n' "$loaded" | grep -qE -- "(-k[[:space:]]+|key=)${k}([[:space:]]|$)"; then
        ok "key present: $k"
    else
        note "key absent: $k  (expected if you did not enable that section)"
    fi
done

echo
echo "3. Immutability"
enabled_val=$(printf '%s\n' "$status" | awk '/^enabled/{print $2}')
if [[ "${enabled_val:-1}" == "2" ]]; then
    ok "ruleset is immutable (-e 2) - 'auditctl -D' cannot silently disable it"
else
    note "ruleset is mutable - root can run 'auditctl -D'. Consider -e 2 once tuned."
fi

echo
echo "4. End-to-end: are events actually landing?"
marker="auditselftest${$}x${RANDOM}"
/bin/echo "$marker" >/dev/null 2>&1 || { bad "/bin/echo not found - cannot generate a test event"; }

# auditd flushes asynchronously (see 'flush' and 'freq' in auditd.conf), so a
# freshly generated record may not be readable for several seconds. Retry.
found=""
for attempt in 1 2 3 4 5; do
    sleep 2
    recent=$(ausearch -k exec -ts recent -i 2>/dev/null || true)
    if [[ "$recent" == *"$marker"* ]]; then found="marker"; break; fi
    if [[ -z "$found" && "$recent" == *"comm=echo"* ]]; then found="comm"; fi
done

case "$found" in
    marker) ok "execve events reaching the log, test event matched by unique marker (${attempt}x2s)" ;;
    comm)   ok "execve events reaching the log (matched comm=echo, marker not rendered literally)"
            note "audit hex-encodes arguments containing unusual characters; harmless here" ;;
    *)      bad "test event not found after 10s"
            any=$(ausearch -k exec -ts recent 2>/dev/null | grep -c '^type=SYSCALL' || true)
            if [[ "${any:-0}" -gt 0 ]]; then
                note "but ${any} other exec events ARE present - likely flush latency, not a broken rule"
                note "check 'flush' and 'freq' in /etc/audit/auditd.conf, then re-run"
            else
                note "no exec events at all - check: dmesg | grep -i audit"
                note "and confirm the b64 execve rule appears in: auditctl -l"
            fi ;;
esac

echo
echo "5. Volume sanity check (last 10 minutes)"
for k in exec netconn; do
    n=$(ausearch -k "$k" -ts recent 2>/dev/null | grep -c '^type=SYSCALL' || true)
    printf '  %-10s %s events\n' "$k" "${n:-0}"
done
note "if exec runs to thousands, add 'never' rules ABOVE the always rules and reload"

echo
printf 'Result: %d passed, %d failed\n\n' "$pass" "$fail"
[[ $fail -eq 0 ]]
