#!/usr/bin/env bash
# preload_check.sh - read-only triage for LD_PRELOAD / ld.so.preload userland hooking.
#
# Companion script for "LD_PRELOAD Rootkits" - https://for577.com/
#
# IMPORTANT: every check below reads through libc, so a rootkit that hooks
# open(), read() or readdir() can lie to this script. A clean result means
# "nothing obvious", never "clean". Confirm findings with a statically linked
# toolkit you brought with you.

set -uo pipefail
shopt -s nullglob

section() { printf '\n===== %s =====\n' "$1"; }
report()  { [[ -n "$1" ]] && printf '%s\n' "$1" || echo "none"; }

section "1. /etc/ld.so.preload"
if [[ -e /etc/ld.so.preload ]]; then
    stat -c 'file=%n size=%s mtime=%y ctime=%z' /etc/ld.so.preload
    report "$(grep -vE '^\s*(#|$)' /etc/ld.so.preload 2>/dev/null)"
else
    echo "not present"
fi

section "2. LD_* variables in live process environments"
hits=""
for env in /proc/[0-9]*/environ; do
    pid=${env%/environ}; pid=${pid#/proc/}
    hit=$(tr '\0' '\n' <"$env" 2>/dev/null | grep -E '^LD_(PRELOAD|AUDIT|LIBRARY_PATH)=') || continue
    comm=$(cat "/proc/$pid/comm" 2>/dev/null)
    hits+=$(printf '%-7s %-18s %s\n' "$pid" "${comm:-?}" "${hit//$'\n'/ | }")$'\n'
done
report "${hits%$'\n'}"

section "3. Mapped shared objects outside standard library paths"
report "$(awk 'NF>5 && /\.so/ { $1=$2=$3=$4=$5=""; sub(/^ +/,""); print }' \
    /proc/[0-9]*/maps 2>/dev/null | sort -u \
    | grep -Ev '^/(usr/)?lib(32|64|x32)?/|^/usr/local/lib/|^/snap/')"

section "4. Deleted files still mapped into running processes"
report "$(awk '/\(deleted\)/ { $1=$2=$3=$4=$5=""; sub(/^ +/,""); print }' \
    /proc/[0-9]*/maps 2>/dev/null | sort -u)"

section "5. Persistence locations that also set LD_PRELOAD"
report "$(grep -rslE '^[^#]*LD_PRELOAD' /etc/environment /etc/profile /etc/profile.d \
    /etc/systemd/system /etc/security/pam_env.conf 2>/dev/null)"

printf '\nDone. Verify any hit with a static binary, e.g. busybox-static cat /etc/ld.so.preload\n'
