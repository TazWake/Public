# Halkyn YARA starter pack

Original, behaviour-based YARA rules for common Linux threats, plus a runner. Part of the Halkyn Consulting Friday Threat Hunting series. The rules encode published *concepts* — the primitives and shapes these threats rely on — and contain no third-party rule text. Licence: MIT.

## What's here

- `rules/webshells.yar` — PHP (request→eval/exec, and decode-and-execute obfuscation), JSP and ASPX web shells.
- `rules/linux_implants.yar` — reverse shells (`/dev/tcp`, `nc -e`, socat, python socket→pty), fetch-and-run droppers (`curl … | sh`), and coin miners (stratum/xmrig/cryptonight).
- `run-yara.sh` — applies the pack to a target tree and writes the standard suite output (`findings.tsv`, `inventory.tsv`, `summary.txt`, log, `SHA256SUMS`).
- `run-yara.tests.sh` — proves every rule fires on a matching fixture and that a benign corpus of real system files yields zero matches.

## Design principle

Every rule combines a **capability** (an exec/eval primitive, a shell-to-socket construct) with **context** (attacker-controllable request input, a `/dev/tcp` endpoint, a pool URL). A single dangerous string on its own is noisy; the combination is what the threat actually needs and what benign code rarely shows. This keeps the false-positive rate low — the rules are tested to zero hits against real framework and system files.

## Usage

```sh
# Preferred: drives mini-ioc-scan.py so hits land in the standard findings.tsv
./run-yara.sh -o /cases/host01/yara /var/www

# Add hash/filename indicators in the same run (passed through to the scanner)
./run-yara.sh -o /cases/host01/yara /var/www --hash-list known-bad.txt
```

Requires a YARA engine: `yara-python` (preferred, used via `mini-ioc-scan.py`) or the `yara` command-line tool. Read-only — the target is never modified. Findings are investigative leads, not proof of compromise.
