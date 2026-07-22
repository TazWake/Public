# AGENTS.md

Guidance for coding agents working in `D:\Development\Public`.

## Repository purpose

This is a public collection of tools, scripts, plugins, notes, notebooks, and containerized labs for incident responders, investigators, and other security professionals. It includes evidence collection and analysis utilities, Volatility plugins, synthetic evidence generators, and isolated training environments. All content is intended for authorized defensive security, forensic analysis, research, and education.

## Working conventions

- The host is Windows with PowerShell; run bash-only tooling through WSL2 or Docker.
- Read the relevant directory README before changing a tool. Consult `README.md` and `CLAUDE.md` for broader context and Bash conventions.
- Prefer small, focused changes and preserve established styles across Bash, PowerShell, Python, Go, C/C++, Lisp, notebooks, and container configuration.
- Use `rg` for search. In PowerShell, redirect to `$null`, never `nul`.
- New or changed tools should document their purpose, usage, dependencies, privileges, outputs, and important safety considerations.
- Validate inputs, quote paths and shell variables, provide actionable errors, and retain forensic logging and integrity checks where applicable.
- Test changes with the narrowest relevant check; use WSL2 or an isolated container for Linux-specific or potentially risky tooling.

## Safety

- Do not run destructive, collection, malware-analysis, scanning, rootkit, or attack-range tooling without explicit authorization and an appropriate isolated target.
- Do not modify files outside this repository without approval, and do not commit generated evidence, case data, credentials, secrets, or large build artifacts.
