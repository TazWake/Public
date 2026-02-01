# AGENTS.md

This file provides guidance for coding agents working in this repository.

## Scope
- Repository root: D:\Development\Public
- OS: Windows with PowerShell; use WSL2 for bash-only scripts.

## Repository Context
- This repo is a public collection of DFIR scripts, notes, and containerized tooling.
- Prefer small, incremental changes and avoid churn in unrelated files.

## Conventions
- Use `rg` for fast search; avoid `grep` unless `rg` is unavailable.
- Avoid piping to `nul` in PowerShell; use `>$null` instead.
- For bash scripts, follow strict mode and safe quoting practices (see CLAUDE.md).

## Safety
- Do not run destructive commands unless explicitly requested.
- Do not modify files outside the repository root without approval.

## Suggestions Before Edits
- Skim `README.md` and `CLAUDE.md` for context before larger changes.
- For new scripts, include brief usage notes and dependencies.
