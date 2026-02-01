# build_plan.md

## Purpose
Outline the approach to designing and building the triage tooling suite across Bash, Python, and compiled languages.

## Goals
- Provide consistent triage outcomes across implementations (similar in function, not identical).
- Preserve evidence integrity (hashing, metadata retention, logging).
- Offer a clear, user-friendly help system.
- Support both live response and captured-evidence workflows.
- Align collection order and handling with RFC3227 (order of volatility, minimal handling, thorough documentation).

## Scope
- Implement three script-based tools: Bash, Python, and compiled binaries.
- Compiled targets: C++, Go, and Rust (ideally three binaries).
- Two operational modes: Captured Evidence and Live Response.

## Approach Outline

### 1) Define Requirements
- Enumerate required artifacts from `plan.md` for both modes.
- Define minimum outputs and report structure.
- Establish non-functional requirements (logging, hashing, metadata retention, help UX).

### 2) Design Data Model and Outputs
- Standardize output directory layout and naming.
- Define consistent CSV schemas for user logins, cron, history, etc.
- Specify report content and summary heuristics (e.g., recent logins, recent service changes).

### 3) Build Common Specification
- Document a shared “artifact spec” used by all implementations.
- Define hashing algorithm(s), log format, and compression behavior.
- Provide a profile system placeholder for future artifact groupings.

### 4) Implementation Order
1. Bash reference implementation (proves workflow and platform commands).
2. Python implementation (adds portability, structured parsing, and testability).
3. Compiled implementations (C++, Go, Rust) aligned to the spec.

### 5) Validation and Testing
- Test on multiple Linux distros and filesystems (XFS, Btrfs, ext4).
- Validate statx usage and timestamp extraction.
- Confirm metadata preservation and archive integrity.
- Verify outputs match spec across implementations.

### 6) Release and Lifecycle
- Define versioning and changelog practices.
- Provide usage docs and examples.
- Establish a feedback loop for new artifacts and profiles.

## Deliverables
- Artifact specification document.
- Implementations: Bash, Python, and compiled binaries.
- Standardized output layout and report format.
- Test notes and validation checklist.

