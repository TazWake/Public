# Lisp DFIR Tools

A collection of standalone Common Lisp utilities for digital forensics and
incident response (DFIR). Each tool is a single, dependency-light `.lisp` file
that can be run directly with [SBCL](http://www.sbcl.org/) or compiled into a
self-contained native executable.

> **Defensive use only.** These tools are intended for authorised incident
> response, forensic analysis, and training.

---

## Tools

| File                | Purpose                                                                 | Entry point                  |
| ------------------- | ----------------------------------------------------------------------- | ---------------------------- |
| `cartographer.lisp` | Parse and triage a Linux `System.map` kernel symbol table for signs of malicious activity (rootkit heuristics, baseline diffing, JSON export). | `cartographer:main`   |

> _Adding a new tool?_ Drop the `.lisp` file in this directory, add a row to the
> table above, and document its flags in its own section below. The build and
> run instructions in this README are generic — substitute the file name and the
> tool's exported `main` symbol where shown.

---

## Requirements

- **SBCL** (Steel Bank Common Lisp) — the only hard requirement for the tools
  currently in this directory.
- **Quicklisp** — _optional_. None of the tools here pull in external libraries
  yet, but Quicklisp is the standard way to add them if a future tool needs one
  (see [Quicklisp](#quicklisp-optional)).

`cartographer.lisp` uses no third-party packages — it implements its own
whitespace splitting and hex parsing — so plain SBCL is sufficient.

---

## Installing SBCL

### Ubuntu / Debian

```bash
sudo apt-get update
sudo apt-get install -y sbcl
```

### RHEL / CentOS / Rocky / AlmaLinux / Fedora

```bash
# RHEL/CentOS/Rocky/Alma: SBCL lives in EPEL
sudo dnf install -y epel-release        # not needed on Fedora
sudo dnf install -y sbcl

# Older systems using yum:
# sudo yum install -y epel-release && sudo yum install -y sbcl
```

### openSUSE

```bash
sudo zypper refresh
sudo zypper install -y sbcl
```

### Verify the install

```bash
sbcl --version
```

If a distro ships an old SBCL and you want the latest, prebuilt binaries are
available from <http://www.sbcl.org/platform-table.html> (extract and run
`sh install.sh`).

---

## Running with SBCL (no compilation)

This is the quickest way to use a tool — no build step, just load and run.
Because SBCL parses its own command-line options first, the tool's arguments
must be placed **after** `--end-toplevel-options`:

```bash
sbcl --load cartographer.lisp \
     --eval '(cartographer:main)' \
     --end-toplevel-options \
     --map /boot/System.map-$(uname -r) --summary
```

Everything after `--end-toplevel-options` is passed straight through to the
tool. The same pattern works for any flags:

```bash
sbcl --load cartographer.lisp --eval '(cartographer:main)' \
     --end-toplevel-options --map System.map --json > symbols.json
```

### Interactive REPL workflow

For ad-hoc analysis it can be handier to load the file and drive it from the
REPL:

```bash
sbcl --load cartographer.lisp
```

```lisp
* (in-package :cartographer)
* (defparameter *syms* (load-system-map "/boot/System.map-6.5.0"))
* (print-summary *syms*)
* (writable-hooklike-symbols *syms*)   ; explore individual heuristics
```

---

## Compiling to a standalone binary

`save-lisp-and-die` dumps the running image to disk. To produce a binary that
runs the tool directly, you **must** specify the entry point with `:toplevel`
(otherwise the binary boots into the SBCL REPL and ignores your arguments):

```bash
sbcl --non-interactive \
     --load cartographer.lisp \
     --eval '(sb-ext:save-lisp-and-die "cartographer" :toplevel (function cartographer:main) :executable t)'
```

Notes:
- `(function cartographer:main)` is just `#'cartographer:main`
  written so it survives shell single-quoting.
- `--non-interactive` ensures the build exits cleanly in scripts/CI.

Then run it like any native program:

```bash
./cartographer --map /boot/System.map-$(uname -r) --summary
./cartographer --map System.map --json > symbols.json
./cartographer --baseline System.map.clean --map System.map.suspect --compare
```

The resulting executable embeds the SBCL runtime, so it is large (~30–50 MB) but
has **no runtime dependencies** — handy for dropping onto a triage host.

---

## Quicklisp (optional)

[Quicklisp](https://www.quicklisp.org/) is the de-facto Common Lisp library
manager. The tools in this directory don't need it today, but here's how to set
it up for future tools that do.

### Install Quicklisp

```bash
curl -O https://beta.quicklisp.org/quicklisp.lisp
sbcl --load quicklisp.lisp \
     --eval '(quicklisp-quickstart:install)' \
     --eval '(ql:add-to-init-file)' \
     --quit
```

`(ql:add-to-init-file)` writes a loader into `~/.sbclrc` so Quicklisp is
available in every future SBCL session.

### Loading a library

Once Quicklisp is installed, **yes — `(ql:quickload :split-sequence)` works** and
will download/compile/load the `split-sequence` library on first use:

```lisp
* (ql:quickload :split-sequence)
* (split-sequence:split-sequence #\Space "a b c")
```

> **However, `cartographer.lisp` does _not_ use `split-sequence`.** It has its
> own `split-spaces` function and deliberately avoids external dependencies so it
> can run on a clean triage host with nothing but SBCL. You only need Quicklisp
> if you write a new tool that depends on a third-party system.

If a future tool _does_ depend on a Quicklisp library, load it before the tool —
e.g. when building a binary:

```bash
sbcl --non-interactive \
     --eval '(ql:quickload :split-sequence)' \
     --load newtool.lisp \
     --eval '(sb-ext:save-lisp-and-die "newtool" :toplevel (function newtool:main) :executable t)'
```

---

## `cartographer.lisp` — usage

Parses a Linux `System.map` (the kernel's symbol-to-address table, found at
`/boot/System.map-<version>`) and applies a set of heuristics aimed at spotting
rootkits and tampering.

### Flags

| Flag                | Argument | Description                                                        |
| ------------------- | -------- | ------------------------------------------------------------------ |
| `--map <file>`      | path     | Load the primary `System.map` (the "suspect" map when comparing).  |
| `--baseline <file>` | path     | Load a second `System.map` to diff against (a known-good map).     |
| `--summary`         | —        | Print a human-readable summary with heuristic counts.              |
| `--json`            | —        | Emit all parsed symbols as JSON (to stdout).                       |
| `--compare`         | —        | Diff baseline vs. suspect; print symbols present only in the suspect map. |

If no output flag is given, the tool just reports how many symbols it loaded.

### Examples

```bash
# Human-readable triage summary of the running kernel's map
./cartographer --map /boot/System.map-$(uname -r) --summary

# Export every symbol as JSON for ingestion elsewhere
./cartographer --map System.map --json > symbols.json

# Diff a suspect map against a known-good baseline
./cartographer --baseline System.map.clean \
               --map System.map.suspect \
               --compare
```

### What the summary heuristics mean

| Heuristic                         | What it flags                                                                 |
| --------------------------------- | ----------------------------------------------------------------------------- |
| **Writable globals**              | Symbols in data/BSS (`D`/`d`/`B`/`b`) — mutable kernel state.                  |
| **Executable outliers**           | `T`/`t` symbols whose address falls **outside** the normal kernel text range (`0xffffffff80000000`–`0xffffffffff000000`) — possible injected/relocated code. |
| **Shadowed symbols**              | The same symbol name appearing more than once — a classic symbol-hijack tell. |
| **Writable syscall-patterns**     | Writable symbols named like syscalls (`sys_`, `__x64_sys_`, `do_sys_`) — potential syscall-table tampering. |
| **Address monotonicity anomalies**| Symbols whose address is lower than the preceding entry, even though `System.map` should be address-sorted — a sign of an edited/forged map. |
| **Writable hook-like symbols**    | Writable symbols named `*_hook`, `*_handler`, `*_ops`, `*_table` — common rootkit hook points. |

These are **indicators, not verdicts.** A clean kernel can legitimately trip
some of them; use them to prioritise where to look, ideally alongside a
`--compare` against a trusted baseline.

---

## Caveats

- `--compare` with no `--baseline` treats every suspect symbol as "new", so
  always supply a baseline when diffing.
- JSON output assumes symbol names are standard C identifiers (they always are
  in a real `System.map`); names containing literal `"` or `\` are not fully
  escaped.
- Heuristic address bounds in `cartographer.lisp` target x86-64 kernels. Other
  architectures will need the `executable-outliers` range adjusted.
