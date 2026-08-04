#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mini-timeline.py - lightweight filesystem MACB timeliner
========================================================

Hunt hypothesis
---------------
Individual findings are dots; a timeline is the line through them. Ordering the
filesystem activity in a directory subtree turns scattered leads - a dropped
webshell, a new service, a fresh SSH key - into a narrative of what happened
when, and exposes attempts to fake that order (timestomping). This is a poor
responder's log2timeline for a single subtree: no database, no dependencies,
just the metadata the kernel already holds.

It is the timeline-lane companion to the rest of the suite and shares their
conventions: read-only, deterministic, standard-library only, the same
findings/summary/log/manifest output contract, and the same exit codes.

Metadata only - this matters
----------------------------
The tool NEVER opens a file's contents. It uses lstat(2) semantics exclusively,
which reads the inode and does not update the file's access time. Opening a file
to hash it would rewrite atime on a live, writable mount and destroy one of the
very timestamps this tool exists to report. There is therefore no SHA-256 column
in the findings: hashing would defeat the tool's own purpose. Where you need a
content hash, run a content scanner (webshell-hunter, mini-ioc-scan) separately
and accept the atime cost knowingly.

What it produces
----------------
  * timeline.tsv  - one row per timestamp per object (the classic "exploded"
    MACB view), or one row per object with combined MACB flags (--combined).
  * findings.tsv  - timestomping and ordering anomalies.

MACB is Modify, Access, Change, Birth. On Linux, birth (crtime) is only exposed
on some kernels/filesystems; where it is unavailable the B column is simply
absent, and the tool says so rather than inventing a value.

What it flags
-------------
  MT-CTIME-BEFORE-MTIME  MEDIUM  inode change time precedes modify time by more
                                 than the skew tolerance - the usual signature
                                 of a tool that set mtime backwards but could not
                                 forge ctime
  MT-FUTURE-STAMP        MEDIUM  a timestamp in the future relative to run time
  MT-SUBSECOND-ZERO      LOW     mtime has a zeroed sub-second part while sibling
                                 files in the same directory carry sub-second
                                 precision - consistent with a coarse forged value
  MT-PREDATES-REFERENCE  LOW     a timestamp older than --not-before (e.g. the
                                 known build date of the system)

Scores are additive per path, using the suite weights HIGH=5.0, MEDIUM=2.0,
LOW=1.0, INFO=0.5.

Forensic notes
--------------
  * Read-only and metadata-only. No file body is ever opened; the walk cannot
    change access times. The only writes are to --output.
  * Timestamps are reported as recorded, in UTC, without "correction". A clever
    attacker can forge all of M, A, B; ctime is harder to forge from user space,
    which is why the ordering rule leans on it. None of this is proof.

Author: Halkyn Consulting - Friday Threat Hunting series.
Licence: MIT. Original code; no third-party code included.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import stat as statmod
import sys
from datetime import datetime, timezone

VERSION = "1.0.0"
PROGRAM = "mini-timeline"

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2
EXIT_INTERRUPT = 130

WEIGHT = {"HIGH": 5.0, "MEDIUM": 2.0, "LOW": 1.0, "INFO": 0.5}
SEV_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}

DEFAULT_SKIP_DIRS = {".git", ".svn", ".hg", "node_modules", "__pycache__"}


# --------------------------------------------------------------------------- #
# Shared helpers (self-contained, matching hunterlib semantics)
# --------------------------------------------------------------------------- #

def die(message):
    sys.stderr.write("ERROR: %s\n" % message)
    sys.exit(EXIT_USAGE)


def utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def iso(epoch):
    if epoch is None:
        return ""
    try:
        return datetime.fromtimestamp(epoch, timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return ""


def scrub(value, maxlen=400):
    s = "" if value is None else str(value)
    s = s.replace("\t", " ").replace("\r", " ").replace("\n", " ")
    if len(s) > maxlen:
        s = s[:maxlen] + "..."
    return s


def sha256_file(path):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return ""


class AuditLog:
    def __init__(self, path, echo=True, verbose=False):
        self.path = path
        self.echo = echo
        self.verbose = verbose
        self.errors = 0
        self._fh = open(path, "a", encoding="utf-8")

    def _write(self, level, msg):
        line = "%s\t%s\t%s" % (utc_now(), level, msg)
        self._fh.write(line + "\n")
        self._fh.flush()
        if self.echo:
            if level in ("ERROR", "WARNING"):
                sys.stderr.write(line + "\n")
            elif level == "DETAIL":
                if self.verbose:
                    sys.stderr.write(line + "\n")
            else:
                sys.stdout.write(line + "\n")

    def info(self, m):
        self._write("INFO", m)

    def detail(self, m):
        self._write("DETAIL", m)

    def warning(self, m):
        self._write("WARNING", m)

    def error(self, m):
        self.errors += 1
        self._write("ERROR", m)

    def section(self, m):
        self._write("SECTION", "--- %s ---" % m)

    def close(self):
        self._fh.close()


class Findings:
    def __init__(self, columns):
        self.columns = columns
        self.rows = []
        self.high = self.medium = self.low = 0

    def add(self, subject, severity, rule_id, fields):
        self.rows.append((subject, severity, rule_id, fields))
        if severity == "HIGH":
            self.high += 1
        elif severity == "MEDIUM":
            self.medium += 1
        else:
            self.low += 1

    @property
    def count(self):
        return len(self.rows)

    @property
    def flagged(self):
        return len({r[0] for r in self.rows})

    def write(self, path):
        score = {}
        for subject, severity, _rid, _f in self.rows:
            score[subject] = score.get(subject, 0.0) + WEIGHT.get(severity, 0.5)

        def key(r):
            subject, severity, rule_id, _f = r
            return (-score[subject], SEV_ORDER.get(severity, 3), subject, rule_id)

        header = ["score", "severity", "rule_id"] + self.columns
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\t".join(header) + "\n")
            for subject, severity, rule_id, fields in sorted(self.rows, key=key):
                row = ["%.1f" % score[subject], severity, rule_id]
                row += [scrub(x) for x in fields]
                fh.write("\t".join(row) + "\n")


def resolve_output(outdir, force, roots):
    outdir = os.path.abspath(outdir)
    note = ""
    for root in roots:
        if not root:
            continue
        aroot = os.path.abspath(root)
        if aroot == os.sep:
            note = ("scan root is / - output directory containment check skipped;"
                    " keep output on separate media where possible")
            continue
        if outdir == aroot or outdir.startswith(aroot + os.sep):
            die("output directory %s is inside scan root %s. Choose a location "
                "outside the target." % (outdir, aroot))
    if os.path.exists(outdir):
        if not os.path.isdir(outdir):
            die("output path exists and is not a directory: %s" % outdir)
        if os.listdir(outdir) and not force:
            die("output directory %s exists and is not empty. Choose a new "
                "directory or pass --force." % outdir)
    else:
        try:
            os.makedirs(outdir)
        except OSError as exc:
            die("cannot create output directory: %s (%s)" % (outdir, exc))
    return outdir, note


def write_manifest(outdir):
    manifest = os.path.join(outdir, "SHA256SUMS")
    names = sorted(n for n in os.listdir(outdir) if n != "SHA256SUMS")
    with open(manifest, "w", encoding="utf-8") as fh:
        for name in names:
            full = os.path.join(outdir, name)
            if not os.path.isfile(full):
                continue
            digest = sha256_file(full)
            if digest:
                fh.write("%s  %s\n" % (digest, name))


# --------------------------------------------------------------------------- #
# Timeline
# --------------------------------------------------------------------------- #

def type_char(mode):
    if statmod.S_ISDIR(mode):
        return "d"
    if statmod.S_ISLNK(mode):
        return "l"
    if statmod.S_ISREG(mode):
        return "r"
    if statmod.S_ISSOCK(mode):
        return "s"
    if statmod.S_ISFIFO(mode):
        return "p"
    if statmod.S_ISBLK(mode):
        return "b"
    if statmod.S_ISCHR(mode):
        return "c"
    return "?"


def parse_when(value):
    """Parse an ISO-ish date/time to epoch seconds (UTC). Accepts YYYY-MM-DD or
    full ISO. Returns None on failure."""
    if not value:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
            return dt.timestamp()
        except ValueError:
            continue
    die("cannot parse date/time: %s (use YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS)" % value)


class Node:
    __slots__ = ("path", "kind", "size", "mode_oct", "owner", "inode",
                 "mtime", "atime", "ctime", "btime", "mtime_ns")

    def __init__(self, path, st):
        self.path = path
        self.kind = type_char(st.st_mode)
        self.size = st.st_size
        self.mode_oct = oct(statmod.S_IMODE(st.st_mode))[2:].zfill(3)
        self.owner = st.st_uid
        self.inode = st.st_ino
        self.mtime = st.st_mtime
        self.atime = st.st_atime
        self.ctime = st.st_ctime
        self.btime = getattr(st, "st_birthtime", None)
        self.mtime_ns = getattr(st, "st_mtime_ns", int(st.st_mtime * 1e9))


def walk(roots, excludes, cross_fs, log, max_files):
    """Yield Node objects via lstat only. Never opens file contents."""
    seen = 0
    excl = {os.path.abspath(e) for e in excludes}
    for root in roots:
        root = os.path.abspath(root)
        try:
            root_dev = os.lstat(root).st_dev
        except OSError as exc:
            log.error("cannot stat root %s (%s)" % (root, exc))
            continue
        stack = [root]
        while stack:
            current = stack.pop()
            if os.path.abspath(current) in excl:
                log.detail("excluded: %s" % current)
                continue
            try:
                st = os.lstat(current)
            except OSError as exc:
                log.error("lstat failed: %s (%s)" % (current, exc))
                continue
            if seen >= max_files:
                log.warning("--max-files reached; stopping the walk")
                return
            seen += 1
            yield Node(current, st)
            if statmod.S_ISDIR(st.st_mode) and not statmod.S_ISLNK(st.st_mode):
                if not cross_fs and st.st_dev != root_dev:
                    log.detail("not crossing filesystem at: %s" % current)
                    continue
                base = os.path.basename(current)
                if base in DEFAULT_SKIP_DIRS and current != root:
                    log.detail("skip noise dir: %s" % current)
                    continue
                try:
                    for name in sorted(os.listdir(current), reverse=True):
                        stack.append(os.path.join(current, name))
                except OSError as exc:
                    log.error("cannot list %s (%s)" % (current, exc))


# --------------------------------------------------------------------------- #
# Writers
# --------------------------------------------------------------------------- #

MACB_LETTERS = [("mtime", "M"), ("atime", "A"), ("ctime", "C"), ("btime", "B")]


def write_timeline(path, nodes, combined, sort_desc, since, until):
    """Exploded or combined MACB timeline, time-ordered."""
    rows = []
    for n in nodes:
        stamps = {"mtime": n.mtime, "atime": n.atime, "ctime": n.ctime,
                  "btime": n.btime}
        if combined:
            # group timestamp types that share the same value
            groups = {}
            for field, letter in MACB_LETTERS:
                v = stamps[field]
                if v is None:
                    continue
                key = round(v, 6)
                groups.setdefault(key, []).append(letter)
            for value, letters in groups.items():
                rows.append((value, "".join(
                    l if l in letters else "." for _f, l in MACB_LETTERS), n))
        else:
            for field, letter in MACB_LETTERS:
                v = stamps[field]
                if v is None:
                    continue
                flags = "".join(l if fname == field else "."
                                for fname, l in MACB_LETTERS)
                rows.append((v, flags, n))
    rows = [r for r in rows if (since is None or r[0] >= since)
            and (until is None or r[0] <= until)]
    rows.sort(key=lambda r: (r[0], r[2].path), reverse=sort_desc)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("timestamp_utc\tepoch\tmacb\ttype\tsize\tmode\towner\tinode\t"
                 "path\n")
        for value, flags, n in rows:
            fh.write("\t".join(scrub(x) for x in [
                iso(value), int(value), flags, n.kind, n.size, n.mode_oct,
                n.owner, n.inode, n.path]) + "\n")
    return len(rows)


def write_summary(path, ctx, findings, stats, quiet):
    lines = ["%s %s - hunt summary" % (PROGRAM, VERSION), "=" * 48]
    for k, v in ctx:
        lines.append("%-18s %s" % (k + ":", v))
    lines += ["",
              "%-18s %s" % ("objects walked:", stats["objects"]),
              "%-18s %s" % ("timeline rows:", stats["rows"]),
              "%-18s %s" % ("birth times:", stats["btime"]),
              "%-18s %s" % ("paths flagged:", findings.flagged),
              "%-18s %s" % ("findings:", findings.count),
              "%-18s %s" % ("high:", findings.high),
              "%-18s %s" % ("medium:", findings.medium),
              "%-18s %s" % ("low/info:", findings.low),
              "%-18s %s" % ("read errors:", stats["errors"]),
              "", "Rule reference:"]
    for rid, count in sorted(stats["rules"].items()):
        lines.append("  %-24s %d" % (rid, count))
    lines += ["",
              "Coverage note: this tool reads metadata only and never opens file",
              "bodies, so access times are preserved. Timestamps can be forged;",
              "ctime is harder to forge from user space, which the ordering rule",
              "relies on. Findings are leads, not proof.",
              "",
              "Reminder: findings are investigative leads, not proof of compromise.",
              "Validate provenance and known-good state before acting."]
    text = "\n".join(lines) + "\n"
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    if not quiet:
        sys.stdout.write(text)


# --------------------------------------------------------------------------- #
# Rules
# --------------------------------------------------------------------------- #

def analyse(nodes, findings, args, log):
    now = datetime.now(timezone.utc).timestamp()
    skew = args.skew
    not_before = parse_when(args.not_before) if args.not_before else None

    # Sub-second precision per directory, for the zeroed-subsecond heuristic.
    dir_has_subsec = {}
    for n in nodes:
        d = os.path.dirname(n.path)
        if n.mtime_ns % 1000000000 != 0:
            dir_has_subsec[d] = True

    for n in nodes:
        # ctime earlier than mtime: the classic timestomp signature.
        if n.ctime is not None and n.mtime is not None and \
                n.ctime < n.mtime - skew:
            findings.add(n.path, "MEDIUM", "MT-CTIME-BEFORE-MTIME",
                         [n.path, iso(n.mtime), "mtime>ctime",
                          "inode change time (%s) precedes modify time (%s) by "
                          "%ds - consistent with a backdated mtime"
                          % (iso(n.ctime), iso(n.mtime), int(n.mtime - n.ctime)),
                          "ctime=%s mtime=%s" % (iso(n.ctime), iso(n.mtime))])
        # future timestamps
        for field, label in (("mtime", n.mtime), ("ctime", n.ctime),
                             ("btime", n.btime)):
            if label is not None and label > now + skew:
                findings.add(n.path, "MEDIUM", "MT-FUTURE-STAMP",
                             [n.path, iso(label), field,
                              "%s is in the future (%s)" % (field, iso(label)),
                              "%s=%s" % (field, iso(label))])
        # zeroed sub-second while siblings carry precision
        d = os.path.dirname(n.path)
        if n.kind == "r" and n.mtime_ns % 1000000000 == 0 and dir_has_subsec.get(d):
            findings.add(n.path, "LOW", "MT-SUBSECOND-ZERO",
                         [n.path, iso(n.mtime), "mtime",
                          "mtime has zero sub-second part while sibling files in "
                          "this directory carry sub-second precision",
                          "mtime_ns=%d" % n.mtime_ns])
        # predates a known-good reference
        if not_before is not None and n.mtime is not None and n.mtime < not_before:
            findings.add(n.path, "LOW", "MT-PREDATES-REFERENCE",
                         [n.path, iso(n.mtime), "mtime",
                          "mtime predates the reference date %s" % args.not_before,
                          "mtime=%s" % iso(n.mtime)])


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def build_parser():
    p = argparse.ArgumentParser(
        prog=PROGRAM, formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Lightweight metadata-only MACB filesystem timeliner "
                    "(read-only). Builds a time-ordered view of a subtree and "
                    "flags timestomping and ordering anomalies. Never opens file "
                    "contents, so access times are preserved.",
        epilog="Findings are investigative leads, not proof of compromise.")
    g = p.add_argument_group("target selection")
    g.add_argument("-p", "--path", action="append", dest="paths", metavar="DIR",
                   help="Subtree to timeline. Repeatable. Defaults to --root.")
    g.add_argument("--root", default=None, metavar="DIR",
                   help="Root subtree to timeline (used if no --path given).")
    g.add_argument("-x", "--exclude", action="append", default=[], metavar="PATH",
                   help="Prune this path from the walk. Repeatable.")
    g.add_argument("--cross-filesystems", action="store_true",
                   help="Cross mount boundaries (default off).")

    g2 = p.add_argument_group("output and case metadata")
    g2.add_argument("-o", "--output", metavar="DIR", required=True,
                    help="Output directory (required). Refused if inside a scan "
                         "root, or non-empty without --force.")
    g2.add_argument("--force", action="store_true",
                    help="Permit writing into an existing non-empty directory.")
    g2.add_argument("--case", default="", help="Case/incident reference.")
    g2.add_argument("--examiner", default="", help="Examiner/operator name.")
    g2.add_argument("--source-id", default="", help="Evidence/host identifier.")

    g3 = p.add_argument_group("timeline options")
    g3.add_argument("--since", default=None, metavar="WHEN",
                    help="Only include timeline rows at/after this time.")
    g3.add_argument("--until", default=None, metavar="WHEN",
                    help="Only include timeline rows at/before this time.")
    g3.add_argument("--combined", action="store_true",
                    help="One row per object with combined MACB flags, instead "
                         "of the exploded one-row-per-timestamp view.")
    g3.add_argument("--desc", action="store_true",
                    help="Sort newest first (default oldest first).")
    g3.add_argument("--not-before", default=None, metavar="WHEN",
                    help="Flag mtimes older than this (e.g. system build date).")
    g3.add_argument("--skew", type=int, default=2, metavar="SECS",
                    help="Clock-skew tolerance for ordering rules (default 2s).")
    g3.add_argument("--max-files", type=int, default=2000000, metavar="N",
                    help="Stop after N objects (default 2,000,000).")

    g4 = p.add_argument_group("output verbosity")
    g4.add_argument("-v", "--verbose", action="store_true",
                    help="Per-item detail on stderr.")
    g4.add_argument("-q", "--quiet", action="store_true",
                    help="Suppress console summary. Files are still written.")
    p.add_argument("-V", "--version", action="version",
                   version="%s %s" % (PROGRAM, VERSION))
    return p


def main(argv):
    args = build_parser().parse_args(argv)
    if args.paths:
        roots = args.paths
    elif args.root:
        roots = [args.root]
    else:
        die("no target given: pass --path or --root (use -h for help)")
    for r in roots:
        if not os.path.isdir(r):
            die("target is not a directory: %s" % r)

    since = parse_when(args.since) if args.since else None
    until = parse_when(args.until) if args.until else None

    outdir, note = resolve_output(args.output, args.force, roots)
    log = AuditLog(os.path.join(outdir, PROGRAM + ".log"),
                   echo=not args.quiet, verbose=args.verbose)
    ctx = [
        ("tool", "%s %s" % (PROGRAM, VERSION)),
        ("started_utc", utc_now()),
        ("host", os.uname().nodename if hasattr(os, "uname") else "unknown"),
        ("platform", " ".join(os.uname()[:3]) if hasattr(os, "uname") else sys.platform),
        ("python", sys.version.split()[0]),
        ("operator_user", _whoami()),
        ("case", args.case),
        ("examiner", args.examiner),
        ("source_id", args.source_id),
        ("roots", " ; ".join(os.path.abspath(r) for r in roots)),
        ("output_dir", outdir),
        ("command", " ".join([os.path.basename(sys.argv[0])] + argv)),
    ]
    log.section("run start")
    for k, v in ctx:
        log.info("%s = %s" % (k, v))
    if note:
        log.warning(note)

    log.section("walking subtree (metadata only)")
    nodes = list(walk(roots, args.exclude, args.cross_filesystems, log,
                      args.max_files))
    btime_count = sum(1 for n in nodes if n.btime is not None)
    if btime_count == 0:
        log.info("no birth (crtime) times available on this platform/filesystem "
                 "- the B column is omitted")
    log.info("walked %d object(s)" % len(nodes))

    findings = Findings(["path", "timestamp", "field", "detail", "evidence"])
    log.section("analysis")
    analyse(nodes, findings, args, log)

    log.section("writing reports")
    findings.write(os.path.join(outdir, "findings.tsv"))
    rows = write_timeline(os.path.join(outdir, "timeline.tsv"), nodes,
                          args.combined, args.desc, since, until)
    log.info("timeline rows written: %d" % rows)

    rules = {}
    for _s, _sev, rid, _f in findings.rows:
        rules[rid] = rules.get(rid, 0) + 1
    ctx.append(("completed_utc", utc_now()))
    stats = {"objects": len(nodes), "rows": rows, "btime": btime_count,
             "errors": log.errors, "rules": rules}
    write_summary(os.path.join(outdir, "summary.txt"), ctx, findings, stats,
                  args.quiet)
    for f in ("findings.tsv", "timeline.tsv", "summary.txt"):
        log.info("wrote %s" % os.path.join(outdir, f))
    log.section("run end")
    log.info("objects=%d rows=%d flagged=%d findings=%d errors=%d"
             % (len(nodes), rows, findings.flagged, findings.count, log.errors))
    log.info("writing SHA256SUMS last; it covers this log, so this is the final "
             "log line")
    log.close()
    write_manifest(outdir)

    if not args.quiet:
        sys.stdout.write("\n%s complete. %d object(s) walked, %d timeline row(s),"
                         " %d finding(s).\nReports in: %s\n"
                         % (PROGRAM, len(nodes), rows, findings.count, outdir))
    return EXIT_FINDINGS if findings.count > 0 else EXIT_OK


def _whoami():
    try:
        import getpass
        return getpass.getuser()
    except Exception:
        return os.environ.get("USER", "unknown")


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except KeyboardInterrupt:
        sys.stderr.write("\ninterrupted\n")
        sys.exit(EXIT_INTERRUPT)
