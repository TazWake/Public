#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mini-ioc-scan.py - a small, auditable IOC scanner
=================================================

Hunt hypothesis
---------------
A hunt you can only run by hand does not scale. The lasting value of hunting is
turning what you learn into repeatable detection you can run across the estate.
This is a deliberately small, readable IOC scanner - filename/path indicators,
hash lists (MD5/SHA1/SHA256), and optional YARA - so a responder can operate it,
read every line of it, and trust the result. It is explicitly NOT a LOKI clone;
it is the teachable subset that shows how the commercial scanners work.

It shares the suite conventions: read-only, deterministic, the same
findings/inventory/summary/log/manifest output contract, and the same exit
codes. The standard library carries the filename and hash matching with no
dependencies; YARA matching is used when the optional `yara` Python module is
present, and is skipped with a clear note when it is not.

Indicator sources
-----------------
  --hash-list FILE     One indicator per line: a hex MD5/SHA1/SHA256, optionally
                       followed by whitespace and a label. The algorithm is
                       inferred from the digest length (32/40/64). Lines starting
                       with '#' are comments.
  --filename-ioc FILE  One path indicator per line: a shell glob (matched against
                       the path and the basename) or a plain substring. '#'
                       comments allowed.
  --yara-rules PATH    A YARA rule file or a directory of .yar/.yara files.

What it flags
-------------
  IOC-HASH      HIGH    a file whose content hash matches a hash indicator
  IOC-YARA      HIGH    a file matching a YARA rule
  IOC-FILENAME  MEDIUM  a file whose path/name matches a filename indicator
                        (weaker: names are trivially changed)

Scores are additive per file, using the suite weights HIGH=5.0, MEDIUM=2.0,
LOW=1.0, INFO=0.5.

Forensic notes
--------------
  * Read-only. Nothing under the target is written, renamed or executed. The
    only writes are to --output.
  * Hashing and YARA both read file contents, which updates access time on a
    live writable mount. Access times are NOT restored (that would rewrite
    ctime). Prefer a read-only mount or a copy.
  * Filename indicators are inherently weak and false-positive prone; they are
    scored MEDIUM for that reason. Every result is a lead, not a verdict.

Author: Halkyn Consulting - Friday Threat Hunting series.
Licence: MIT. Original code; no third-party code included.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import os
import sys
from datetime import datetime, timezone

try:
    import yara  # optional; only used if installed
    HAVE_YARA = True
except ImportError:
    HAVE_YARA = False

VERSION = "1.0.0"
PROGRAM = "mini-ioc-scan"

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2
EXIT_INTERRUPT = 130

WEIGHT = {"HIGH": 5.0, "MEDIUM": 2.0, "LOW": 1.0, "INFO": 0.5}
SEV_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}

HASH_LEN = {32: "md5", 40: "sha1", 64: "sha256"}
DEFAULT_SKIP_DIRS = {".git", ".svn", ".hg", "node_modules", "__pycache__", ".cache"}


# --------------------------------------------------------------------------- #
# Shared helpers (self-contained, matching hunterlib semantics)
# --------------------------------------------------------------------------- #

def die(message):
    sys.stderr.write("ERROR: %s\n" % message)
    sys.exit(EXIT_USAGE)


def utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def scrub(value, maxlen=400):
    s = "" if value is None else str(value)
    s = s.replace("\t", " ").replace("\r", " ").replace("\n", " ")
    if len(s) > maxlen:
        s = s[:maxlen] + "..."
    return s


def sha256_file_only(path):
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
            digest = sha256_file_only(full)
            if digest:
                fh.write("%s  %s\n" % (digest, name))


# --------------------------------------------------------------------------- #
# Indicator loading
# --------------------------------------------------------------------------- #

def load_hash_list(paths, log):
    """Return {algo: {digest: label}} across all --hash-list files."""
    iocs = {"md5": {}, "sha1": {}, "sha256": {}}
    total = 0
    for path in paths:
        try:
            fh = open(path, "r", encoding="utf-8", errors="replace")
        except OSError as exc:
            die("cannot read --hash-list %s (%s)" % (path, exc))
        with fh:
            for line in fh:
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                parts = s.split(None, 1)
                digest = parts[0].lower()
                label = parts[1] if len(parts) > 1 else ""
                algo = HASH_LEN.get(len(digest))
                if not algo or any(c not in "0123456789abcdef" for c in digest):
                    log.warning("ignoring unrecognised hash indicator: %s" % s[:80])
                    continue
                iocs[algo][digest] = label
                total += 1
    log.info("loaded %d hash indicator(s): md5=%d sha1=%d sha256=%d"
             % (total, len(iocs["md5"]), len(iocs["sha1"]), len(iocs["sha256"])))
    return iocs, total


def load_filename_iocs(paths, log):
    items = []
    for path in paths:
        try:
            fh = open(path, "r", encoding="utf-8", errors="replace")
        except OSError as exc:
            die("cannot read --filename-ioc %s (%s)" % (path, exc))
        with fh:
            for line in fh:
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                items.append(s)
    log.info("loaded %d filename indicator(s)" % len(items))
    return items


def compile_yara(rule_path, log):
    if not rule_path:
        return None
    if not HAVE_YARA:
        log.warning("--yara-rules given but the 'yara' Python module is not "
                    "installed; YARA matching is skipped. Install yara-python to "
                    "enable it.")
        return None
    filepaths = {}
    if os.path.isdir(rule_path):
        for root, _dirs, files in os.walk(rule_path):
            for fn in sorted(files):
                if fn.endswith((".yar", ".yara")):
                    key = os.path.relpath(os.path.join(root, fn), rule_path)
                    filepaths[key] = os.path.join(root, fn)
    elif os.path.isfile(rule_path):
        filepaths[os.path.basename(rule_path)] = rule_path
    else:
        die("--yara-rules path not found: %s" % rule_path)
    if not filepaths:
        log.warning("no .yar/.yara files found under %s" % rule_path)
        return None
    try:
        rules = yara.compile(filepaths=filepaths)
    except yara.Error as exc:
        die("YARA rules failed to compile: %s" % exc)
    log.info("compiled YARA from %d rule file(s)" % len(filepaths))
    return rules


# --------------------------------------------------------------------------- #
# Scan
# --------------------------------------------------------------------------- #

def multi_hash(path, want_md5, want_sha1, want_sha256):
    """Compute only the digests actually needed by the loaded indicators,
    in a single pass over the file. Returns (md5, sha1, sha256_or_empty)."""
    hs = {}
    if want_md5:
        hs["md5"] = hashlib.md5()
    if want_sha1:
        hs["sha1"] = hashlib.sha1()
    hs["sha256"] = hashlib.sha256()  # always: used for the inventory record
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                for h in hs.values():
                    h.update(chunk)
    except OSError:
        return None
    return {k: v.hexdigest() for k, v in hs.items()}


def scan(roots, excludes, cross_fs, hash_iocs, name_iocs, yara_rules,
         findings, inv_fh, log, args):
    want_md5 = bool(hash_iocs["md5"])
    want_sha1 = bool(hash_iocs["sha1"])
    want_sha256 = bool(hash_iocs["sha256"])
    need_hash = want_md5 or want_sha1 or want_sha256
    excl = {os.path.abspath(e) for e in excludes}
    examined = 0
    for root in roots:
        root = os.path.abspath(root)
        try:
            root_dev = os.lstat(root).st_dev
        except OSError as exc:
            log.error("cannot stat root %s (%s)" % (root, exc))
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            if os.path.abspath(dirpath) in excl:
                dirnames[:] = []
                continue
            dirnames[:] = [d for d in sorted(dirnames)
                           if d not in DEFAULT_SKIP_DIRS
                           and os.path.abspath(os.path.join(dirpath, d)) not in excl]
            if not cross_fs:
                kept = []
                for d in dirnames:
                    try:
                        if os.lstat(os.path.join(dirpath, d)).st_dev == root_dev:
                            kept.append(d)
                    except OSError:
                        pass
                dirnames[:] = kept
            for fn in sorted(filenames):
                path = os.path.join(dirpath, fn)
                try:
                    st = os.lstat(path)
                except OSError as exc:
                    log.error("lstat failed: %s (%s)" % (path, exc))
                    continue
                if not (st.st_mode & 0o170000) == 0o100000:  # regular files only
                    continue
                if st.st_size > args.max_size:
                    log.detail("skip oversize (%d bytes): %s" % (st.st_size, path))
                    continue
                examined += 1
                sha256 = ""
                matched_here = False

                # Filename indicators (cheap; no read).
                for ind in name_iocs:
                    if (fnmatch.fnmatch(path, ind) or fnmatch.fnmatch(fn, ind)
                            or ind in path):
                        findings.add(path, "MEDIUM", "IOC-FILENAME",
                                     [path, "filename", ind,
                                      "path/name matches filename indicator '%s'"
                                      % ind, ""])
                        matched_here = True

                # Hash indicators.
                if need_hash:
                    digests = multi_hash(path, want_md5, want_sha1, want_sha256)
                    if digests is None:
                        log.error("cannot read for hashing: %s" % path)
                    else:
                        sha256 = digests.get("sha256", "")
                        for algo in ("md5", "sha1", "sha256"):
                            d = digests.get(algo)
                            if d and d in hash_iocs[algo]:
                                label = hash_iocs[algo][d] or "-"
                                findings.add(path, "HIGH", "IOC-HASH",
                                             [path, algo, d,
                                              "%s hash matches indicator (%s)"
                                              % (algo, label), sha256])
                                matched_here = True
                elif yara_rules is not None:
                    sha256 = sha256_file_only(path)

                # YARA.
                if yara_rules is not None:
                    try:
                        matches = yara_rules.match(path)
                    except Exception as exc:  # yara.Error and friends
                        log.error("YARA match failed on %s (%s)" % (path, exc))
                        matches = []
                    for m in matches:
                        if not sha256:
                            sha256 = sha256_file_only(path)
                        findings.add(path, "HIGH", "IOC-YARA",
                                     [path, "yara", m.rule,
                                      "matches YARA rule '%s'" % m.rule, sha256])
                        matched_here = True

                inv_fh.write("\t".join(scrub(x) for x in [
                    path, st.st_size, sha256, "yes" if matched_here else "no"])
                    + "\n")
    return examined


def write_summary(path, ctx, findings, stats, quiet):
    lines = ["%s %s - hunt summary" % (PROGRAM, VERSION), "=" * 48]
    for k, v in ctx:
        lines.append("%-18s %s" % (k + ":", v))
    lines += ["",
              "%-18s %s" % ("files examined:", stats["examined"]),
              "%-18s %s" % ("hash indicators:", stats["hashes"]),
              "%-18s %s" % ("filename indicators:", stats["names"]),
              "%-18s %s" % ("yara:", stats["yara"]),
              "%-18s %s" % ("files flagged:", findings.flagged),
              "%-18s %s" % ("findings:", findings.count),
              "%-18s %s" % ("high:", findings.high),
              "%-18s %s" % ("medium:", findings.medium),
              "%-18s %s" % ("read errors:", stats["errors"]),
              "", "Rule reference:"]
    for rid, count in sorted(stats["rules"].items()):
        lines.append("  %-16s %d" % (rid, count))
    lines += ["",
              "Coverage note: filename indicators are weak and are scored MEDIUM.",
              "Hash and YARA matches are strong but only find what you already",
              "have an indicator for. Findings are leads, not proof.",
              "",
              "Reminder: findings are investigative leads, not proof of compromise.",
              "Validate provenance and known-good state before acting."]
    text = "\n".join(lines) + "\n"
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    if not quiet:
        sys.stdout.write(text)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def build_parser():
    p = argparse.ArgumentParser(
        prog=PROGRAM, formatter_class=argparse.RawDescriptionHelpFormatter,
        description="A small, auditable IOC scanner (read-only): filename, hash "
                    "(MD5/SHA1/SHA256) and optional YARA matching over a tree. "
                    "Not a LOKI clone - a teachable subset you can read and trust.",
        epilog="Findings are investigative leads, not proof of compromise.")
    g = p.add_argument_group("target selection")
    g.add_argument("-p", "--path", action="append", dest="paths", metavar="DIR",
                   help="Tree to scan. Repeatable. Defaults to --root.")
    g.add_argument("--root", default=None, metavar="DIR",
                   help="Root tree to scan (used if no --path given).")
    g.add_argument("-x", "--exclude", action="append", default=[], metavar="PATH",
                   help="Prune this path from the walk. Repeatable.")
    g.add_argument("--cross-filesystems", action="store_true",
                   help="Cross mount boundaries (default off).")

    g2 = p.add_argument_group("indicators")
    g2.add_argument("--hash-list", action="append", default=[], metavar="FILE",
                    help="File of MD5/SHA1/SHA256 indicators. Repeatable.")
    g2.add_argument("--filename-ioc", action="append", default=[], metavar="FILE",
                    help="File of glob/substring path indicators. Repeatable.")
    g2.add_argument("--yara-rules", default=None, metavar="PATH",
                    help="A YARA rule file or directory of .yar/.yara files "
                         "(requires the yara-python module).")

    g3 = p.add_argument_group("output and case metadata")
    g3.add_argument("-o", "--output", metavar="DIR", required=True,
                    help="Output directory (required). Refused if inside a scan "
                         "root, or non-empty without --force.")
    g3.add_argument("--force", action="store_true",
                    help="Permit writing into an existing non-empty directory.")
    g3.add_argument("--case", default="", help="Case/incident reference.")
    g3.add_argument("--examiner", default="", help="Examiner/operator name.")
    g3.add_argument("--source-id", default="", help="Evidence/host identifier.")
    g3.add_argument("--max-size", type=lambda s: int(float(s) * 1024 * 1024),
                    default=128 * 1024 * 1024, metavar="MIB",
                    help="Largest file to read for hashing/YARA (default 128).")

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
    if not (args.hash_list or args.filename_ioc or args.yara_rules):
        die("no indicators given: pass at least one of --hash-list, "
            "--filename-ioc or --yara-rules")

    outdir, note = resolve_output(args.output, args.force, roots)
    log = AuditLog(os.path.join(outdir, PROGRAM + ".log"),
                   echo=not args.quiet, verbose=args.verbose)
    ctx = [
        ("tool", "%s %s" % (PROGRAM, VERSION)),
        ("started_utc", utc_now()),
        ("host", os.uname().nodename if hasattr(os, "uname") else "unknown"),
        ("platform", " ".join(os.uname()[:3]) if hasattr(os, "uname") else sys.platform),
        ("python", sys.version.split()[0]),
        ("yara", "available" if HAVE_YARA else "not installed"),
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

    log.section("loading indicators")
    hash_iocs, n_hashes = load_hash_list(args.hash_list, log) if args.hash_list \
        else ({"md5": {}, "sha1": {}, "sha256": {}}, 0)
    name_iocs = load_filename_iocs(args.filename_ioc, log) if args.filename_ioc else []
    yara_rules = compile_yara(args.yara_rules, log)

    findings = Findings(["path", "ioc_type", "indicator", "detail", "sha256"])
    inv_path = os.path.join(outdir, "inventory.tsv")
    inv_fh = open(inv_path, "w", encoding="utf-8")
    inv_fh.write("path\tsize\tsha256\tmatched\n")

    log.section("scanning")
    examined = scan(roots, args.exclude, args.cross_filesystems, hash_iocs,
                    name_iocs, yara_rules, findings, inv_fh, log, args)
    inv_fh.close()

    log.section("writing reports")
    findings.write(os.path.join(outdir, "findings.tsv"))
    rules = {}
    for _s, _sev, rid, _f in findings.rows:
        rules[rid] = rules.get(rid, 0) + 1
    ctx.append(("completed_utc", utc_now()))
    stats = {"examined": examined, "hashes": n_hashes, "names": len(name_iocs),
             "yara": "yes" if yara_rules is not None else "no",
             "errors": log.errors, "rules": rules}
    write_summary(os.path.join(outdir, "summary.txt"), ctx, findings, stats,
                  args.quiet)
    for f in ("findings.tsv", "inventory.tsv", "summary.txt"):
        log.info("wrote %s" % os.path.join(outdir, f))
    log.section("run end")
    log.info("examined=%d flagged=%d findings=%d errors=%d"
             % (examined, findings.flagged, findings.count, log.errors))
    log.info("writing SHA256SUMS last; it covers this log, so this is the final "
             "log line")
    log.close()
    write_manifest(outdir)

    if not args.quiet:
        sys.stdout.write("\n%s complete. %d file(s) examined, %d flagged, %d "
                         "finding(s).\nReports in: %s\n"
                         % (PROGRAM, examined, findings.flagged, findings.count,
                            outdir))
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
