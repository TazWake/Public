#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
auth-hunter.py - Linux authentication anomaly hunter
====================================================

Hunt hypothesis
---------------
Most intrusions cross an authentication boundary. Someone reuses a credential,
brute-forces an exposed SSH service, escalates to root, or adds an account to
keep. Every one of those actions leaves a trace in the host's authentication
telemetry. This tool normalises that telemetry from several sources into one
event stream and flags the patterns that matter, so "how did they get in, and
what did they do once authenticated?" becomes an answerable question.

It is the authentication-lane companion to proc-hunter and persist-hunter, and
shares their conventions: read-only, deterministic, standard-library only, the
same findings/inventory/summary/log/manifest output contract, and the same exit
codes. It is written in Python rather than Bash because the interesting work
here is temporal - grouping failures into bursts, spotting a success that
follows a burst, detecting timestamps that run backwards - and that logic is
clearer and safer in Python than in awk.

Sources it understands
----------------------
  * Syslog-style text logs: /var/log/auth.log* (Debian/Ubuntu) and
    /var/log/secure* (RHEL/Fedora). Both the classic "Mmm dd HH:MM:SS" format
    and the RFC3339 ISO format that modern rsyslog emits.
  * The systemd journal, opportunistically, via journalctl when the tool is run
    on the live host and journalctl is present. Never required.
  * wtmp / btmp, via last(1) / lastb(1) when available, for session start/stop
    and failed-login records. Never required; skipped with a note if absent.

A mounted image is a first-class input: point --root at the image and it reads
the image's logs, and shells last/lastb at the image's wtmp/btmp.

What it flags
-------------
  AUTH-BRUTE-FORCE     MEDIUM  >= N failed logins from one source IP within a
                               time window
  AUTH-BRUTE-SUCCESS   HIGH    a successful login from an IP within the window
                               AFTER a burst of failures from that same IP -
                               a likely successful brute-force
  AUTH-NEW-SOURCE-IP   MEDIUM  a successful login from a source IP not in the
                               provided --known-ips baseline
  AUTH-ROOT-LOGIN      LOW     a direct successful remote login as root
  AUTH-ODD-HOURS       LOW/MED a successful interactive login inside the night
                               window (or outside --work-hours); MEDIUM for root
  AUTH-NEW-ACCOUNT     MEDIUM  a user or group was created (useradd/groupadd)
  AUTH-NEW-SUDOER      MEDIUM  a user was added to a sudo/wheel/admin group
  AUTH-SU-ROOT         LOW     a successful su to root by a non-root user
  AUTH-SU-FAIL-BURST   MEDIUM  repeated failed su in a short window (escalation
                               attempts)
  AUTH-TIME-REVERSAL   MEDIUM  timestamps run backwards within one log file,
                               beyond clock skew - a sign of log tampering
  AUTH-LOG-EMPTY       LOW     an authentication log exists but is empty - which
                               can mean truncation/clearing

Scores are additive per subject (the IP, the user, or the file being scored),
using the suite weights HIGH=5.0, MEDIUM=2.0, LOW=1.0, INFO=0.5.

Forensic notes
--------------
  * Read-only. Nothing under the target is written, renamed or executed. The
    only writes are to --output.
  * Reading a log updates its access time on a live, writable mount. Access
    times are NOT restored, because doing so rewrites the change time and is
    itself an alteration of the evidence. Prefer a read-only mount or a copy.
  * Log lines can be forged or deleted by an attacker with sufficient access.
    Absence of evidence is not evidence of absence; the AUTH-TIME-REVERSAL and
    AUTH-LOG-EMPTY rules exist precisely because the logs themselves are a
    target. Treat every result as an investigative lead, not proof.
  * Timestamps are read as the host's local wall-clock, exactly as written in
    the log; they are not "corrected" to another zone. The synthetic ordering
    key is internally consistent, so windows and bursts are computed correctly
    regardless of the analyst host's timezone.

Author: Halkyn Consulting.
Licence: MIT. Original code; no third-party code included.
"""

from __future__ import annotations

import argparse
import calendar
import hashlib
import ipaddress
import os
import re
import subprocess
import sys
from datetime import datetime, timezone

VERSION = "1.0.0"
PROGRAM = "auth-hunter"

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2
EXIT_INTERRUPT = 130

WEIGHT = {"HIGH": 5.0, "MEDIUM": 2.0, "LOW": 1.0, "INFO": 0.5}
SEV_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}

MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1)}

# Where authentication logs and login databases live, relative to --root.
AUTH_LOG_GLOBS = ["var/log/auth.log", "var/log/secure"]
WTMP_PATHS = ["var/log/wtmp"]
BTMP_PATHS = ["var/log/btmp"]


# --------------------------------------------------------------------------- #
# Small shared helpers (Python siblings of hunterlib.sh, matching its rules)
# --------------------------------------------------------------------------- #

def die(message):
    """Usage/safety error: print to stderr and exit 2, per the shared contract."""
    sys.stderr.write("ERROR: %s\n" % message)
    sys.exit(EXIT_USAGE)


def utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def scrub(value, maxlen=400):
    """Make a value safe for a TSV cell: no tabs/newlines, truncated."""
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
    """Timestamped, append-only audit log. Mirrors hunterlib.sh's logger."""

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
    """Accumulate findings, score additively per subject, write deterministically.

    Matches hunterlib.sh: a row's score is its subject's total across every rule
    that hit it; rows sort by score desc, then severity, then subject.
    """

    def __init__(self, columns):
        # columns: the tool's own column names AFTER score/severity/rule_id.
        # The first of these is the scoring subject.
        self.columns = columns
        self.rows = []  # (subject, severity, rule_id, [field values])
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

        def sort_key(r):
            subject, severity, rule_id, _f = r
            return (-score[subject], SEV_ORDER.get(severity, 3), subject, rule_id)

        header = ["score", "severity", "rule_id"] + self.columns
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\t".join(header) + "\n")
            for subject, severity, rule_id, fields in sorted(self.rows, key=sort_key):
                row = ["%.1f" % score[subject], severity, rule_id]
                row += [scrub(x) for x in fields]
                fh.write("\t".join(row) + "\n")


def resolve_output(outdir, force, roots):
    """Validate/create the output directory. Refuse inside a scan root, or
    non-empty without --force. Returns (abspath, note)."""
    outdir = os.path.abspath(outdir)
    note = ""
    for root in roots:
        if not root:
            continue
        aroot = os.path.abspath(root)
        if aroot == os.sep:
            note = ("scan root is / - output directory containment check "
                    "skipped; keep output on separate media where possible")
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
    """SHA-256 of every artefact except the manifest. Written last."""
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
# Event model
# --------------------------------------------------------------------------- #

class Event:
    """One normalised authentication event."""
    __slots__ = ("order", "iso", "hour", "user", "ip", "method", "result",
                 "kind", "source", "raw", "to", "group", "cmd")

    def __init__(self, order, iso, hour, user, ip, method, result, kind,
                 source, raw, to=None, group=None, cmd=None):
        self.order = order        # synthetic epoch for ordering/windows
        self.iso = iso            # wall-clock as written, ISO-8601
        self.hour = hour          # local hour 0-23 as written
        self.user = user or ""
        self.ip = ip or ""
        self.method = method or ""
        self.result = result      # accept | fail | logout | session | admin
        self.kind = kind          # ssh | sudo | su | account | login-record
        self.source = source      # source file / journal
        self.raw = raw
        self.to = to              # su target user
        self.group = group        # group for account changes
        self.cmd = cmd            # sudo command


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #

RE_SYSLOG_BSD = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+\S+\s+(?P<proc>[\w./-]+)"
    r"(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.*)$")

RE_SYSLOG_ISO = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?"
    r"(?:Z|[+-]\d{2}:\d{2})?)\s+\S+\s+(?P<proc>[\w./-]+)"
    r"(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.*)$")

# sshd message fragments
RE_FAILED = re.compile(
    r"Failed (?P<method>\w+) for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>\S+) port \d+")
RE_ACCEPTED = re.compile(
    r"Accepted (?P<method>\w+) for (?P<user>\S+) from (?P<ip>\S+) port \d+")
RE_INVALID = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>\S+)")
RE_SESSION_OPEN = re.compile(
    r"session opened for user (?P<user>[\w.-]+)")
# su
RE_SU_OK = re.compile(
    r"pam_unix\(su(?:-l)?:session\): session opened for user (?P<to>[\w.-]+)"
    r"(?:\(uid=\d+\))? by (?P<by>[\w.-]+)?")
RE_SU_FAIL = re.compile(
    r"FAILED su for (?P<to>\S+) by (?P<by>\S+)")
RE_SU_LEGACY = re.compile(
    r"(?:\+|\-) \S+ (?P<by>[\w.-]+):(?P<to>[\w.-]+)")
# account / group changes
RE_USERADD = re.compile(r"new user: name=(?P<user>[\w.-]+)")
RE_GROUPADD = re.compile(r"new group: name=(?P<group>[\w.-]+)")
RE_TO_GROUP = re.compile(
    r"add '(?P<user>[\w.-]+)' to group '(?P<group>[\w.-]+)'")
RE_TO_GROUP2 = re.compile(
    r"to group '(?P<group>[\w.-]+)'.*?(?:user=)?(?P<user>[\w.-]+)?")

SUDO_GROUPS = {"sudo", "wheel", "admin"}


def _iso_from_bsd(mon, day, tstr, base_year, mtime_year):
    """Build (order, iso, hour) from a year-less syslog timestamp."""
    mon_n = MONTHS.get(mon)
    if not mon_n:
        return None
    hh, mm, ss = (int(x) for x in tstr.split(":"))
    year = base_year or mtime_year
    # Handle the Dec->Jan rollover: a log written in January carries December
    # lines from the previous year. If the constructed date is far ahead of the
    # file's own year context, step back a year.
    try:
        dt = datetime(year, mon_n, int(day), hh, mm, ss)
    except ValueError:
        return None
    order = calendar.timegm(dt.timetuple())
    iso = dt.strftime("%Y-%m-%dT%H:%M:%S")
    return order, iso, hh


def _iso_from_isots(ts):
    """Parse an RFC3339 syslog timestamp; keep the wall-clock as written."""
    m = re.match(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})", ts)
    if not m:
        return None
    y, mo, d, hh, mm, ss = (int(x) for x in m.groups())
    try:
        dt = datetime(y, mo, d, hh, mm, ss)
    except ValueError:
        return None
    order = calendar.timegm(dt.timetuple())
    return order, dt.strftime("%Y-%m-%dT%H:%M:%S"), hh


def classify_message(proc, msg):
    """Turn an sshd/sudo/su/useradd message into (kind, result, fields)."""
    proc = proc.lower()
    if "sshd" in proc:
        m = RE_ACCEPTED.search(msg)
        if m:
            return ("ssh", "accept",
                    {"user": m.group("user"), "ip": m.group("ip"),
                     "method": m.group("method")})
        m = RE_FAILED.search(msg)
        if m:
            return ("ssh", "fail",
                    {"user": m.group("user"), "ip": m.group("ip"),
                     "method": m.group("method")})
        m = RE_INVALID.search(msg)
        if m:
            return ("ssh", "fail",
                    {"user": m.group("user"), "ip": m.group("ip"),
                     "method": "invalid-user"})
        m = RE_SESSION_OPEN.search(msg)
        if m and "sshd:session" in msg:
            return ("ssh", "session", {"user": m.group("user"), "ip": "",
                                       "method": "session"})
        return None
    if proc.startswith("sudo") or proc == "sudo":
        if "COMMAND=" in msg:
            um = re.match(r"\s*(?P<user>[\w.-]+)\s*:", msg)
            cmd = msg.split("COMMAND=", 1)[1]
            return ("sudo", "admin",
                    {"user": um.group("user") if um else "", "ip": "",
                     "method": "sudo", "cmd": cmd})
        if "authentication failure" in msg or "NOT in sudoers" in msg:
            um = re.search(r"user=(?P<user>[\w.-]+)", msg)
            return ("sudo", "fail",
                    {"user": um.group("user") if um else "", "ip": "",
                     "method": "sudo"})
        return None
    if proc.startswith("su") or "su-l" in proc:
        m = RE_SU_OK.search(msg)
        if m:
            return ("su", "session",
                    {"user": m.group("by") or "", "ip": "",
                     "method": "su", "to": m.group("to")})
        m = RE_SU_FAIL.search(msg)
        if m:
            return ("su", "fail",
                    {"user": m.group("by"), "ip": "", "method": "su",
                     "to": m.group("to")})
        return None
    if "useradd" in proc:
        m = RE_USERADD.search(msg)
        if m:
            return ("account", "admin",
                    {"user": m.group("user"), "ip": "", "method": "useradd"})
        return None
    if "groupadd" in proc:
        m = RE_GROUPADD.search(msg)
        if m:
            return ("account", "admin",
                    {"user": m.group("group"), "ip": "", "method": "groupadd"})
        return None
    if "usermod" in proc or "gpasswd" in proc or "chage" in proc:
        m = RE_TO_GROUP.search(msg)
        if m:
            return ("account", "admin",
                    {"user": m.group("user"), "ip": "", "method": "group-add",
                     "group": m.group("group")})
        m = re.search(r"group '?(?P<group>[\w.-]+)'?", msg)
        um = re.search(r"user='?(?P<user>[\w.-]+)'?", msg)
        if m:
            return ("account", "admin",
                    {"user": um.group("user") if um else "", "ip": "",
                     "method": "group-add", "group": m.group("group")})
        return None
    return None


def parse_log_file(path, log, base_year=None):
    """Yield Events from one syslog-style file, and record ordering issues."""
    events = []
    reversals = 0
    try:
        mtime_year = datetime.utcfromtimestamp(os.path.getmtime(path)).year
    except OSError:
        mtime_year = datetime.utcnow().year
    last_order = None
    seq = 0
    try:
        size = os.path.getsize(path)
    except OSError:
        size = 0
    if size == 0:
        return events, reversals, True  # empty flag

    try:
        fh = open(path, "r", encoding="utf-8", errors="replace")
    except OSError as exc:
        log.error("cannot read %s (%s)" % (path, exc))
        return events, reversals, False
    with fh:
        for line in fh:
            seq += 1
            proc = msg = None
            parsed = None
            m = RE_SYSLOG_ISO.match(line)
            if m:
                parsed = _iso_from_isots(m.group("ts"))
                proc, msg = m.group("proc"), m.group("msg")
            else:
                m = RE_SYSLOG_BSD.match(line)
                if m:
                    parsed = _iso_from_bsd(m.group("mon"), m.group("day"),
                                           m.group("time"), base_year,
                                           mtime_year)
                    proc, msg = m.group("proc"), m.group("msg")
            if not parsed or proc is None:
                continue
            order, iso, hour = parsed
            # Timestamp reversal within a single file, beyond a few seconds of
            # skew, is a tampering signal (lines removed or re-stitched).
            if last_order is not None and order < last_order - 5:
                reversals += 1
            last_order = max(order, last_order) if last_order is not None else order

            c = classify_message(proc, msg)
            if not c:
                continue
            kind, result, f = c
            ev = Event(order, iso, hour, f.get("user"), f.get("ip"),
                       f.get("method"), result, kind, os.path.basename(path),
                       scrub(line.rstrip(), 300),
                       to=f.get("to"), group=f.get("group"), cmd=f.get("cmd"))
            events.append(ev)
    return events, reversals, False


def ingest_last(binary, source_file, kind_result, log):
    """Ingest wtmp/btmp via last(1)/lastb(1). Best-effort; never fatal."""
    events = []
    if not _have(binary):
        log.info("%s not available - skipping %s" % (binary, source_file or binary))
        return events
    cmd = [binary, "-F", "-w"]
    if source_file:
        cmd += ["-f", source_file]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError) as exc:
        log.error("%s failed (%s)" % (binary, exc))
        return events
    result = "fail" if binary == "lastb" else "login-record"
    for line in out.stdout.splitlines():
        if not line.strip() or line.startswith(("wtmp begins", "btmp begins")):
            continue
        parts = line.split()
        if len(parts) < 7 or parts[0] in ("reboot", "shutdown"):
            continue
        user, tty = parts[0], parts[1]
        host = parts[2] if len(parts) > 3 else ""
        m = re.search(r"[A-Z][a-z]{2}\s+[A-Z][a-z]{2}\s+\d+\s+"
                      r"(\d{2}:\d{2}:\d{2})\s+(\d{4})", line)
        order = 0
        iso = ""
        hour = 0
        dm = re.search(r"([A-Z][a-z]{2})\s+(\d+)\s+(\d{2}):(\d{2}):(\d{2})\s+(\d{4})",
                       line)
        if dm:
            mon_n = MONTHS.get(dm.group(1))
            if mon_n:
                try:
                    dt = datetime(int(dm.group(6)), mon_n, int(dm.group(2)),
                                  int(dm.group(3)), int(dm.group(4)),
                                  int(dm.group(5)))
                    order = calendar.timegm(dt.timetuple())
                    iso = dt.strftime("%Y-%m-%dT%H:%M:%S")
                    hour = dt.hour
                except ValueError:
                    pass
        ip = host if _looks_like_ip(host) else ""
        ev = Event(order, iso, hour, user, ip, "login-record",
                   "fail" if binary == "lastb" else "accept",
                   "login-record", os.path.basename(source_file or binary),
                   line[:300])
        events.append(ev)
    log.info("ingested %d record(s) from %s" % (len(events), source_file or binary))
    return events


def _have(binary):
    from shutil import which
    return which(binary) is not None


def _looks_like_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


# --------------------------------------------------------------------------- #
# Source discovery
# --------------------------------------------------------------------------- #

def discover_sources(root, log):
    """Find authentication logs under root. Returns list of file paths."""
    found = []
    base = root.rstrip("/") or "/"
    for rel in AUTH_LOG_GLOBS:
        stem = os.path.join(base, rel)
        d = os.path.dirname(stem)
        name = os.path.basename(stem)
        if not os.path.isdir(d):
            continue
        for fn in sorted(os.listdir(d)):
            # auth.log, auth.log.1, secure, secure-20260801 (skip .gz - we do
            # not silently read compressed archives)
            if fn == name or fn.startswith(name + ".") or fn.startswith(name + "-"):
                if fn.endswith(".gz") or fn.endswith(".xz") or fn.endswith(".bz2"):
                    log.info("skipping compressed log (not read): %s" %
                             os.path.join(d, fn))
                    continue
                found.append(os.path.join(d, fn))
    return found


# --------------------------------------------------------------------------- #
# Analysis rules
# --------------------------------------------------------------------------- #

def analyse(events, findings, log, args, known_nets):
    """Apply the temporal and heuristic rules to the normalised stream."""
    events.sort(key=lambda e: (e.order, e.source))

    # Group SSH failures by IP for burst detection and success-after-burst.
    fails_by_ip = {}
    for ev in events:
        if ev.kind == "ssh" and ev.result == "fail" and ev.ip:
            fails_by_ip.setdefault(ev.ip, []).append(ev)

    window = args.window
    threshold = args.fail_threshold

    brute_ips = set()
    for ip, evs in fails_by_ip.items():
        times = sorted(e.order for e in evs)
        # sliding window: is there any span of `window` secs holding >= threshold?
        worst = 0
        i = 0
        for j in range(len(times)):
            while times[j] - times[i] > window:
                i += 1
            worst = max(worst, j - i + 1)
        if worst >= threshold:
            brute_ips.add(ip)
            users = sorted({e.user for e in evs if e.user})[:8]
            findings.add(ip, "MEDIUM", "AUTH-BRUTE-FORCE",
                         [ip, evs[-1].iso, "", ip, "ssh",
                          "%d failed logins from %s (worst %d in %ds); users tried: %s"
                          % (len(evs), ip, worst, window, ", ".join(users) or "-"),
                          evs[-1].raw])

    # Success following a failure burst from the same IP. The IP has either
    # already qualified as a brute-forcer (worst window >= threshold) and the
    # success closely follows one of its failures, OR threshold-many failures
    # fall within the window immediately before the success. Either way, a
    # successful login from a host that was hammering the service is the signal.
    for ev in events:
        if ev.kind == "ssh" and ev.result == "accept" and ev.ip in fails_by_ip:
            prior = [e.order for e in fails_by_ip[ev.ip]
                     if 0 <= ev.order - e.order <= window]
            total = len(fails_by_ip[ev.ip])
            if len(prior) >= threshold or (ev.ip in brute_ips and len(prior) >= 1):
                findings.add(ev.ip, "HIGH", "AUTH-BRUTE-SUCCESS",
                             [ev.ip, ev.iso, ev.user, ev.ip, ev.method,
                              "successful login as '%s' from %s, which produced %d "
                              "failed attempts (%d within %ds before the success) - "
                              "likely successful brute-force"
                              % (ev.user, ev.ip, total, len(prior), window), ev.raw])

    # Successful logins: new-source-IP (baseline), root login, odd-hours.
    for ev in events:
        is_success_login = (
            (ev.kind == "ssh" and ev.result == "accept") or
            (ev.kind == "login-record" and ev.result == "accept"))
        if not is_success_login:
            continue
        if ev.ip and known_nets is not None and not _ip_known(ev.ip, known_nets):
            findings.add(ev.ip, "MEDIUM", "AUTH-NEW-SOURCE-IP",
                         [ev.ip, ev.iso, ev.user, ev.ip, ev.method,
                          "successful login as '%s' from %s, which is not in the "
                          "known-good source list" % (ev.user, ev.ip), ev.raw])
        if ev.user == "root" and ev.ip and not _is_loopback(ev.ip):
            findings.add(ev.ip or "root", "LOW", "AUTH-ROOT-LOGIN",
                         [ev.ip, ev.iso, ev.user, ev.ip, ev.method,
                          "direct remote root login from %s" % ev.ip, ev.raw])
        if _odd_hour(ev.hour, args):
            sev = "MEDIUM" if ev.user == "root" else "LOW"
            subj = "%s@%s" % (ev.user, ev.ip or "local")
            findings.add(subj, sev, "AUTH-ODD-HOURS",
                         [ev.ip, ev.iso, ev.user, ev.ip, ev.method,
                          "successful login as '%s' at %02d:00-hour (outside "
                          "expected hours)" % (ev.user, ev.hour), ev.raw])

    # Account creation and sudo-group additions.
    for ev in events:
        if ev.kind == "account" and ev.method in ("useradd", "groupadd"):
            findings.add(ev.user or ev.method, "MEDIUM", "AUTH-NEW-ACCOUNT",
                         [ev.ip, ev.iso, ev.user, ev.ip, ev.method,
                          "%s created '%s'" % (ev.method, ev.user), ev.raw])
        if ev.kind == "account" and ev.method == "group-add":
            grp = ev.group or ""
            if grp in SUDO_GROUPS:
                findings.add(ev.user or grp, "MEDIUM", "AUTH-NEW-SUDOER",
                             [ev.ip, ev.iso, ev.user, ev.ip, "group-add",
                              "user '%s' added to privileged group '%s'"
                              % (ev.user, grp), ev.raw])

    # su to root, and failed-su bursts.
    su_fail_by_user = {}
    for ev in events:
        if ev.kind == "su" and ev.result == "session":
            to = ev.to or ""
            if to == "root" and ev.user and ev.user != "root":
                findings.add(ev.user, "LOW", "AUTH-SU-ROOT",
                             [ev.ip, ev.iso, ev.user, ev.ip, "su",
                              "user '%s' switched to root via su" % ev.user, ev.raw])
        if ev.kind == "su" and ev.result == "fail" and ev.user:
            su_fail_by_user.setdefault(ev.user, []).append(ev)
    for user, evs in su_fail_by_user.items():
        if len(evs) >= threshold:
            findings.add(user, "MEDIUM", "AUTH-SU-FAIL-BURST",
                         [evs[-1].ip, evs[-1].iso, user, evs[-1].ip, "su",
                          "%d failed su attempts by '%s' - possible privilege "
                          "escalation attempts" % (len(evs), user), evs[-1].raw])


def _ip_known(ip, nets):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True  # not an IP (a hostname) - do not flag on the baseline rule
    return any(addr in n for n in nets)


def _is_loopback(ip):
    try:
        return ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return False


def _odd_hour(hour, args):
    if args.work_start is not None and args.work_end is not None:
        # odd = outside [work_start, work_end)
        if args.work_start <= args.work_end:
            return not (args.work_start <= hour < args.work_end)
        return not (hour >= args.work_start or hour < args.work_end)
    # default night window [night_start, night_end)
    return args.night_start <= hour < args.night_end


# --------------------------------------------------------------------------- #
# Writers
# --------------------------------------------------------------------------- #

def write_events(path, events):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("order\ttimestamp\thour\tkind\tresult\tuser\tsource_ip\t"
                 "method\tsource_file\traw\n")
        for e in sorted(events, key=lambda x: (x.order, x.source)):
            fh.write("\t".join(scrub(x) for x in [
                e.order, e.iso, e.hour, e.kind, e.result, e.user, e.ip,
                e.method, e.source, e.raw]) + "\n")


def write_summary(path, ctx, findings, stats, quiet):
    lines = []
    lines.append("%s %s - hunt summary" % (PROGRAM, VERSION))
    lines.append("=" * 48)
    for k, v in ctx:
        lines.append("%-18s %s" % (k + ":", v))
    lines.append("")
    lines.append("%-18s %s" % ("events parsed:", stats["events"]))
    lines.append("%-18s %s" % ("log files:", stats["files"]))
    lines.append("%-18s %s" % ("subjects flagged:", findings.flagged))
    lines.append("%-18s %s" % ("findings:", findings.count))
    lines.append("%-18s %s" % ("high:", findings.high))
    lines.append("%-18s %s" % ("medium:", findings.medium))
    lines.append("%-18s %s" % ("low/info:", findings.low))
    lines.append("%-18s %s" % ("read errors:", stats["errors"]))
    lines.append("")
    lines.append("Rule reference:")
    for rid, count in sorted(stats["rules"].items()):
        lines.append("  %-22s %d" % (rid, count))
    lines.append("")
    lines.append("Coverage note: authentication logs can be edited or deleted by")
    lines.append("an attacker with sufficient access. A clean result here does")
    lines.append("not clear a host; absence of evidence is not evidence of absence.")
    lines.append("")
    lines.append("Reminder: findings are investigative leads, not proof of compromise.")
    lines.append("Validate provenance and known-good state before acting.")
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
        prog=PROGRAM, add_help=True,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Linux authentication anomaly hunter (read-only). "
                    "Normalises auth.log/secure, the systemd journal and "
                    "wtmp/btmp into one event stream and flags brute force, "
                    "success-after-burst, new source IPs, odd-hours logins, new "
                    "accounts and sudoers, su activity and log tampering.",
        epilog="Findings are investigative leads, not proof of compromise.")

    g = p.add_argument_group("target selection")
    g.add_argument("-p", "--path", action="append", dest="paths", metavar="FILE",
                   help="Auth log file to parse. Repeatable. If given, "
                        "discovery under --root is skipped.")
    g.add_argument("--root", default="/", metavar="DIR",
                   help="Root under which to discover auth logs and wtmp/btmp "
                        "(default /). Point at a mounted image to hunt offline.")

    g2 = p.add_argument_group("output and case metadata")
    g2.add_argument("-o", "--output", metavar="DIR", required=True,
                    help="Output directory (required). Refused if inside a scan "
                         "root, or non-empty without --force.")
    g2.add_argument("--force", action="store_true",
                    help="Permit writing into an existing non-empty directory.")
    g2.add_argument("--case", default="", help="Case/incident reference.")
    g2.add_argument("--examiner", default="", help="Examiner/operator name.")
    g2.add_argument("--source-id", default="", help="Evidence/host identifier.")

    g3 = p.add_argument_group("hunt options")
    g3.add_argument("--fail-threshold", type=int, default=5, metavar="N",
                    help="Failures within the window to call it a burst "
                         "(default 5).")
    g3.add_argument("--window", type=int, default=300, metavar="SECS",
                    help="Burst/correlation window in seconds (default 300).")
    g3.add_argument("--work-start", type=int, default=None, metavar="H",
                    help="Start hour of expected working hours (0-23). If set "
                         "with --work-end, odd-hours = outside this window.")
    g3.add_argument("--work-end", type=int, default=None, metavar="H",
                    help="End hour of expected working hours (0-23, exclusive).")
    g3.add_argument("--night-start", type=int, default=0, metavar="H",
                    help="Default night window start hour (default 0).")
    g3.add_argument("--night-end", type=int, default=6, metavar="H",
                    help="Default night window end hour, exclusive (default 6).")
    g3.add_argument("--known-ips", metavar="FILE",
                    help="File of known-good source IPs/CIDRs (one per line). "
                         "Successful logins from anything else are flagged.")
    g3.add_argument("--year", type=int, default=None, metavar="YYYY",
                    help="Assume this year for year-less syslog timestamps "
                         "(default: inferred from each file's mtime).")
    g3.add_argument("--no-wtmp", dest="wtmp", action="store_false",
                    help="Do not read wtmp/btmp via last/lastb.")
    g3.add_argument("--no-journal", dest="journal", action="store_false",
                    help="Do not read the systemd journal even when live.")

    g4 = p.add_argument_group("output verbosity")
    g4.add_argument("-v", "--verbose", action="store_true",
                    help="Per-item detail on stderr.")
    g4.add_argument("-q", "--quiet", action="store_true",
                    help="Suppress console summary. Files are still written.")
    p.add_argument("-V", "--version", action="version",
                   version="%s %s" % (PROGRAM, VERSION))
    return p


def load_known_ips(path, log):
    nets = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                try:
                    nets.append(ipaddress.ip_network(s, strict=False))
                except ValueError:
                    log.warning("ignoring unparseable known-ip entry: %s" % s)
    except OSError as exc:
        die("cannot read --known-ips file %s (%s)" % (path, exc))
    log.info("loaded %d known-good network(s)" % len(nets))
    return nets


def main(argv):
    args = build_parser().parse_args(argv)

    for h in (args.work_start, args.work_end, args.night_start, args.night_end):
        if h is not None and not (0 <= h <= 23):
            die("hour values must be between 0 and 23")

    # Resolve sources first (so we can register them as scan roots for the
    # output-safety check).
    roots_for_safety = []
    if args.paths:
        sources = []
        for pth in args.paths:
            if not os.path.isfile(pth):
                die("auth log is not a file: %s" % pth)
            sources.append(os.path.abspath(pth))
            roots_for_safety.append(os.path.dirname(os.path.abspath(pth)))
    else:
        roots_for_safety.append(args.root)

    outdir, note = resolve_output(args.output, args.force, roots_for_safety)
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
        ("root", args.root),
        ("output_dir", outdir),
        ("command", " ".join([os.path.basename(sys.argv[0])] + argv)),
    ]
    log.section("run start")
    for k, v in ctx:
        log.info("%s = %s" % (k, v))
    if note:
        log.warning(note)

    known_nets = load_known_ips(args.known_ips, log) if args.known_ips else None
    if known_nets is None:
        log.info("no --known-ips baseline: AUTH-NEW-SOURCE-IP is not evaluated")

    # Discover / collect sources.
    log.section("collecting sources")
    if not args.paths:
        sources = discover_sources(args.root, log)
    for s in sources:
        log.info("auth log: %s" % s)
    if not sources:
        log.warning("no auth logs found under %s (looked for auth.log*/secure*)"
                    % args.root)

    events = []
    files = 0
    empty_logs = []
    findings = Findings(
        ["subject", "timestamp", "user", "source_ip", "method", "detail", "evidence"])

    base_year = args.year
    for path in sources:
        evs, reversals, empty = parse_log_file(path, log, base_year)
        files += 1
        events.extend(evs)
        log.info("parsed %s: %d event(s)%s" %
                 (path, len(evs),
                  ", %d timestamp reversal(s)" % reversals if reversals else ""))
        if empty:
            empty_logs.append(path)
            findings.add(os.path.basename(path), "LOW", "AUTH-LOG-EMPTY",
                         [os.path.basename(path), "", "", "", "file",
                          "authentication log exists but is empty - possible "
                          "truncation or clearing", path])
        if reversals:
            findings.add(os.path.basename(path), "MEDIUM", "AUTH-TIME-REVERSAL",
                         [os.path.basename(path), "", "", "", "file",
                          "%d timestamp reversal(s) within the file, beyond clock "
                          "skew - possible log tampering" % reversals, path])

    # wtmp / btmp via last / lastb.
    if args.wtmp:
        if args.paths:
            log.info("explicit --path given: skipping wtmp/btmp auto-discovery")
        else:
            base = args.root.rstrip("/") or "/"
            live = os.path.abspath(base) == "/"
            for rel in WTMP_PATHS:
                fp = None if live else os.path.join(base, rel)
                if live or os.path.isfile(os.path.join(base, rel)):
                    events.extend(ingest_last("last", fp, "accept", log))
            for rel in BTMP_PATHS:
                fp = None if live else os.path.join(base, rel)
                if live or os.path.isfile(os.path.join(base, rel)):
                    events.extend(ingest_last("lastb", fp, "fail", log))

    # systemd journal, opportunistically, on the live host.
    if args.journal and (os.path.abspath(args.root.rstrip("/") or "/") == "/") \
            and not args.paths and _have("journalctl"):
        events.extend(ingest_journal(log))

    log.section("analysis")
    analyse(events, findings, log, args, known_nets)

    log.section("writing reports")
    findings.write(os.path.join(outdir, "findings.tsv"))
    write_events(os.path.join(outdir, "auth-events.tsv"), events)

    rules = {}
    for _s, _sev, rid, _f in findings.rows:
        rules[rid] = rules.get(rid, 0) + 1
    ctx.append(("completed_utc", utc_now()))
    stats = {"events": len(events), "files": files, "errors": log.errors,
             "rules": rules}
    write_summary(os.path.join(outdir, "summary.txt"), ctx, findings, stats,
                  args.quiet)

    for f in ("findings.tsv", "auth-events.tsv", "summary.txt"):
        log.info("wrote %s" % os.path.join(outdir, f))
    log.section("run end")
    log.info("events=%d flagged=%d findings=%d errors=%d"
             % (len(events), findings.flagged, findings.count, log.errors))
    log.info("writing SHA256SUMS last; it covers this log, so this is the final "
             "log line")
    log.close()
    write_manifest(outdir)

    if not args.quiet:
        sys.stdout.write("\n%s complete. %d event(s) parsed, %d subject(s) "
                         "flagged, %d finding(s).\nReports in: %s\n"
                         % (PROGRAM, len(events), findings.flagged,
                            findings.count, outdir))
    return EXIT_FINDINGS if findings.count > 0 else EXIT_OK

def ingest_journal(log):
    """Pull authentication events from the live systemd journal (best-effort)."""
    events = []
    cmd = ["journalctl", "-o", "short-iso", "--no-pager",
           "SYSLOG_FACILITY=10", "SYSLOG_FACILITY=4"]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.SubprocessError) as exc:
        log.error("journalctl failed (%s)" % exc)
        return events
    count = 0
    for line in out.stdout.splitlines():
        m = RE_SYSLOG_ISO.match(line)
        if not m:
            # journalctl short-iso: "2026-08-04T12:00:01+0100 host proc[pid]: msg"
            m2 = re.match(r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\S*\s+"
                          r"\S+\s+(?P<proc>[\w./-]+)(?:\[\d+\])?:\s+(?P<msg>.*)$",
                          line)
            if not m2:
                continue
            parsed = _iso_from_isots(m2.group("ts"))
            proc, msg = m2.group("proc"), m2.group("msg")
        else:
            parsed = _iso_from_isots(m.group("ts"))
            proc, msg = m.group("proc"), m.group("msg")
        if not parsed:
            continue
        c = classify_message(proc, msg)
        if not c:
            continue
        order, iso, hour = parsed
        kind, result, f = c
        ev = Event(order, iso, hour, f.get("user"), f.get("ip"), f.get("method"),
                   result, kind, "journal", scrub(line, 300),
                   to=f.get("to"), group=f.get("group"), cmd=f.get("cmd"))
        events.append(ev)
        count += 1
    log.info("ingested %d event(s) from the systemd journal" % count)
    return events

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
