#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
webshell-hunter.py - statistical and signature web shell hunter
================================================================

A forensically-minded, cross-platform hunter for web shells and obfuscated
server-side code. It is a modern Python 3 reimagining of the ideas behind the
classic (and now unmaintained, Python 2) tools *NeoPI* and *BackdoorMan*:

  * NeoPI's contribution was *statistical* - it ranked files by entropy, index
    of coincidence and longest-word length to surface obfuscated or encoded
    payloads that signature scanners miss.
  * BackdoorMan's contribution was *signature and heuristic* - it looked for the
    function primitives and shell families that web shells rely on.

This tool combines both approaches in one dependency-free script and is designed
to be **useful entirely on its own** - a hunter who only runs this Python script
should still get a high-value result. To that end, it also performs light-touch
web-root discovery and access-log analysis, so it does not depend on any other
tool to find its targets or spot shell interaction.

It happily complements the companion Bash tool *WebShellHuntr*
(https://for577.com/web-shell-bash) if you run both, but it does not require it.
The one capability deliberately left to a separate tool is live-process hunting,
which is operating-system specific and is not web-shell file analysis. This tool
runs anywhere Python 3 does - including natively on Windows against a mounted
image.

This is a HUNTING aid. Every result is an *investigative lead*, not proof of
compromise. A high entropy score can be a minified library; a `system()` call can
be legitimate. Human judgement decides.

Design goals
------------
* **Standard library only.** No pip installs. It will run on a locked-down
  incident-response host or a clean analysis VM without preparation.
* **Read-only and forensically sound.** The target is never written to, decoded,
  quarantined, executed or uploaded. Pre-read metadata and SHA-256 are recorded
  for every candidate. All output goes to a separate directory, which the tool
  refuses to place inside the target. A timestamped audit log and a final
  SHA-256 manifest of the outputs are produced.
* **Cross-platform.** Windows, Linux and macOS. On Windows, point it at a
  mounted image or an extracted web root.

Forensic caveats
----------------
* Reading a file can update its access time (atime) on a writable, live
  filesystem. Prefer a read-only mount or a working copy of the evidence. This
  tool does NOT attempt to restore atimes, because doing so rewrites the change
  time (ctime) and is itself an alteration of the evidence.
* Ownership, mode and some timestamps are platform-dependent. The tool records
  whatever the operating system exposes and says so in the log.

Author: Halkyn Consulting.
Licence: MIT (see repository). Reimplementation of published concepts; contains
no third-party code.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import math
import os
import platform
import re
import signal
import sys
import zlib
from collections import Counter
from datetime import datetime, timezone

VERSION = "1.0.0"
PROGRAM = "webshell-hunter"

# Exit codes chosen to match the companion Bash tool.
EXIT_OK = 0            # completed, no findings
EXIT_FINDINGS = 1      # completed, one or more findings
EXIT_USAGE = 2         # invalid use, unsafe path, or incomplete run
EXIT_INTERRUPT = 130   # interrupted by operator/signal

# --------------------------------------------------------------------------- #
# File selection defaults
# --------------------------------------------------------------------------- #

# Extensions that commonly hold server-side code. Files with these extensions are
# always treated as candidates. With --all-files, every readable file is a
# candidate (non-script extensions are still probed for embedded server-side
# code, catching image/document masquerading).
SCRIPT_EXTENSIONS = {
    ".php", ".php3", ".php4", ".php5", ".php7", ".php8", ".phtml", ".pht",
    ".phar", ".inc",
    ".asp", ".aspx", ".ashx", ".asmx", ".ascx", ".cshtml", ".vbhtml",
    ".jsp", ".jspx", ".jspf", ".jsw", ".jsv", ".jhtml",
    ".cfm", ".cfml", ".cfc",
    ".pl", ".pm", ".cgi",
    ".py", ".pyc",
    ".rb", ".rhtml", ".erb",
    ".js", ".mjs", ".cjs", ".ts",
    ".sh", ".bash",
    ".htaccess", ".conf",
}

# Extensions that should not normally contain server-side code. When embedded
# code IS found in these, that is itself suspicious (masquerading).
MASQUERADE_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico", ".svg",
    ".txt", ".log", ".csv", ".xml", ".json", ".html", ".htm",
    ".css", ".pdf", ".doc", ".docx", ".xls", ".xlsx",
}

# Directories that are noise on most web servers. Skipped unless the path is
# explicitly requested.
DEFAULT_SKIP_DIRS = {".git", ".svn", ".hg", "node_modules", "vendor",
                     "__pycache__", ".cache"}

# Common web-root locations, relative to --root. Used for auto-discovery when the
# operator does not name a --path, so the tool still finds targets on its own.
COMMON_WEB_ROOTS = [
    "var/www", "var/www/html", "srv/www", "srv/www/htdocs", "srv/http",
    "usr/share/nginx/html", "usr/local/apache2/htdocs", "usr/local/www",
    "usr/local/www/apache24/data", "opt/lampp/htdocs", "opt/bitnami/apache/htdocs",
    "var/www/localhost/htdocs", "home",  # user public_html folders live here
    "inetpub/wwwroot",           # IIS, e.g. under a mounted Windows image
    "Inetpub/wwwroot",
]

# Common access-log directories, relative to --root. Used for log analysis
# auto-discovery. Only uncompressed logs are read.
COMMON_LOG_DIRS = [
    "var/log/apache2", "var/log/httpd", "var/log/nginx", "var/log/lighttpd",
    "var/log/caddy", "var/log/openlitespeed", "usr/local/apache2/logs",
    "opt/lampp/logs", "var/log",
]
RE_ACCESS_LOG_NAME = re.compile(r"access|\.log(\.\d+)?$", re.IGNORECASE)

# --------------------------------------------------------------------------- #
# Signature rules (BackdoorMan lineage - original expressions, not copied code)
# --------------------------------------------------------------------------- #
# Each rule: (id, severity, description, compiled regex). Severity HIGH means the
# construct is strongly associated with web shells; MEDIUM means it warrants a
# look in context. These are deliberately conservative; false positives are
# expected and are the analyst's to resolve.

def _c(pattern: str) -> "re.Pattern":
    return re.compile(pattern, re.IGNORECASE)


# Map a file extension to a language code, so language-specific signatures only
# run against the right files (this keeps cross-language noise down - e.g. PHP
# system() should not also fire the Perl rule).
LANG_BY_EXT = {
    ".php": "php", ".php3": "php", ".php4": "php", ".php5": "php",
    ".php7": "php", ".php8": "php", ".phtml": "php", ".pht": "php",
    ".phar": "php", ".inc": "php",
    ".asp": "asp", ".aspx": "asp", ".ashx": "asp", ".asmx": "asp",
    ".ascx": "asp", ".cshtml": "asp", ".vbhtml": "asp",
    ".jsp": "jsp", ".jspx": "jsp", ".jspf": "jsp", ".jsw": "jsp",
    ".jsv": "jsp", ".jhtml": "jsp",
    ".cfm": "cfm", ".cfml": "cfm", ".cfc": "cfm",
    ".pl": "perl", ".pm": "perl", ".cgi": "perl",
    ".py": "py", ".pyc": "py",
    ".rb": "ruby", ".rhtml": "ruby", ".erb": "ruby",
    ".js": "js", ".mjs": "js", ".cjs": "js", ".ts": "js",
    ".conf": "conf", ".htaccess": "conf",
}

# Language markers used to classify masquerading/ambiguous files by content.
LANG_MARKERS = [
    ("php", _c(r"<\?php|<\?=")),
    ("jsp", _c(r"<%[@!]?|<jsp:|Runtime\.getRuntime|ProcessBuilder")),
    ("asp", _c(r"<%|System\.Diagnostics\.Process|WScript\.Shell|Request\.")),
    ("cfm", _c(r"<cf(execute|script)")),
    ("perl", _c(r"#!.*perl\b")),
    ("py", _c(r"#!.*python\b|import\s+os|import\s+subprocess")),
    ("ruby", _c(r"#!.*ruby\b")),
    ("js", _c(r"require\s*\(\s*['\"]child_process|module\.exports")),
]

# Which rule-id prefixes apply to which language. FAMILY always runs.
RULE_LANG = {
    "SIG-PHP": "php", "SIG-JSP": "jsp", "SIG-ASP": "asp", "SIG-JS": "js",
    "SIG-PY": "py", "SIG-PERL": "perl", "SIG-RUBY": "ruby", "SIG-CONF": "conf",
}


def rule_language(rule_id):
    for prefix, lang in RULE_LANG.items():
        if rule_id.startswith(prefix):
            return lang
    return None  # universal (e.g. SIG-FAMILY)


def classify_language(path, text):
    ext = os.path.splitext(path)[1].lower()
    name = os.path.basename(path).lower()
    if name == ".htaccess":
        return "conf"
    lang = LANG_BY_EXT.get(ext)
    if lang:
        return lang
    for code, rx in LANG_MARKERS:
        if rx.search(text):
            return code
    return None

SIGNATURE_RULES = [
    # Known web-shell family fingerprints
    ("SIG-FAMILY", "HIGH",
     "Recognisable web-shell family fingerprint (c99/r57/b374k/wso/china chopper).",
     _c(r"(c99sh|r57shell|b374k|wsoshell|wso\s*shell|filesman|"
        r"china\s*chopper|>\s*(c99|r57|b374k|wso)\s*<|antichat|"
        r"safe_?mode\s*bypass)")),

    # --- PHP ---
    ("SIG-PHP-EXEC", "HIGH",
     "PHP command/process-execution primitive.",
     _c(r"(?:^|[^A-Za-z0-9_>])(system|passthru|shell_exec|proc_open|popen|"
        r"pcntl_exec|exec)\s*\(")),
    ("SIG-PHP-EVAL-DECODE", "HIGH",
     "PHP eval/assert combined with decoding or decompression (packed payload).",
     _c(r"(eval|assert)\s*\([^;]{0,200}?(base64_decode|gzinflate|gzuncompress|"
        r"str_rot13|gzdecode|convert_uudecode|rawurldecode)")),
    ("SIG-PHP-PREG-E", "HIGH",
     "PHP preg_replace with /e modifier (code execution).",
     _c(r"preg_replace\s*\(\s*([\"']).*?\1\s*\.\s*['\"]?[a-z]*e[a-z]*['\"]?")),
    ("SIG-PHP-REQ-CALL", "HIGH",
     "PHP request variable invoked directly as a function (classic one-liner shell).",
     _c(r"\$_(GET|POST|REQUEST|COOKIE|SERVER)\s*\[[^]]+\]\s*\(")),
    ("SIG-PHP-CREATE-FUNCTION", "MEDIUM",
     "Deprecated PHP create_function (used to smuggle eval).",
     _c(r"create_function\s*\(")),
    ("SIG-PHP-REVB64", "HIGH",
     "Reversed 'base64_decode' string - a common obfuscation tell.",
     _c(r"edoced_46esab")),
    ("SIG-PHP-DYNAMIC", "MEDIUM",
     "PHP variable-variable or dynamic-function invocation.",
     _c(r"(\$\{[^}]+\}|\$\$[A-Za-z_]\w*)\s*\(")),
    ("SIG-PHP-BACKTICK", "MEDIUM",
     "PHP backtick shell-execution operator.",
     _c(r"`[^`\n]{1,400}`")),
    ("SIG-PHP-UPLOAD", "MEDIUM",
     "PHP file write/upload primitive (payload staging).",
     _c(r"(file_put_contents|fwrite|move_uploaded_file|fputs)\s*\(")),

    # --- JSP / Java ---
    ("SIG-JSP-EXEC", "HIGH",
     "JSP/Java launches an operating-system process.",
     _c(r"(Runtime\.getRuntime\s*\(\s*\)\s*\.\s*exec|new\s+ProcessBuilder|"
        r"ProcessBuilder\s*\()")),
    ("SIG-JSP-LOADER", "MEDIUM",
     "JSP/Java dynamic class definition or script engine.",
     _c(r"(defineClass\s*\(|URLClassLoader|ScriptEngineManager)")),

    # --- ASP / ASP.NET ---
    ("SIG-ASP-EXEC", "HIGH",
     "ASP/ASP.NET starts a shell or process.",
     _c(r"(System\.Diagnostics\.Process|Process\.Start|WScript\.Shell|"
        r"ShellExecute|cmd\.exe|powershell(\.exe)?)")),

    # --- Server-side JavaScript (Node) ---
    ("SIG-JS-CHILDPROC", "MEDIUM",
     "Server-side JavaScript child_process execution.",
     _c(r"(require\s*\(\s*['\"]child_process['\"]|from\s+['\"]child_process['\"]|"
        r"child_process\.(exec|execFile|spawn|fork)|execSync\s*\()")),

    # --- Python ---
    ("SIG-PY-EXEC", "MEDIUM",
     "Python launches a process or shell.",
     _c(r"(subprocess\.(Popen|run|call|check_output|check_call)|"
        r"os\.(system|popen)|pty\.spawn)\s*\(")),

    # --- Perl / CGI ---
    ("SIG-PERL-EXEC", "MEDIUM",
     "Perl/CGI command-execution primitive.",
     _c(r"(?:\bsystem\b|\bexec\b|\bqx)\s*[({]|`[^`\n]+`")),

    # --- Ruby ---
    ("SIG-RUBY-EXEC", "MEDIUM",
     "Ruby launches a command or process.",
     _c(r"(Kernel\.(system|exec)|Open3\.(capture|popen)|IO\.popen)")),

    # --- Web server config ---
    ("SIG-CONF-APPEND", "HIGH",
     "Web config redirects PHP startup to another file (auto_prepend/append).",
     _c(r"auto_(pre|ap)pend_file")),
    ("SIG-CONF-HANDLER", "MEDIUM",
     "Web config adds an executable handler for an unusual extension.",
     _c(r"(AddHandler|AddType|SetHandler)[^\n#]*(php|cgi|fcgi)")),
]

# Correlation rule: request input AND an execution/eval primitive in the same
# file is a much stronger signal than either alone.
RE_TAINT_SOURCE = _c(
    r"(\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)|php://input|"          # PHP
    r"getParameter|getInputStream|getHeader|"                           # JSP
    r"Request\.(Form|QueryString|Cookies)|Request\[|"                   # ASP
    r"req\.(query|body|params|headers|cookies)|"                        # Node
    r"request\.(args|form|values|cookies|data)|cgi\.FieldStorage|"      # Python
    r"param\s*\(|QUERY_STRING|HTTP_COOKIE|"                             # Perl
    r"params\[|cookies\[)")                                             # Ruby
RE_TAINT_SINK = _c(
    r"(eval|assert|system|passthru|shell_exec|exec|proc_open|popen|"
    r"pcntl_exec|Runtime\.getRuntime|ProcessBuilder|Process\.Start|"
    r"WScript\.Shell|child_process|subprocess\.|os\.system|os\.popen|"
    r"Kernel\.(system|exec)|IO\.popen)\s*\(?")

# Markers used to detect embedded server-side code inside masquerading files.
RE_EMBEDDED_CODE = _c(r"(<\?php|<\?=|<%[@!]?|<jsp:|Runtime\.getRuntime|"
                      r"<cf(execute|script)|#!/usr/bin/(perl|python|env))")

# --------------------------------------------------------------------------- #
# Access-log rules - traces of a shell being *used* (BackdoorMan/WebShellHuntr
# lineage; original expressions). Each hit is a lead to correlate with the file
# findings above.
# --------------------------------------------------------------------------- #
LOG_RULES = [
    ("LOG-CMD", "HIGH",
     "Request parameter resembles command execution.",
     _c(r"[?&](cmd|exec|command|c|shell|run|proc)=[^&\s]*"
        r"(whoami|id|uname|ls|cat|wget|curl|/bin/|cmd\.exe|powershell|nc |ncat)")),
    ("LOG-SHELLNAME", "HIGH",
     "Request targets a known web-shell filename.",
     _c(r"/(c99|r57|b374k|wso|shell|cmd|backdoor|webshell|up\.php|"
        r"adminer|alfa|indoxploit)[\w.]*\.(php|asp|aspx|jsp)")),
    ("LOG-B64URL", "MEDIUM",
     "Long base64-like blob in the request (possible encoded command).",
     _c(r"[?&][^=\s]+=[A-Za-z0-9+/]{80,}={0,2}")),
    ("LOG-UPLOAD", "MEDIUM",
     "POST to a script often seen in upload/interaction with a shell.",
     _c(r"\"POST\s+[^\"]+\.(php|asp|aspx|jsp|cfm)")),
    ("LOG-TRAVERSAL", "MEDIUM",
     "Directory traversal or sensitive-file access in the request.",
     _c(r"(\.\./){2,}|/etc/passwd|/etc/shadow|win\.ini|boot\.ini")),
]

# --------------------------------------------------------------------------- #
# Statistical engine (NeoPI lineage - original implementation)
# --------------------------------------------------------------------------- #


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy of a byte string in bits/byte (0.0 - 8.0).

    High values (> ~5.5 for source code, approaching 8.0) indicate compressed,
    encrypted or densely encoded content."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def index_of_coincidence(text: str) -> float:
    """Index of Coincidence over letters.

    Natural-language source sits around 0.06-0.07. Encoded, encrypted or
    machine-generated blobs trend toward a low, uniform IC. LOW IC is the
    suspicious direction."""
    letters = [c.lower() for c in text if c.isalpha()]
    n = len(letters)
    if n < 2:
        return 0.0
    counts = Counter(letters)
    numerator = sum(v * (v - 1) for v in counts.values())
    return numerator / (n * (n - 1))


RE_TOKEN = re.compile(r"[A-Za-z0-9+/=_\\-]+")


def longest_token(text: str) -> int:
    """Length of the longest unbroken token.

    Base64/hex payloads and packed one-liners produce very long tokens. Ordinary
    source rarely exceeds ~50-60 characters in a single token."""
    longest = 0
    for match in RE_TOKEN.finditer(text):
        length = match.end() - match.start()
        if length > longest:
            longest = length
    return longest


def compression_ratio(data: bytes) -> float:
    """Ratio compressed/original using zlib.

    Already-encoded or encrypted content compresses poorly (ratio near 1.0);
    plain source compresses well (ratio well below 1.0). High ratio alongside
    high entropy strengthens the 'encoded payload' hypothesis."""
    if not data:
        return 0.0
    try:
        compressed = zlib.compress(data, 6)
    except zlib.error:
        return 0.0
    return len(compressed) / len(data)


def non_printable_ratio(data: bytes) -> float:
    """Fraction of bytes outside the common printable/whitespace range."""
    if not data:
        return 0.0
    printable = sum(1 for b in data if 9 <= b <= 13 or 32 <= b <= 126)
    return 1.0 - (printable / len(data))


# Absolute thresholds for the statistical tests. These flag a file on its own
# merits; the tool ALSO flags corpus-relative outliers (mean + k*stdev) so that
# an environment with unusually clean or unusually noisy code still surfaces its
# own extremes. Tune with the CLI options.
DEFAULT_THRESHOLDS = {
    "entropy": 5.6,        # bits/byte
    "ioc_low": 0.033,      # below this is suspicious
    "longest_token": 120,  # characters
    "compression": 0.85,   # compressed/original
}


# --------------------------------------------------------------------------- #
# Audit logging
# --------------------------------------------------------------------------- #


class AuditLog:
    """Minimal, dependency-free audit logger.

    Writes UTC-timestamped lines to the output log file and (optionally) echoes
    to the console. Kept deliberately simple so the evidence trail is easy to
    read and hard to break."""

    def __init__(self, path, echo=True, verbose=False):
        self.path = path
        self.echo = echo
        self.verbose = verbose
        self._fh = open(path, "a", encoding="utf-8", newline="\n")

    def _write(self, level, message):
        line = "%s\t%s\t%s" % (utc_now(), level, message)
        self._fh.write(line + "\n")
        self._fh.flush()
        if self.echo and (level != "DETAIL" or self.verbose):
            stream = sys.stderr if level in ("ERROR", "WARNING") else sys.stdout
            stream.write(line + "\n")

    def info(self, message):
        self._write("INFO", message)

    def warning(self, message):
        self._write("WARNING", message)

    def error(self, message):
        self._write("ERROR", message)

    def detail(self, message):
        self._write("DETAIL", message)

    def section(self, message):
        self._write("SECTION", "--- %s ---" % message)

    def close(self):
        try:
            self._fh.close()
        except Exception:
            pass


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------- #
# Core hunter
# --------------------------------------------------------------------------- #


class Finding:
    __slots__ = ("path", "rule_id", "severity", "detail", "evidence")

    def __init__(self, path, rule_id, severity, detail, evidence=""):
        self.path = path
        self.rule_id = rule_id
        self.severity = severity
        self.detail = detail
        self.evidence = evidence


class Candidate:
    __slots__ = ("path", "size", "mtime", "ctime", "atime", "mode", "uid",
                 "gid", "sha256", "entropy", "ioc", "longest", "compression",
                 "nonprint", "kind", "findings", "score")

    def __init__(self, path):
        self.path = path
        self.findings = []
        self.score = 0.0
        self.sha256 = ""
        self.entropy = self.ioc = self.longest = 0.0
        self.compression = self.nonprint = 0.0
        self.kind = ""


SEVERITY_WEIGHT = {"HIGH": 5.0, "MEDIUM": 2.0, "LOW": 1.0, "INFO": 0.5}


class WebShellHunter:
    def __init__(self, args, log: AuditLog):
        self.args = args
        self.log = log
        self.candidates = []
        self.hash_iocs = {}
        self.known_good = {}
        self.files_seen = 0
        self.files_skipped = 0
        self.errors = 0

    # ---- evidence helpers ------------------------------------------------- #

    def stat_file(self, path, cand: Candidate):
        """Record pre-read metadata. Best-effort across platforms."""
        try:
            st = os.stat(path)
        except OSError as exc:
            self.log.error("stat failed: %s (%s)" % (path, exc))
            self.errors += 1
            return False
        cand.size = st.st_size
        cand.mtime = _iso(st.st_mtime)
        cand.ctime = _iso(st.st_ctime)
        cand.atime = _iso(st.st_atime)
        cand.mode = oct(st.st_mode & 0o7777)
        cand.uid = getattr(st, "st_uid", "")
        cand.gid = getattr(st, "st_gid", "")
        return True

    def read_bytes(self, path, limit):
        """Read up to `limit` bytes read-only. Returns bytes or None."""
        try:
            with open(path, "rb") as fh:
                return fh.read(limit)
        except (OSError, PermissionError) as exc:
            self.log.error("read failed: %s (%s)" % (path, exc))
            self.errors += 1
            return None

    def hash_file(self, path):
        """Full-file SHA-256, streamed. Independent of the analysis read so the
        whole file is always hashed even when analysis is size-capped."""
        h = hashlib.sha256()
        try:
            with open(path, "rb") as fh:
                for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                    h.update(chunk)
        except (OSError, PermissionError) as exc:
            self.log.error("hash failed: %s (%s)" % (path, exc))
            self.errors += 1
            return ""
        return h.hexdigest()

    # ---- selection -------------------------------------------------------- #

    def is_candidate(self, path):
        ext = os.path.splitext(path)[1].lower()
        name = os.path.basename(path).lower()
        if name in (".htaccess",) or ext in SCRIPT_EXTENSIONS:
            return True, "script"
        if self.args.all_files:
            if ext in MASQUERADE_EXTENSIONS:
                return True, "masquerade-probe"
            return True, "other"
        if ext in MASQUERADE_EXTENSIONS:
            return True, "masquerade-probe"
        return False, ""

    def walk(self, root):
        """Yield candidate file paths under root, read-only, honouring excludes,
        skip-dirs, filesystem boundaries and the max-files cap."""
        excludes = [os.path.normpath(e) for e in (self.args.exclude or [])]
        root_dev = None
        if not self.args.cross_filesystems:
            try:
                root_dev = os.stat(root).st_dev
            except OSError:
                root_dev = None
        for dirpath, dirnames, filenames in os.walk(root, topdown=True):
            # prune noise directories unless explicitly targeted
            dirnames[:] = [d for d in dirnames
                           if d not in DEFAULT_SKIP_DIRS or self.args.all_files]
            # filesystem boundary
            if root_dev is not None:
                kept = []
                for d in dirnames:
                    try:
                        if os.stat(os.path.join(dirpath, d)).st_dev == root_dev:
                            kept.append(d)
                    except OSError:
                        pass
                dirnames[:] = kept
            for fn in filenames:
                full = os.path.join(dirpath, fn)
                norm = os.path.normpath(full)
                if any(norm == ex or norm.startswith(ex + os.sep)
                       for ex in excludes):
                    continue
                if os.path.islink(full):
                    self.log.detail("skip symlink: %s" % full)
                    continue
                yield full

    # ---- analysis --------------------------------------------------------- #

    def analyse(self, path):
        cand = Candidate(path)
        if not self.stat_file(path, cand):
            return None
        if cand.size > self.args.max_size:
            self.log.detail("skip oversize (%d bytes): %s" % (cand.size, path))
            self.files_skipped += 1
            # still hash and inventory oversize files for completeness
            cand.sha256 = self.hash_file(path)
            cand.kind = "oversize"
            return cand
        cand.sha256 = self.hash_file(path)

        # hash IOC check first - cheap and decisive
        if cand.sha256 and cand.sha256.lower() in self.hash_iocs:
            label = self.hash_iocs[cand.sha256.lower()]
            cand.findings.append(Finding(path, "IOC-HASH", "HIGH",
                "File SHA-256 matches a supplied IOC hash list. %s" % label,
                cand.sha256))

        data = self.read_bytes(path, self.args.max_size)
        if data is None:
            return cand
        text = data.decode("utf-8", errors="replace")

        # known-good comparison
        if self.known_good:
            rel = self._relpath_for_known_good(path)
            kg = self.known_good.get(rel)
            if kg is not None and kg != cand.sha256:
                cand.findings.append(Finding(path, "BASELINE-DIFF", "MEDIUM",
                    "File differs from the known-good baseline for the same path.",
                    "baseline=%s current=%s" % (kg[:12], cand.sha256[:12])))
            elif kg is None and rel is not None:
                cand.findings.append(Finding(path, "BASELINE-NEW", "MEDIUM",
                    "File is not present in the known-good baseline (new file).",
                    rel))

        # statistical metrics
        cand.entropy = round(shannon_entropy(data), 4)
        cand.ioc = round(index_of_coincidence(text), 5)
        cand.longest = longest_token(text)
        cand.compression = round(compression_ratio(data), 4)
        cand.nonprint = round(non_printable_ratio(data), 4)

        if self.args.stats:
            self._apply_stat_rules(cand)
        if self.args.signatures:
            self._apply_signature_rules(cand, text)

        return cand

    def _apply_stat_rules(self, cand: Candidate):
        t = self.thresholds
        if cand.entropy >= t["entropy"]:
            cand.findings.append(Finding(cand.path, "STAT-ENTROPY", "MEDIUM",
                "High byte entropy (%.2f bits/byte) - possible encoded/packed "
                "payload." % cand.entropy, "entropy=%.3f" % cand.entropy))
        if 0 < cand.ioc <= t["ioc_low"]:
            cand.findings.append(Finding(cand.path, "STAT-IOC", "MEDIUM",
                "Low index of coincidence (%.4f) - uniform/encoded content."
                % cand.ioc, "ioc=%.5f" % cand.ioc))
        if cand.longest >= t["longest_token"]:
            cand.findings.append(Finding(cand.path, "STAT-LONGTOKEN", "MEDIUM",
                "Very long unbroken token (%d chars) - base64/hex blob or packed "
                "one-liner." % cand.longest, "longest_token=%d" % cand.longest))
        if (cand.compression >= t["compression"]
                and cand.entropy >= t["entropy"] - 0.5):
            cand.findings.append(Finding(cand.path, "STAT-COMPRESS", "LOW",
                "Poorly compressible AND high entropy - consistent with "
                "already-encoded data.",
                "compress=%.3f entropy=%.3f" % (cand.compression, cand.entropy)))

    def _apply_signature_rules(self, cand: Candidate, text: str):
        ext = os.path.splitext(cand.path)[1].lower()
        masquerade = ext in MASQUERADE_EXTENSIONS
        if masquerade and not RE_EMBEDDED_CODE.search(text):
            return  # nothing server-side inside a non-script file
        if masquerade:
            cand.findings.append(Finding(cand.path, "SIG-MASQUERADE", "HIGH",
                "Server-side code embedded in a non-script file extension "
                "(masquerading).", ext))
        lang = classify_language(cand.path, text)
        for rule_id, severity, desc, rx in SIGNATURE_RULES:
            rlang = rule_language(rule_id)
            # Universal rules (FAMILY) always run. Language rules run only when
            # the file's language matches, or is unknown (be permissive rather
            # than miss a masquerading shell we could not classify).
            if rlang is not None and lang is not None and rlang != lang:
                continue
            m = rx.search(text)
            if m:
                cand.findings.append(Finding(cand.path, rule_id, severity, desc,
                                             _snippet(text, m.start())))
        # taint correlation
        if RE_TAINT_SOURCE.search(text) and RE_TAINT_SINK.search(text):
            m = RE_TAINT_SOURCE.search(text)
            cand.findings.append(Finding(cand.path, "SIG-TAINT", "HIGH",
                "Attacker-controllable request input and an execution/eval "
                "primitive occur in the same file.", _snippet(text, m.start())))

    def _relpath_for_known_good(self, path):
        for root in self.args.scan_roots:
            try:
                if os.path.commonpath([os.path.abspath(path),
                                       os.path.abspath(root)]) == os.path.abspath(root):
                    return os.path.relpath(path, root)
            except ValueError:
                continue
        return None

    # ---- scoring ---------------------------------------------------------- #

    def score_candidates(self):
        """Assign a composite suspicion score and add corpus-relative outlier
        flags for the statistical metrics."""
        if self.args.stats and self.candidates:
            for metric, high_is_bad in (("entropy", True), ("longest", True),
                                        ("compression", True), ("ioc", False)):
                values = [getattr(c, metric) for c in self.candidates
                          if getattr(c, metric)]
                if len(values) < 8:
                    continue
                mean = sum(values) / len(values)
                var = sum((v - mean) ** 2 for v in values) / len(values)
                std = math.sqrt(var)
                if std == 0:
                    continue
                for c in self.candidates:
                    v = getattr(c, metric)
                    if not v:
                        continue
                    z = (v - mean) / std
                    if high_is_bad and z >= self.args.zscore:
                        c.findings.append(Finding(c.path, "STAT-OUTLIER-%s"
                            % metric.upper(), "LOW",
                            "Statistical outlier for %s (z=%.1f) versus this "
                            "corpus." % (metric, z), "%s=%.4f" % (metric, v)))
                    if (not high_is_bad) and z <= -self.args.zscore:
                        c.findings.append(Finding(c.path, "STAT-OUTLIER-%s"
                            % metric.upper(), "LOW",
                            "Statistical outlier for %s (z=%.1f) versus this "
                            "corpus." % (metric, z), "%s=%.4f" % (metric, v)))
        for c in self.candidates:
            c.score = round(sum(SEVERITY_WEIGHT.get(f.severity, 0.5)
                                for f in c.findings), 2)

    # ---- discovery -------------------------------------------------------- #

    def discover_web_roots(self, root):
        """Return existing common web-root directories beneath `root`.

        Lets the tool find its own targets when the operator does not pass
        --path, so a Python-only user is not forced to know the layout."""
        found = []
        for rel in COMMON_WEB_ROOTS:
            cand = os.path.join(root, rel.replace("/", os.sep))
            if os.path.isdir(cand):
                found.append(os.path.abspath(cand))
        # de-duplicate while keeping order, and drop nested duplicates
        unique = []
        for d in found:
            if not any(d != u and d.startswith(u + os.sep) for u in found):
                if d not in unique:
                    unique.append(d)
        return unique

    def discover_access_logs(self, root):
        """Return uncompressed access-log files beneath common log directories."""
        logs = []
        for rel in COMMON_LOG_DIRS:
            base = os.path.join(root, rel.replace("/", os.sep))
            if not os.path.isdir(base):
                continue
            for dirpath, _dirs, files in os.walk(base):
                for fn in files:
                    if fn.endswith((".gz", ".bz2", ".xz", ".zip")):
                        continue
                    if "access" in fn.lower() or fn.lower().endswith(".log"):
                        logs.append(os.path.join(dirpath, fn))
        return sorted(set(logs))

    def analyse_logs(self, log_paths, out_path, max_log_size):
        """Scan access logs for shell-interaction traces. Read-only; writes a
        TSV of leads. Returns the number of suspicious lines recorded."""
        hits = 0
        with open(out_path, "w", encoding="utf-8", newline="") as out:
            w = csv.writer(out, delimiter="\t")
            w.writerow(["severity", "rule_id", "log_file", "line_no", "detail",
                        "excerpt"])
            for lp in log_paths:
                try:
                    size = os.path.getsize(lp)
                except OSError:
                    continue
                if size > max_log_size:
                    self.log.detail("skip oversize log (%d bytes): %s"
                                    % (size, lp))
                    continue
                self.log.info("log analysis: %s" % lp)
                try:
                    with open(lp, "r", encoding="utf-8", errors="replace") as fh:
                        for n, line in enumerate(fh, 1):
                            for rid, sev, desc, rx in LOG_RULES:
                                if rx.search(line):
                                    w.writerow([sev, rid, lp, n, desc,
                                                line.strip()[:300]])
                                    hits += 1
                                    break
                except OSError as exc:
                    self.log.error("log read failed: %s (%s)" % (lp, exc))
                    self.errors += 1
        return hits

    # ---- IOC / baseline loaders ------------------------------------------ #

    def load_hash_list(self, path):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split(None, 1)
                    h = parts[0].lower()
                    if re.fullmatch(r"[0-9a-f]{64}", h):
                        self.hash_iocs[h] = parts[1] if len(parts) > 1 else ""
        except OSError as exc:
            self.log.error("could not read hash list %s (%s)" % (path, exc))
        self.log.info("loaded %d hash IOC(s)" % len(self.hash_iocs))

    def load_known_good(self, kg_root):
        count = 0
        for dirpath, _dirs, files in os.walk(kg_root):
            for fn in files:
                full = os.path.join(dirpath, fn)
                rel = os.path.relpath(full, kg_root)
                self.known_good[rel] = self.hash_file(full)
                count += 1
        self.log.info("baseline: hashed %d known-good file(s)" % count)


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #


def _iso(epoch):
    try:
        return datetime.fromtimestamp(epoch, timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return ""


def _snippet(text, pos, width=80):
    start = max(0, pos - 10)
    end = min(len(text), pos + width)
    frag = text[start:end].replace("\n", " ").replace("\t", " ").replace("\r", " ")
    return frag.strip()[:width]


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


# --------------------------------------------------------------------------- #
# Output writers
# --------------------------------------------------------------------------- #


def write_inventory(path, candidates):
    with open(path, "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh, delimiter="\t")
        w.writerow(["path", "size", "mtime_utc", "ctime_utc", "atime_utc",
                    "mode", "uid", "gid", "sha256", "entropy", "ioc",
                    "longest_token", "compression", "nonprintable", "kind",
                    "finding_count", "score"])
        for c in candidates:
            w.writerow([c.path, getattr(c, "size", ""), getattr(c, "mtime", ""),
                        getattr(c, "ctime", ""), getattr(c, "atime", ""),
                        getattr(c, "mode", ""), getattr(c, "uid", ""),
                        getattr(c, "gid", ""), c.sha256, c.entropy, c.ioc,
                        c.longest, c.compression, c.nonprint, c.kind,
                        len(c.findings), c.score])


def write_findings(path, candidates):
    n = 0
    with open(path, "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh, delimiter="\t")
        w.writerow(["score", "severity", "rule_id", "path", "detail",
                    "evidence", "sha256"])
        rows = []
        for c in candidates:
            for f in c.findings:
                rows.append((c.score, f.severity, f.rule_id, f.path, f.detail,
                             f.evidence, c.sha256))
        # highest score, then severity
        sev_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
        rows.sort(key=lambda r: (-r[0], sev_order.get(r[1], 9)))
        for r in rows:
            w.writerow(r)
            n += 1
    return n


def write_summary(path, hunter, ctx, findings_count, flagged):
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("%s %s - hunt summary\n" % (PROGRAM, VERSION))
        fh.write("=" * 48 + "\n")
        for k, v in ctx.items():
            fh.write("%-18s %s\n" % (k + ":", v))
        fh.write("\n")
        fh.write("%-18s %d\n" % ("files examined:", hunter.files_seen))
        fh.write("%-18s %d\n" % ("files skipped:", hunter.files_skipped))
        fh.write("%-18s %d\n" % ("files flagged:", flagged))
        fh.write("%-18s %d\n" % ("file findings:", findings_count))
        fh.write("%-18s %s\n" % ("log leads:", ctx.get("log_leads", 0)))
        fh.write("%-18s %d\n" % ("read/stat errors:", hunter.errors))
        fh.write("\nTop flagged files (by score):\n")
        top = sorted([c for c in hunter.candidates if c.findings],
                     key=lambda c: -c.score)[:20]
        for c in top:
            fh.write("  %6.1f  %s  (%d findings)\n"
                     % (c.score, c.path, len(c.findings)))
        fh.write("\nReminder: findings are investigative leads, not proof of "
                 "compromise.\n")


def write_manifest(outdir):
    """SHA-256 manifest of every output artefact except the manifest itself."""
    manifest = os.path.join(outdir, "SHA256SUMS")
    entries = []
    for fn in sorted(os.listdir(outdir)):
        full = os.path.join(outdir, fn)
        if fn == "SHA256SUMS" or not os.path.isfile(full):
            continue
        entries.append((sha256_of(full), fn))
    with open(manifest, "w", encoding="utf-8", newline="\n") as fh:
        for digest, fn in entries:
            fh.write("%s  %s\n" % (digest, fn))
    return manifest


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def build_parser():
    epilog = """\
EVIDENCE PRACTICE
    * The target is read only. No decoding, quarantine, execution or upload.
    * Point --output at a directory OUTSIDE the target. The tool refuses to
      write its output inside a scan root.
    * Reading may update access times on a writable live filesystem; prefer a
      read-only mount or a working copy. Access times are NOT restored, because
      restoring them rewrites the change time.
    * Pre-read metadata and a full-file SHA-256 are recorded for every file.
      A SHA256SUMS manifest covers all output artefacts.

STANDS ALONE
    This tool is designed to give a strong result on its own. If you do not name
    a --path, it auto-discovers common web roots under --root (default /), and it
    analyses common access logs for signs a shell has been used. You do not need
    to run any other tool to get value. Live-process hunting is the one job left
    to a separate, OS-specific tool.

WHAT IT LOOKS FOR
    Statistical (NeoPI lineage): Shannon entropy, index of coincidence, longest
    unbroken token, and compression ratio - plus corpus-relative outliers.
    Signature (BackdoorMan lineage): execution/eval primitives and known shell
    families across PHP, JSP/Java, ASP/.NET, Node, Python, Perl, Ruby and web
    server configuration, with a request-input-to-execution correlation rule and
    detection of server-side code hidden in non-script files.
    Access logs: command-like parameters, known shell filenames, base64 blobs,
    suspicious POSTs and traversal - traces of a shell being used.

OUTPUTS (in --output)
    webshell-hunter.log   Timestamped audit/action log
    findings.tsv          Ranked file findings with rule, evidence and SHA-256
    inventory.tsv         Every candidate with metadata and statistical metrics
    web_log_leads.tsv     Suspicious access-log lines (when logs are found)
    summary.txt           Counts, scope and top flagged files
    SHA256SUMS            SHA-256 manifest of the output artefacts

EXIT STATUS
    0  completed, no findings        2  invalid use / unsafe path
    1  completed, findings recorded  130 interrupted

EXAMPLES
    # Live Linux web root
    python3 webshell-hunter.py -p /var/www -o /cases/web01 --case IR-2026-041

    # Mounted image on Windows, all files, baseline compare
    python webshell-hunter.py -p E:\\mount\\www -o C:\\cases\\web01 \\
        --all-files --known-good D:\\baselines\\web01

    # Add an IOC hash list and treat corpus outliers aggressively
    python3 webshell-hunter.py -p /srv/site -o out --hash-list bad.sha256 --zscore 2.5

Findings are investigative leads. Validate provenance and known-good state
before acting. This tool complements the Bash WebShellHuntr
(https://for577.com/web-shell-bash), which adds server discovery, access-log and
live-process analysis on Linux.
"""
    p = argparse.ArgumentParser(
        prog=PROGRAM,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Statistical and signature web shell hunter (Python 3, "
                    "standard library only, read-only).",
        epilog=epilog)

    g_t = p.add_argument_group("target selection")
    g_t.add_argument("-p", "--path", action="append", dest="paths",
                     metavar="DIR", help="Directory to scan. Repeatable. If "
                     "omitted, common web roots are auto-discovered under --root.")
    g_t.add_argument("--root", default=None, metavar="DIR",
                     help="Base for auto-discovery of web roots and logs when "
                          "--path is omitted (default: / on Unix). Use a mount "
                          "point for an image.")
    g_t.add_argument("-x", "--exclude", action="append", metavar="PATH",
                     help="Path to exclude. Repeatable.")
    g_t.add_argument("--all-files", action="store_true",
                     help="Examine every readable file, not just known "
                          "script/masquerade extensions.")
    g_t.add_argument("--cross-filesystems", action="store_true",
                     help="Permit descent into other filesystems (default stays "
                          "on the scan root's filesystem).")

    g_o = p.add_argument_group("output and case metadata")
    g_o.add_argument("-o", "--output", metavar="DIR", required=True,
                     help="Output directory (created if absent; must be empty "
                          "or new; must be outside the target).")
    g_o.add_argument("--case", default="", help="Case/incident reference.")
    g_o.add_argument("--examiner", default="", help="Examiner/operator name.")
    g_o.add_argument("--source-id", default="", help="Evidence/host identifier.")

    g_h = p.add_argument_group("hunt options")
    g_h.add_argument("--hash-list", metavar="FILE",
                     help="File of SHA-256 IOCs (one per line, optional label).")
    g_h.add_argument("--known-good", metavar="DIR",
                     help="Known-good mirror; candidates compared by relative "
                          "path and SHA-256.")
    g_h.add_argument("--no-signatures", dest="signatures", action="store_false",
                     help="Disable signature rules (statistics only).")
    g_h.add_argument("--no-stats", dest="stats", action="store_false",
                     help="Disable statistical tests (signatures only).")
    g_h.add_argument("--max-size", type=_mib, default=8 * 1024 * 1024,
                     metavar="MIB", help="Largest file to analyse "
                     "(default 8 MiB). Larger files are still hashed and listed.")
    g_h.add_argument("--max-files", type=int, default=200000, metavar="N",
                     help="Stop after visiting N files (default 200000).")
    g_h.add_argument("--zscore", type=float, default=3.0, metavar="Z",
                     help="Std-deviations from the corpus mean to flag a "
                          "statistical outlier (default 3.0).")
    g_h.add_argument("--min-entropy", type=float, metavar="BITS",
                     help="Override the entropy threshold (default %.1f)."
                          % DEFAULT_THRESHOLDS["entropy"])
    g_h.add_argument("--log-path", action="append", metavar="PATH",
                     help="Access log file or directory to analyse. Repeatable. "
                          "Adds to any auto-discovered logs.")
    g_h.add_argument("--no-log-analysis", dest="log_analysis",
                     action="store_false",
                     help="Do not analyse web access logs for shell interaction.")
    g_h.add_argument("--max-log-size", type=_mib, default=100 * 1024 * 1024,
                     metavar="MIB",
                     help="Largest access log to read (default 100 MiB).")

    g_m = p.add_argument_group("output verbosity")
    g_m.add_argument("-v", "--verbose", action="store_true",
                     help="Show per-file detail on the console.")
    g_m.add_argument("-q", "--quiet", action="store_true",
                     help="Suppress console echo (log file still written).")
    p.add_argument("-V", "--version", action="version",
                   version="%s %s" % (PROGRAM, VERSION))
    return p


def die(message):
    """Print a usage/safety error and exit with the documented usage code (2)."""
    sys.stderr.write("ERROR: %s\n" % message)
    sys.exit(EXIT_USAGE)


def _mib(value):
    return int(float(value) * 1024 * 1024)


def _resolve_output(outdir, scan_roots):
    outdir = os.path.abspath(outdir)
    for root in scan_roots:
        root_abs = os.path.abspath(root)
        try:
            common = os.path.commonpath([outdir, root_abs])
        except ValueError:
            continue
        if common == root_abs:
            die("output directory %s is inside scan root %s. "
            "Choose a location outside the target." % (outdir, root_abs))
    if os.path.exists(outdir):
        if os.listdir(outdir):
            die("output directory %s exists and is not empty. "
                "Choose a new directory." % outdir)
    else:
        os.makedirs(outdir)
    return outdir


def main(argv=None):
    args = build_parser().parse_args(argv)

    discovery_root = args.root or ("/" if os.name != "nt" else None)

    # Build the list of scan roots: explicit --path wins; otherwise discover.
    scan_roots = []
    discovered = False
    if args.paths:
        for pth in args.paths:
            ap = os.path.abspath(pth)
            if not os.path.isdir(ap):
                die("scan path is not a directory: %s" % pth)
            scan_roots.append(ap)
    else:
        if not discovery_root or not os.path.isdir(discovery_root):
            die("no --path given and no usable --root for discovery. On "
                "Windows, pass --path or --root explicitly. Use -h for help.")
        # temporary hunter-less discovery via a helper instance later; do it now
        for rel in COMMON_WEB_ROOTS:
            cand = os.path.join(discovery_root, rel.replace("/", os.sep))
            if os.path.isdir(cand):
                scan_roots.append(os.path.abspath(cand))
        # drop nested duplicates
        scan_roots = [d for d in dict.fromkeys(scan_roots)
                      if not any(d != u and d.startswith(u + os.sep)
                                 for u in scan_roots)]
        discovered = True
        if not scan_roots:
            die("no common web roots found under %s. Pass --path explicitly. "
                "Use -h for help." % discovery_root)
    args.scan_roots = scan_roots

    outdir = _resolve_output(args.output, scan_roots)

    log = AuditLog(os.path.join(outdir, "webshell-hunter.log"),
                   echo=not args.quiet, verbose=args.verbose)
    if discovered:
        log.info("auto-discovered %d web root(s) under %s"
                 % (len(scan_roots), discovery_root))

    interrupted = {"flag": False}

    def _handler(signum, _frame):
        interrupted["flag"] = True
        log.warning("interrupt signal %d received - finalising" % signum)
    try:
        signal.signal(signal.SIGINT, _handler)
        if hasattr(signal, "SIGTERM"):
            signal.signal(signal.SIGTERM, _handler)
    except (ValueError, OSError):
        pass  # not in main thread, or unsupported

    ctx = {
        "tool": "%s %s" % (PROGRAM, VERSION),
        "started_utc": utc_now(),
        "host": platform.node(),
        "platform": platform.platform(),
        "python": platform.python_version(),
        "operator_user": _safe_user(),
        "case": args.case,
        "examiner": args.examiner,
        "source_id": args.source_id,
        "scan_roots": " ; ".join(scan_roots),
        "output_dir": outdir,
        "command": " ".join(_quote(a) for a in sys.argv),
    }
    log.section("hunt start")
    for k, v in ctx.items():
        log.info("%s = %s" % (k, v))

    hunter = WebShellHunter(args, log)
    hunter.thresholds = dict(DEFAULT_THRESHOLDS)
    if args.min_entropy is not None:
        hunter.thresholds["entropy"] = args.min_entropy

    if args.hash_list:
        hunter.load_hash_list(args.hash_list)
    if args.known_good:
        if not os.path.isdir(args.known_good):
            log.error("known-good path is not a directory: %s" % args.known_good)
        else:
            log.section("baseline hashing")
            hunter.load_known_good(os.path.abspath(args.known_good))

    log.section("scanning")
    stop = False
    for root in scan_roots:
        log.info("scan root: %s" % root)
        for path in hunter.walk(root):
            if interrupted["flag"] or hunter.files_seen >= args.max_files:
                stop = True
                break
            ok, kind = hunter.is_candidate(path)
            if not ok:
                continue
            hunter.files_seen += 1
            cand = hunter.analyse(path)
            if cand is None:
                continue
            if not cand.kind:
                cand.kind = kind
            hunter.candidates.append(cand)
            if cand.findings:
                log.detail("%d finding(s): %s" % (len(cand.findings), path))
        if stop:
            break

    # access-log analysis (traces of shell interaction)
    log_hits = 0
    if args.log_analysis and not interrupted["flag"]:
        log.section("access-log analysis")
        log_targets = []
        droot = discovery_root
        if droot and os.path.isdir(droot):
            log_targets.extend(hunter.discover_access_logs(droot))
        for lp in (args.log_path or []):
            ap = os.path.abspath(lp)
            if os.path.isdir(ap):
                for dp, _d, fs in os.walk(ap):
                    for fn in fs:
                        if not fn.endswith((".gz", ".bz2", ".xz", ".zip")):
                            log_targets.append(os.path.join(dp, fn))
            elif os.path.isfile(ap):
                log_targets.append(ap)
        log_targets = sorted(set(log_targets))
        if log_targets:
            leads = os.path.join(outdir, "web_log_leads.tsv")
            log_hits = hunter.analyse_logs(log_targets, leads, args.max_log_size)
            log.info("wrote %s (%d lead line(s))" % (leads, log_hits))
        else:
            log.info("no uncompressed access logs found to analyse")

    log.section("scoring")
    hunter.score_candidates()

    # write outputs
    log.section("writing reports")
    inv = os.path.join(outdir, "inventory.tsv")
    fnd = os.path.join(outdir, "findings.tsv")
    smry = os.path.join(outdir, "summary.txt")
    write_inventory(inv, hunter.candidates)
    findings_count = write_findings(fnd, hunter.candidates)
    flagged = sum(1 for c in hunter.candidates if c.findings)
    ctx["completed_utc"] = utc_now()
    ctx["completion"] = "interrupted" if interrupted["flag"] else "complete"
    ctx["log_leads"] = log_hits
    write_summary(smry, hunter, ctx, findings_count, flagged)
    for artefact in (inv, fnd, smry):
        log.info("wrote %s" % artefact)

    manifest = write_manifest(outdir)
    log.info("wrote %s" % manifest)
    log.section("hunt end")
    log.info("files_examined=%d flagged=%d findings=%d errors=%d"
             % (hunter.files_seen, flagged, findings_count, hunter.errors))

    print("\n%s complete. %d file(s) examined, %d flagged, %d file finding(s), "
          "%d log lead(s)." % (PROGRAM, hunter.files_seen, flagged,
                               findings_count, log_hits))
    print("Reports in: %s" % outdir)
    log.close()

    if interrupted["flag"]:
        return EXIT_INTERRUPT
    return EXIT_FINDINGS if (findings_count or log_hits) else EXIT_OK


def _safe_user():
    try:
        import getpass
        return getpass.getuser()
    except Exception:
        return os.environ.get("USER") or os.environ.get("USERNAME") or ""


def _quote(arg):
    if any(ch.isspace() for ch in arg):
        return '"%s"' % arg
    return arg


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.stderr.write("\nInterrupted.\n")
        sys.exit(EXIT_INTERRUPT)
