#!/usr/bin/env python3
"""
vt_hash_lookup.py

Reads a UAC-style hash file (lines of "<sha1>  <path>") and queries the
VirusTotal v3 API for each hash. Prints a minimal verdict line per hash:

    <sha1>  <verdict>  <malicious>/<total_engines>

Verdicts:
    malicious  - at least one engine flagged the sample
    clean      - sample is known to VT, zero detections
    unknown    - VT has no record of this hash (HTTP 404)
    error      - lookup failed (network/auth/quota/etc.)

Usage:
    python3 vt_hash_lookup.py /path/to/hash_executables.sha1
"""

import argparse
import re
import sys
import time
from pathlib import Path

import requests

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Paste your VirusTotal API key here.
API_KEY = "REPLACE_ME_WITH_YOUR_VT_API_KEY"

# Set to "public" or "private".
#   public  -> 4 requests/min, hard cap of 500 lookups per run
#   private -> no local rate limiting, no lookup cap
API_TIER = "public"

# Public-tier constraints (VT free/community quotas).
PUBLIC_RPM = 4
PUBLIC_MAX_LOOKUPS = 500

# VT v3 endpoint for a single file by hash.
VT_FILE_URL = "https://www.virustotal.com/api/v3/files/{hash}"

# Regex: SHA-1 is 40 hex chars. UAC hash files are "<hash><whitespace><path>".
# We deliberately capture only the hash and discard the filename.
HASH_LINE_RE = re.compile(r"^\s*([A-Fa-f0-9]{40})\b")

# HTTP request timeout in seconds.
HTTP_TIMEOUT = 30


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def parse_hash_file(path: Path):
    """Yield unique lowercase SHA-1 hashes from a UAC hash file.

    Silently skips blank lines, comments (#...), and any line that does
    not start with a 40-char hex string.
    """
    seen = set()
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for lineno, line in enumerate(fh, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            m = HASH_LINE_RE.match(line)
            if not m:
                print(f"[warn] line {lineno}: no SHA-1 found, skipping",
                      file=sys.stderr)
                continue
            h = m.group(1).lower()
            if h in seen:
                continue
            seen.add(h)
            yield h


def classify(stats: dict) -> str:
    """Map VT last_analysis_stats to a one-word verdict."""
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    if malicious > 0 or suspicious > 0:
        return "malicious"
    return "clean"


def totals(stats: dict):
    """Return (malicious_or_suspicious_count, total_engine_count)."""
    hits = stats.get("malicious", 0) + stats.get("suspicious", 0)
    total = sum(stats.get(k, 0) for k in (
        "harmless", "malicious", "suspicious", "undetected", "timeout",
        "confirmed-timeout", "failure", "type-unsupported",
    ))
    return hits, total


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------

class PublicRateLimiter:
    """Sliding-window limiter: max N requests per 60 seconds."""

    def __init__(self, max_per_minute: int):
        self.max = max_per_minute
        self.window = 60.0
        self.timestamps = []

    def wait(self):
        now = time.monotonic()
        # Drop timestamps older than the window.
        self.timestamps = [t for t in self.timestamps if now - t < self.window]
        if len(self.timestamps) >= self.max:
            sleep_for = self.window - (now - self.timestamps[0]) + 0.1
            if sleep_for > 0:
                time.sleep(sleep_for)
        self.timestamps.append(time.monotonic())


# ---------------------------------------------------------------------------
# VT lookup
# ---------------------------------------------------------------------------

def lookup(session: requests.Session, sha1: str):
    """Query VT for a single hash.

    Returns a tuple: (verdict, hits, total, quota_locked_flag)
    """
    url = VT_FILE_URL.format(hash=sha1)
    try:
        r = session.get(url, timeout=HTTP_TIMEOUT)
    except requests.RequestException as e:
        return ("error", 0, 0, False), f"network: {e}"

    # 404 -> VT does not know this hash. This is a legitimate result,
    # not an error, and should not count against anything special.
    if r.status_code == 404:
        return ("unknown", 0, 0, False), None

    # 401 -> bad/missing API key. Fatal.
    if r.status_code == 401:
        return ("error", 0, 0, True), "unauthorized (bad API key)"

    # 403 -> endpoint forbidden. On VT this usually means the key tier
    # does not permit this call, which is exactly what happens if a
    # public key has been declared as "private" and is now getting
    # hammered past its quota, or if the account has been flagged.
    if r.status_code == 403:
        return ("error", 0, 0, True), "forbidden (quota/tier lock)"

    # 429 -> rate limit / quota exceeded. On the public tier this is
    # also the signal that VT has had enough.
    if r.status_code == 429:
        return ("error", 0, 0, True), "rate limited / quota exceeded"

    if not r.ok:
        return ("error", 0, 0, False), f"HTTP {r.status_code}"

    try:
        data = r.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
    except (ValueError, KeyError) as e:
        return ("error", 0, 0, False), f"malformed response: {e}"

    verdict = classify(stats)
    hits, total = totals(stats)
    return (verdict, hits, total, False), None


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description="Look up SHA-1 hashes from a UAC hash_executables file "
                    "against the VirusTotal v3 API."
    )
    ap.add_argument("hash_file", type=Path,
                    help="Path to hash_executables.sha1 (or similar).")
    args = ap.parse_args()

    if not args.hash_file.is_file():
        print(f"[fatal] not a file: {args.hash_file}", file=sys.stderr)
        sys.exit(2)

    if API_KEY == "REPLACE_ME_WITH_YOUR_VT_API_KEY" or not API_KEY:
        print("[fatal] set API_KEY at the top of this script", file=sys.stderr)
        sys.exit(2)

    tier = API_TIER.lower().strip()
    if tier not in {"public", "private"}:
        print(f"[fatal] API_TIER must be 'public' or 'private', got {API_TIER!r}",
              file=sys.stderr)
        sys.exit(2)

    session = requests.Session()
    session.headers.update({
        "x-apikey": API_KEY,
        "Accept": "application/json",
        "User-Agent": "uac-vt-hash-lookup/1.0",
    })

    limiter = PublicRateLimiter(PUBLIC_RPM) if tier == "public" else None
    cap = PUBLIC_MAX_LOOKUPS if tier == "public" else None

    # Header
    print(f"# tier={tier}  file={args.hash_file}")
    if tier == "public":
        print(f"# public tier: {PUBLIC_RPM} req/min, max {PUBLIC_MAX_LOOKUPS} lookups")
    print(f"# {'sha1':40s}  verdict     hits/total")

    processed = 0
    consecutive_quota_errors = 0

    for sha1 in parse_hash_file(args.hash_file):
        if cap is not None and processed >= cap:
            print(f"# stopping: public-tier cap of {cap} lookups reached",
                  file=sys.stderr)
            break

        if limiter is not None:
            limiter.wait()

        (verdict, hits, total, quota_locked), err = lookup(session, sha1)
        processed += 1

        if quota_locked:
            consecutive_quota_errors += 1
        else:
            consecutive_quota_errors = 0

        ratio = f"{hits}/{total}" if total else "-/-"
        if err:
            print(f"{sha1}  {verdict:10s}  {ratio}   # {err}")
        else:
            print(f"{sha1}  {verdict:10s}  {ratio}")

        # Heuristic: if a user lies about having a private key, VT will
        # start returning 401/403/429 consistently once the public
        # quota is blown. Bail after 3 in a row rather than burning
        # through the rest of the file.
        if consecutive_quota_errors >= 3:
            print("# aborting: 3 consecutive quota/auth errors from VT.",
                  file=sys.stderr)
            print("# if API_TIER is set to 'private' but the key is public,",
                  file=sys.stderr)
            print("# VT has locked it. Switch API_TIER back to 'public'.",
                  file=sys.stderr)
            sys.exit(3)

    print(f"# done: {processed} hashes queried", file=sys.stderr)


if __name__ == "__main__":
    main()
