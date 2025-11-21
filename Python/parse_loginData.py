#!/usr/bin/env python3
"""
Parse utmp-style files (wtmp, btmp, utmp) and print human-readable records.

Supports multiple output formats:
  - table  (human-readable fixed-width lines)
  - csv    (one record per row, header included)
  - jsonl  (one JSON object per line)

Usage examples:
  python3 parse_utmp.py /var/log/wtmp
  python3 parse_utmp.py /var/log/wtmp --format csv
  python3 parse_utmp.py /var/log/btmp --type USER_PROCESS --format jsonl
"""

############################
# This is an ALPHA release #
############################

import argparse
import struct
import datetime
import ipaddress
import string
import csv
import json
import sys
from typing import Optional, Dict, Any, Generator

# ---------------------------------------------------------------------------
# Glibc utmp on-disk layout (384 bytes), per Kaitai spec:
#
#   int32  ut_type;
#   int32  pid;
#   char   line[32];
#   char   id[4];
#   char   user[32];
#   char   host[256];
#   uint32 exit;         // packed exit_status (2x uint16)
#   int32  session;
#   uint32 tv_sec;
#   int32  tv_usec;
#   byte   addr_v6[16];
#   byte   reserved[20];
# ---------------------------------------------------------------------------

UTMP_STRUCT_FORMAT = "<ii32s4s32s256sIiIi16s20s"
UTMP_STRUCT = struct.Struct(UTMP_STRUCT_FORMAT)
RECORD_SIZE = UTMP_STRUCT.size  # should be 384

if RECORD_SIZE != 384:
    raise RuntimeError(
        f"UTMP struct size is {RECORD_SIZE}, expected 384 – ABI/layout mismatch?"
    )

UT_TYPES: Dict[int, str] = {
    0: "EMPTY",
    1: "RUN_LVL",
    2: "BOOT_TIME",
    3: "NEW_TIME",
    4: "OLD_TIME",
    5: "INIT_PROCESS",
    6: "LOGIN_PROCESS",
    7: "USER_PROCESS",
    8: "DEAD_PROCESS",
    9: "ACCOUNTING",
}

# A *derived* semantic label – purely for readability.
# We DO NOT remove or alter the underlying type_name, so forensic accuracy is preserved.
UT_EVENTS: Dict[int, str] = {
    2: "boot",
    3: "time-change-new",
    4: "time-change-old",
    5: "init-process",
    6: "login-process",
    7: "login",     # USER_PROCESS => login/session active
    8: "logout",    # DEAD_PROCESS => session ended
    1: "runlevel",
    9: "accounting",
    0: "empty",
}


def clean_str(raw: bytes) -> str:
    """
    Decode a fixed-length C string, remove trailing NULs, and strip
    control characters / weird whitespace (except regular space).
    """
    s = raw.rstrip(b"\x00").decode(errors="ignore")
    out = []
    for ch in s:
        if ch in string.printable and ch not in "\r\n\t\v\f":
            out.append(ch)
        elif ch == " ":
            out.append(ch)
        # drop control chars
    return "".join(out).strip()


def decode_ip_bytes(raw: bytes) -> Optional[str]:
    """
    Decode the 16-byte addr_v6 field into an IPv4/IPv6 string if possible.

    Common glibc usage:
    - all zeros: no address
    - IPv4: stored in last 4 bytes, first 12 bytes are zero
    - otherwise: treat as IPv6 address
    """
    if len(raw) != 16:
        return None

    if raw == b"\x00" * 16:
        return None

    # IPv4 stored in last 4 bytes (first 12 zero)
    if raw[:12] == b"\x00" * 12:
        try:
            return str(ipaddress.IPv4Address(raw[12:16]))
        except ipaddress.AddressValueError:
            pass

    # Fallback: full 16-byte IPv6
    try:
        return str(ipaddress.IPv6Address(raw))
    except ipaddress.AddressValueError:
        return None


def split_exit_status(raw_exit: int) -> (int, int):
    """
    exit_status is 2 x uint16 (termination, exit) packed in a u32.
    Layout is little endian, so lower 16 bits = termination.
    """
    e_term = raw_exit & 0xFFFF
    e_exit = (raw_exit >> 16) & 0xFFFF
    return e_term, e_exit


def parse_utmp_record(rec: bytes) -> Dict[str, Any]:
    """
    Parse a single 384-byte utmp record into a dictionary.
    """
    (ut_type,
     ut_pid,
     raw_line,
     raw_id,
     raw_user,
     raw_host,
     raw_exit,
     ut_session,
     tv_sec,
     tv_usec,
     addr_raw,
     reserved) = UTMP_STRUCT.unpack(rec)

    ut_line = clean_str(raw_line)
    ut_id = clean_str(raw_id)
    ut_user = clean_str(raw_user)
    ut_host = clean_str(raw_host)

    # tv_sec is uint32, tv_usec is int32
    if tv_sec > 0:
        try:
            timestamp = datetime.datetime.fromtimestamp(tv_sec)
        except (OSError, OverflowError, ValueError):
            timestamp = None
    else:
        timestamp = None

    ip_str = None
    if not ut_host:
        ip_str = decode_ip_bytes(addr_raw)

    e_term, e_exit = split_exit_status(raw_exit)

    type_name = UT_TYPES.get(ut_type, f"UNKNOWN({ut_type})")
    event = UT_EVENTS.get(ut_type, "other")

    return {
        "type": ut_type,
        "type_name": type_name,
        "event": event,                 # derived, human-friendly
        "pid": ut_pid,
        "line": ut_line,
        "id": ut_id,
        "user": ut_user,
        "host": ut_host,
        "exit_termination": e_term,
        "exit_status": e_exit,
        "session": ut_session,
        "timestamp": timestamp,         # datetime or None
        "tv_sec": tv_sec,
        "tv_usec": tv_usec,
        "ip": ip_str,
    }


def read_utmp_file(path: str) -> Generator[Dict[str, Any], None, None]:
    """
    Generator that yields parsed UTMP records from a file.
    Skips trailing partial records.
    """
    with open(path, "rb") as f:
        while True:
            data = f.read(RECORD_SIZE)
            if not data:
                break
            if len(data) < RECORD_SIZE:
                # Truncated / partial record at end
                break
            yield parse_utmp_record(data)


def format_record_table(rec: Dict[str, Any]) -> str:
    """
    Turn a utmp record dict into a human-readable single-line summary.
    Includes both type_name *and* event so it's obvious what's going on.
    """
    ts = rec["timestamp"].strftime("%Y-%m-%d %H:%M:%S") if rec["timestamp"] else "N/A"
    user = rec["user"] or "-"
    line = rec["line"] or "-"
    host = rec["host"] or (rec["ip"] or "-")
    type_name = rec["type_name"]
    event = rec["event"].upper()
    pid = rec["pid"]

    extra = []
    if rec["exit_status"] or rec["exit_termination"]:
        extra.append(f"exit={rec['exit_termination']}/{rec['exit_status']}")
    if rec["session"]:
        extra.append(f"session={rec['session']}")
    if rec["ip"] and rec["host"] and rec["ip"] != rec["host"]:
        extra.append(f"ip={rec['ip']}")

    extra_str = f" ({', '.join(extra)})" if extra else ""

    # Example:
    # 2023-01-05 19:45:27  LOGIN    USER_PROCESS   user=bmorse ...
    return (
        f"{ts}  {event:8s} {type_name:13s}  "
        f"user={user:16s}  line={line:12s}  host={host:30s}  pid={pid}{extra_str}"
    )


# Fields used for CSV / JSONL so output is consistent
CSV_FIELDS = [
    "timestamp_iso",
    "event",
    "type",
    "type_name",
    "user",
    "line",
    "host",
    "ip",
    "pid",
    "session",
    "exit_termination",
    "exit_status",
    "tv_sec",
    "tv_usec",
]


def rec_to_flat(rec: Dict[str, Any]) -> Dict[str, Any]:
    """
    Flatten a record for CSV/JSONL (timestamp -> ISO string, keep all core fields).
    """
    return {
        "timestamp_iso": rec["timestamp"].isoformat(sep=" ") if rec["timestamp"] else None,
        "event": rec["event"],
        "type": rec["type"],
        "type_name": rec["type_name"],
        "user": rec["user"],
        "line": rec["line"],
        "host": rec["host"],
        "ip": rec["ip"],
        "pid": rec["pid"],
        "session": rec["session"],
        "exit_termination": rec["exit_termination"],
        "exit_status": rec["exit_status"],
        "tv_sec": rec["tv_sec"],
        "tv_usec": rec["tv_usec"],
    }


def main():
    parser = argparse.ArgumentParser(
        description="Parse Linux utmp/wtmp/btmp binary files and print records."
    )
    parser.add_argument(
        "path",
        help="Path to utmp-style file (e.g. /var/log/wtmp, /var/log/btmp, /var/run/utmp)",
    )
    parser.add_argument(
        "--show-empty",
        action="store_true",
        help="Include EMPTY records (type=EMPTY/user/line/host all blank). Default: skip them.",
    )
    parser.add_argument(
        "--type",
        dest="types",
        action="append",
        help="Filter by record type name (e.g. USER_PROCESS, BOOT_TIME, DEAD_PROCESS). "
             "Can be specified multiple times.",
    )
    parser.add_argument(
        "--format", "-F",
        choices=["table", "csv", "jsonl"],
        default="table",
        help="Output format: table (default), csv, or jsonl.",
    )
    args = parser.parse_args()

    type_filter = None
    if args.types:
        type_filter = {t.strip().upper() for t in args.types}

    records = read_utmp_file(args.path)

    # Apply filters and empty-record skip
    def filtered_records():
        for rec in records:
            if not args.show_empty:
                if (
                    rec["type"] == 0
                    and not rec["user"]
                    and not rec["line"]
                    and not rec["host"]
                ):
                    continue

            if type_filter is not None:
                if rec["type_name"].upper() not in type_filter:
                    continue

            yield rec

    if args.format == "table":
        for rec in filtered_records():
            print(format_record_table(rec))

    elif args.format == "csv":
        writer = csv.DictWriter(sys.stdout, fieldnames=CSV_FIELDS)
        writer.writeheader()
        for rec in filtered_records():
            writer.writerow(rec_to_flat(rec))

    elif args.format == "jsonl":
        for rec in filtered_records():
            flat = rec_to_flat(rec)
            print(json.dumps(flat, ensure_ascii=False))


if __name__ == "__main__":
    main()
