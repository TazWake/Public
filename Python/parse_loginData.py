#!/usr/bin/env python3
"""
Parse utmp-style files (wtmp, btmp, utmp) and print human-readable records.

Usage:
    python3 parse_utmp.py /var/log/wtmp
    python3 parse_utmp.py /var/log/btmp
"""

import argparse
import struct
import datetime
import ipaddress
import string
from typing import Optional, Dict, Any, Generator

###################################
# NOTE: This is an alpha version! #
###################################

# ---------------------------------------------------------------------------
# Glibc utmp on-disk layout (384 bytes), per Kaitai spec:
# https://formats.kaitai.io/glibc_utmp/graphviz.html
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
#   int32  addr_v6[4];
#   char   reserved[20];
# ---------------------------------------------------------------------------

UTMP_STRUCT_FORMAT = "<ii32s4s32s256sIii4i20s"
UTMP_STRUCT = struct.Struct(UTMP_STRUCT_FORMAT)
RECORD_SIZE = UTMP_STRUCT.size  # 380 on your system

# Sanity check – we expect common glibc layouts to be 380 or 384 bytes
if RECORD_SIZE not in (380, 384):
    raise RuntimeError(
        f"UTMP struct size is {RECORD_SIZE}, expected 380 or 384 – real ABI/layout mismatch?"
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
        # else drop control chars
    return "".join(out).strip()


def decode_ip(addr_v6) -> Optional[str]:
    """
    Decode ut_addr_v6[4] into an IPv4/IPv6 string if present.

    Fields are stored as 4 x int32, little endian. We reinterpret
    them as unsigned for packing.
    """
    a0, a1, a2, a3 = (x & 0xFFFFFFFF for x in addr_v6)

    # All zeros -> no address
    if a0 == 0 and a1 == 0 and a2 == 0 and a3 == 0:
        return None

    # Common pattern: IPv4 stored in last element
    if a0 == 0 and a1 == 0 and a2 == 0:
        try:
            return str(ipaddress.IPv4Address(struct.pack("!I", a3)))
        except ipaddress.AddressValueError:
            pass

    # Fallback: treat full 16 bytes as IPv6
    try:
        packed = struct.pack("!4I", a0, a1, a2, a3)
        return str(ipaddress.IPv6Address(packed))
    except (ipaddress.AddressValueError, struct.error):
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
     a0, a1, a2, a3,
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
        ip_str = decode_ip((a0, a1, a2, a3))

    e_term, e_exit = split_exit_status(raw_exit)

    return {
        "type": ut_type,
        "type_name": UT_TYPES.get(ut_type, f"UNKNOWN({ut_type})"),
        "pid": ut_pid,
        "line": ut_line,
        "id": ut_id,
        "user": ut_user,
        "host": ut_host,
        "exit_termination": e_term,
        "exit_status": e_exit,
        "session": ut_session,
        "timestamp": timestamp,
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


def format_record(rec: Dict[str, Any]) -> str:
    """
    Turn a utmp record dict into a human-readable single-line summary.
    """
    ts = rec["timestamp"].strftime("%Y-%m-%d %H:%M:%S") if rec["timestamp"] else "N/A"
    user = rec["user"] or "-"
    line = rec["line"] or "-"
    host = rec["host"] or (rec["ip"] or "-")
    type_name = rec["type_name"]
    pid = rec["pid"]

    extra = []
    if rec["exit_status"] or rec["exit_termination"]:
        extra.append(f"exit={rec['exit_termination']}/{rec['exit_status']}")
    if rec["session"]:
        extra.append(f"session={rec['session']}")
    if rec["ip"] and rec["host"] and rec["ip"] != rec["host"]:
        extra.append(f"ip={rec['ip']}")

    extra_str = f" ({', '.join(extra)})" if extra else ""

    return f"{ts}  {type_name:13s}  user={user:16s}  line={line:12s}  host={host:30s}  pid={pid}{extra_str}"


def main():
    parser = argparse.ArgumentParser(
        description="Parse Linux utmp/wtmp/btmp binary files and print human-readable records."
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
    args = parser.parse_args()

    type_filter = None
    if args.types:
        type_filter = {t.strip().upper() for t in args.types}

    for rec in read_utmp_file(args.path):
        # Skip completely empty records unless --show-empty
        if not args.show_empty:
            if (rec["type"] == 0 and
                not rec["user"] and
                not rec["line"] and
                not rec["host"]):
                continue

        if type_filter is not None:
            if rec["type_name"].upper() not in type_filter:
                continue

        print(format_record(rec))


if __name__ == "__main__":
    main()
