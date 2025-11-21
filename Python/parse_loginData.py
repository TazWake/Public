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
from typing import Optional, Dict, Any, Generator

###################################
# NOTE: This is an alpha version! #
###################################

# ---------------------------------------------------------------------------
# UTMP record format (on-disk, Linux, 384 bytes)
#
#   short  ut_type;
#   pid_t  ut_pid;              (int32)
#   char   ut_line[32];
#   char   ut_id[4];
#   char   ut_user[32];
#   char   ut_host[256];
#   short  ut_exit.e_termination;
#   short  ut_exit.e_exit;
#   int    ut_session;
#   int    ut_tv.tv_sec;
#   int    ut_tv.tv_usec;
#   int    ut_addr_v6[4];
#   char   __unused[20];
#   (2 bytes padding)
# ---------------------------------------------------------------------------

UTMP_STRUCT_FORMAT = "<hi32s4s32s256shhiii4i20s2x"
UTMP_STRUCT = struct.Struct(UTMP_STRUCT_FORMAT)
RECORD_SIZE = UTMP_STRUCT.size  # should be 384

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


def decode_ip(addr_v6) -> Optional[str]:
    """
    Decode ut_addr_v6[4] into an IPv4/IPv6 string if present.

    The fields are stored as int32_t, so they may be negative; we interpret
    them as unsigned 32-bit values by masking with 0xffffffff.
    """
    # Reinterpret as unsigned 32-bit
    a0, a1, a2, a3 = (x & 0xFFFFFFFF for x in addr_v6)

    # All zeros -> no address
    if a0 == 0 and a1 == 0 and a2 == 0 and a3 == 0:
        return None

    # Common pattern: IPv4 stored in last element only
    if a0 == 0 and a1 == 0 and a2 == 0:
        try:
            return str(ipaddress.IPv4Address(struct.pack("!I", a3)))
        except ipaddress.AddressValueError:
            # Fall through to IPv6 attempt
            pass

    # Fallback: treat entire 16 bytes as IPv6
    try:
        packed = struct.pack("!4I", a0, a1, a2, a3)
        return str(ipaddress.IPv6Address(packed))
    except (ipaddress.AddressValueError, struct.error):
        return None


def parse_utmp_record(rec: bytes) -> Dict[str, Any]:
    """
    Parse a single 384-byte utmp record into a dictionary.
    """
    (ut_type,
     ut_pid,
     ut_line,
     ut_id,
     ut_user,
     ut_host,
     e_term,
     e_exit,
     ut_session,
     tv_sec,
     tv_usec,
     a0, a1, a2, a3,
     unused) = UTMP_STRUCT.unpack(rec)

    ut_line = ut_line.rstrip(b"\x00").decode(errors="ignore")
    ut_id = ut_id.rstrip(b"\x00").decode(errors="ignore")
    ut_user = ut_user.rstrip(b"\x00").decode(errors="ignore")
    ut_host = ut_host.rstrip(b"\x00").decode(errors="ignore")

    if tv_sec > 0:
        timestamp = datetime.datetime.fromtimestamp(tv_sec)
    else:
        timestamp = None

    # Only bother decoding IP if host field is empty. This avoids
    # spurious "ip=0:a::" style nonsense on local entries.
    ip_str = None
    if not ut_host:
        ip_str = decode_ip((a0, a1, a2, a3))

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
    # Prefer host, fall back to IP if host is empty
    host = rec["host"] or (rec["ip"] or "-")
    type_name = rec["type_name"]
    pid = rec["pid"]

    extra = []
    if rec["exit_status"] or rec["exit_termination"]:
        extra.append(f"exit={rec['exit_termination']}/{rec['exit_status']}")
    if rec["session"]:
        extra.append(f"session={rec['session']}")
    # If both host and ip exist and differ (rare but possible), show ip as extra
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
        # Normalise to upper case and strip
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
