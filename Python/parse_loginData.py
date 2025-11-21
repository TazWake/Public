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
            retur
