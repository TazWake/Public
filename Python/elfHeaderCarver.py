#!/usr/bin/env python3
"""
elf_header_carver.py

Read the ELF identification bytes, determine class (32/64) and endianness,
then extract (carve) the ELF header and display its fields as a table.

Notes:
- The script uses e_ehsize as the authoritative header length to carve,
  after validating it against expected minimums.
- Output is intended to reflect the on-disk values (decoded using EI_DATA).
"""

from __future__ import annotations

import argparse
import os
import struct
import sys
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

# --- ELF constants (subset) ---
ELF_MAGIC = b"\x7fELF"

EI_NIDENT = 16
EI_CLASS = 4
EI_DATA = 5
EI_VERSION = 6
EI_OSABI = 7
EI_ABIVERSION = 8

ELFCLASS32 = 1
ELFCLASS64 = 2

ELFDATA2LSB = 1
ELFDATA2MSB = 2

# Common e_type values
ET_MAP: Dict[int, str] = {
    0: "ET_NONE (none)",
    1: "ET_REL (relocatable)",
    2: "ET_EXEC (executable)",
    3: "ET_DYN (shared object / PIE)",
    4: "ET_CORE (core)",
}

# Common e_machine values (not exhaustive)
EM_MAP: Dict[int, str] = {
    0: "EM_NONE",
    2: "EM_SPARC",
    3: "EM_386",
    8: "EM_MIPS",
    20: "EM_PPC",
    21: "EM_PPC64",
    40: "EM_ARM",
    62: "EM_X86_64",
    183: "EM_AARCH64",
    243: "EM_RISCV",
}

OSABI_MAP: Dict[int, str] = {
    0: "System V",
    1: "HP-UX",
    2: "NetBSD",
    3: "Linux",
    6: "Solaris",
    7: "AIX",
    8: "IRIX",
    9: "FreeBSD",
    12: "OpenBSD",
}

DATA_MAP: Dict[int, str] = {
    ELFDATA2LSB: "2's complement, little-endian",
    ELFDATA2MSB: "2's complement, big-endian",
}

CLASS_MAP: Dict[int, str] = {
    ELFCLASS32: "ELF32",
    ELFCLASS64: "ELF64",
}


@dataclass
class ElfHeaderParsed:
    e_ident: bytes
    e_type: int
    e_machine: int
    e_version: int
    e_entry: int
    e_phoff: int
    e_shoff: int
    e_flags: int
    e_ehsize: int
    e_phentsize: int
    e_phnum: int
    e_shentsize: int
    e_shnum: int
    e_shstrndx: int


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="elf_header_carver.py",
        description=(
            "Detect ELF files, carve the ELF header (based on e_ehsize), "
            "and print decoded header fields."
        ),
        epilog=(
            "Examples:\n"
            "  python3 elf_header_carver.py /path/to/binary\n"
            "  python3 elf_header_carver.py /path/to/binary --out header.bin\n"
            "  python3 elf_header_carver.py /path/to/binary --no-human\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("path", help="Path to the input file to examine.")
    p.add_argument(
        "--out",
        metavar="FILE",
        help="Optional: write the carved ELF header bytes to FILE.",
        default=None,
    )
    p.add_argument(
        "--offset",
        type=int,
        default=0,
        help="Offset to read ELF header from (default: 0).",
    )
    p.add_argument(
        "--no-human",
        action="store_true",
        help="Do not include human-readable interpretations in the table.",
    )
    p.add_argument(
        "--max-header",
        type=int,
        default=4096,
        help="Maximum header size allowed for carving (default: 4096).",
    )
    return p


def read_exact(f, n: int) -> bytes:
    data = f.read(n)
    if len(data) != n:
        raise ValueError(f"File too small: expected {n} bytes, got {len(data)}")
    return data


def parse_e_ident(e_ident: bytes) -> Tuple[int, int, int, int, int]:
    if len(e_ident) != EI_NIDENT:
        raise ValueError("Invalid e_ident length")

    if e_ident[0:4] != ELF_MAGIC:
        raise ValueError("Not an ELF file (magic mismatch)")

    eclass = e_ident[EI_CLASS]
    edata = e_ident[EI_DATA]
    ever = e_ident[EI_VERSION]
    osabi = e_ident[EI_OSABI]
    abiver = e_ident[EI_ABIVERSION]

    if eclass not in (ELFCLASS32, ELFCLASS64):
        raise ValueError(f"Unknown ELF class: {eclass}")

    if edata not in (ELFDATA2LSB, ELFDATA2MSB):
        raise ValueError(f"Unknown ELF data encoding: {edata}")

    return eclass, edata, ever, osabi, abiver


def endian_prefix(edata: int) -> str:
    return "<" if edata == ELFDATA2LSB else ">"


def parse_elf_header(path: str, offset: int) -> Tuple[ElfHeaderParsed, bytes]:
    with open(path, "rb") as f:
        if offset < 0:
            raise ValueError("Offset cannot be negative")
        f.seek(offset, os.SEEK_SET)

        e_ident = read_exact(f, EI_NIDENT)
        eclass, edata, _ever, _osabi, _abiver = parse_e_ident(e_ident)
        ep = endian_prefix(edata)

        # Read the rest of the ELF header based on class minimum sizes:
        # ELF32 header total is typically 52 bytes; ELF64 typically 64 bytes.
        # We will read the class minimum first, then use e_ehsize to carve exact bytes.
        min_size = 52 if eclass == ELFCLASS32 else 64
        rest_len = min_size - EI_NIDENT
        rest = read_exact(f, rest_len)

        header_min = e_ident + rest

        # Now decode fields from the minimum header bytes.
        if eclass == ELFCLASS32:
            fmt = ep + "HHIIIIIHHHHHH"
            # fields after e_ident: e_type, e_machine, e_version, e_entry, e_phoff, e_shoff,
            # e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx
            vals = struct.unpack(fmt, header_min[EI_NIDENT:EI_NIDENT + struct.calcsize(fmt)])
        else:
            fmt = ep + "HHIQQQIHHHHHH"
            vals = struct.unpack(fmt, header_min[EI_NIDENT:EI_NIDENT + struct.calcsize(fmt)])

        parsed = ElfHeaderParsed(
            e_ident=e_ident,
            e_type=vals[0],
            e_machine=vals[1],
            e_version=vals[2],
            e_entry=vals[3],
            e_phoff=vals[4],
            e_shoff=vals[5],
            e_flags=vals[6],
            e_ehsize=vals[7],
            e_phentsize=vals[8],
            e_phnum=vals[9],
            e_shentsize=vals[10],
            e_shnum=vals[11],
            e_shstrndx=vals[12],
        )

        # Carve exact header length based on e_ehsize:
        # Validate e_ehsize is plausible.
        if parsed.e_ehsize < min_size:
            raise ValueError(f"e_ehsize too small ({parsed.e_ehsize}); expected >= {min_size}")
        if parsed.e_ehsize > 4096:
            # caller can override via --max-header, but hard fail unless explicitly allowed
            # (we enforce in main with the arg)
            pass

        # Rewind to offset and read exact e_ehsize bytes
        f.seek(offset, os.SEEK_SET)
        carved = read_exact(f, parsed.e_ehsize)

        return parsed, carved


def hex_bytes(b: bytes) -> str:
    return " ".join(f"{x:02x}" for x in b)


def format_value(v: int) -> str:
    # Show both decimal and hex for numeric fields
    return f"{v} (0x{v:x})"


def render_table(rows: List[Tuple[str, str, str]]) -> str:
    # Simple aligned columns without external deps
    col1 = max(len(r[0]) for r in rows)
    col2 = max(len(r[1]) for r in rows)
    # col3 can be empty if --no-human
    lines = []
    header = ("Field".ljust(col1), "Value".ljust(col2), "Human".rstrip())
    sep = ("-" * col1, "-" * col2, "-" * max(5, len(header[2])))
    lines.append(f"{header[0]}  {header[1]}  {header[2]}")
    lines.append(f"{sep[0]}  {sep[1]}  {sep[2]}")
    for name, val, human in rows:
        lines.append(f"{name.ljust(col1)}  {val.ljust(col2)}  {human}")
    return "\n".join(lines)


def make_rows(parsed: ElfHeaderParsed, no_human: bool) -> List[Tuple[str, str, str]]:
    e_ident = parsed.e_ident
    eclass = e_ident[EI_CLASS]
    edata = e_ident[EI_DATA]
    ever = e_ident[EI_VERSION]
    osabi = e_ident[EI_OSABI]
    abiver = e_ident[EI_ABIVERSION]

    def H(s: str) -> str:
        return "" if no_human else s

    rows: List[Tuple[str, str, str]] = []

    rows.append(("e_ident[0:4]", hex_bytes(e_ident[0:4]), H("ELF magic")))
    rows.append(("e_ident[EI_CLASS]", str(eclass), H(CLASS_MAP.get(eclass, "unknown"))))
    rows.append(("e_ident[EI_DATA]", str(edata), H(DATA_MAP.get(edata, "unknown"))))
    rows.append(("e_ident[EI_VERSION]", str(ever), H("current" if ever == 1 else "unknown")))
    rows.append(("e_ident[EI_OSABI]", str(osabi), H(OSABI_MAP.get(osabi, "unknown"))))
    rows.append(("e_ident[EI_ABIVERSION]", str(abiver), H(f"ABI version {abiver}")))
    # Show the full 16 bytes too (handy for training)
    rows.append(("e_ident (16 bytes)", hex_bytes(e_ident), H("raw identification bytes")))

    rows.append(("e_type", format_value(parsed.e_type), H(ET_MAP.get(parsed.e_type, "unknown"))))
    rows.append(("e_machine", format_value(parsed.e_machine), H(EM_MAP.get(parsed.e_machine, "unknown"))))
    rows.append(("e_version", format_value(parsed.e_version), H("current" if parsed.e_version == 1 else "unknown")))
    rows.append(("e_entry", format_value(parsed.e_entry), H("entry point VA")))
    rows.append(("e_phoff", format_value(parsed.e_phoff), H("program header table offset")))
    rows.append(("e_shoff", format_value(parsed.e_shoff), H("section header table offset")))
    rows.append(("e_flags", format_value(parsed.e_flags), H("architecture-specific")))
    rows.append(("e_ehsize", format_value(parsed.e_ehsize), H("ELF header size (bytes)")))
    rows.append(("e_phentsize", format_value(parsed.e_phentsize), H("PH entry size (bytes)")))
    rows.append(("e_phnum", format_value(parsed.e_phnum), H("PH entry count")))
    rows.append(("e_shentsize", format_value(parsed.e_shentsize), H("SH entry size (bytes)")))
    rows.append(("e_shnum", format_value(parsed.e_shnum), H("SH entry count")))
    rows.append(("e_shstrndx", format_value(parsed.e_shstrndx), H("section-name string table index")))

    return rows


def main() -> int:
    args = build_arg_parser().parse_args()

    try:
        st = os.stat(args.path)
        if not os.path.isfile(args.path):
            print(f"ERROR: not a regular file: {args.path}", file=sys.stderr)
            return 2
        if st.st_size < EI_NIDENT:
            print("ERROR: file too small to contain an ELF header", file=sys.stderr)
            return 2

        parsed, carved = parse_elf_header(args.path, args.offset)

        if parsed.e_ehsize > args.max_header:
            print(
                f"ERROR: e_ehsize={parsed.e_ehsize} exceeds --max-header={args.max_header}. "
                f"Refusing to carve.",
                file=sys.stderr,
            )
            return 2

        # Optional output of raw header bytes
        if args.out:
            with open(args.out, "wb") as out_f:
                out_f.write(carved)

        rows = make_rows(parsed, no_human=args.no_human)

        print(f"File: {args.path}")
        print(f"Offset: {args.offset}")
        print(f"Carved header length: {len(carved)} bytes")
        if args.out:
            print(f"Wrote carved header to: {args.out}")
        print()
        print(render_table(rows))
        return 0

    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
