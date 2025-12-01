#!/usr/bin/env python3

import os
import argparse
import pefile

def parse_args():
    parser = argparse.ArgumentParser(
        description="Inspect PE headers and exported functions from a PE file (.exe, .dll)."
    )
    parser.add_argument(
        "filepath",
        help="Path to the PE file (e.g., /cases/evidence/example-library.dll)"
    )
    return parser.parse_args()

def main():
    args = parse_args()
    dll_path = args.filepath

    if not os.path.isfile(dll_path):
        raise FileNotFoundError(f"PE file not found: {dll_path}")

    # Load PE file
    pe = pefile.PE(dll_path)
    print(f"[+] Loaded PE file: {dll_path}\n")

    # --- FILE HEADER ---
    fh = pe.FILE_HEADER
    print("=== PE FILE HEADER ===")
    print(f"Machine:               0x{fh.Machine:04x}")
    print(f"Number of Sections:    {fh.NumberOfSections}")
    print(f"TimeDateStamp:         {fh.TimeDateStamp}")
    print(f"PointerToSymbolTable:  {fh.PointerToSymbolTable}")
    print(f"NumberOfSymbols:       {fh.NumberOfSymbols}")
    print(f"SizeOfOptionalHeader:  {fh.SizeOfOptionalHeader}")
    print(f"Characteristics:       0x{fh.Characteristics:04x}")
    print()

    # --- EXPORTED FUNCTIONS ---
    print("=== EXPORTED FUNCTIONS ===")
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for symbol in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            name = symbol.name.decode("utf-8", errors="ignore") if symbol.name else "<no name>"
            ordinal = symbol.ordinal
            address = symbol.address
            print(f"Ordinal: {ordinal:4d}  Address: 0x{address:08x}  Name: {name}")
    else:
        print("No export directory found in this PE file.")

    pe.close()

if __name__ == "__main__":
    main()
