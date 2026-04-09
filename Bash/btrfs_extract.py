#!/usr/bin/env python3
"""
btrfs_extract.py
Extract inode, timestamps, and file content from a btrfs image without mounting.
Usage: ./btrfs_extract.py <filename> <btrfs_image>
"""

import sys
import os
import re
import subprocess
import shutil
from datetime import datetime

# ─── Colour codes ─────────────────────────────────────────────────────────────
RED  = '\033[0;31m'
GRN  = '\033[0;32m'
YLW  = '\033[1;33m'
CYN  = '\033[0;36m'
BLD  = '\033[1m'
RST  = '\033[0m'

def err(msg):
    print(f"{RED}[ERROR]{RST} {msg}")

def info(msg):
    print(f"{CYN}[*]{RST} {msg}")

def ok(msg):
    print(f"{GRN}[+]{RST} {msg}")

def warn(msg):
    print(f"{YLW}[!]{RST} {msg}")

# ─── Usage ────────────────────────────────────────────────────────────────────
def usage():
    print(f"{BLD}Usage:{RST} {sys.argv[0]} <filename> <btrfs_image>")
    print("  filename    : name of the file to locate (root directory only)")
    print("  btrfs_image : path to the btrfs disk image")
    sys.exit(1)

# ─── Argument checks ──────────────────────────────────────────────────────────
if len(sys.argv) != 3:
    err("Incorrect number of arguments.")
    usage()

TARGET_FILE = sys.argv[1]
IMAGE       = sys.argv[2]

if not TARGET_FILE:
    err("Filename argument is empty.")
    usage()

if not os.path.isfile(IMAGE):
    err(f"Image file not found: {IMAGE}")
    sys.exit(1)

if not os.access(IMAGE, os.R_OK):
    err(f"Image file is not readable: {IMAGE}")
    sys.exit(1)

# ─── Dependency checks ────────────────────────────────────────────────────────
for cmd in ['btrfs', 'file']:
    if not shutil.which(cmd):
        err(f"Required command not found: {cmd}")
        sys.exit(1)

# ─── Verify btrfs image ───────────────────────────────────────────────────────
info("Verifying image type...")
try:
    result = subprocess.run(
        ['btrfs', 'inspect-internal', 'dump-super', IMAGE],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        err(f"Image does not appear to be a valid btrfs filesystem: {IMAGE}")
        sys.exit(1)
except Exception as e:
    err(f"Failed to inspect image: {e}")
    sys.exit(1)

ok("Image verified as btrfs.")

# ─── Dump the tree once ───────────────────────────────────────────────────────
info("Parsing btrfs tree (this may take a moment)...")
try:
    result = subprocess.run(
        ['btrfs', 'inspect-internal', 'dump-tree', IMAGE],
        capture_output=True, text=True
    )
    tree_dump = result.stdout
except Exception as e:
    err(f"Failed to dump btrfs tree: {e}")
    sys.exit(1)

if not tree_dump.strip():
    err("btrfs dump-tree returned no output.")
    sys.exit(1)

# ─── Locate inode via DIR_ITEM only ──────────────────────────────────────────
inode = None
block = []
in_dir_item = False

for line in tree_dump.splitlines():
    if re.search(r'key \(\d+ DIR_ITEM \d+\)', line):
        block = [line]
        in_dir_item = True
        continue
    if in_dir_item:
        if re.search(r'key \(\d+ DIR_', line):
            in_dir_item = False
            block = []
            continue
        block.append(line)
        if re.search(rf'name: {re.escape(TARGET_FILE)}$', line):
            block_text = '\n'.join(block)
            m = re.search(r'\((\d+) INODE_ITEM', block_text)
            if m:
                inode = int(m.group(1))
            in_dir_item = False
            block = []
            break

if inode is None:
    err(f"File '{TARGET_FILE}' not found in the btrfs image root directory.")
    sys.exit(1)

ok("File located.")

# ─── Extract INODE_ITEM block ─────────────────────────────────────────────────
inode_block_lines = []
in_inode = False
for line in tree_dump.splitlines():
    if re.search(rf'key \({inode} INODE_ITEM 0\)', line):
        in_inode = True
    if in_inode:
        inode_block_lines.append(line)
        if len(inode_block_lines) > 12:
            break

inode_block = '\n'.join(inode_block_lines)

def extract_timestamp(label):
    m = re.search(rf'{label}\s+[\d.]+\s+\(([^)]+)\)', inode_block)
    return m.group(1) if m else 'unknown'

def extract_field(pattern):
    m = re.search(pattern, inode_block)
    return m.group(1) if m else 'unknown'

atime    = extract_timestamp('atime')
ctime    = extract_timestamp('ctime')
mtime    = extract_timestamp('mtime')
otime    = extract_timestamp('otime')
filesize = extract_field(r'size (\d+)')
filemode = extract_field(r'mode (\d+)')
fileuid  = extract_field(r'uid (\d+)')
filegid  = extract_field(r'gid (\d+)')

# ─── Output results ───────────────────────────────────────────────────────────
print()
print(f"{BLD}════════════════════════════════════════════════════{RST}")
print(f"{BLD}  btrfs File Extraction Report{RST}")
print(f"{BLD}════════════════════════════════════════════════════{RST}")
print(f"  {BLD}Image   :{RST} {IMAGE}")
print(f"  {BLD}File    :{RST} {TARGET_FILE}")
print(f"  {BLD}Inode   :{RST} {YLW}{inode}{RST}")
print(f"  {BLD}Size    :{RST} {filesize} bytes")
print(f"  {BLD}Mode    :{RST} {filemode}  UID: {fileuid}  GID: {filegid}")
print(f"{BLD}────────────────────────────────────────────────────{RST}")
print(f"  {BLD}Timestamps{RST}")
print(f"  atime (last access)          : {atime}")
print(f"  mtime (last modification)    : {mtime}")
print(f"  ctime (last metadata change) : {ctime}")
print(f"  otime (inode creation)       : {otime}")
print(f"{BLD}════════════════════════════════════════════════════{RST}")

# ─── Restore file ─────────────────────────────────────────────────────────────
timestamp    = datetime.now().strftime("%Y%m%d_%H%M%S")
restore_dir  = f"/tmp/restore_{timestamp}"
os.makedirs(restore_dir, exist_ok=True)

info(f"Restoring '{TARGET_FILE}' to {restore_dir}...")

try:
    result = subprocess.run(
        ['btrfs', 'restore', '-s', '--path-regex', f'^/({re.escape(TARGET_FILE)})$',
         IMAGE, restore_dir],
        capture_output=True, text=True
    )
    restored_path = os.path.join(restore_dir, TARGET_FILE)

    if not os.path.isfile(restored_path):
        err("Restore completed but file not found at expected path.")
        print(f"    Check restore directory: {restore_dir}")
        sys.exit(1)

    ok(f"File restored to: {BLD}{restored_path}{RST}")

    # Determine MIME type
    mime_result = subprocess.run(
        ['file', '--mime-type', '-b', restored_path],
        capture_output=True, text=True
    )
    mime = mime_result.stdout.strip()
    print(f"  {BLD}MIME type:{RST} {mime}")

    if mime.startswith('text/'):
        with open(restored_path, 'r', errors='replace') as f:
            lines = f.readlines()
        if len(lines) <= 50:
            print()
            print(f"{BLD}────────────────────────────────────────────────────{RST}")
            warn(f"File content ({len(lines)} lines):")
            print(f"{BLD}────────────────────────────────────────────────────{RST}")
            print(''.join(lines), end='')
            print(f"{BLD}────────────────────────────────────────────────────{RST}")
        else:
            warn(f"File is text but {len(lines)} lines — content not printed automatically.")
            print(f"    View with: {BLD}cat {restored_path}{RST}")
    else:
        warn(f"File is not plain text ({mime}) — content not printed.")
        print(f"    Inspect with: {BLD}xxd {restored_path} | head -20{RST}")

except Exception as e:
    err(f"btrfs restore failed: {e}")
    try:
        os.rmdir(restore_dir)
    except Exception:
        pass
    sys.exit(1)

print()
ok("Done.\n")
