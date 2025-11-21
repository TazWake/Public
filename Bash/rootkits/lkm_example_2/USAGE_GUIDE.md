# Educational Rootkit - Usage Guide (Version 2.0)

## Overview

This educational rootkit has been updated to **actually hide files** while maintaining forensic detection artifacts for training purposes. It is designed for kernel 5.15.0-124-generic and newer.

---

## What's New in Version 2.0

### ✅ Implemented File Hiding

- **Actually filters directory entries** using `getdents64` syscall hooking
- Hides any file/directory starting with the configured prefix (default: `evil_`)
- Logs all hidden files for forensic analysis

### ✅ Two Detection Artifacts

#### 1. Obvious Detection Point (Live Response)

- **Location**: `/proc/rootkit_forensics`
- **Visibility**: Easy to find during live response
- **Purpose**: Training students on basic rootkit detection
- **Contents**: Full logs, configuration, and hidden file list

#### 2. Subtle Detection Point (Disk Forensics)

- **Location**: `/proc/sys/kernel/pci_latency_timer`
- **Visibility**: Blends in with legitimate kernel tunables
- **Purpose**: Teaches students to look beyond obvious artifacts
- **Contents**: Appears as "1" with comments containing rootkit info
- **Detection**: Visible in disk forensics when analyzing `/proc` filesystem

---

## Compilation

```bash
cd /path/to/rootkits/lkm_example_2/
make clean
make
```

**Requirements:**

- Kernel headers: `sudo apt-get install linux-headers-$(uname -r)`
- GCC compiler
- Kernel version 5.7.0 or newer (tested on 5.15.0-124-generic)

---

## Loading the Module

### Basic Load (hides files starting with "evil_")

```bash
sudo insmod educational_rootkit.ko
```

### Load with Custom Prefix

```bash
# Hide files starting with "malware_"
sudo insmod educational_rootkit.ko hide_prefix="malware_"

# Hide files starting with "bad"
sudo insmod educational_rootkit.ko hide_prefix="bad"
```

### Verify Module Loaded

```bash
lsmod | grep educational_rootkit
dmesg | grep pci_gateway_driver
```

---

## Testing File Hiding

### 1. Create Test Files

```bash
# Create files that should be hidden
touch /tmp/evil_backdoor.sh
touch /tmp/evil_payload.bin
mkdir /tmp/evil_data

# Create normal files (should remain visible)
touch /tmp/normal_file.txt
touch /tmp/legitimate.sh
```

### 2. Test Hiding Behavior

```bash
# Without rootkit loaded - should see all files
ls -la /tmp/

# Load rootkit
sudo insmod educational_rootkit.ko

# Now check again - evil_* files should be hidden
ls -la /tmp/
# evil_backdoor.sh, evil_payload.bin, evil_data should NOT appear

# Files still exist (not deleted)
cat /tmp/evil_backdoor.sh  # Should work if you know the name
stat /tmp/evil_backdoor.sh  # Should work

# But directory listing won't show them
find /tmp -name "evil*"  # May or may not work depending on implementation
```

### 3. Test with Processes

```bash
# Create a "hidden" process
cp /bin/sleep /tmp/evil_sleep
/tmp/evil_sleep 999 &

# Check if hidden
ps aux | grep evil  # Should not appear
ls -la /tmp/ | grep evil  # Should not appear in directory listing

# But process is still running
pgrep -f evil_sleep  # May still find the PID
kill $(pgrep sleep)  # Can still kill if you find the PID
```

---

## Detection Methods for Training

### 🎯 Detection Point 1: Obvious Artifact (Live Response)

```bash
# Easy to find - checks obvious locations
cat /proc/rootkit_forensics
```

**Expected Output:**

```bash
Educational Rootkit Log (Forensic Analysis Data)
=============================================
Hide prefix: evil_
Magic string: forensics_key
Log entries:
Module loaded at 1234567890
Hidden: evil_backdoor.sh
Hidden: evil_payload.bin
Hidden: evil_data
=============================================
This is an educational example for forensics training.
It demonstrates common rootkit techniques in a safe way.
```

### 🎯 Detection Point 2: Subtle Artifact (Disk Forensics)

```bash
# Harder to spot - looks like a legitimate kernel parameter
cat /proc/sys/kernel/pci_latency_timer
```

**Expected Output:**

```bash
1
# pci_gateway_driver active
# prefix=evil_ magic=forensics_key
# logs=234 bytes
```

**Analysis:**

- First line shows "1" (mimics a kernel tunable)
- Comments contain rootkit identification strings
- Students need to examine the content, not just the filename
- In disk forensics, this file will be present in `/proc` snapshots

### 🎯 Detection Point 3: Kernel Logs

```bash
# Check dmesg for loading messages
dmesg | tail -20
dmesg | grep pci_gateway_driver
```

**Expected Output:**

```bash
[12345.678] pci_gateway_driver: Loading module
[12345.679] pci_gateway_driver: syscall table found at 0x...
[12345.680] pci_gateway_driver: Syscalls hooked - hiding prefix: evil_
[12345.681] pci_gateway_driver: Module loaded successfully
[12345.682] pci_gateway_driver: Check /proc/rootkit_forensics for forensic data
```

### 🎯 Detection Point 4: Loaded Modules

```bash
# Check loaded kernel modules
lsmod | grep educational
cat /proc/modules | grep educational
ls /sys/module/ | grep educational
```

### 🎯 Detection Point 5: Syscall Table Anomalies

```bash
# Advanced: Check syscall table integrity (requires tools)
# Compare current syscall addresses with known-good baseline
# Look for unexpected modifications

# Example using volatility (on memory dump):
vol.py -f memory.img linux.check_syscall_table
```

### 🎯 Detection Point 6: Directory Entry Discrepancies

```bash
# Compare different methods of listing files
ls -la /tmp/ | wc -l          # Uses getdents64 (hooked)
stat /tmp/evil_backdoor.sh    # Direct stat call (not hooked)

# Compare results - if stat succeeds but ls doesn't show it, rootkit present
```

### 🎯 Detection Point 7: Disk Forensics Analysis

When analyzing a disk image:

1. **Mount the filesystem read-only**
2. **Search for suspicious proc entries:**

   ```bash
   grep -r "pci_gateway_driver" /mnt/forensic_image/proc/
   grep -r "forensics_key" /mnt/forensic_image/proc/
   ```

3. **Check for unusual kernel tunables:**

   ```bash
   find /mnt/forensic_image/proc/sys/kernel/ -type f -exec cat {} \; | grep -i "pci_gateway"
   ```

4. **Analyze filesystem metadata:**
   - Files that exist in inodes but don't appear in directory listings
   - Timestamps showing recent kernel module activity

---

## Unloading the Module

```bash
# Remove the rootkit
sudo rmmod educational_rootkit

# Verify removal
lsmod | grep educational_rootkit
dmesg | tail -10

# Files should now be visible again
ls -la /tmp/
```

---

## Training Scenarios

### Scenario 1: Basic Live Response Detection

**Objective**: Students find the obvious detection artifact
**Difficulty**: Easy
**Expected Time**: 5-10 minutes

**Steps:**

1. Investigate running system
2. Check `/proc` filesystem for anomalies
3. Find `/proc/rootkit_forensics`
4. Document findings

### Scenario 2: Subtle Artifact Detection

**Objective**: Students find the disguised proc entry
**Difficulty**: Medium
**Expected Time**: 15-30 minutes

**Steps:**

1. Review all files in `/proc/sys/kernel/`
2. Read contents of suspicious entries
3. Identify `pci_latency_timer` with rootkit markers
4. Document how it differs from legitimate entries

### Scenario 3: Comprehensive Forensic Analysis

**Objective**: Students identify all indicators and document TTPs
**Difficulty**: Advanced
**Expected Time**: 45-60 minutes

**Steps:**

1. Capture memory dump
2. Analyze disk image
3. Correlate multiple artifacts
4. Document complete rootkit functionality
5. Identify hidden files
6. Trace syscall hooks

### Scenario 4: Disk Forensics Challenge

**Objective**: Find rootkit artifacts in offline disk analysis
**Difficulty**: Medium-Advanced
**Expected Time**: 30-45 minutes

**Setup:**

1. Mount disk image read-only
2. Students cannot perform live response
3. Must find artifacts in `/proc` snapshot

**Expected Findings:**

- `/proc/rootkit_forensics` contents
- `/proc/sys/kernel/pci_latency_timer` with markers
- Kernel log entries (if captured)
- Module information in `/sys/module/`

---

## Important Notes

### ⚠️ Safety and Usage Restrictions

1. **VM ONLY**: Never run on production systems or bare metal
2. **Isolated Environment**: Use isolated virtual networks
3. **Snapshot Before**: Take VM snapshot before loading
4. **Educational Purpose**: This is for defensive security training only
5. **Monitoring**: Monitor student usage in controlled environments

### 🔍 Forensic Value

This rootkit provides:

- **Realistic hiding behavior** (actually filters directory entries)
- **Obvious artifacts** (for beginner students)
- **Subtle artifacts** (for advanced students)
- **Disk forensics practice** (persistent artifacts)
- **Memory forensics practice** (syscall hooks visible in memory)

### 🛡️ Limitations (Intentional)

**This rootkit does NOT:**

- Hide itself from `lsmod` (students can see it loaded)
- Hide network connections
- Hide log file entries
- Provide privilege escalation
- Include persistence mechanisms
- Encrypt or exfiltrate data
- Hide from memory forensics tools

**These limitations are intentional** to keep the rootkit safe for educational use while still teaching core detection concepts.

---

## Expected Student Outcomes

After completing exercises with this rootkit, students should be able to:

1. ✅ Identify syscall hooking in kernel modules
2. ✅ Recognize file hiding techniques
3. ✅ Distinguish between live response and disk forensics artifacts
4. ✅ Use multiple detection methods (process listing, filesystem analysis, memory forensics)
5. ✅ Document rootkit capabilities and TTPs
6. ✅ Understand the difference between obvious and subtle indicators
7. ✅ Practice both live response and dead-box forensic analysis

---

## Troubleshooting

### Module Won't Load

```bash
# Check kernel version
uname -r  # Should be 5.7.0 or newer

# Check for kernel headers
ls /lib/modules/$(uname -r)/build

# Check dmesg for errors
dmesg | tail -30
```

### Files Not Hiding

```bash
# Check if module is actually loaded
lsmod | grep educational

# Check module parameters
cat /sys/module/educational_rootkit/parameters/hide_prefix

# Check logs
cat /proc/rootkit_forensics
```

### Compilation Errors

```bash
# Install kernel headers
sudo apt-get install linux-headers-$(uname -r)

# Clean and rebuild
make clean
make

# Check kernel version compatibility
cat /proc/version
```

---

## Version History

- **v2.0** (Current): Implements actual file hiding, adds second detection artifact
- **v1.0** (Original): Non-functional hooks, single obvious detection point

---

## Contact and Support

For questions about this educational tool, refer to the instructor guide or repository documentation.

**Remember: This is a training tool. Use responsibly and only in authorized educational environments.**
