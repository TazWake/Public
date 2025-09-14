# Instructor Guide - Educational Rootkit Example

## Overview

This directory contains an educational Loadable Kernel Module (LKM) designed for teaching Linux forensics and rootkit detection. The example demonstrates common rootkit techniques in a safe, controlled manner.

## Contents

- `educational_rootkit.c` - Main kernel module source code
- `Makefile` - Build instructions for the module
- `README.md` - Student documentation
- `demo.sh` - Demonstration script for classroom use
- `detect.sh` - Forensic detection script for student exercises

## Prerequisites

Students should have:
- Basic understanding of Linux kernel modules
- Familiarity with C programming
- Knowledge of system calls
- Understanding of forensic analysis principles

## Installation for Classroom Use

1. Ensure the system has kernel headers installed:
   ```bash
   # Ubuntu/Debian
   sudo apt install linux-headers-$(uname -r) build-essential
   
   # CentOS/RHEL/Fedora
   sudo yum install kernel-devel kernel-headers
   ```

2. Navigate to this directory:
   ```bash
   cd /mnt/d/Development/Public/Bash/rootkits/lkm_example_2
   ```

3. Build the module:
   ```bash
   make
   ```

## Classroom Demonstration

1. Show students the source code and explain each component
2. Build and load the module using the demo script:
   ```bash
   sudo ./demo.sh
   ```
3. Demonstrate detection techniques using the detect script:
   ```bash
   sudo ./detect.sh
   ```

## Learning Activities

### Activity 1: Code Analysis
Have students examine the source code and identify:
- How system calls are hooked
- How the syscall table is modified
- How /proc entries are created
- How logging is implemented

### Activity 2: Detection Exercise
Students run the detection script and:
- Identify indicators of compromise (IOCs)
- Practice forensic analysis techniques
- Document their findings

### Activity 3: Memory Analysis
Using tools like Volatility (if available):
- Analyze memory dumps for rootkit signatures
- Compare clean vs. infected system states

## Safety Notes

- This module is designed to be safe for educational use
- It does not actually hide processes or files
- All functionality is limited and detectable
- Always unload the module after demonstrations:
  ```bash
  sudo rmmod educational_rootkit
  ```

## Assessment Ideas

1. Written exam questions about rootkit techniques
2. Practical exercise: Detect the rootkit in a prepared VM
3. Code modification: Add new "malicious" functionality (educational only)
4. Research project: Compare with real-world rootkits like Adore or Diamorphine

## Troubleshooting

### Module won't build
- Ensure kernel headers are installed for the current kernel
- Check that build tools are available

### Module won't load
- Verify the system supports loading unsigned modules
- Check kernel logs: `dmesg | tail`

### Detection script shows no results
- Ensure the module is loaded before running detection
- Run as root for full access to system information

## Extensions

Advanced students can:
- Modify the module to hook additional system calls
- Implement actual process hiding (in a controlled environment)
- Create a more sophisticated detection mechanism
- Research and implement memory analysis techniques