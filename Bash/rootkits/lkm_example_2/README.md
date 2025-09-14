# Educational Rootkit Example - LKM Example 2

This is an educational Loadable Kernel Module (LKM) designed for Linux forensics training. It demonstrates common rootkit techniques in a safe, limited way that helps students understand how rootkits work without the risks associated with actual malicious rootkits.

## Purpose

This module is designed for educational purposes only to help students in digital forensics and incident response understand:

1. How rootkits operate at the kernel level
2. Common techniques used by malicious rootkits
3. How to detect and analyze rootkits in forensic investigations
4. The importance of kernel-level security

## Features (Educational Only)

This example demonstrates:

1. **System Call Hooking**: Hooks `getdents64` and `kill` system calls to show how rootkits can intercept system calls.
2. **Kernel Memory Manipulation**: Shows how to modify the syscall table (with proper protection handling).
3. **Proc Filesystem Interface**: Creates a `/proc/rootkit_forensics` entry for forensic analysis.
4. **Module Parameters**: Demonstrates how rootkits can be configured at load time.
5. **Logging Mechanism**: Maintains a log of intercepted calls for forensic analysis.

## Forensic Value

Students can learn to detect this rootkit by:

1. Checking loaded kernel modules: `lsmod | grep educational_rootkit`
2. Examining the syscall table for modifications
3. Checking `/proc` entries for unexpected files
4. Monitoring kernel logs for suspicious messages
5. Analyzing the forensic log at `/proc/rootkit_forensics`

## Building and Loading

**WARNING**: This code is for educational purposes in controlled environments only.

To build the module:
```bash
make
```

To load the module (requires root):
```bash
sudo insmod educational_rootkit.ko
```

To unload the module (requires root):
```bash
sudo rmmod educational_rootkit
```

To check the forensic log:
```bash
cat /proc/rootkit_forensics
```

## Detection Techniques for Students

As a forensic exercise, students should be able to detect this rootkit by:

1. **Module Listing**: `lsmod` will show the loaded module
2. **Proc Filesystem**: The `/proc/rootkit_forensics` entry is unusual
3. **Kernel Logs**: Check `dmesg` for module load/unload messages
4. **Syscall Table Analysis**: Compare syscall table addresses before/after loading
5. **Memory Analysis**: Tools like Volatility can detect hooked syscalls

## Educational Parameters

The module accepts two parameters for forensic analysis:

- `hide_process`: String used to demonstrate process hiding (default: "educational_rootkit")
- `magic_string`: String used to demonstrate detection techniques (default: "forensics_key")

Example with parameters:
```bash
sudo insmod educational_rootkit.ko hide_process="malware" magic_string="backdoor"
```

## Important Notes

1. This is **NOT** a real rootkit and should not be used maliciously
2. This module is for **EDUCATIONAL PURPOSES ONLY**
3. Only use in controlled laboratory environments
4. Always unload the module after testing
5. Do not use on production systems
6. This module does not actually hide processes or files (for safety)

## Learning Objectives

After studying this example, students should understand:

1. How kernel modules work and how they can be abused
2. The dangers of system call hooking
3. How to detect kernel-level modifications
4. The importance of kernel integrity monitoring
5. Techniques for analyzing suspicious kernel modules

## References

This example is based on common techniques found in real-world rootkits like:
- Adore
- KBeast
- Diamorphine
- Reptile

But implemented in a safe, detectable way for educational purposes.