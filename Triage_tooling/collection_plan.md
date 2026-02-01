# collection_plan.md

## Purpose
Define the evidence collection scope and sequencing for Linux incident response, aligned to RFC3227 best practice and suitable for live response and captured evidence workflows.

## Guiding Principles
- Follow RFC3227 order of volatility (collect most-volatile first).
- Minimize handling; avoid altering evidence whenever possible.
- Prefer read-only access and non-intrusive methods.
- Preserve metadata and hash all collected artifacts.
- Maintain a clear audit log of actions, tool versions, and timestamps.

## RFC3227 Order of Volatility (High to Low)
1. CPU registers, cache, and other ephemeral processor state
2. Routing tables, ARP cache, process table, kernel statistics, memory
3. Temporary filesystems and swap
4. Disk
5. Remote logging and monitoring data
6. Physical configuration, network topology, and archival media

## Evidence Collection Order (Live Response)
1. **Volatile data**
   - Current date/time, uptime, timezone
   - Logged-in users, sessions, and recent logins
   - Running processes (ps, top snapshot, pstree)
   - Network connections and listening services (ss, lsof)
   - Open files and active sockets
   - Kernel modules and loaded drivers
   - If approved, memory capture (tool-specific)

2. **System state and configuration**
   - Host identification (hostname, OS version, kernel)
   - User and group listings; password last-change timestamps
   - Scheduled tasks (cron, systemd timers)
   - Services and unit files with modification times
   - Installed packages and recent updates

3. **Persistence and execution artifacts**
   - Autostart and init locations (systemd, init.d, rc.local)
   - Shell profiles and scripts (/etc/profile, ~/.bashrc, etc.)
   - SSH authorized_keys and configs

4. **Logs and audit data**
   - System logs (syslog, auth, messages, journal)
   - Security/audit logs (auditd)
   - Application and service logs where relevant

5. **Filesystem triage**
   - Full filesystem bodyfile (mactime format) using statx
   - Targeted triage of /etc and other critical directories
   - Triage of user home directories (history, recent files)

6. **Optional full disk image**
    - dd with 32kb block size; compress output if required

## Evidence Collection (Captured Evidence)
- Mount disk image read-only.
- Collect the same artifacts as above, excluding live-only volatile data.
- Emphasize filesystem bodyfile generation and log/config capture.

## Core Artifacts to Collect
- Full filesystem bodyfile (statx-based, works on XFS/Btrfs/ext4).
- Users and password last-change times.
- Service unit files with modification timestamps.
- Login events exported to CSV.
- Cron jobs exported to CSV.
- Shell history exported to CSV (including timestamped histories).
- Copy of logs and key configuration files in /etc.

## Output and Integrity Requirements
- Store artifacts in a structured directory layout.
- Generate hashes for all collected files (and record in a manifest).
- Produce a collection report summarizing key findings and timings.
- Retain filesystem metadata during collection where possible.

