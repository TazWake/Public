# Triage Tooling Plan


## Scripts

1. Bash
2. Python
3. Compiled code

Notes:

- Must be well documented
- Must keep a log of all actions
- Must hash all objects recovered from filesystem
- Must retain filesystem metadata wherever possible
- Must have a user-friendly help system

*Important*: The three approaches must be similar in function but do **not** need to be identical.

### Compiled Options

- C++
- GoLang
- Rust

*Note*: Ideally three binary versions.

## Development Plan

- Plan the overarching approach
- Build the bash version
- Build the python version
- Build the *three* (hopefully) compiled versions
- Plan a development lifecycle

## Types

1. Captured Evidence
2. Live Response

## Captured Evidence

### Captured Evidence Actions

1. Mount Disk Image
2. Recover Triage Data and store as a Tar.gz file
3. Generate Initial Report (optional - to be developed)

#### Captured Evidence Triage Data

- Use Profiles or list items.
- Build Plan Note: Start with individual items but include a place holder to use profiles in the future. 
- Collect:
  - A full filesystem bodyfile in Mactime format. Ideally using a call to `statx` rather than relying on The Sleuth Kit etc. This should include creation timestamps and must work on XFS and Btrfs systems.
  - List of users and the last password change times
  - List of all service files and the file last mod time
  - Extract login events and provide this as a CSV
  - Extract all cron jobs and provide this as a CSV
  - Extract user shell history and provide this as a CSV (account for any users who have timestamps enabled as well)
  - Create an evidence archive
     - Copy of all logs
     - Copy of significant config files in etc

(anything else?)

- The evidence report should be a record of what was collected and if possible any key insights. Like "X users have logged in in the last 3 days" or "these services have been modified in the last 12 hours" or something.

## Live System

### Live System Actions

1. Capture evidence
2. Save to Tar.gz file or similar with storage options to include local, USB, SFTP, AWS S3, Azure blob, Google Cloud, etc
3. Store a log of actions alongside the tar.gz file.

#### Evidence

- Same as Captured Evidence plus:
- All running processes - ps, top, pstree etc - multiple views.
- If possible the /proc/[pid]/map data from each process
- All network connections - lsof and ss
- Volatile data should be first
- Provide an option for a full disk image - using dd and a 32kb blocksize, with the final results gziped or otherwise compressed

(anything else?)





