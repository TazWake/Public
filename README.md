# DFIR Tools Repository

A collection of Digital Forensics and Incident Response (DFIR) tools, scripts, notes, and containerised lab environments for cybersecurity professionals and researchers. All tools are for **defensive security and legitimate forensic analysis only**.

Most top-level directories have their own `README.md` with full details — this file is a map, not a manifest.

## Repository Structure

### Tooling by language

| Directory | Contents |
|---|---|
| **[Bash/](Bash/README.md)** | Production shell scripts: evidence collection, memory/process artifact recovery, filesystem carving (ext4/xfs/btrfs/LVM), malware triage, log/timeline processing, plus `lab_ctf_generators/` and educational `rootkits/`. See its README for the full script index. |
| **[Python/](Python/README.md)** | Forensic utilities — EXIF/metadata extraction, ELF/XFS parsing, process checking, VirusTotal hash lookups, login-data parsing. |
| **[Powershell/](Powershell/README.md)** | Windows-specific collection and auditing scripts (KAPE/MRC-based collection, logging/audit policy config, botnet checks, PPTX helpers). |
| **[Applications/](Applications/README.md)** | Compiled tools — `malreview` in both C (`malreview.c`) and Go (`malreview.go`). |
| **[Lisp/](Lisp/README.md)** | Standalone Common Lisp (SBCL) DFIR utilities: kernel symbol table triage, process-map injection detection, ELF section entropy profiling. |

### Memory analysis (Volatility)

- **`Vol2.6/`** — Volatility 2.6 plugins (deprecated but functional): `ramscan`, `triagecheck`, `cmdcheck`, `Fastvadscan`, `pathcheck`.
- **`Vol3/`** — Volatility 3 plugin: `fasttriage`.

### Lab & testing environments

- **[docker/](docker/README.md)** — Containerised environments: ELK/OpenSearch log analysis, malware/maldoc analysis, a vulnerable web app, and nmap scanning labs. See its README for per-environment ports and compose commands.
- **`Range/`** — Multi-container attack range (Kali, nmap scanner, Ubuntu target) on an isolated `10.10.10.0/24` network.
- **[EvidenceGenerator/](EvidenceGenerator/README.md)** — Synthetic evidence/log generation for training and testing.
- **[JupyterNotebooks/](JupyterNotebooks/README.md)** — Interactive notebooks for web-log review, evidence overview, and user analytics; a `velociraptor/` guide; a `Testing/` scratch area.

### Reference & planning

- **`plaso/`** — log2timeline/plaso filter files for Linux timelines.
- **`dfir_collection.md`** — Vendor-neutral guidance on RAM/disk collection tooling and process.
- **[Examples/](Examples/README.md)** — Sample data (e.g. Potato privilege-escalation technique writeup).
- **`SOAR_Ideas/`** — Reference architecture notes (e.g. Node-RED as a lightweight SOAR for Linux IR).
- **`Triage_tooling/`** — Working notes/plans for a cross-language (Bash/Python/compiled) triage tool.

### Agent & repo guidance

- **`CLAUDE.md`** / **`AGENTS.md`** — Instructions for AI coding agents working in this repo (environment notes, coding conventions, safety rules).

## Quick Start

### Docker environments

```bash
cd docker/Analysis_ELK && docker-compose up -d        # Kibana: http://localhost:8889
cd docker/Analysis_OpenSearch && docker-compose up -d  # Dashboards: http://localhost:8899
cd docker/MalwareAnalyzer && docker-compose up -d
cd docker/testingweb && docker-compose up -d           # http://localhost:9999
cd Range && docker-compose up -d
```

### Memory & process analysis

```bash
./Bash/memory_precook.sh memory.img Win7SP1x64
python vol.py -p Vol3 -f memory.img windows.fasttriage
sudo ./Bash/proc_recovery.sh -p 1234 -d /evidence/proc_1234 -j -J
```

### Evidence collection

```bash
sudo ./Bash/evidence_collector.sh /mnt/evidence   # Linux
.\Powershell\collectEvidence.ps1                  # Windows
```

### Building applications

```bash
g++ -std=c++17 -o malreview Applications/malreview.c -lstdc++fs
go build -o malreview Applications/malreview.go
cd Bash/rootkits/ && make all   # Kernel module (requires kernel headers)
```

## Prerequisites & Dependencies

- **Docker & Docker Compose** for containerised environments
- **Python 3.x** for Python utilities and Volatility plugins
- **Bash/WSL2** for shell script execution on Windows
- **Volatility** (`vol.py` in PATH) with appropriate memory profiles for memory analysis
- **The Sleuth Kit (TSK)**, **LiME**, **ewfacquire**/`dd` for evidence collection and disk/filesystem work
- **C++17 compiler**, **Go 1.16+**, and **kernel headers** for building the compiled tools/kernel modules
- **SBCL** for the Lisp tools
- ELK containers expect logs in `/cases/logstore` (create it before starting them)

Individual scripts and subfolder READMEs note any additional dependencies.

## Important Notes

- All tools are for **defensive security and legitimate forensic analysis**; educational components (`Bash/rootkits/`) are for isolated lab use only and must never be deployed on production systems.
- Evidence-handling scripts follow RFC3227 guidance: integrity verification (hashing), action logging, and chain-of-custody documentation.
- Always verify checksums of collected evidence and review a script's header/help output (`-h`/`--help`) before running it against a case.

## License

See [LICENSE](LICENSE) for details.

## Contributing

Contributions should follow existing code style, include documentation (usage in script headers/help output), use descriptive names, and add appropriate error handling and logging.
