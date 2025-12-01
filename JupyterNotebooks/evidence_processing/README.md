# Evidence Processing Notebooks

This directory contains Jupyter notebooks for analysing DFIR evidence, with a focus on **mounted Linux images** and log / filesystem artefacts.

- **`evidence_overview.ipynb`**: high‑level triage of a mounted Linux filesystem (logins, audit commands, executables, SUID/SGID/sticky bits).
- **`user_analytics.ipynb`**: deeper analysis of user behaviour (login history, shell history, sudo/su activity).
- **`WebServer_review.ipynb`**: HTTP / web‑server–focused analysis (log parsing, request patterns, etc.).

The guidance below is intended to make these notebooks easy to use, reproducible, and safe for evidence handling.

---

## 1. Using Jupyter notebooks for DFIR

- **Work on copies**: always mount / copy evidence read‑only and work from that copy, never from original media.
- **Keep provenance**: record the image hash, mount path and time window you use in your case notes; notebooks should complement, not replace, your formal documentation.
- **Be explicit about context**: the notebooks assume Linux‑style paths and logs; adapt paths if your triage scripts store logs elsewhere.

### Recommended workflow

1. Start Jupyter (Lab, Notebook, or your IDE’s notebook support) in the DFIR work directory.
2. Open the notebook you want (for example `evidence_overview.ipynb`).
3. Read the top markdown cell for **environment requirements** and **workflow**.
4. Configure the evidence mount and date range in the configuration cell.
5. Run cells from top to bottom so that derived variables (e.g. `login_df`, `exec_fs_df`, `special_df`) are populated for later sections and reports.

---

## 2. Environment and kernel setup

All notebooks assume a **Python 3** kernel with at least:

- `pandas`
- `matplotlib`
- `seaborn`
- a compatible `scipy` / `numpy` combination

If you see version‑mismatch errors (for example SciPy complaining about your NumPy version), upgrade SciPy **in the same environment as the notebook kernel**:

```bash
pip install --upgrade scipy
```

General tips:

- Use one dedicated **DFIR virtualenv or conda environment** for notebooks, and select that as the kernel.
- You can check which Python the kernel is using with:

```python
import sys
print(sys.executable)
```

If you are in the wrong environment, switch the notebook’s kernel/interpreter to the correct one rather than reinstalling packages randomly.

---

## 3. Investigating with `evidence_overview.ipynb`

`evidence_overview.ipynb` is designed as a quick triage pass over a **mounted Linux image**.

### Step 1: Mount the evidence

1. Mount the forensic image read‑only somewhere on your analysis host, for example:

```bash
sudo mkdir -p /mnt/evidence
sudo mount -o ro,loop image.dd /mnt/evidence
```

2. Confirm that typical Linux directories (e.g. `var/log`, `home`, `etc`) are visible under `/mnt/evidence`.

### Step 2: Configure the notebook

In the **“Evidence root and time window configuration”** cell:

- Set:

```python
EVIDENCE_ROOT = "/mnt/evidence"        # or your actual mount point
DATE_FROM = "2024-01-01 00:00:00"
DATE_TO   = "2024-01-02 23:59:59"
```

- The window is inclusive and should match the period of interest (for example, the suspected intrusion window).

Run this cell and ensure it prints the expected root and window.

### Step 3: Run each analysis block

Run the notebook cells in order:

- **User login events**: parses `auth.log` (or equivalent) to show who logged in, from where and when, with histograms and IP ranking.
- **Audit log command ranking**: if `audit.log` exists, stack‑ranks commands from `EXECVE` events and shows the **top 5** and **bottom 5** by frequency.
- **Executable files created/changed**: walks the filesystem under `EVIDENCE_ROOT` and finds executable files whose `st_mtime` or `st_ctime` falls in the window.
- **SUID/SGID/sticky bit survey**: lists files and directories with special bits set and summarises them by type and flag combination.

You can adjust the window and re‑run the analysis to focus on specific time slices (for example just after initial compromise).

### Step 4: Generate a triage report

The final code cell in `evidence_overview.ipynb` builds a **Markdown report** from the data frames populated by earlier steps and writes:

- `evidence_triage_report.md` in the same directory as the notebook.

It also renders the report inline for a quick sanity check.

You can attach this Markdown file to your case notes or commit it alongside other artefacts in version control.

---

## 4. Working with other notebooks

### `user_analytics.ipynb`

- Focuses on:
  - login/session behaviour (e.g. `wtmp`, `btmp`)
  - shell history (`.bash_history`, `.zsh_history`)
  - sudo / su usage (`auth.log`)
- Similar pattern:
  - Configure evidence root and log locations at the top.
  - Run the presence‑check cell to verify files are visible from the mount.
  - Step through each analysis section (timelines, IP distributions, command frequency, time‑of‑day behaviour).

### `WebServer_review.ipynb`

- Intended for HTTP / web log analysis:
  - pointing at access logs exported from the evidence or collected via triage.
  - summarising status codes, methods, URLs, user‑agents and IPs.
- As with other notebooks, you will need to set the **log file path(s)** at the top before running the analysis cells.

---

## 5. Exporting notebooks with `nbconvert`

Once you are happy with the notebook output, you can turn it into a static report with **nbconvert**.

### Export to HTML

From a terminal in the `JupyterNotebooks` directory:

```bash
jupyter nbconvert --to html evidence_processing/evidence_overview.ipynb
```

This produces `evidence_overview.html`, which contains the notebook text, tables and plots as a single self‑contained HTML file you can share or archive.

### Export to Markdown or PDF

Other useful formats:

```bash
# Markdown
jupyter nbconvert --to markdown evidence_processing/evidence_overview.ipynb

# PDF (requires a LaTeX stack)
jupyter nbconvert --to pdf evidence_processing/evidence_overview.ipynb
```

For Markdown export, you can combine the generated `.md` with the `evidence_triage_report.md` produced by the notebook’s final cell, or simply store both as part of your case documentation.

---

## 6. Good practice when using notebooks for DFIR

- **Record parameters**: include mount paths, case IDs and time windows in the notebook (and in the generated report) so someone else can reproduce your work.
- **Avoid modifying evidence**: keep all writes (temporary files, exported CSV/Markdown/HTML) on a separate working directory, not in the mounted evidence tree.
- **Version‑control your notebooks**: treat notebooks and generated reports as part of the case artefacts; commit changes with meaningful messages.
- **Cross‑check results**: notebooks are an aid to triage, not an oracle. Cross‑validate key findings with other tools (command line, SIEM, forensic suites) where appropriate.
