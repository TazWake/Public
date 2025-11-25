# Jupyter Notebooks for DFIR Analysis

This directory contains interactive Jupyter notebooks for digital forensics and incident response (DFIR) analysis. These notebooks provide visual, interactive workflows for analyzing various types of forensic evidence.

## Overview

The notebooks are designed to be run in JupyterLab or Jupyter Notebook environments and provide reproducible analysis workflows for common DFIR tasks. Each notebook combines data processing, statistical analysis, and visualization to help incident responders quickly identify suspicious activity and understand system behavior.

## Available Notebooks

### 1. WebServer_review.ipynb
**Purpose**: Comprehensive web server log analysis for Apache/Nginx access logs

**Features**:
- Parses Common and Combined Log Format
- Top 10 most frequent IP addresses with visualizations
- HTTP method statistical analysis (valid vs invalid)
- Detection of junk/malicious HTTP methods with source IPs
- User Agent analysis and categorization
- Suspicious User Agent detection (scanning tools)
- Export findings to CSV for further investigation

**Use Cases**:
- Web application attack investigation
- Identifying reconnaissance/scanning activity
- Bot detection and classification
- Traffic pattern analysis
- Security event correlation

**Requirements**:
- pandas
- matplotlib
- seaborn
- re (standard library)

**Input**: Apache/Nginx access logs
```
# Common Log Format
127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326

# Combined Log Format (includes referrer and user agent)
127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://www.example.com/start.html" "Mozilla/4.08"
```

**Outputs**:
- `invalid_http_methods.csv` - Invalid methods with source IPs
- `suspicious_user_agents.csv` - Potentially malicious User Agents
- `top_user_agents.csv` - Most common User Agent strings

---

### 2. Test2.ipynb (NetFlow Analysis)
**Purpose**: Network flow analysis for identifying top network talkers

**Features**:
- Processes NetFlow data files (nfcapd format)
- Identifies top 10 endpoints by traffic volume
- Aggregates multiple NetFlow files
- WSL2 integration for nfdump processing
- Traffic summarization by source IP

**Use Cases**:
- Network traffic baseline analysis
- Data exfiltration detection
- Anomalous traffic volume identification
- Internal threat detection
- Network reconnaissance

**Requirements**:
- pandas
- WSL2 with Linux distribution
- nfdump installed in WSL environment
- subprocess (standard library)

**Input**: NetFlow capture files (nfcapd format)

**Configuration**:
```python
netflow_directory = './Downloads/netflow/'  # Update to your NetFlow directory
```

**Setup**:
```bash
# Install nfdump in WSL2
wsl
sudo apt-get update
sudo apt-get install nfdump
```

---

### 3. evidence_processing/user_analytics.ipynb
**Purpose**: Linux user behavior and session analysis from forensic logs

**Features**:
- User login timeline analysis from wtmp logs
- Source IP frequency tracking
- SUDO/SU privilege escalation detection
- Shell history analysis (bash/zsh)
- Command frequency statistics
- Temporal analysis (command usage by hour)
- Failed login attempt tracking (btmp)

**Use Cases**:
- Insider threat investigation
- Unauthorized access detection
- Privilege escalation analysis
- User behavior profiling
- Account compromise investigation

**Requirements**:
- pandas
- matplotlib
- seaborn
- re (standard library)
- subprocess (for parsing wtmp/btmp)

**Input Files**:
- `/var/log/audit/audit.log` - Audit daemon logs
- `~/.bash_history` - Bash command history
- `~/.zsh_history` - Zsh command history
- `/var/log/wtmp` - Login records
- `/var/log/btmp` - Failed login attempts
- `/var/log/auth.log` or `/var/log/secure` - Authentication logs

**Key Visualizations**:
- User login timeline histogram
- Top source IPs for login attempts
- Command frequency bar chart
- Command usage by hour of day

---

### 4. velociraptor/ - Velociraptor API Integration
**Purpose**: Programmatic endpoint interrogation and automated DFIR workflows

The `velociraptor/` directory enables API-driven interaction with Velociraptor for scalable artifact collection, threat hunting, and incident response automation.

**Directory Contents**:
- `jupyter_guide.md` - Complete setup guide for Velociraptor API integration
- `updates.md` - Suggested enhancements and future improvements
- (Planned) Interactive notebooks for hunt orchestration, triage automation, and AI integration

**Key Features**:
- Automated artifact collection across thousands of endpoints
- Flow monitoring and result retrieval via Python
- VQL query execution from Jupyter environment
- Integration-ready for agentic AI systems

**Quick Start**:
```bash
pip install pyvelociraptor
# See velociraptor/jupyter_guide.md for server configuration
```

**Use Cases**: Rapid IR, threat hunting, compliance monitoring, autonomous investigation

**Documentation**: See `velociraptor/jupyter_guide.md` for comprehensive setup instructions and [Velociraptor API docs](https://docs.velociraptor.app/docs/server_automation/server_api/)

---

## Installation and Setup

### Prerequisites

1. **Python 3.8+** with Jupyter installed:
```bash
pip install jupyter jupyterlab
```

2. **Required Python packages**:
```bash
pip install pandas matplotlib seaborn

# For Velociraptor API integration
pip install pyvelociraptor
```

3. **WSL2 Setup** (for NetFlow analysis):
```bash
# Enable WSL2 on Windows
wsl --install

# Inside WSL, install nfdump
sudo apt-get update
sudo apt-get install nfdump
```

### Quick Start

1. **Launch Jupyter**:
```bash
# From the JupyterNotebooks directory
cd D:\Development\Public\JupyterNotebooks
jupyter notebook

# Or use JupyterLab for a better experience
jupyter lab
```

2. **Open a notebook** and update configuration cells with your evidence paths

3. **Run all cells** or step through the analysis sequentially

4. **Review visualizations** and exported CSV files for findings

## Usage Guidelines

### General Workflow

1. **Prepare Evidence**: Mount forensic images or copy evidence to accessible location
2. **Update Paths**: Modify notebook configuration cells to point to your evidence
3. **Execute Analysis**: Run cells sequentially or use "Run All"
4. **Interpret Results**: Review charts, tables, and statistical summaries
5. **Export Findings**: Save generated CSV files and screenshots for reporting
6. **Document**: Add markdown cells to document findings and observations

### Best Practices

- **Create Copies**: Never modify original notebooks; create working copies for investigations
- **Document Changes**: Add markdown cells explaining your analysis decisions
- **Version Control**: Save notebooks with meaningful names (e.g., `case_2025_001_webserver.ipynb`)
- **Validate Data**: Always check that log files parsed correctly before drawing conclusions
- **Cross-Reference**: Correlate findings across multiple notebooks for comprehensive analysis
- **Export Early**: Save visualizations and CSV outputs before closing notebooks

### Evidence Handling

- **Read-Only Access**: Mount evidence in read-only mode when possible
- **Hash Verification**: Verify evidence integrity before analysis
- **Chain of Custody**: Document evidence sources in notebook markdown cells
- **Timestamping**: Record analysis timestamps in notebook
- **Backup Results**: Save notebook outputs and exported files to case directory

## Integration with DFIR Toolkit

### Evidence Collection Scripts
The notebooks complement collection scripts in the repository:

```bash
# Linux evidence collection
sudo D:\Development\Public\Bash\evidence_collector.sh /mnt/evidence

# Memory analysis preprocessing
D:\Development\Public\Bash\memory_precook.sh memory.img PROFILE

# Docker evidence collection
D:\Development\Public\Bash\docker_triage.sh
```

### Velociraptor Integration
Programmatic endpoint interrogation via API for automated evidence collection at scale. See `velociraptor/jupyter_guide.md` for complete documentation.

### ELK Stack Integration
For large-scale log analysis, use the ELK Docker environment:

```bash
cd D:\Development\Public\docker\Analysis_ELK
docker-compose up -d

# Copy logs to /cases/logstore
# Access Kibana at http://localhost:8889
```

Use notebooks for targeted analysis of specific log files, then upload aggregated data to ELK for broader correlation.

### Timeline Analysis
Combine notebook outputs with plaso/log2timeline:

```bash
# Generate timeline
log2timeline.py timeline.plaso /mnt/evidence

# Filter using plaso configs
psort.py -z UTC --analysis-file D:\Development\Public\plaso\filter_linux.yaml \
  timeline.plaso -o dynamic -w timeline.csv
```

Import `timeline.csv` into pandas for visualization in custom notebooks.

## Creating Custom Notebooks

### Template Structure

```python
# Cell 1: Imports and Setup
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Cell 2: Configuration
EVIDENCE_PATH = '/path/to/evidence'

# Cell 3: Data Loading
def load_evidence(path):
    # Implementation
    pass

# Cell 4: Analysis
df = load_evidence(EVIDENCE_PATH)
# Analysis code

# Cell 5: Visualization
plt.figure(figsize=(12, 6))
# Plotting code
plt.show()

# Cell 6: Export
df.to_csv('findings.csv', index=False)
```

### Recommended Sections

1. **Header**: Markdown cell with notebook purpose and requirements
2. **Setup**: Imports and configuration
3. **Data Loading**: Evidence parsing and DataFrame creation
4. **Validation**: Data quality checks and statistics
5. **Analysis**: Core analytical code with comments
6. **Visualization**: Charts and graphs
7. **Summary**: Key findings and statistics
8. **Export**: Save results to CSV/JSON

## Troubleshooting

### Common Issues

#### WSL Path Conversion Errors
```python
# Use wslpath for path conversion
import subprocess
def convert_path_to_wsl(windows_path):
    return subprocess.check_output(['wsl', 'wslpath', '-a', windows_path]).decode('utf-8').strip()
```

#### Missing Dependencies
```bash
# Install all common packages
pip install pandas matplotlib seaborn jupyter ipython
```

#### Large File Performance
```python
# Read files in chunks for large logs
chunk_size = 100000
for chunk in pd.read_csv('large_file.log', chunksize=chunk_size):
    # Process chunk
    pass
```

#### Memory Errors
```python
# Reduce memory usage by specifying dtypes
df = pd.read_csv('file.csv', dtype={'column': 'category'})

# Or use dask for out-of-core processing
import dask.dataframe as dd
df = dd.read_csv('large_file.csv')
```

#### Encoding Issues
```python
# Handle various encodings
with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
    data = f.read()
```

### Windows-Specific Considerations

- **Path Separators**: Use raw strings `r'D:\path\to\file'` or forward slashes `'D:/path/to/file'`
- **WSL Integration**: NetFlow notebook requires WSL2 for nfdump
- **Permissions**: Run Jupyter as administrator if accessing system logs
- **Line Endings**: Be aware of CRLF vs LF when processing cross-platform logs

## Performance Tips

### Optimize Pandas Operations

```python
# Use vectorized operations instead of loops
df['new_col'] = df['col1'] + df['col2']  # Good
df['new_col'] = df.apply(lambda x: x['col1'] + x['col2'], axis=1)  # Slower

# Filter efficiently
filtered = df[df['status'] == 200]  # Good
filtered = df.query('status == 200')  # Also good for complex queries

# Use categories for repeated strings
df['method'] = df['method'].astype('category')
```

### Visualization Performance

```python
# Limit data points for scatter plots
df.sample(10000).plot.scatter(x='x', y='y')

# Use aggregation for large datasets
df.groupby('hour')['count'].sum().plot()
```

## Security Considerations

### Sensitive Data

- **Redaction**: Remove PII before sharing notebooks
- **API Keys**: Never hardcode credentials; use environment variables
- **IP Addresses**: Consider anonymizing internal IPs in exported results
- **User Data**: Sanitize usernames and commands in shared outputs

### Notebook Security

```python
# Use environment variables for sensitive config
import os
API_KEY = os.getenv('FORENSICS_API_KEY')
EVIDENCE_PATH = os.getenv('CASE_EVIDENCE_PATH')
```

## Contributing

When adding new notebooks to this directory:

1. **Include Documentation**: Add markdown cells explaining purpose and methodology
2. **Parameterize Paths**: Use configuration cells for all file paths
3. **Error Handling**: Include try/except blocks for robust execution
4. **Requirements**: List all dependencies in a markdown cell
5. **Examples**: Provide sample data or clear instructions on data format
6. **Update README**: Add your notebook to this README with description

## Additional Resources

### DFIR Analysis Tools
- **Velociraptor Notebooks**: `JupyterNotebooks/velociraptor/` for API-driven endpoint interrogation
- **Volatility Plugins**: `/Vol2.6` and `/Vol3` for memory analysis
- **Bash Scripts**: `/Bash` for evidence collection automation
- **Docker Labs**: `/docker` for containerized analysis environments
- **PowerShell Scripts**: `/Powershell` for Windows-specific tasks

### Related Documentation
- Main Repository: `D:\Development\Public\CLAUDE.md`
- Application Tools: `D:\Development\Public\Applications\README.md`
- Velociraptor API Guide: `JupyterNotebooks/velociraptor/jupyter_guide.md`
- ELK Stack Setup: `D:\Development\Public\docker\Analysis_ELK\README.md`

### External Resources
- [Pandas Documentation](https://pandas.pydata.org/docs/)
- [Jupyter Documentation](https://jupyter.org/documentation)
- [Velociraptor API Documentation](https://docs.velociraptor.app/docs/server_automation/server_api/)
- [Velociraptor Artifacts Reference](https://docs.velociraptor.app/artifact_references/)
- [DFIR Best Practices](https://www.sans.org/reading-room/whitepapers/incident)
- [RFC 3227 - Evidence Collection](https://tools.ietf.org/html/rfc3227)

## License

Part of the DFIR Tools Repository. For educational and authorized security testing purposes only.

---

**Note**: Always ensure you have proper authorization before analyzing systems or evidence. These notebooks are designed for legitimate forensic investigations, incident response, security research, and educational purposes only.
