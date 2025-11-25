# Interacting with the Velociraptor API from Jupyter Notebooks: Guide and Reference

## Introduction

Integrating Jupyter Notebooks with the Velociraptor API enables powerful, interactive automation for digital forensics, incident response (DFIR), and threat hunting tasks. This workflow allows analysts to programmatically schedule collections, monitor flow completion, and analyze results directly from a Jupyter environment, supporting rapid investigation and broader automation within security operations.

## Prerequisites

- **Velociraptor server** set up and API enabled ([API docs][1])
- **Python 3** and [Jupyter Notebook](https://jupyter.org/)
- **pyvelociraptor** Python package for interacting with the Velociraptor API
- **API client configuration** (YAML) with a properly issued client certificate

## 1. Setting Up the Jupyter Notebook Environment

### Install Required Packages

Install pyvelociraptor in your notebook environment:

```python
!pip install pyvelociraptor
```

Ensure Jupyter can access your `api_client.yaml` configuration file with your client certificate, and you know your Velociraptor API endpoint (e.g., `api_connection_string: your.server:8001`).

### Example: Import Modules and Load API Config

```python
from pyvelociraptor.api import APIClient

API_CONFIG = "api_client.yaml"  # Path to your client YAML
client = APIClient(config=API_CONFIG)
```

## 2. Launching Hunts/Flows from Jupyter

Scheduling artifact collections or hunts ("flows") is achieved by running VQL queries. In notebooks, this can be fully scripted.

### Example: Launch a Hunt/Flow

```python
client_id = "C.abcdef0123456789"
artifacts = ["Generic.Client.Info"]
flow = client.collect_client(client_id=client_id, artifacts=artifacts)
print("Launched flow with ID:", flow.flow_id)
```

This starts a collection (asynchronously) and returns a flow ID to monitor.

### Monitor Flow Completion

Wait for flow completion using a VQL query:

```python
flow_id = flow.flow_id
results = client.query(f"LET _ <= SELECT * FROM watch_monitoring(artifact='System.Flow.Completion')"
                      f" WHERE FlowId = '{flow_id}' LIMIT 1")
print("Flow completed:", results)
```

### Retrieve Collection Results

Once the flow is complete, fetch the output with:

```python
# Replace the artifact/source as needed. Example shown: Generic.Client.Info/BasicInformation
results = client.query(f"SELECT * FROM source(client_id='{client_id}',"
                      f" flow_id='{flow_id}',"
                      f" artifact='Generic.Client.Info/BasicInformation')")

for row in results:
    print(row)
```

## 3. Accelerating Incident Response and Threat Hunting

Leveraging Jupyter Notebooks with the Velociraptor API enables:

- **Rapid automation:** Schedule multiple collections across targets in one notebook cell and process all outputs programmatically.
- **Interactive analysis:** Results can be visualized, filtered, and correlated live using Python libraries, supporting advanced DFIR workflows.
- **Repeatable, documented playbooks:** Store and share actionable workflows as code and narrative combined.
- **Integration with data science:** Use tools like pandas, matplotlib, and NumPy for post-processing, enrichment, and visualization of results.

### Example Scenario

Suppose a suspicious process is detected on one endpoint. Using Jupyter + Velociraptor, an analyst can:

- Launch artifact collections across the environment targeting similar behaviors
- Aggregate and analyze live results in Python
- Escalate findings or trigger remediation actions from the notebook

## 4. Connecting to an Agentic AI System for Automation

To fully automate this workflow using agentic AI (such as a custom orchestration platform or an LLM-based agent):

1. **Wrap the collection and monitoring logic in Python functions**
2. **Expose hooks (APIs/functions) for the AI agent to trigger collections, process results, and execute remediation**
3. **Integrate Jupyter with agentic orchestration using libraries like [LangChain](https://docs.langchain.com/) or custom logic**

### Example: Function Interface

```python
def schedule_and_wait_for_collection(client_id, artifact_name):
    flow = client.collect_client(client_id=client_id, artifacts=[artifact_name])
    flow_id = flow.flow_id
    client.query(f"LET _ <= SELECT * FROM watch_monitoring(artifact='System.Flow.Completion')"
                f" WHERE FlowId = '{flow_id}' LIMIT 1")
    results = client.query(f"SELECT * FROM source(client_id='{client_id}',"
                          f" flow_id='{flow_id}',"
                          f" artifact='{artifact_name}/BasicInformation')")
    return list(results)
```

An AI agent (or workflow engine) can call this function to orchestrate dynamic DFIR collections, data analysis, and even response—fully automated and auditable within a notebook environment.

## References

- [Velociraptor API Documentation][1]

[1]: https://docs.velociraptor.app/docs/server_automation/server_api/
