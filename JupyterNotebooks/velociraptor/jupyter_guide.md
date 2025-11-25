# Interacting with the Velociraptor API from Jupyter Notebooks: Guide and Reference

## Introduction

Integrating Jupyter Notebooks with the Velociraptor API enables powerful, interactive automation for digital forensics, incident response (DFIR), and threat hunting tasks. This workflow allows analysts to programmatically schedule collections, monitor flow completion, and analyse results directly from a Jupyter environment, supporting rapid investigation and broader automation within security operations.

## Prerequisites

- **Velociraptor server** set up and API enabled ([API docs][1])
- **Python 3** and [Jupyter Notebook](https://jupyter.org/)
- **pyvelociraptor** Python package for interacting with the Velociraptor API
- **API client configuration** (YAML) with a properly issued client certificate

## 1. Setting Up the Jupyter Notebook Environment

### Install Required Packages

Install `pyvelociraptor` in your notebook environment:

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

## 2. Configuring Velociraptor to Support the API

Velociraptor's API is exposed over a gRPC server that uses mutual certificate authentication to identify and authorise clients. Setting up the API requires configuring the server to listen on appropriate network interfaces and generating client certificates for programs that will connect to it.

### Step 1: Configure the Server to Listen on Network Interfaces
By default, the Velociraptor API server only listens on 127.0.0.1 (localhost), which restricts connections to the local machine. To allow external API clients to connect, you need to modify the server configuration file.

Edit your server.config.yaml file and locate the API section:

```text
API:
  hostname: www.example.com
  bind_address: 0.0.0.0
  bind_port: 8001
  bind_scheme: tcp
  pinned_gw_name: GRPC_GW
```

Change bind_address from 127.0.0.1 to 0.0.0.0 to bind on all interfaces. Ensure the hostname field is set to your server's DNS name or IP address, as this value is used to construct the API connection string for clients.

After making this change, restart the Velociraptor server. You should see a log message confirming the API server is listening on all interfaces:

```text
[INFO] 2021-11-07T01:57:26+10:00 Starting gRPC API server on 0.0.0.0:8001
```

### Step 2: Generate API Client Configuration with Certificate

API clients authenticate using certificates signed by the Velociraptor CA. Use the Velociraptor binary to generate an API client configuration file that includes the necessary certificate material.

Run the following command from your server:

```bash
velociraptor --config server.config.yaml config api_client --name <username> --role <role> api.config.yaml
```

**Parameters**:

- --config server.config.yaml: Loads the server configuration, which contains the CA private keys needed to sign new certificates
- --name <username>: Specifies the identity for the API client certificate (e.g., "Mike" or "jupyter_automation")
- --role <role>: Assigns roles to the user, controlling permissions. At minimum, use api role; for broader permissions, consider administrator, investigator, or custom roles
- api.config.yaml: Output filename for the generated API client configuration

**Example**:

```bash
velociraptor --config server.config.yaml config api_client --name jupyter_user --role api,investigator api_client.yaml
```

The generated api_client.yaml file contains:

- Client certificate and private key
- CA certificate for verification
- API connection string (e.g., www.example.com:8001)
- User identity name

### Step 3: Managing Roles and Permissions

For an API user to connect, they must have at least the api role. Additional roles grant specific permissions appropriate to the user's needs. The administrator role is very powerful and should be avoided for external programs; instead, use least-privilege principles.

**View user roles**:

```bash
velociraptor --config server.config.yaml acl show <username>
```

**Grant or change roles**:

```bash
velociraptor --config server.config.yaml acl grant <username> --role investigator,api
```

Note that role changes made via CLI require a server restart. Changes made through the GUI or VQL do not require restarts.

### Step 4: Certificate Validity and Security Considerations

API client certificates are valid for one year. Before expiry, generate a new API client configuration to avoid connection failures. If an API client's credentials are compromised, revoke all roles to prevent access:

```bash
velociraptor --config server.config.yaml acl grant <username> --role ""
```

The API is extremely powerful, so protect API configuration files and their embedded private keys. Consider restricting API access to trusted networks and using appropriate firewall rules.

### Step 5: Testing the API Connection

Once configured, test the API connection using the pyvelociraptor command-line tool:

```bash
pip install pyvelociraptor
pyvelociraptor --config api_client.yaml "SELECT * FROM info()"
```

This should return system information from the Velociraptor server, confirming successful API connectivity.


## 3. Launching Hunts/Flows from Jupyter

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

## 4. Accelerating Incident Response and Threat Hunting

Leveraging Jupyter Notebooks with the Velociraptor API enables:

- **Rapid automation:** Schedule multiple collections across targets in one notebook cell and process all outputs programmatically.
- **Interactive analysis:** Results can be visualised, filtered, and correlated live using Python libraries, supporting advanced DFIR workflows.
- **Repeatable, documented playbooks:** Store and share actionable workflows as code and narrative combined.
- **Integration with data science:** Use tools like pandas, matplotlib, and NumPy for post-processing, enrichment, and visualisation of results.

### Example Scenario

Suppose a suspicious process is detected on one endpoint. Using Jupyter + Velociraptor, an analyst can:

- Launch artifact collections across the environment targeting similar behaviours
- Aggregate and analyze live results in Python
- Escalate findings or trigger remediation actions from the notebook

## 5. Connecting to an Agentic AI System for Automation

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
