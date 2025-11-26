# Node-RED as Lightweight SOAR for Linux Incident Response

**Status**: Initial Reference Architecture (v0.1)

---

## 1. Purpose and Scope

This document describes a reference architecture for using **Node-RED** as a **free, lightweight SOAR platform** to orchestrate and automate **Linux-focused Incident Response (IR)** and Security Operations.

It assumes:

- You are an experienced cybersecurity / IR practitioner.
- You are comfortable with Linux, containers, SIEMs, and common IR tools.
- You have **never** used SOAR or Node-RED before.

The goal is **not** to replicate a full commercial SOAR, but to:

- Provide a **low-friction automation layer** for Linux IR.
- Orchestrate your **existing tooling** (CLI tools, APIs, SIEM, chat, ticketing).
- Provide a **visual, inspectable playbook engine** suitable for labs, small environments, and consultancy use.

---

## 2. Conceptual Overview

### 2.1 What Node-RED Gives You

Node-RED is a **flow-based automation engine** built on Node.js. You create automation by dragging nodes onto a canvas and wiring them together. Each flow corresponds roughly to a **playbook**.

For our purposes, Node-RED acts as:

- A **SOAR-lite orchestration layer**:
  - Ingest alerts (webhooks, polling, message queues).
  - Enrich with external and internal context (REST APIs, databases, CLI tools).
  - Trigger actions (tickets, notifications, containment scripts).
- A **visual playbook editor**:
  - Playbooks are JSON-backed “flows”.
  - Easy to demonstrate and review in IR training and tabletop exercises.

### 2.2 What You Will Build Around It

To turn Node-RED into a SOAR-like platform, you will add:

- **Inbound connectors** from SIEM, EDR, log pipelines, email, and human triggers.
- **Outbound actions** to ticketing systems, chat, firewalls, Linux hosts, cloud APIs.
- **Automation logic** for triage, enrichment, containment, and evidence handling.

Node-RED orchestrates these components; it does **not** replace them.

---

## 3. High-Level Architecture

### 3.1 Core Components

- **Node-RED SOAR Node**
  - Hardened Linux host or container running Node-RED.
  - Stores flows, credentials (via environment variables or a secret store), and configuration.

- **Security Data Sources**
  - SIEM / logging stack (Elastic, Security Onion, Wazuh, Zeek).
  - Linux host logs and telemetry.
  - EDR or endpoint monitoring where available.

- **Action Targets**
  - Ticketing / case management systems (TheHive, Jira, etc.).
  - Chat and alerting platforms.
  - Firewalls, Linux gateways, cloud APIs for containment.
  - An IR jump box with your triage tools installed.

- **Analyst Interface**
  - Node-RED editor for playbook development.
  - Optional dashboards for buttons and status views.
  - SIEM and case management remain primary investigation tools.

### 3.2 Conceptual Data Flow

1. SIEM or tool emits an alert.  
2. Node-RED ingests it.  
3. Node-RED enriches the alert using external/internal sources.  
4. Node-RED applies logic/conditions.  
5. Node-RED triggers actions (ticket, notification, containment, triage).  

---

## 4. Deployment Topologies

### 4.1 Lab / Training Deployment

- Single VM or container running Node-RED.
- Ideal for DFIR training, demos, or proof-of-concept.
- Quick rebuilds, minimal risk.

### 4.2 Small Production Deployment

- Single hardened VM with Node-RED.
- TLS termination via nginx or Traefik.
- Integrated with SIEM, ticketing, and chat.
- Good for small SOC/IR teams.

---

## 5. Prerequisites

### 5.1 Technical Requirements

- Comfortable with Linux and containers.
- Familiar with JSON, HTTP APIs, and basic scripting.
- Access to:
  - SIEM or logging stack.
  - Ticketing system.
  - Chat/notification platform.
  - IR utilities.

### 5.2 Host Requirements

- 2 vCPU, 2–4 GB RAM, 20 GB disk.
- Modern Linux distribution (Ubuntu, Debian, RHEL, Rocky).
- Restricted network access (management zone only).

---

## 6. Step-by-Step: Deploying Node-RED

### 6.1 Recommended Approach

Install Node-RED as a **container** on a dedicated platform/VM.

### 6.2 Install Using Docker

```bash
sudo mkdir -p /opt/nodered-data
sudo chown 1000:1000 /opt/nodered-data

docker run -d   --name nodered-soar   -p 1880:1880   -v /opt/nodered-data:/data   --restart unless-stopped   nodered/node-red
```

Access it at:

```text
http://<server-ip>:1880
```

### 6.3 Hardening (Essential)

- Put Node-RED **behind HTTPS** (nginx or Traefik).
- Enable **adminAuth** in `settings.js`.
- Restrict access via firewall or security groups.
- Back up `/opt/nodered-data`.
- Log all deployments and flow changes.

---

## 7. Core Integrations

### 7.1 SIEM / Alert Ingestion

1. Decide on ingest method:
   - Webhooks (ideal).
   - API polling.
   - Message queues.

2. In Node-RED:
   - Use **HTTP In** or **HTTP Request** nodes.
   - Parse alert JSON into a **normalised schema**:
     - `alert.host`
     - `alert.user`
     - `alert.ip`
     - `alert.rule`
     - `alert.severity`

### 7.2 Ticketing / Case Management

- Use **HTTP Request** nodes to open or update cases.
- Wrap in subflows such as:
  - `createIncident`
  - `updateIncident`
- Include all enriched context.

### 7.3 Chat / Notification

Integrate Rocket.Chat, Slack, Teams, or email.

Subflow example:

- `notifySOC`: sends a formatted alert and case link.

### 7.4 Linux IR Tooling (SSH / Exec)

1. Decide execution location:
   - IR jump box (preferred).
   - Node-RED host (lab only).

2. Use:
   - SSH nodes (remote execution).
   - Exec nodes (local).

3. Standards:
   - Output JSON for easier parsing.
   - Store triage output in the SIEM or ticket system.

---

## 8. Example Playbooks

### 8.1 Playbook 1: Alert Enrichment

**Flow:**

1. Receive alert.  
2. Normalise fields.  
3. Enrich (asset database, threat intelligence).  
4. Switch node decides severity.  
5. Create or update ticket.  
6. Notify SOC.

**Outcome:**  
A raw alert becomes a contextualised incident.

---

### 8.2 Playbook 2: Linux Triage Orchestration

**Trigger:** Analyst clicks a dashboard button or a webhook fires.

**Actions:**

- SSH/Exec triage pack:
  - Process listing.  
  - Network activity.  
  - Persistence mechanisms.  
  - Recent authentication events.  
- Store output in Elastic.
- Attach summary to incident.

---

### 8.3 Playbook 3: Conditional Containment

**Flow:**

1. High-confidence alert triggers flow.  
2. Pre-check and enrichment.  
3. Chat message sent requesting approval.  
4. Analyst clicks approval link calling a Node-RED endpoint.  
5. Node-RED:
   - Blocks IP on firewall,  
   - Disables user,  
   - Or isolates host.  
6. Case updated.

---

## 9. Flow Design Principles

### 9.1 Treat Flows as Code

- Export flows to version control.
- Use naming conventions.
- Use subflows to avoid duplication.

### 9.2 Separation of Concerns

- Trigger flows.  
- Worker flows.  
- Utility subflows.  

### 9.3 Safety and Idempotence

- Ensure re-running a flow will not create duplicates.
- State tracking for containment actions.
- Avoid destructive operations without human approval.

---

## 10. Security and Governance

### 10.1 Node-RED is a High-Value Target

A compromise provides:

- Access to all automation.
- Access to credentials.
- Ability to run commands on hosts.

### 10.2 Required Controls

- TLS and reverse proxy.
- Strong adminAuth and IP restriction.
- Audit of all flow edits and deployments.
- Centralised logging.
- Use secrets via environment variables or Docker secrets.

---

## 11. Roadmap and Next Steps

1. Implement the three core playbooks:
   - Alert enrichment.  
   - Triage orchestration.  
   - Conditional containment.  

2. Standardise your Linux IR tools:
   - JSON output.  
   - Consistent CLI interface.  
   - Documented behaviours.  

3. Create analyst user guides:
   - “How to trigger triage for a host”.  
   - “Where to find enriched alerts”.  
   - “Interpreting containment decisions”.  

4. Expand into:
   - Windows flows.  
   - Cloud flows.  
   - Network device automation.  
   - API-driven evidence collection.  

