# Shuffle SOAR - Malware Incident Response Workflow

> This document provides a detailed overview of the Automated Incident Response Workflow for Malware alerts on the **Shuffle SOAR** platform. This guide will help you build the workflow from scratch.

---

## Workflow Overview

This workflow is designed to automatically ingest malware detection alerts from security monitoring systems (such as SIEM or EDR) via a Webhook. The system then automatically extracts data, creates an incident management alert, enriches threat intelligence data, isolates the infected machine, and notifies the SOC team.

---

## Detailed Steps (Nodes) in the Workflow

The automated process includes the following components, configured in a logical sequence:

| Step | Node Name | App | Functional Description |
| :--- | :--- | :--- | :--- |
| **1** | `repeat_back_to_me` | **Shuffle Tools** | The starting point (Webhook). Receives the JSON payload from the detection system, containing critical data: `file_name`, `host_ip`, `file_hash_sha256`, `risk_score`... |
| **2** | `String_Modifier` | **Shuffle Tools** | Sanitizes and formats strings using Regex. Particularly useful for filtering and keeping only the IPv4 address format from network data fields, making the alert display cleaner. |
| **3** | `post_create_alert` | **TheHive** | Automatically creates an Alert in TheHive with the title `Malware Detection: <file_name>`. Attaches ML probability, hash, risk score, and automatically assigns tags. |
| **4** | `VT_Tools` | **Shuffle Tools** | Executes a Python script to query the VirusTotal and Hybrid Analysis APIs. Evaluates domains, maps behaviors to the MITRE ATT&CK framework, and generates a Markdown report. |
| **5** | `post_run_analyzer` | **Cortex** | Triggers Cortex to run specific Analyzers based on the hash (configured at TLP: 2 / Amber) to gather additional Threat Intel data. |
| **6** | `POST` | **HTTP** | Pushes the analysis results and hash data to an external database or endpoint, tagging the data as `shuffle-enriched`. |
| **7** | `Isolate_Machine` | **HTTP (PATCH)** | Automated containment action. Sends an API command to the EDR or Network Controller to isolate the infected machine (`host_ip`) from the network. |
| **8** | `email_3` | **Email** | Sends an emergency email to the security administration team, attaching incident details and a direct link to investigate the alert in TheHive. |

---

## How to Build the Workflow from Scratch

To set up this process on your system, follow these steps:

### 1. Initialize the Workflow
Log into the **Shuffle** web interface, navigate to the **Workflows** section, and click **New Workflow**. Give your workflow a memorable name.

### 2. Setup the Trigger
* Look at the **Apps** toolbar in the bottom left corner and drag the **Triggers** app into the workspace.
* Select the Trigger type as **Webhook** to act as the data input point.

### 3. Drag and Drop Apps (Nodes)
Search and drag the following apps from the left menu onto the screen:
* **Shuffle Tools** (Needs 2 nodes: 1 for String Modifier, 1 for Python code).
* **TheHive**
* **Cortex**
* **HTTP** (Needs 2 nodes: 1 for POST, 1 for PATCH).
* **Email**

### 4. Connect and Transfer Data
* Drag a connection line from the output of one node to the input of the next node in the exact order shown in the table above.
* Click on each node to select the corresponding **Action**.
* Use Execution Variables from the Webhook to fill in the data fields. 
  * *Example:* Use the variable `$exec.host_ip` to pass the IP address to the isolation node, or `$exec.file_hash_sha256` into the Cortex node.

### 5. Configure Authentication
> **Important Note:** You must configure the App Authentication section for TheHive, Cortex, and Email nodes. 

Enter the exact Base URL, API Keys, or Bearer Tokens of your current lab system into the corresponding fields so the services can communicate with each other.

### 6. Save and Test
Click the **Save** button in the top corner. Activate the Webhook (Start button) and send a sample payload (Test Alert) from your monitoring system to ensure data flows smoothly across all nodes.
