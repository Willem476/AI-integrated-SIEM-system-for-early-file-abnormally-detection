
---

# Shuffle SOAR - Malware Incident Response Workflow

> This document provides a detailed guide on the configuration and how to build from scratch an Automated Incident Response Workflow for Malware alerts on the Shuffle SOAR platform.

---

## Workflow Overview

This workflow is designed to automatically ingest malware detection alerts from security monitoring systems (e.g., SIEM or EDR) via a Webhook. The workflow will then automatically:

1. **Extract and sanitize data** (specifically filtering for IPv4 addresses).
2. **Create an incident alert** on the incident management system (TheHive).
3. **Enrich threat intelligence data** via VirusTotal, Hybrid Analysis, and Cortex.
4. **Automate containment** by issuing a command to isolate the infected machine.
5. **Send an emergency email notification** to the security operations team.

---

## Step-by-Step Node Configurations

Below are the detailed configurations for each Node in Shuffle. You can use these parameters to accurately set up your data flow.

### 1. Data Reception (Webhook Trigger)

* **Node Name:** `repeat_back_to_me`
* **App:** Shuffle Tools | **Action:** Repeat back to me
* **Description:** The data input point. Receives the JSON payload containing critical fields such as file name, IP, hash, and risk score.
* **Configuration:**
* `call`: `$exec`



### 2. String Sanitization & IP Extraction (String Manipulation)

* **Node Name:** `String_Modifier` & `regex_tool`
* **App:** Shuffle Tools | **Action:** Regex replace / Regex capture group
* **Description:** Formats the file path and extracts network data. The Regex expression is configured to **strictly retain only the IPv4 address format**, completely filtering out IPv6 ranges or extraneous characters. This ensures the output alerts are precise and clean.
* **IP Regex Configuration:**
* `input_data`: `$exec.host_ip`
* `regex`: `\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`



### 3. Create Alert on TheHive (`post_create_alert`)

* **App:** TheHive | **Action:** Create Alert
* **Body Configuration (JSON):**

```json
{
  "title": "Malware Detection: $exec.file_name",
  "description": "Host: $exec.agent_name | Path: $string_modifier",
  "severity": $exec.severity,
  "source": "Shuffle-SOAR",
  "type": "Malware",
  "summary": "Malware detected: $exec.file_name \n- Host: $exec.agent_name \n- Type:  $exec.alert_type \n- ML Prob:  $exec.ml_probability \n- Hash: $exec.file_hash_sha256 \n- Risk Score: $exec.risk_score ($exec.risk_level)",
  "tags": ["Shuffle", "Malware", "$exec.risk_level"],
  "sourceRef": "$exec.alert_id"
}

```

### 4. Threat Intelligence Enrichment (`VT_Tools`)

* **App:** Shuffle Tools | **Action:** Execute Python
* **Description:** Executes a Python script to call APIs for malicious hash evaluation and generates a standard Markdown report.
* **Python Code Configuration (API Keys Redacted):**

```python
import requests
import json
import re

VT_API_KEY = "<YOUR_VIRUSTOTAL_API_KEY>"
HA_API_KEY = "<YOUR_HYBRID_ANALYSIS_API_KEY>"
raw_hash = "$exec.file_hash_sha256"

def clean_hash(raw_input):
    return re.sub(r'[^a-fA-F0-9]', '', raw_input)

def get_vt_data(url, headers):
    try:
        res = requests.get(url, headers=headers, timeout=15)
        return res.json() if res.status_code == 200 else None
    except: return None

def get_ha_report(file_hash, ha_key):
    url = "https://www.hybrid-analysis.com/api/v2/search/hash"
    headers = {
        "api-key": ha_key,
        "user-agent": "Falcon Sandbox",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    try:
        res = requests.post(url, headers=headers, data={"hash": file_hash}, timeout=15)
        if res.status_code == 200:
            data = res.json()
            return data[0] if data else None
        return None
    except: return None

def evaluate_trust(item, category):
    item = str(item).lower()
    trusted = ['microsoft', 'windows', 'bing', 'msn', 'google', 'pki.goog', 'akamai', 'digicert', 'apple']
    if category == "domain":
        for t in trusted:
            if t in item: return "TRUSTED"
        return "UNKNOWN"
    if category == "command":
        suspicious = ["powershell", "-enc", "vssadmin", "temp", "cmd /c", "bypass", "net user", "reg add"]
        for s in suspicious:
            if s in item: return "SUSPICIOUS"
        return "NORMAL"
    return "INFO"

file_id = clean_hash(raw_hash)
if not file_id or len(file_id) < 32:
    print("Invalid Hash.")
else:
    vt_headers = {"x-apikey": VT_API_KEY}
    vt_info = get_vt_data(f"https://www.virustotal.com/api/v3/files/{file_id}", vt_headers)
    vt_beh = get_vt_data(f"https://www.virustotal.com/api/v3/files/{file_id}/behaviours", vt_headers)
    ha_info = get_ha_report(file_id, HA_API_KEY)

    md = f"## THREAT INTEL REPORT\n"
    md += f"**Hash:** `{file_id}`\n\n---\n\n"
    
    md += "### 1. Verdicts\n\n"
    vt_verdict = "N/A"
    if vt_info and 'data' in vt_info and 'attributes' in vt_info['data']:
        stats = vt_info['data']['attributes']['last_analysis_stats']
        vt_verdict = f"{stats['malicious']}/{sum(stats.values())} engines"
    
    ha_verdict = "N/A"
    ha_score = 0
    if ha_info:
        ha_verdict = ha_info.get('verdict', 'Unknown').upper()
        ha_score = ha_info.get('threat_score', 0)
    
    md += f"| Analysis Source | Score/Verdict | Details |\n"
    md += f"| :--- | :--- | :--- |\n"
    md += f"| **VirusTotal** | {vt_verdict} | Based on AV Engines |\n"
    md += f"| **Hybrid Analysis** | {ha_verdict} ({ha_score}/100) | Based on Behavior |\n\n"

    md = md.replace("\\", "/")
    md = md.replace('"', "'")
    md = md.replace("\n", "\\n")
    print(md)

```

### 5. Send Analysis to Cortex (`post_run_analyzer`)

* **App:** Cortex | **Action:** Run Analyzer
* **Parameters Configuration:**
* `analyzer_id`: `<YOUR_CORTEX_ANALYZER_ID>/run`
* `body`:



```json
{
  "data": "$exec.file_hash_sha256",
  "dataType": "hash",
  "tlp": 2
}

```

* `headers`: `Authorization: Bearer <YOUR_CORTEX_TOKEN>`

### 6. Isolate Machine (`Isolate_Machine`)

* **App:** HTTP | **Action:** PATCH
* **Description:** The core containment response action, sending an API command to the EDR/Firewall to isolate the device.
* **Parameters Configuration:**
* `body`:



```json
{
  "id": 2,
  "address": ["$regex_tool.result"],
  "detail": ["Isolate command from Shuffle SOAR"],
  "apply": True
}

```

* `headers`: `X-API-Key: <YOUR_EDR_API_KEY>`

### 7. Send Email Notification (`email_2`)

* **App:** Email | **Action:** Send email
* **Parameters Configuration:**
* `recipients`: `<YOUR_EMAIL_ADDRESS>`
* `subject`: `[SOC ALERT] $exec.alert_type: $exec.file_name`
* `body`:



```text
[SOC SYSTEM ALERT] 
Suspicious behavior detected from the system.

Host: $exec.agent_name
Risk Level: $exec.risk_level (Score: $exec.risk_score)
IP Address: $exec.host_ip
File Path: $exec.file_path
Hash: $exec.file_hash_sha256

---------------------------------------------------
VIEW INCIDENT DETAILS ON THEHIVE:
http://<YOUR_THEHIVE_IP>:9000/alerts/$thehive_1.body._id/details

```

---

## How to Build from Scratch

1. **Initialize:** Log into Shuffle, navigate to the **Workflows** section, and click **New Workflow**.
2. **Setup Trigger:** From the Apps menu on the left, drag the **Triggers** app into the workspace and select **Webhook**.
3. **Drag and Drop Nodes:** Search for and drag the respective applications mentioned above into the workspace: **Shuffle Tools**, **TheHive**, **Cortex**, **HTTP**, and **Email**.
4. **Link the Data Flow:** Click and drag lines from the Webhook node output successively through the next nodes in logical order.
5. **Configure Variables:** Click on each node and paste the configurations provided above. Use the `$node_name` syntax (e.g., `$exec.host_ip`) to pass data between steps.
6. **Authentication:** In the *App Authentication* section for each Node, accurately enter the Base URL, API Keys, or Bearer Tokens of your current lab environment.
7. **Save & Test:** Click the **Save** button, activate the Webhook (Start button), and send a test payload (Test Alert) to verify the execution flow of the entire process.
