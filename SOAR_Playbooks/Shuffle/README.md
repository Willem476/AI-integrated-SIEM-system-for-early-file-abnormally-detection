
# Shuffle SOAR - Incident Response Workflow

This document provides a detailed guide on the configuration and how to build an Automated Incident Response Workflow for Malware and Suspicious Command Line alerts on the Shuffle SOAR platform.

---

## Workflow Branches (Conditions)

This workflow utilizes branching logic to determine the appropriate response based on the alert type and the severity of the threat.

### 1. Branching by Alert Type

After the file path is sanitized in the `String_Modifier` node, the data is evaluated to route to the correct sub-workflow:

* **Route to Command Line Analysis (`Shuffle_Tools_2`):**
* **Condition:** If `$exec.alert_type` **equals** `command_line_anomaly`<img width="590" height="698" alt="image" src="https://github.com/user-attachments/assets/538fd641-2764-47a7-abe3-4bb6be892faa" />



* **Route to Malware Analysis (`VT_Tools`):**
* **Condition:** If `$exec.alert_type` **does not equal** `command_line_anomaly`<img width="577" height="690" alt="image" src="https://github.com/user-attachments/assets/2a1b12be-0013-48d8-94e9-a249e3797370" />




### 2. Branching by Risk Level (Malware Sub-workflow)

After the Python script analyzes the hash, the system decides whether to isolate the host or only create an alert based on severity.

* **Route to Create Alert Only (`TheHive_1`):**
* **Condition 1:** If `$exec.risk_level` **does not equal** `CRITICAL`
* **Condition 2:** If `$exec.risk_level` **does not equal** `HIGH`<img width="609" height="439" alt="image" src="https://github.com/user-attachments/assets/361cccbc-a165-41ba-81c6-1ee4f1064cb4" />



* **Route to Automated Containment (`Isolate_Machine`):**
* **Condition 1:** If `$exec.risk_level` **does not equal** `LOW`
* **Condition 2:** If `$exec.risk_level` **does not equal** `MEDIUM`<img width="610" height="438" alt="image" src="https://github.com/user-attachments/assets/f4a4f665-8f43-4887-9f8e-23c8c3591dad" />




### 3. Branching by Risk Level (Command Line Sub-workflow)

After an initial email notification is sent regarding the suspicious command line, the workflow decides the next containment steps.

* **Route to Automated Containment (`Isolate_Machine_copy`):**
* **Condition:** If `$exec.risk_level` **does not equal** `LOW`<img width="842" height="540" alt="image" src="https://github.com/user-attachments/assets/23607b27-6e29-4b24-82f5-af7cdd253d5d" />



* **Route to Create Case Only (`TheHive_6`):**
* **Condition:** If `$exec.risk_level` **equals** `LOW`<img width="845" height="543" alt="image" src="https://github.com/user-attachments/assets/0fe89dc7-f11f-498c-bf8e-aac3d636bc76" />




---

## Step-by-Step Node Configurations

Below are the exact configurations for every Node in this workflow. Sensitive values such as API Keys, Tokens, and Emails have been replaced with placeholders.

### Node 1: Shuffle_Tools_1

* **App:** Shuffle Tools
* **Action:** repeat_back_to_me
* **Parameters:**
* `call`: `$exec`


  <img width="841" height="495" alt="image" src="https://github.com/user-attachments/assets/5a92b005-bb31-44e8-8b98-fad5d79e8cc4" />




### Node 2: String_Modifier

* **App:** Shuffle Tools
* **Action:** regex_replace
* **Parameters:**
* `input_data`: `$exec.file_path`
* `regex`: `\\`
* `replace_string`: `/`
* `ignore_case`: `false`

  <img width="675" height="454" alt="image" src="https://github.com/user-attachments/assets/56470a5e-15fa-45ba-bc9b-cfa69ce9a8d8" />




### Node 3: Shuffle_Tools_2

* **App:** Shuffle Tools
* **Action:** regex_replace
* **Parameters:**
* `input_data`: `$exec.process_chain.#.cmdline`
* `regex`: `"`
* `replace_string`: `'`
* `ignore_case`: `false`

  <img width="618" height="773" alt="image" src="https://github.com/user-attachments/assets/30c44ef9-2922-4d18-8521-afd65a88ff2b" />




### Node 4: Shuffle_Tools_3

* **App:** Shuffle Tools
* **Action:** regex_replace
* **Parameters:**
* `input_data`: `$shuffle_tools_2.#`
* `regex`: `\\+`
* `replace_string`: `/`
* `ignore_case`: `false`

  <img width="614" height="758" alt="image" src="https://github.com/user-attachments/assets/79b808ea-c87b-4bbf-80c3-059be5230be8" />




### Node 6: VT_Tools

* **App:** Shuffle Tools
* **Action:** execute_python
* **Parameters:**

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
    url = "[https://www.hybrid-analysis.com/api/v2/search/hash](https://www.hybrid-analysis.com/api/v2/search/hash)"
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
    vt_info = get_vt_data(f"[https://www.virustotal.com/api/v3/files/](https://www.virustotal.com/api/v3/files/){file_id}", vt_headers)
    vt_beh = get_vt_data(f"[https://www.virustotal.com/api/v3/files/](https://www.virustotal.com/api/v3/files/){file_id}/behaviours", vt_headers)
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

<img width="603" height="848" alt="image" src="https://github.com/user-attachments/assets/aa423db9-d07d-44f7-ba94-5f9cbf5edd8a" />


### Node 7: TheHive_1

* **App:** TheHive
* **Action:** post_create_alert
* **Parameters:**
* `ssl_verify`: `False`
* `to_file`: `False`
* `headers`: `Content-Type=application/json\nAccept=application/json`
* `body`:



```json
{
  "title": "Malware Detection: $exec.file_name",
  "description": "Host: $exec.agent_name | Path: $string_modifier",
  "severity": $exec.severity,
  "source": "Shuffle-SOAR",
  "type": "Malware"
}

```

<img width="606" height="849" alt="image" src="https://github.com/user-attachments/assets/4fc7715c-caba-41da-82e4-bfd7534a873d" />


### Node 8: Create_Case

* **App:** TheHive
* **Action:** post_create_case
* **Parameters:**
* `ssl_verify`: `False`
* `to_file`: `False`
* `headers`: `Content-Type=application/json\nAccept=application/json`
* `body`:



```json
{
  "title": "$exec.alert_type: $exec.file_name",
  "description": "Host: $exec.agent_name | Path: $string_modifier \n $vt_tools.message",
  "severity": $exec.severity,
  "source": "Shuffle-SOAR"
}

```

<img width="592" height="826" alt="image" src="https://github.com/user-attachments/assets/5c36e108-a901-477f-8655-86a73841a7cc" />


### Node 9: TheHive_4

* **App:** TheHive
* **Action:** post_create_case
* **Parameters:**
* `ssl_verify`: `False`
* `to_file`: `False`
* `headers`: `Content-Type=application/json\nAccept=application/json`
* `body`:



```json
{
  "title": "$exec.alert_type: $exec.file_name",
  "description": "Host: $exec.agent_name | Path: $string_modifier \n $vt_tools.message",
  "severity": $exec.severity,
  "source": "Shuffle-SOAR"
}

```

<img width="617" height="824" alt="image" src="https://github.com/user-attachments/assets/f6132ee0-531c-4a59-9348-665e47eba0c9" />


### Node 10: TheHive_5

* **App:** TheHive
* **Action:** post_create_case
* **Parameters:**
* `ssl_verify`: `False`
* `to_file`: `False`
* `headers`: `Content-Type=application/json\nAccept=application/json`
* `body`:



```json
{
  "title": "Alert: $exec.alert_type on host $ipv4_filter.result",
  "description": "### SUSPICIOUS PROCESS ALERT DETAILS\n\n- **Alert Name:** $exec.alert_type\n- **Host:** $exec.host",
  "severity": $exec.severity,
  "source": "Shuffle-SOAR"
}

```

<img width="602" height="822" alt="image" src="https://github.com/user-attachments/assets/60841864-4c52-4546-a212-e804f18af14e" />


### Node 11: TheHive_6

* **App:** TheHive
* **Action:** post_create_case
* **Parameters:**
* `ssl_verify`: `False`
* `to_file`: `False`
* `headers`: `Content-Type=application/json\nAccept=application/json`
* `body`:



```json
{
  "title": "Alert: $exec.alert_type on host $ipv4_filter.result",
  "description": "### SUSPICIOUS PROCESS ALERT DETAILS\n\n- **Alert Name:** $exec.alert_type\n- **Host:** $exec.host",
  "severity": $exec.severity,
  "source": "Shuffle-SOAR"
}

```

<img width="586" height="824" alt="image" src="https://github.com/user-attachments/assets/1cb1d032-1394-4ef9-8dde-8c263d9a26f6" />


### Node 12: Cortex_1

* **App:** Cortex
* **Action:** post_run_analyzer
* **Parameters:**
* `ssl_verify`: `False`
* `to_file`: `False`
* `analyzer_id`: `8e07d997fac90f4a9a71f13a2a6c7bac/run`
* `headers`: `Content-Type: application/json\nAuthorization: Bearer <YOUR_CORTEX_TOKEN>`
* `body`:



```json
{
  "data": "$exec.file_hash_sha256",
  "dataType": "hash",
  "tlp": 2
}

```

<img width="593" height="839" alt="image" src="https://github.com/user-attachments/assets/7647365f-2df0-41a1-84ba-5de4c5a31a0e" />


### Node 13: Cortex_1_copy

* **App:** Cortex
* **Action:** post_run_analyzer
* **Parameters:**
* `ssl_verify`: `False`
* `to_file`: `False`
* `analyzer_id`: `8e07d997fac90f4a9a71f13a2a6c7bac/run`
* `headers`: `Content-Type: application/json\nAuthorization: Bearer <YOUR_CORTEX_TOKEN>`
* `body`:



```json
{
  "data": "$exec.file_hash_sha256",
  "dataType": "hash",
  "tlp": 2
}

```

<img width="601" height="846" alt="image" src="https://github.com/user-attachments/assets/409e53cb-e1b5-4e18-a175-744d8ed66b08" />


### Node 14: http_1

* **App:** http
* **Action:** POST
* **Parameters:**
* `verify`: `false`
* `headers`: `Content-Type: application/json\nAuthorization: Bearer <YOUR_HTTP_TOKEN>`
* `body`:



```json
{
  "dataType": "hash",
  "data": "$exec.file_hash_sha256",
  "message": "$vt_tools.message",
  "tags": ["shuffle-enriched"]
}

```

<img width="613" height="840" alt="image" src="https://github.com/user-attachments/assets/559bef9f-1634-43aa-94d7-59eefcb66924" />


### Node 15: Observable1

* **App:** http
* **Action:** POST
* **Parameters:**
* `verify`: `false`
* `headers`: `Content-Type: application/json\nAuthorization: Bearer <YOUR_HTTP_TOKEN>`
* `body`:



```json
{
  "dataType": "hash",
  "data": "$exec.file_hash_sha256",
  "message": "### MALWARE DETECTION DETAILS\n\n| Information Field | Value |\n| :--- | :--- |\n| **Alert ID** | $exec.alert_id |"
}

```

<img width="613" height="850" alt="image" src="https://github.com/user-attachments/assets/d71a3778-1c59-4c10-ab8b-333860a714be" />


### Node 16: Observable2

* **App:** http
* **Action:** POST
* **Parameters:**
* `verify`: `false`
* `headers`: `Content-Type: application/json\nAuthorization: Bearer <YOUR_HTTP_TOKEN>`
* `body`:



```json
{
  "dataType": "hash",
  "data": "$exec.file_hash_sha256",
  "message": "### MALWARE DETECTION DETAILS\n\n| Information Field | Value |\n| :--- | :--- |\n| **Alert ID** | $exec.alert_id |"
}

```

<img width="604" height="825" alt="image" src="https://github.com/user-attachments/assets/0824761d-44c2-4558-9dc1-64993cfab55e" />


### Node 17: Observable1_copy

* **App:** http
* **Action:** POST
* **Parameters:**
* `verify`: `false`
* `headers`: `Content-Type: application/json\nAuthorization: Bearer <YOUR_HTTP_TOKEN>`
* `body`:



```json
{
  "dataType": "hostname",
  "data": "$exec.host",
  "message": "### AFFECTED HOST DETAILS\n\n| Information Field | Value |\n| :--- | :--- |\n| **Alert Name** | $exec.alert_type |"
}

```

<img width="609" height="841" alt="image" src="https://github.com/user-attachments/assets/f44b5557-dfc1-40ee-a8a4-afc5ff66101d" />


### Node 18: Observable1_copy_copy

* **App:** http
* **Action:** POST
* **Parameters:**
* `verify`: `false`
* `headers`: `Content-Type: application/json\nAuthorization: Bearer <YOUR_HTTP_TOKEN>`
* `body`:



```json
{
  "dataType": "hostname",
  "data": "$exec.host",
  "message": "### AFFECTED HOST DETAILS\n\n| Information Field | Value |\n| :--- | :--- |\n| **Alert Name** | $exec.alert_type |"
}

```

<img width="603" height="832" alt="image" src="https://github.com/user-attachments/assets/73f34610-306b-44d3-a405-cd3ea5372082" />


### Node 19: http_2

* **App:** http
* **Action:** POST
* **Parameters:**
* `verify`: `false`
* `headers`: `Authorization: Bearer <YOUR_HTTP_TOKEN>\nContent-Type: application/json`
* `body`:



```json
{
  "cortexId": "cortex0",
  "artifactId": "$observable1.body.#.id",
  "analyzerId": "8e07d997fac90f4a9a71f13a2a6c7bac"
}

```

<img width="614" height="850" alt="image" src="https://github.com/user-attachments/assets/75d6888b-1046-428f-85bb-b6499ff038b3" />


### Node 20: http_2_copy

* **App:** http
* **Action:** POST
* **Parameters:**
* `verify`: `false`
* `headers`: `Authorization: Bearer <YOUR_HTTP_TOKEN>\nContent-Type: application/json`
* `body`:



```json
{
  "cortexId": "cortex0",
  "artifactId": "$observable2.body.#.id",
  "analyzerId": "8e07d997fac90f4a9a71f13a2a6c7bac"
}

```

<img width="600" height="852" alt="image" src="https://github.com/user-attachments/assets/b83f9332-1ea0-4537-8c85-3705fb3e2893" />


### Node 21: Isolate_Machine

* **App:** http
* **Action:** PATCH
* **Parameters:**
* `verify`: `false`
* `headers`: `Content-Type: application/json\nX-API-Key: <YOUR_EDR_API_KEY>`
* `body`:



```json
{
  "id": 2,
  "address": ["$ipv4_filter.result"],
  "detail": ["Test block from Shuffle"],
  "apply": true
}

```

<img width="605" height="829" alt="image" src="https://github.com/user-attachments/assets/7c72989e-432c-4e72-be81-3d905a3ff123" />


### Node 22: Isolate_Machine_copy

* **App:** http
* **Action:** PATCH
* **Parameters:**
* `verify`: `false`
* `headers`: `Content-Type: application/json\nX-API-Key: <YOUR_EDR_API_KEY>`
* `body`:



```json
{
  "id": 2,
  "address": ["10.10.10.53"],
  "detail": ["Test block from Shuffle"],
  "apply": true
}

```

<img width="608" height="852" alt="image" src="https://github.com/user-attachments/assets/bb17bd90-d312-451d-9168-0ad4e52c8601" />


### Node 23: email_2_copy

* **App:** email
* **Action:** send_email_shuffle
* **Parameters:**
* `recipients`: `<YOUR_EMAIL_ADDRESS>`
* `subject`: `[SOC ALERT] $exec.alert_type: $exec.file_name`
* `body`:



```text
[HIGH SEVERITY ALERT] SUSPICIOUS BEHAVIOR DETECTED

The Security Operations Center (SOC) system has just recorded a security alert. Incident Response (IR) team is required to investigate immediately!

GENERAL INFORMATION
---------------------------------------------------
Alert Name: $exec.alert_type
Incident ID: $exec.alert_id
Time Detected: $exec.detected_at
Risk Level: $exec.risk_level (Score: $exec.risk_score/100)

ENDPOINT INFORMATION
---------------------------------------------------
Hostname: $exec.agent_name
IP Address: $exec.host_ip

PROCESS / MALWARE DETAILS
---------------------------------------------------
File Name: $exec.file_name
File Path: $exec.file_path
Hash (SHA-256): $exec.file_hash_sha256

RECOMMENDED NEXT STEPS:
1. Immediately check the process history of this endpoint on the monitoring tool.
2. If confirmed as malware, activate the IP Isolation workflow.
3. Collect the file sample (Hash) for deep analysis in a Sandbox environment.

Access TheHive to handle this Case: http://<YOUR_THEHIVE_IP>:9000
---------------------------------------------------
Automated notification generated by the Shuffle SOAR system

```

<img width="611" height="813" alt="image" src="https://github.com/user-attachments/assets/f77ee7d7-ae0d-42b5-8cd0-51cbbdae8e83" />


### Node 24: email_3

* **App:** email
* **Action:** send_email_shuffle
* **Parameters:**
* `recipients`: `<YOUR_EMAIL_ADDRESS>`
* `subject`: `[BLOCKED BY SOC_SYSTEM]`
* `body`:



```html
<div style="font-family: Arial, Helvetica, sans-serif; max-width: 650px; margin: 0 auto; border: 1px solid #e0e0e0; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 10px rgba(0,0,0,0.05);">
  <div style="background-color: #d32f2f; color: #ffffff; padding: 12px 15px; text-align: center;">
    <h2 style="margin: 0; font-size: 17px; letter-spacing: 1px;">[SOC NOTIFICATION] MACHINE ISOLATION SUCCESSFUL</h2>
  </div>
  <div style="padding: 15px 20px; background-color: #ffffff; color: #333333;">
    <p style="font-size: 14px; line-height: 1.5; margin: 0 0 15px 0;">
      The SOAR system automatically executed a firewall block command due to detected malicious behavior.<br>
      <span style="color: #2e7d32; font-weight: bold;">Network propagation risk has been successfully mitigated!</span>
    </p>
    <h3 style="font-size: 15px; border-bottom: 2px solid #eeeeee; padding-bottom: 3px; margin: 0 0 10px 0; color: #d32f2f;">Alert Information</h3>
    <table style="width: 100%; border-collapse: collapse; font-size: 13px; margin-bottom: 15px;">
      <tr>
        <td style="padding: 5px 0; border-bottom: 1px solid #eeeeee; width: 35%;"><strong>Incident Name:</strong></td>
        <td style="padding: 5px 0; border-bottom: 1px solid #eeeeee; font-weight: bold; color: #333;">$exec.alert_type (Code: $exec.alert_id)</td>
      </tr>
      <tr>
        <td style="padding: 5px 0; border-bottom: 1px solid #eeeeee;"><strong>Detected File:</strong></td>
        <td style="padding: 5px 0; border-bottom: 1px solid #eeeeee; font-family: monospace;">$exec.file_name</td>
      </tr>
      <tr>
        <td style="padding: 5px 0; border-bottom: 1px solid #eeeeee;"><strong>Path:</strong></td>
        <td style="padding: 5px 0; border-bottom: 1px solid #eeeeee; font-family: monospace;">$exec.file_path</td>
      </tr>
      <tr>
        <td style="padding: 5px 0; border-bottom: 1px solid #eeeeee;"><strong>Severity:</strong></td>
        <td style="padding: 5px 0; border-bottom: 1px solid #eeeeee; color: #d32f2f; font-weight: bold;">$exec.risk_level (Level $exec.severity)</td>
      </tr>
      <tr>
        <td style="padding: 5px 0; border-bottom: 1px solid #eeeeee;"><strong>Time Detected:</strong></td>
        <td style="padding: 5px 0; border-bottom: 1px solid #eeeeee;">$exec.detected_at</td>
      </tr>
    </table>
    <h3 style="font-size: 15px; border-bottom: 2px solid #eeeeee; padding-bottom: 3px; margin: 0 0 10px 0; color: #1976d2;">Isolation Details</h3>
    <div style="background-color: #f8f9fa; border-left: 4px solid #4caf50; padding: 10px 15px; margin: 0 0 15px 0; border-radius: 0 4px 4px 0;">
      <table style="width: 100%; border-collapse: collapse; font-size: 13px;">
        <tr>
          <td style="padding: 5px 0; border-bottom: 1px solid #eeeeee; width: 35%;"><strong>Hostname:</strong></td>
          <td style="padding: 5px 0; border-bottom: 1px solid #eeeeee; font-family: monospace; font-size: 14px;"><b>$exec.agent_name</b></td>
        </tr>
        <tr>
          <td style="padding: 5px 0; border-bottom: 1px solid #eeeeee;"><strong>Blocked IP:</strong></td>
          <td style="padding: 5px 0; border-bottom: 1px solid #eeeeee; font-family: monospace; font-size: 14px; color: #d32f2f;"><b>$exec.host_ip</b></td>
        </tr>
        <tr>
          <td style="padding: 5px 0;"><strong>Status:</strong></td>
          <td style="padding: 5px 0; color: #2e7d32; font-weight: bold;">Success</td>
        </tr>
      </table>
    </div>
    <div style="background-color: #fff3cd; border: 1px solid #ffeeba; color: #856404; padding: 10px 15px; border-radius: 4px; font-size: 13px; line-height: 1.5; margin-bottom: 15px;">
      <strong>Action Required:</strong> The machine has been disconnected from the LAN/Internet. The IT team is requested to go directly to the site to scan for malware and remediate before requesting network reconnection.
    </div>
    <div style="text-align: center; margin-top: 15px; margin-bottom: 5px;">
      <a href="http://<YOUR_THEHIVE_IP>:9000/cases/$create_case.body._id/details" style="background-color: #1976d2; color: #ffffff; text-decoration: none; padding: 10px 20px; border-radius: 5px; font-weight: bold; font-size: 13px; display: inline-block; box-shadow: 0 2px 5px rgba(0,0,0,0.2);">View Case Details on TheHive</a>
    </div>
  </div>
  <div style="background-color: #f1f1f1; padding: 10px; text-align: center; border-top: 1px solid #e0e0e0;">
    <p style="margin: 0; font-size: 11px; color: #666666; font-style: italic;">
      Automated notification generated by the Shuffle SOAR system
    </p>
  </div>
</div>

```

<img width="608" height="851" alt="image" src="https://github.com/user-attachments/assets/3f913801-5d35-4243-98d3-19d02d9c5011" />


### Node 25: email_3_copy

* **App:** email
* **Action:** send_email_shuffle
* **Parameters:**
* `recipients`: `<YOUR_EMAIL_ADDRESS>`
* `subject`: `[BLOCKED BY SOC_SYSTEM]`
* `body`:



```html
<div style="font-family: Arial, Helvetica, sans-serif; max-width: 650px; margin: 0 auto; border: 1px solid #e0e0e0; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 10px rgba(0,0,0,0.05);">
  <div style="background-color: #d32f2f; color: #ffffff; padding: 12px 15px; text-align: center;">
    <h2 style="margin: 0; font-size: 17px; letter-spacing: 1px;">[SOC NOTIFICATION] MACHINE ISOLATION SUCCESSFUL</h2>
  </div>
  <div style="padding: 15px 20px; background-color: #ffffff; color: #333333;">
    <p style="font-size: 14px; line-height: 1.5; margin: 0 0 15px 0;">
      The SOAR system automatically executed a firewall block command due to detected malicious behavior.<br>
      <span style="color: #2e7d32; font-weight: bold;">Network propagation risk has been successfully mitigated!</span>
    </p>
    <h3 style="font-size: 15px; border-bottom: 2px solid #eeeeee; padding-bottom: 3px; margin: 0 0 10px 0; color: #d32f2f;">Alert Information</h3>
    <table style="width: 100%; border-collapse: collapse; font-size: 13px; margin-bottom: 15px;">
      <tr>
        <td style="padding: 5px 0; border-bottom: 1px solid #eeeeee; width: 35%;"><strong>Incident Name:</strong></td>
        <td style="padding: 5px 0; border-bottom: 1px solid #eeeeee; font-weight: bold; color: #333;">$exec.alert_type (Code: $exec.alert_id)</td>
      </tr>
      <tr>
        <td style="padding: 5px 0; border-bottom: 1px solid #eeeeee;"><strong>Detected File:</strong></td>
        <td style="padding: 5px 0; border-bottom: 1px solid #eeeeee; font-family: monospace;">$exec.file_name</td>
      </tr>
      <tr>
        <td style="padding: 5px 0; border-bottom: 1px solid #eeeeee;"><strong>Path:</strong></td>
        <td style="padding: 5px 0; border-bottom: 1px solid #eeeeee; font-family: monospace;">$exec.file_path</td>
      </tr>
      <tr>
        <td style="padding: 5px 0; border-bottom: 1px solid #eeeeee;"><strong>Severity:</strong></td>
        <td style="padding: 5px 0; border-bottom: 1px solid #eeeeee; color: #d32f2f; font-weight: bold;">$exec.risk_level (Level $exec.severity)</td>
      </tr>
      <tr>
        <td style="padding: 5px 0; border-bottom: 1px solid #eeeeee;"><strong>Time Detected:</strong></td>
        <td style="padding: 5px 0; border-bottom: 1px solid #eeeeee;">$exec.detected_at</td>
      </tr>
    </table>
    <h3 style="font-size: 15px; border-bottom: 2px solid #eeeeee; padding-bottom: 3px; margin: 0 0 10px 0; color: #1976d2;">Isolation Details</h3>
    <div style="background-color: #f8f9fa; border-left: 4px solid #4caf50; padding: 10px 15px; margin: 0 0 15px 0; border-radius: 0 4px 4px 0;">
      <table style="width: 100%; border-collapse: collapse; font-size: 13px;">
        <tr>
          <td style="padding: 5px 0; border-bottom: 1px solid #eeeeee; width: 35%;"><strong>Hostname:</strong></td>
          <td style="padding: 5px 0; border-bottom: 1px solid #eeeeee; font-family: monospace; font-size: 14px;"><b>$exec.agent_name</b></td>
        </tr>
        <tr>
          <td style="padding: 5px 0; border-bottom: 1px solid #eeeeee;"><strong>Blocked IP:</strong></td>
          <td style="padding: 5px 0; border-bottom: 1px solid #eeeeee; font-family: monospace; font-size: 14px; color: #d32f2f;"><b>$exec.host_ip</b></td>
        </tr>
        <tr>
          <td style="padding: 5px 0;"><strong>Status:</strong></td>
          <td style="padding: 5px 0; color: #2e7d32; font-weight: bold;">Success</td>
        </tr>
      </table>
    </div>
    <div style="background-color: #fff3cd; border: 1px solid #ffeeba; color: #856404; padding: 10px 15px; border-radius: 4px; font-size: 13px; line-height: 1.5; margin-bottom: 15px;">
      <strong>Action Required:</strong> The machine has been disconnected from the LAN/Internet. The IT team is requested to go directly to the site to scan for malware and remediate before requesting network reconnection.
    </div>
    <div style="text-align: center; margin-top: 15px; margin-bottom: 5px;">
      <a href="http://<YOUR_THEHIVE_IP>:9000/cases/$create_case.body._id/details" style="background-color: #1976d2; color: #ffffff; text-decoration: none; padding: 10px 20px; border-radius: 5px; font-weight: bold; font-size: 13px; display: inline-block; box-shadow: 0 2px 5px rgba(0,0,0,0.2);">View Case Details on TheHive</a>
    </div>
  </div>
  <div style="background-color: #f1f1f1; padding: 10px; text-align: center; border-top: 1px solid #e0e0e0;">
    <p style="margin: 0; font-size: 11px; color: #666666; font-style: italic;">
      Automated notification generated by the Shuffle SOAR system
    </p>
  </div>
</div>

```

<img width="590" height="842" alt="image" src="https://github.com/user-attachments/assets/b95a7d30-c052-412c-bc4c-d6d77062867a" />


### Node 26: email_4

* **App:** email
* **Action:** send_email_shuffle
* **Parameters:**
* `recipients`: `<YOUR_EMAIL_ADDRESS>`
* `subject`: `[SOC ALERT] $exec.alert_type`
* `body`:



```html
<div style="font-family: 'Segoe UI', Arial, sans-serif; max-width: 680px; margin: 0 auto; border: 1px solid #e0e0e0; border-radius: 8px; box-shadow: 0 4px 15px rgba(0,0,0,0.08); background-color: #ffffff;">
  <div style="background-color: #f39c12; color: #ffffff; padding: 20px; text-align: center; border-radius: 8px 8px 0 0;">
    <h2 style="margin: 0; font-size: 20px; letter-spacing: 1px;">[SOC ALERT]</h2>
    <p style="margin: 8px 0 0 0; font-size: 16px; font-weight: 500;">SUSPICIOUS COMMAND LINE BEHAVIOR</p>
  </div>
  <div style="padding: 25px; color: #333333;">
    <p style="font-size: 15px; line-height: 1.6; margin-top: 0;">
      The system has detected an account executing commands that indicate potential scanning or sensitive information gathering (Credential Hunting).
    </p>
    <h3 style="font-size: 16px; color: #f39c12; border-bottom: 2px solid #eeeeee; padding-bottom: 5px; margin-top: 25px;">INCIDENT INFORMATION</h3>
    <table style="width: 100%; border-collapse: collapse; font-size: 14px; margin-bottom: 20px;">
      <tr>
        <td style="padding: 10px 0; border-bottom: 1px solid #eeeeee; width: 35%;"><strong>Alert Type:</strong></td>
        <td style="padding: 10px 0; border-bottom: 1px solid #eeeeee; font-weight: bold; color: #2c3e50;">$exec.alert_type</td>
      </tr>
      <tr>
        <td style="padding: 10px 0; border-bottom: 1px solid #eeeeee;"><strong>MITRE Technique:</strong></td>
        <td style="padding: 10px 0; border-bottom: 1px solid #eeeeee; color: #d32f2f;"><b>$exec.matched_mitre.#0</b> ($exec.matched_iocs.#0)</td>
      </tr>
      <tr>
        <td style="padding: 10px 0; border-bottom: 1px solid #eeeeee;"><strong>Risk Level:</strong></td>
        <td style="padding: 10px 0; border-bottom: 1px solid #eeeeee; font-weight: bold;">$exec.risk_level <span style="font-weight: normal; color: #666;">(Score: $exec.max_risk_score/100)</span></td>
      </tr>
    </table>
    <h3 style="font-size: 16px; color: #1976d2; border-bottom: 2px solid #eeeeee; padding-bottom: 5px;">EXECUTION DETAILS</h3>
    <div style="background-color: #f4f7f6; border-left: 4px solid #1976d2; padding: 15px; margin-bottom: 20px; border-radius: 0 4px 4px 0;">
      <p style="margin: 0 0 8px 0; font-size: 14px;"><strong>Host:</strong> <span style="font-family: 'Courier New', Courier, monospace; font-size: 15px; background-color: #e2e8f0; padding: 2px 6px; border-radius: 4px;">$exec.host</span></p>
      <p style="margin: 0 0 8px 0; font-size: 14px;"><strong>User Account:</strong> <span style="color: #d32f2f; font-weight: bold;">$exec.user</span></p>
      <p style="margin: 0 0 8px 0; font-size: 14px;"><strong>Process:</strong> $exec.process_chain.#0.process</p>
      <p style="margin: 0; font-size: 14px;"><strong>Command Line:</strong></p>
      <p style="margin: 5px 0 0 0; background-color: #2d3436; color: #00cec9; padding: 10px; font-family: monospace; border-radius: 4px; word-break: break-all;">$exec.process_chain.#0.cmdline</p>
    </div>
    <div style="background-color: #fff8e1; border: 1px solid #ffe082; padding: 15px; border-radius: 6px; margin-bottom: 25px;">
      <h4 style="margin: 0 0 10px 0; font-size: 15px; color: #b71c1c;">RECOMMENDED ACTIONS:</h4>
      <ul style="margin: 0; padding-left: 20px; font-size: 14px; color: #3e2723; line-height: 1.6;">
        <li>Contact the account owner <b>$exec.user</b> to verify if this is a legitimate administrative action or a compromised account.</li>
        <li>Check if the output file of this command was exfiltrated.</li>
      </ul>
    </div>
  </div>
  <div style="background-color: #f8f9fa; padding: 15px; text-align: center; border-top: 1px solid #e0e0e0; border-radius: 0 0 8px 8px;">
    <p style="margin: 0; font-size: 12px; color: #7f8c8d; font-style: italic;">Automated notification generated by the Shuffle SOAR system</p>
  </div>
</div>

```

<img width="618" height="934" alt="image" src="https://github.com/user-attachments/assets/62db1216-9a8f-4185-b206-768a528f4f73" />

