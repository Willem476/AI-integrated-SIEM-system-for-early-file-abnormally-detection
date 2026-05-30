
### 1. Shuffle Tools Group (Data Pre-processing)

**Node 1: Shuffle_Tools_1**

* **App:** Shuffle Tools
* **Action:** repeat_back_to_me
* **Parameters:**
* `call`: `$exec`



**Node 2: String_Modifier**

* **App:** Shuffle Tools
* **Action:** regex_replace
* **Parameters:**
* `input_data`: `$exec.file_path`
* `regex`: `\\`
* `replace_string`: `/`
* `ignore_case`: `false`



**Node 3: Shuffle_Tools_2**

* **App:** Shuffle Tools
* **Action:** regex_replace
* **Parameters:**
* `input_data`: `$exec.process_chain.#.cmdline`
* `regex`: `"`
* `replace_string`: `'`
* `ignore_case`: `false`



**Node 4: Shuffle_Tools_3**

* **App:** Shuffle Tools
* **Action:** regex_replace
* **Parameters:**
* `input_data`: `$shuffle_tools_2.#`
* `regex`: `\\+`
* `replace_string`: `/`
* `ignore_case`: `false`



**Node 5: IPv4_Filter**

* **App:** Shuffle Tools
* **Action:** regex_capture_group
* **Parameters:**
* `input_data`: `$exec.host_ip`
* `regex`: `\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`



**Node 6: VT_Tools**

* **App:** Shuffle Tools
* **Action:** execute_python
* **Parameters:**
* `code`:



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

---

### 2. TheHive Group (Incident Management)

**Node 7: TheHive_1**

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

**Node 8: Create_Case**

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

**Node 9: TheHive_4**

* (Configuration is identical to Node 8: Create_Case)

**Node 10: TheHive_5**

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

**Node 11: TheHive_6**

* (Configuration is identical to Node 10: TheHive_5)

---

### 3. Cortex Group (Automated Analysis)

**Node 12: Cortex_1**

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

**Node 13: Cortex_1_copy**

* (Configuration is identical to Node 12: Cortex_1)

---

### 4. HTTP Group (External API Interaction)

**Node 14: http_1**

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

**Node 15: Observable1**

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

**Node 16: Observable2**

* (Configuration is identical to Node 15: Observable1)

**Node 17: Observable1_copy**

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

**Node 18: Observable1_copy_copy**

* (Configuration is identical to Node 17: Observable1_copy)

**Node 19: http_2**

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

**Node 20: http_2_copy**

* (Configuration is similar to Node 19, but referencing a different artifactId)
* **Body:**

```json
{
  "cortexId": "cortex0",
  "artifactId": "$observable2.body.#.id",
  "analyzerId": "8e07d997fac90f4a9a71f13a2a6c7bac"
}

```

**Node 21: Isolate_Machine**

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
  "detail": ["Isolation command from Shuffle"],
  "apply": true
}

```

**Node 22: Isolate_Machine_copy**

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
  "detail": ["Isolation command from Shuffle"],
  "apply": true
}

```

---

### 5. Email Group (Notifications)

**Node 23: email_2_copy**

* **App:** email
* **Action:** send_email_shuffle
* **Parameters:**
* `recipients`: `<YOUR_EMAIL_ADDRESS>`
* `subject`: `[SOC ALERT] $exec.alert_type: $exec.file_name`
* `body`: `[HIGH SEVERITY ALERT] SUSPICIOUS BEHAVIOR DETECTED\n\nThe Security Operations Center (SOC) system has just recorded...`



**Node 24: email_3**

* **App:** email
* **Action:** send_email_shuffle
* **Parameters:**
* `recipients`: `<YOUR_EMAIL_ADDRESS>`
* `subject`: `[BLOCKED BY SOC_SYSTEM]`
* `body`: `<div style="font-family: Arial, Helvetica, sans-serif; max-width: 650px; margin: 0 auto; border: 1px solid #e0e0e0; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 10px rgba(0,0,0,0.05);">...`



**Node 25: email_3_copy**

* (Configuration is identical to Node 24: email_3)

**Node 26: email_4**

* **App:** email
* **Action:** send_email_shuffle
* **Parameters:**
* `recipients`: `<YOUR_EMAIL_ADDRESS>`
* `subject`: `[SOC ALERT] $exec.alert_type`
* `body`: `<div style="font-family: 'Segoe UI', Arial, sans-serif; max-width: 680px; margin: 0 auto; border: 1px solid #e0e0e0; border-radius: 8px; box-shadow: 0 4px 15px rgba(0,0,0,0.08); background-color: #fff...">...`
