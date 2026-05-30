# Deploying Elastic Agent: Endpoint Enrollment & Policy Configuration (No-Cert)

The **Elastic Agent** is the single daemon running on your monitored endpoints (like Windows Server 2022). Its primary role is to collect security logs, system telemetry, and file metrics, and securely ship them back to the Elasticsearch data lake based on centralized instructions called an **Agent Policy**.

In this guide, we will first construct a tailored security policy in Kibana to capture deep log channels and File Integrity Monitoring (FIM) metrics, and then deploy the agent package onto our Windows target endpoint using the mandatory `--insecure` flags.

---

## Part 1: Centralized Agent Policy Configuration

Before installing the agent on your endpoint, you must define what logs it should collect.

### Step 1: Create a New Agent Policy
1. Open your browser and log into the **Kibana** console.
2. Navigate to **Management -> Fleet -> Agent Policies**.
3. Click **Create agent policy**.
4. Provide a recognizable name (e.g., `Windows-Secure-Endpoint-Policy`) and click **Create policy**.

### Step 2: Add Advanced Event Log Channels
Click on your newly created policy, click **Add integration**, search for **Custom Windows Event Logs**, and add it. You need to repeat this integration setup **three times** to monitor the following critical event streams under the **Channel Name** field:

1. `Microsoft-Windows-Sysmon/Operational`
   * Provides advanced auditing for process anomalies, network connections, and explicit file manipulation metadata (such as `FileCreate` and `FileDelete`), which serves as the core training dataset for our AI detection model.
2. `Microsoft-Windows-WMI-Activity/Operational`
   *  Tracks Windows Management Instrumentation (WMI) query executions. Attackers frequently abuse WMI for stealthy lateral movement, persistence, and host reconnaissance without touching the disk.
3. `Microsoft-Windows-Windows Defender/Operational`
   * Captures real-time alerts from Windows Defender Antivirus. This allows the SIEM to immediately ingest known signature matches while the AI handles unknown zero-day structural anomalies.

### Step 3: Integrate File Integrity Monitoring (FIM)
The AI model relies heavily on tracking unauthorized file mutations. 
1. Search for and add the **File Integrity Monitoring** integration.
2. Under **Target Paths**, you can track the entire drive (`C:\`) or restrict it to critical hidden system paths (e.g., `C:\Users\*\AppData\`, `C:\Windows\System32\`) to optimize storage capacity and avoid flooding the home lab.
3. Under **Hash Algorithms**, explicitly check **`sha256`**.
   *  FIM acts as a dedicated monitoring mechanism. Our Random Forest AI parses these precise metrics to analyze unexpected alterations in `file.path`, `file.size`, `file.extension`, `host.name`, and `host.ip`.

### Step 4: Integrate Native Windows Monitoring
1. Search for and add the native **Windows** integration.
2. Leave all settings at their **default** values.
   *This provides baseline visibility into operating system metrics, native Windows performance, running services, and application availability.

---

## Part 2: Elastic Agent Installation & Enrollment

Once your policy is fully configured, you are ready to bind the target Windows endpoint to the Fleet command stream.

### Step 1: Fetch the Enrollment Token
1. In the **Fleet** dashboard under Kibana, click **Add Agent**.
2. Select your newly created policy from the dropdown list.
3. Click **Enroll in Fleet**.
4. Select **Windows** as your target endpoint operating system.
5. Kibana will automatically generate an installation script. **Do not run the script right now**, as it lacks the certificate bypass flag.

### Step 2: Execute the Patched Windows Command (No-Cert Bypass)
Open **Windows PowerShell** using **Run as Administrator** on your target Windows Server node and execute the generated commands to download, extract, and install the agent securely with the certificate bypass flag like the example below:

```powershell
$ProgressPreference = 'SilentlyContinue'
Invoke-WebRequest -Uri https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-8.19.16-windows-x86_64.zip -OutFile elastic-agent-8.19.16-windows-x86_64.zip 
Expand-Archive .\elastic-agent-8.19.16-windows-x86_64.zip -DestinationPath .
cd elastic-agent-8.19.16-windows-x86_64
.\elastic-agent.exe install --url=https://<YOUR_HOST_IP>:8220 --enrollment-token=<YOUR_GENERATED_TOKEN> --insecure
```

---

## Part 3: Ingestion Verification & Telemetry Hunting

### Step 1: Check Fleet Connection Status
Look back at the Kibana Fleet setup wizard. Under the **Confirm agent enrollment** section, once the console displays **`1 agent has been enrolled`** and **`Incoming data confirmed`**, the connection is secure.

### Step 2: Validate Ingested Logs via Kibana Discover
1. Navigate to **Analytics -> Discover** using the Kibana sidebar.
2. In the left-hand field panel, locate and click on **`agent.name`**.
3. Click the plus icon (**`+`**) next to it to pin it as a primary tracking column.
4. Observe the incoming log stream to verify that rich event types are successfully populating your SIEM pipeline, ready to be fed into the AI processing queue!
