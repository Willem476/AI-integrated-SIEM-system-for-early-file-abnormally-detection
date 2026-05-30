# Endpoint Telemetry Integration Overview

This directory contains the necessary configuration files and structural guides to successfully arm and enroll target endpoints (such as Windows Server 2022) into our central security monitoring pipeline. 

To achieve high-fidelity visibility for early malware anomaly detection, the deployment must be executed in a specific, sequential order across two main phases.

---

## 🛠️ Deployment Roadmap

Please navigate to each subdirectory and follow the comprehensive installation steps in this exact sequence:

### 1. [📂 **`sysmon/`**](./sysmon/) — Deep System Auditing Deployment
* **What it does:** Microsoft Sysmon (System Monitor) operates as a continuous system service on the endpoint. It extends standard Windows logging by capturing crucial low-level kernel activities.
* **Why we need it:** Standard event logs lack the granularity required for deep machine learning analysis. Sysmon records highly specific telemetry—such as **Event ID 1 (Process Creation)**, **Event ID 11 (FileCreate)**, and **Event ID 23 (FileDelete)**. By pairing it with Olaf Hartong's hardened configuration profile, it filters out operating system noise, capturing only the exact behavioral attributes needed to train and trigger our AI detection model.

### 2. [📂 **`agent_setup/`**](./agent_setup/) — Centralized Log Shipping & Enrollment
* **What it does:** The Elastic Agent acts as the localized logistics engine on the target machine, running silently in the background under centralized command.
* **Why we need it:** While Sysmon generates the rich event telemetry locally, it cannot transmit those data streams on its own. The Elastic Agent attaches to our custom-built **Fleet Policy** (which actively hooks into the Sysmon, WMI, and File Integrity Monitoring channels), packages the live telemetry events, and safely streams them straight into the Elasticsearch cluster over our no-cert lab network using the `--insecure` bypass flags.


