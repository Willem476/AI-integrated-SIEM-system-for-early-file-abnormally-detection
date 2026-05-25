# AI-Integrated SIEM Home Lab: Early Malware Detection & Automated Response

Welcome! This repository serves as a practical, step-by-step guide for cybersecurity enthusiasts, students, and professionals looking to build a **proactive SOC Home Lab** from scratch. 

Traditional Security Operations Centers (SOCs) often struggle with alert fatigue, fragmented systems, and the limitations of static, signature-based rules that fail to catch zero-day malware. This project demonstrates how to shift from a reactive posture to a proactive one by integrating a basic Artificial Intelligence (Random Forest) model to detect early file anomalies and orchestrate automated network isolation.

If you want to learn how to combine ELK Stack, SOAR, and Machine Learning into a cohesive defensive pipeline, you are in the right place!

##  What You Will Learn & Build
By following this guide, you will set up a complete pipeline that includes:
1.  **Log Collection:** Gathering file-level events from endpoints.
2.  **Behavior-Driven Inference:** Using a Random Forest AI model to analyze file characteristics instead of relying solely on known hash databases.
3.  **Risk Scoring Engine:** Calculating a dynamic risk score based on ML probability, MITRE ATT&CK techniques, and Indicators of Compromise (IOCs).
4.  **Automated Incident Response:** Triggering isolation and alert creation without manual human intervention.

##  Home Lab Architecture & Tech Stack
This project is designed to be deployed in a localized virtual environment. 

*   **Virtualization:** VMware ESXi (or VMware Workstation, Proxmox)
*   **Operating Systems:** Windows Server 2022 (Endpoint)
*   **Log Management:** Elastic Agent & Elasticsearch, Kibana
*   **SOAR (Automation):** Shuffle
*   **Threat Intelligence & Case Management:**  TheHive, Cortex
*   **Network Enforcement:** pfSense (for endpoint isolation)
*   **AI/ML:** Python - Random Forest Classifier

## The Brains: Random Forest AI Model
At the core of this system is a Random Forest model trained on 185,845 records (benign and malware). We extract **27 engineered features** from every file event, categorized into:
*   **Extension-Based (5):** Detects script types, executables, and double extensions.
*   **Path & Size (15):** Analyzes trustworthiness of directories (e.g., Temp, System32) and abnormal file sizes (droppers vs. packed malware).
*   **Pattern & Trust (7):** Identifies whitelisted locations and suspicious behavioral patterns.


## The Automated Workflow
The system doesn't just detect; it responds. When an anomaly is detected, the following pipeline executes:
1.  **Alert Generation:** The Random Forest model flags an anomaly.
2.  **Risk Scoring:** The system calculates a score (`0-100`).
    *   *Formula: 50% ML Probability + 30% MITRE Score + 20% IOC Score*.
3.  **SOAR Execution:** If the score exceeds the threshold (`>60`, HIGH/CRITICAL), Shuffle orchestrates the response.
4.  **Containment:** The machine is automatically isolated via pfSense.
5.  **SOC Escalation:** A detailed case is enriched by Cortex/OpenCTI and created in TheHive for final analyst review.
*More details about the workflow in[ `SOAR_Playbooks`](./SOAR_Playbooks).*

---

## Getting Started: Build Guide

Follow the detailed directories below to start building your lab:

*   [📂 `AI_integration`](./AI_integration): Feature engineering scripts, and the Random Forest model training guide.
*   [📂 `system_architecture`](./system_architecture): Installing and configuring Elasticsearch, Kibana, TheHive, Cortex, Shuffle
*   [📂 `SOAR_Playbooks`](./SOAR_Playbooks): Shuffle workflow JSON files and API integrations for TheHive and Cortex.

## Contributing
Have ideas to improve the model or add new SOAR playbooks? Feel free to fork the repository, make your changes, and submit a pull request!
