# System Architecture & Infrastructure

This directory contains the configuration files and deployment scripts required to build the core infrastructure of the AI-integrated SIEM system. The architecture is specifically designed to support **early malware detection and automated isolation** within a SOC Home Lab environment.

## Directory Structure

The infrastructure is broken down into the following key components:

*   [📂 **`elasticsearch/`**](./elasticsearch/): Contains configuration files (e.g., `elasticsearch.yml`) for setting up the Elasticsearch cluster. This acts as the central data lake, securely storing and indexing log data collected from endpoint agents.
*   [📂 **`kibana/`**](./kibana/): Contains configuration files (e.g., `kibana.yml`) for Kibana. This provides the graphical user interface for our SIEM, allowing analysts to visualize data, monitor alerts, and hunt for threats.
* [📂 **`fleet/`**](./fleet/): Contains configurations to spin up the Fleet Server container. This serves as the centralized management hub, allowing you to control, update, and push security integrations to all deployed Elastic Agents from a single console.
* [📂 **`elastic_agent/`**](./elastic_agent/): Contains step-by-step telemetry installation guides for target endpoints. This covers deploying Microsoft Sysmon for deep system visibility, hardening configurations, and installing the Elastic Agent in no-cert/insecure mode.
*   [📂 **`SOAR/`**](./SOAR/): Contains the deployment scripts (including `docker-compose.yml`) for the Security Orchestration, Automation, and Response stack. This component is the brain of our automated incident response, orchestrating workflows between detection tools and enforcement points.

## Architecture Overview & Data Flow

Our system operates across four primary layers to ensure a closed-loop defense mechanism against malware:

1.  **Endpoint & Ingestion Layer:** Windows Server 2022 endpoints are monitored using Elastic Agents. These agents collect file-level telemetry and forward the logs to our Elasticsearch database.
2.  **Analysis & Detection Layer:** An integrated Machine Learning model (Random Forest) continuously evaluates the ingested logs in real-time, analyzing file characteristics (extensions, paths, sizes) to predict the probability of malicious intent.
3.  **Orchestration Layer (SOAR):** When a file receives a High or Critical Risk Score, the alert is automatically pushed to our SOAR platform (Shuffle). 
4.  **Response & Enforcement Layer:** The SOAR platform executes automated playbooks to:
    *   **Isolate:** Communicate with pfSense to instantly quarantine the infected endpoint from the network.
    *   **Enrich:** Query threat intelligence platforms (Cortex, VirusTotal) for additional context.
    *   **Manage:** Generate a comprehensive incident case in TheHive for the security team.

## Deployment Instructions & Installation Order

To ensure correct dependency mapping and prevent connection errors, the infrastructure components must be deployed in the exact sequential order listed below. 

Please navigate to each respective subdirectory and follow the specialized, no-cert step-by-step documentation:

### Core Infrastructure Setup (Phases 1 - 3)

1.  **Phase 1: [📂 `elasticsearch/`](./elasticsearch/)**
    * **Task:** Deploy the database engine and core data repository.
    * **Objective:** Setting up this node first is mandatory, as all subsequent services require an active Elasticsearch instance to establish connections and authenticate users.
2.  **Phase 2: [📂 `kibana/`](./kibana/)**
    * **Task:** Deploy the central visualization dashboard and configuration interface.
    * **Objective:** Provides the UI needed to manage the SIEM, interact with security metrics, and generate the mandatory service tokens for the Fleet console.
3.  **Phase 3: [📂 `fleet/`](./fleet/)**
    * **Task:** Initialize the centralized agent orchestration server.
    * **Objective:** Establishes the command node (`https://<YOUR_HOST_IP>:8220`) responsible for pushing integration profiles and security policies out to target endpoints.

---

### Endpoint Telemetry & Automation Setup (Phases 4 - 5)

4.  **Phase 4: [📂 `elastic_agent/`](./elastic_agent/)**
    * **Task:** Install Microsoft Sysmon on the Windows Server node and register the Elastic Agent.
    * **Objective:** Deploys local sensors on the machine to audit process and file activities, hooking them directly into the Fleet Server to stream telemetry back into the primary database.
5.  **Phase 5: [📂 `SOAR/`](./SOAR/)**
    * **Task:** Spin up the Security Orchestration, Automation, and Response containers.
    * **Objective:** Connects Shuffle playbooks to the rest of your established infrastructure, locking down the closed-loop defense pipeline for automated endpoint network isolation via pfSense.
