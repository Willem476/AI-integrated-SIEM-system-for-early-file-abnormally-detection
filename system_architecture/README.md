# System Architecture & Infrastructure

This directory contains the configuration files and deployment scripts required to build the core infrastructure of the AI-integrated SIEM system. The architecture is specifically designed to support **early malware detection and automated isolation** within a SOC Home Lab environment.

## Directory Structure

The infrastructure is broken down into the following key components:

*   [📂 **`elasticsearch/`**](./elasticsearch/): Contains configuration files (e.g., `elasticsearch.yml`) for setting up the Elasticsearch cluster. This acts as the central data lake, securely storing and indexing log data collected from endpoint agents.
*   [📂 **`kibana/`**](./kibana/): Contains configuration files (e.g., `kibana.yml`) for Kibana. This provides the graphical user interface for our SIEM, allowing analysts to visualize data, monitor alerts, and hunt for threats.
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

## Deployment Instructions

Detailed commands and setup instructions to deploy the Elasticsearch, Kibana, and SOAR containers are located within the `README.md` files of their respective folders. 

Please navigate to each directory to follow the specific installation steps:
* Navigate to the [**`elasticsearch`**](./elasticsearch/) folder for database setup.
* Navigate to the [**`kibana`**](./kibana/) folder for dashboard deployment.
* Navigate to the [**`SOAR`**](./SOAR/) folder to spin up the automation tools.
