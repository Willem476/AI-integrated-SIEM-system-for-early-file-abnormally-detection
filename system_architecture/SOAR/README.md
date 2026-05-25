
---

# Security Operations Center (SOC) Lab Environment

This project provides a SOC (Security Operations Center) lab environment partially containerized using Docker Compose, integrating with an existing Elasticsearch backend. The system combines leading open-source platforms for Security Incident Response, Threat Intelligence, and Security Automation.

## System Components

The system includes the following services:

* **TheHive (v5.2):** Security Incident Response Platform.
* **Cortex:** Automated data collection and analysis platform, tightly integrated with TheHive.
* **Elasticsearch (External ELK Stack):** Centralized log storage and indexing backend for TheHive and Shuffle. It is hosted externally at `10.10.10.34:9200` with X-Pack security enabled.
* **Cassandra (v4):** Database management system for TheHive.
* **MinIO:** S3-compatible storage server (used to store attachments for TheHive).
* **OpenCTI - TheHive Connector:** Connector bridging the local TheHive system with an external OpenCTI server to synchronize TLP data and Alerts.
* **Shuffle (SOAR):** Security Orchestration, Automation, and Response platform including Frontend, Backend, and Orborus.

---

## Prerequisites

* **Docker** & **Docker Compose** pre-installed.
* **Operating System:** Recommended to run on a Linux environment or WSL2 (Windows).
* **Hardware Configuration:** Minimum **8GB RAM** (16GB+ RAM recommended) to run the remaining containers smoothly.
* **Elasticsearch Credentials:** Since the external Elasticsearch node has `xpack.security.enabled: true`, you must have the valid username and password to allow TheHive, Cortex, and Shuffle to connect.

---

## Installation Guide

### 1. Prepare the directory structure

Create the following directory structure in the same location as the `docker-compose.yml` file so the system maps the configuration files correctly:

```text
.
├── conf/
│   ├── thehive/
│   │   └── application.conf
│   └── cortex/
│       └── application.conf
├── cortex/
│   └── logs/
├── neurons/
├── shuffle-files/
└── docker-compose.yml

```

### 2. Configure Authentication

Because your Elasticsearch requires authentication, ensure you update your `application.conf` (for Cortex and TheHive) and `docker-compose.yml` (for Shuffle) to include your Elasticsearch credentials.

*(For example, Shuffle needs the Elasticsearch URL formatted with credentials: `http://username:password@10.10.10.34:9200`)*.

### 3. Start the system

Open your Terminal / Command Prompt in the project directory and run the following command to pull the images & start all services:

```bash
docker-compose up -d

```

To check the status of the running containers:

```bash
docker-compose ps

```

---

## Access Points

After the system starts successfully, you can access the services via the following ports:

| Service Name | Web Address (Interface) | Notes |
| --- | --- | --- |
| **TheHive** | `http://localhost:9000` | Main incident management platform |
| **Cortex** | `http://localhost:9001` | Observables management and analysis |
| **MinIO Console** | `http://localhost:9003` | File Server management interface (S3) |
| **Shuffle (SOAR)** | `http://localhost:3001` | Drag-and-drop automation workflow interface |
| **Elasticsearch** | `http://10.10.10.34:9200` | External ELK backend (Requires Login) |

> **Note:** If you run the lab on a Virtual Private Server (VPS) or another machine, replace `localhost` with the IP of that server.

---

## Troubleshooting

1. **Docker Socket error on Linux/macOS:** By default, the configuration file uses the Windows standard (`//var/run/docker.sock`). If you are using Linux, change it to `/var/run/docker.sock` in the `docker-compose.yml` file.
2. **Container Crash due to missing config files:** Ensure you have created the two `application.conf` files for TheHive and Cortex before running the `up -d` command. Otherwise, Docker will mistakenly create them as directories, causing startup failures.
3. **Database Connection Errors:** If TheHive or Shuffle keeps restarting, verify that the Elasticsearch credentials provided in your configuration files match the `elastic` user credentials on your `10.10.10.34` node.

---
