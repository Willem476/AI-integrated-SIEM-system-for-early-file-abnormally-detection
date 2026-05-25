
---

# Security Operations Center (SOC) Lab Environment

This project provides a SOC (Security Operations Center) lab environment fully containerized using Docker Compose. The system integrates leading open-source platforms for Security Incident Response, Threat Intelligence, and Security Automation.

## System Components

The system includes the following services:

* **TheHive (v5.2):** Security Incident Response Platform.
* **Cortex:** Automated data collection and analysis platform, tightly integrated with TheHive.
* **Elasticsearch (v7.17.9) & Cassandra (v4):** Database management systems and index storage for TheHive and Shuffle.
* **MinIO:** S3-compatible storage server (used to store attachments for TheHive).
* **OpenCTI - TheHive Connector:** Connector bridging the local TheHive system with an external OpenCTI server to synchronize TLP data and Alerts.
* **Shuffle (SOAR):** Security Orchestration, Automation, and Response platform including Frontend, Backend, and Orborus.

---

## Prerequisites

* **Docker** & **Docker Compose** pre-installed.
* **Operating System:** Recommended to run on a Linux environment or WSL2 (Windows).
* **Hardware Configuration:** Minimum **8GB RAM** (16GB+ RAM recommended) as the Elasticsearch, Cassandra, and TheHive cluster consumes a significant amount of resources.

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

### 2. Start the system

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

After the system starts successfully (it usually takes about 2-3 minutes for the Databases to initialize), you can access the services via the following ports:

| Service Name | Web Address (Interface) | Notes |
| --- | --- | --- |
| **TheHive** | `http://localhost:9000` | Main incident management platform |
| **Cortex** | `http://localhost:9001` | Observables management and analysis |
| **MinIO Console** | `http://localhost:9003` | File Server management interface (S3) |
| **Shuffle (SOAR)** | `http://localhost:3001` | Drag-and-drop automation workflow interface |

> **Note:** If you run the lab on a Virtual Private Server (VPS) or another machine, replace `localhost` with the IP of that server (e.g., `http://10.10.10.34:9000`).

---

## Troubleshooting

1. **Docker Socket error on Linux/macOS:** By default, the configuration file uses the Windows standard (`//var/run/docker.sock`). If you are using Linux, change it to `/var/run/docker.sock` in the `docker-compose.yml` file.
2. **Container Crash due to missing config files:** Ensure you have created the two `application.conf` files for TheHive and Cortex before running the `up -d` command. Otherwise, Docker will mistakenly create them as directories, causing startup failures.
