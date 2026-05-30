# Setting Up Kibana: The Visualization Interface of the ELK Stack (No SSL/Certs)

**Kibana** is the window into your ELK Stack. It is a powerful frontend application that allows you to search, analyze, and visualize the log data indexed in Elasticsearch. 

With Kibana, you can transform millions of raw, dry log lines into dynamic, interactive dashboards and graphs, making threat hunting, system monitoring, and incident investigation significantly faster and more intuitive.

In this guide, we will install Kibana on the same Proxmox VM alongside Elasticsearch and configure them to communicate over standard HTTP without SSL/TLS certificates for a simplified home lab experience.

---

## Step-by-Step Installation Guide

### Step 1: Install the Kibana Package
Since we are installing Kibana on the same VM host as Elasticsearch, the Elastic repository and GPG signing keys are already configured. You can install Kibana directly with a single command:

```bash
sudo apt install kibana -y
```
*(If you are deploying Kibana on a separate dedicated VM, you must replicate **Step 1: Add the Elastic Repository** from the Elasticsearch build guide first before running the install command).*

### Step 2: Configure Kibana (No-Cert Setup)
Open the main Kibana configuration file using `nano`:
```bash
sudo nano /etc/kibana/kibana.yml
```

Locate and adjust the configuration parameters to match your home lab environment. We will explicitly point Kibana to our host IP, turn off SSL, and establish a connection to Elasticsearch:

```yaml
# Kibana is web server, so we specify its listening port (Default is 5601)
server.port: 5601

# Allow connections from any IP interface on the host machine
server.host: "0.0.0.0"

# The public URL that users will use to access the Kibana interface
server.publicBaseUrl: "http://<YOUR_HOST_IP>:5601"

# The URL of the Elasticsearch instance Kibana will query
elasticsearch.hosts: ["http://<YOUR_HOST_IP>:9200"]

```

Next, to authenticate Kibana with Elasticsearch, we have two approaches. Choose **one** of the methods below:

#### Option A: Using Elasticsearch Service Account Token (Recommended & More Secure)
Instead of hardcoding a raw password, generate a secure service token on your Elasticsearch node by running:
```bash
sudo /usr/share/elasticsearch/bin/elasticsearch-service-tokens create elastic/kibana kibana_token
```
Copy the generated token string, uncomment the following line in `kibana.yml`, and paste your token:
```yaml
elasticsearch.serviceAccountToken: "YOUR_GENERATED_TOKEN_HERE"
```

#### Option B: Hardcoding Plain-Text Credentials (Simplified for Lab Environments Only)
Alternatively, you can manually input the default `elastic` superuser credentials directly into the config file:
```yaml
elasticsearch.username: "elastic"
elasticsearch.password: "YOUR_ELASTIC_USER_PASSWORD"
```

*(Save and exit nano: Press `CTRL+X`, then type `Y`, and press `Enter`)*

### Step 3: Start and Enable the Service
Configure Kibana to start automatically when the host boots up, then start the service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable kibana
sudo systemctl start kibana
```

Verify that the service is running correctly:
```bash
sudo systemctl status kibana
```
> *If you see **`Active: active (running)`** in the output, you are good to go!*

### Step 4: Access the Web Interface
Open your favorite web browser and navigate to your Kibana portal:
```text
http://<YOUR_HOST_IP>:5601
```
Log in using the `elastic` username and the password you configured during the Elasticsearch installation. Welcome to your central SOC dashboard!
