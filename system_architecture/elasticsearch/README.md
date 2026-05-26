# Setting Up Elasticsearch: The Storage Core of the ELK Stack (No SSL/Certs)

To put it simply, **Elasticsearch** is the central repository where all logs sent from Beats or Elastic Agents are stored. Its core mission is to index, categorize, and filter massive amounts of log data with lightning speed and high efficiency.

In this guide, we will install Elasticsearch and Kibana on a single Virtual Machine hosted on Proxmox (a Type 1 Hypervisor, whereas VMware Workstation is a Type 2 Hypervisor). 

*Note: For the sake of simplicity in this home lab, this installation will explicitly disable SSL/TLS certificates.*

---

## Step-by-Step Installation Guide

### Step 1: Add the Elastic Repository
You can follow the instructions at the [Elasticsearch official website](https://www.elastic.co/docs/deploy-manage/deploy/self-managed/install-elasticsearch-with-debian-package) or follow the steps below.

First, download and install the Elastic public GPG signing key:
```bash
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
```

Install the `apt-transport-https` package to allow accessing repositories over HTTPS:
```bash
sudo apt-get install apt-transport-https -y 
```

Add the Elasticsearch repository to your system (Using 8.x branch):
```bash
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/9.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-9.x.list
```

Update your package lists and install Elasticsearch:
```bash
sudo apt-get update
sudo apt-get install elasticsearch -y
```

### Step 2: Configure Elasticsearch (No-Cert Setup)
Open the main configuration file using `nano`:
```bash
sudo nano /etc/elasticsearch/elasticsearch.yml
```

Locate and modify the network settings, and explicitly disable SSL to allow the service to start without certificates:
```yaml
# Set the bind address to your VM's IP address (or 0.0.0.0 to listen on all interfaces)
network.host: <YOUR_MACHINE_IP>
http.port: 9200

# Explicitly disable SSL/Certs 
xpack.security.http.ssl:
  enabled: false
  keystore.path: certs/http.p12
```
*(Save and exit nano: Press `CTRL+X`, then type `Y`, and press `Enter`)*

### Step 3: Start and Enable the Service
Configure Elasticsearch to start automatically when the host boots up, then start the service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable elasticsearch
sudo systemctl start elasticsearch
```

Verify that the service is running correctly:
```bash
sudo systemctl status elasticsearch
```
> *If you see **`Active: active (running)`** in the output, you are good to go!*

### Step 4: Reset the Default User Password
Even without SSL certificates, we must secure the default `elastic` superuser account. Navigate to the Elasticsearch binary directory and run the password reset tool interactively:

```bash
cd /usr/share/elasticsearch/bin 
sudo ./elasticsearch-reset-password -u elastic -i 
```
When prompted, type in and confirm the new password you want to assign to the `elastic` user. Keep this password safe, as you will need it later to connect Kibana and other components to your Elasticsearch node.
