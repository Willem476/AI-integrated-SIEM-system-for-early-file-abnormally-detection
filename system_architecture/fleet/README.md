# Setting Up Fleet Server: Centrally Managing Endpoint Elastic Agents (No SSL/Certs)

**Fleet Server** is the central command station for your detection infrastructure. Instead of manually SSH-ing into and configuring every single Elastic Agent on your endpoints (like Windows Server 2022 or Linux machines), Fleet Server allows you to centrally manage, update, and push security integrations (policies) to all agents directly from the Kibana web console.

In this guide, we will register and deploy Fleet Server on our Proxmox host. Because our home lab is designed running on plain HTTP without SSL/TLS certificates, we will configure Fleet Server using the explicit `--insecure` flags to successfully connect with our non-encrypted Elasticsearch node.

---

## Step-by-Step Installation Guide

### Step 1: Navigate to the Fleet Console
1. Open your browser and log into **Kibana**.
2. Expand the left navigation menu, scroll down to the **Management** section, and click on **Fleet**.

### Step 2: Add a New Fleet Server Node
1. Inside the Fleet dashboard, click on the **Add Fleet Server** button.
2. Select **Advanced** or choose **Add a new Fleet Server**.
3. Provide a recognizable name for your Fleet Server (e.g., `HomeLab-Fleet-Server`).
4. Under the **URLs** field, specify the HTTPS path using your host's IP address:
   ```text
   https://<YOUR_HOST_IP>:8220
   ```
5. Click **Continue**.

### Step 3: Generate the Service Token & Installation Command
1. Select the operating system of your Proxmox VM host (e.g., **Linux Tar** or **Debian** package depending on your environment).
2. Kibana will generate a command block to execute. **Do not copy it directly yet**, as the default command expects an HTTPS connection.

### Step 4: Execute the Patched Installation Command (No-Cert Adjustment)
To allow Fleet Server to install and talk to Elasticsearch without certificates, you need to append the `--insecure` flags to the generated command. 

Open your host terminal via SSH and execute the installation command structured as example follows:

```bash
curl -L -O https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-8.19.13-linux-x86_64.tar.gz
tar xzvf elastic-agent-8.19.13-linux-x86_64.tar.gz
cd elastic-agent-8.19.13-linux-x86_64
sudo ./elastic-agent install \
  --fleet-server-es=http://<YOUR_HOST_IP>:9200 \
  --fleet-server-service-token=<YOUR_GENERATED_FLEET_TOKEN>\
  --fleet-server-policy=fleet-server-policy \
  --fleet-server-port=8220 \
  --insecure
```

#### Key Flags Explained for This Lab:
* `--insecure` Bypasses all SSL certificate validation errors when connecting back to the Elasticsearch core.

### Step 5: Confirm the Connection
Once you run the command in your host terminal, wait a couple of minutes and look back at the Kibana web interface. 

Under the **Confirm connection** block, as soon as the status message transitions and displays **`Fleet Server connected`**, your deployment is officially complete! Your home lab infrastructure is now fully prepared to enroll and orchestrate endpoint agents.
