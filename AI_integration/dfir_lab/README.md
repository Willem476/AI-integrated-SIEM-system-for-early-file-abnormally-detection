# Phishing-to-C2 DFIR Lab

An extension of the AI-integrated SIEM that covers the network stage of an intrusion. A phishing attachment runs on a Windows endpoint and opens a C2 channel. Suricata on pfSense detects the C2 traffic, the alert lands in Elasticsearch, and an automation script triggers memory acquisition on the endpoint through Velociraptor. The evidence is then analyzed offline with Wireshark and Volatility 3.

![DFIR Pipeline](dfir_pipeline.png)

## Scope

The Suricata alert is treated as detection of the C2 (network) stage only. It is not equivalent to phishing detection. The email, attachment and execution stages are left to endpoint telemetry (Sysmon through Elastic Agent, and Velociraptor).

## Lab topology

The lab runs on two physical machines: one PC hosts pfSense and the lab VMs, and a separate laptop hosts the C2 server.

| Component | Address | Role |
|---|---|---|
| pfSense (LAN) | 10.10.12.2 | Firewall, Suricata IDS on the LAN interface |
| pfSense (WAN) | 192.168.166.131 | Upstream interface |
| pfSense (OPT1 / OPT2) | 10.10.13.2 / 10.10.14.2 | Additional lab segments |
| Windows VM | 10.10.12.20 | Victim endpoint, Sysmon, Velociraptor client |
| Ubuntu VM | 10.10.12.11 | Elasticsearch / Kibana |
| Velociraptor server | 10.10.12.22 | Endpoint collection, gRPC API on port 8001 |
| Kali (separate laptop) | 192.168.1.7 | Mythic C2 server, HTTP listener on port 443 |

The victim, pfSense LAN, Elasticsearch and Velociraptor share the VMnet1 subnet (10.10.12.0/24).

Suricata listens on the LAN interface rather than WAN, so alerts carry the endpoint's real pre-NAT IP address. This lets the alert be correlated directly with the Velociraptor client and with Sysmon events on the endpoint.

### VMware network setup

1. In VMware Workstation, open **Edit > Virtual Network Editor**.
2. Set **VMnet1** to host-only, subnet `10.10.12.0/24`, with the VMware DHCP service disabled (pfSense and static IPs handle addressing).
3. Give the pfSense VM two NICs: NIC 1 on **NAT (VMnet8)** for WAN, NIC 2 on **VMnet1** for LAN.
4. Give every other lab VM a single NIC on **VMnet1**, with gateway and DNS set to `10.10.12.2`.

Reference: [VMware Workstation Pro documentation](https://techdocs.broadcom.com/us/en/vmware-cis/desktop-hypervisors/workstation-pro.html)

## Detection and response pipeline

```
Windows VM (victim) --C2--> pfSense + Suricata
                                 |
                                 | eve.json (shell script + curl, Elasticsearch Bulk API)
                                 v
                           Elasticsearch  (index: suricata-eve*)
                                 |
                                 | poll alerts where src_ip or dest_ip = victim
                                 v
                    suricata_velociraptor.py
                                 |
                                 | gRPC + mTLS: collect_client(Windows.Memory.Acquisition)
                                 v
                        Velociraptor server  --->  memory image of the victim
```

1. The malicious attachment executes on the Windows VM and beacons to the Mythic C2 server.
2. Suricata on pfSense matches the C2 traffic and writes an alert to `eve.json`.
3. A shell script on pfSense posts `eve.json` events to the Elasticsearch Bulk API. Filebeat was ruled out because it is not supported on the FreeBSD base of pfSense.
4. `suricata_velociraptor.py` polls Elasticsearch for new alerts involving the victim IP.
5. On a new alert, the script resolves the Velociraptor client by IP and starts `Windows.Memory.Acquisition`.
6. The script tracks the flow until it finishes, fails or times out, and records every step in `incidents.jsonl`.
7. Packet capture for the incident is taken on pfSense with `tcpdump`, started by the trigger process when the alert fires.

## Evidence set

Each incident produces:

| File | Source | Analysis tool |
|---|---|---|
| `alert.json` | Suricata EVE alert | Kibana / jq |
| `traffic.pcap` | pfSense tcpdump | Wireshark |
| `memory.dmp` (`PhysicalMemory.dd`) | Velociraptor `Windows.Memory.Acquisition` | Volatility 3 |
| `suspicious_file` | Extracted from memory or disk | Static analysis, hash lookup |

---

# Build guide

Every component below is installed from its official source. Follow the order in [Recommended build order](#recommended-build-order) at the end.

## 1. pfSense CE

1. Download the installer from [pfSense CE download](https://www.pfsense.org/download/) (Netgate Installer, AMD64).
2. Follow the [Installation Walkthrough](https://docs.netgate.com/pfsense/en/latest/install/install-walkthrough.html). Allocate 2 vCPU, 2 GB RAM, 20 GB disk.
3. Assign interfaces from the console: WAN on the NAT NIC (DHCP), LAN on the VMnet1 NIC set to `10.10.12.2/24`.
4. Open the web GUI at `https://10.10.12.2`. Default credentials are `admin` / `pfsense`; change them in the setup wizard.
5. Confirm **Firewall > NAT > Outbound** is set to automatic so LAN hosts reach the host network through WAN.
6. On the WAN interface, clear **Block private networks** and **Block bogon networks** (the WAN side is itself a private network here).

References: [Installing and Upgrading](https://docs.netgate.com/pfsense/en/latest/install/index.html), [Download Installation Media](https://docs.netgate.com/pfsense/en/latest/install/download-installer-image.html)

## 2. Suricata on pfSense

1. **System > Package Manager > Available Packages**, install `suricata`.
2. **Services > Suricata > Global Settings**: enable **ETOpen Emerging Threats** rules, set an update interval, then run **Updates > Update**.
3. **Services > Suricata > Interfaces**: add the **LAN** interface. Running on LAN (not WAN) is what preserves the endpoint's real pre-NAT IP (10.10.12.20) in each alert.
4. In the LAN interface settings:
   - Enable **EVE JSON Log**, **EVE Output Type** = `FILE`.
   - Log alerts plus HTTP, TLS, and DNS metadata for context.
5. **LAN Categories**: enable the ET categories you need (at minimum `emerging-malware`, `emerging-trojan`, `emerging-policy`).
6. Start Suricata on LAN. Alerts are written to `/var/log/suricata/suricata_<LAN_IF><ID>/eve.json`.

> **Encrypted C2:** beacons over HTTPS are encrypted, so signature rules often match only on metadata (JA3/JA4 hashes, TLS SNI, destination, timing). This is consistent with the scope above — Suricata covers the network stage, endpoint telemetry covers delivery and execution.

References: [pfSense Package Manager](https://docs.netgate.com/pfsense/en/latest/packages/manager.html), [Suricata EVE JSON output](https://docs.suricata.io/en/latest/output/eve/eve-json-output.html), [Suricata rule format](https://docs.suricata.io/en/latest/rules/intro.html), [pfELK: Suricata on pfSense](https://github.com/pfelk/pfelk/wiki/How-To:-Suricata-on-pfSense)

## 3. Shipping eve.json to Elasticsearch

This assumes the existing Elasticsearch + Kibana stack at `10.10.12.11`. Filebeat does not run on pfSense's FreeBSD base, so alerts are sent with a shell script and `curl` to the Elasticsearch Bulk API, into the `suricata-eve*` index that the trigger script polls.

1. If Elasticsearch runs with TLS, copy `/etc/elasticsearch/certs/http_ca.crt` from the Elastic VM to `/root/elastic_ca.crt` on pfSense.
2. Create a dedicated Kibana user (**Stack Management > Users**) with write access to `suricata-eve*`. Do not use `elastic` for ingest.
3. Deploy a shipper script on pfSense (e.g. `/root/scripts/eve_shipper.sh`) that tails new alert lines, wraps them for the Bulk API, and POSTs them:

   ```sh
   #!/bin/sh
   EVE="/var/log/suricata/suricata_<LAN_IF><ID>/eve.json"
   OFFSET_FILE="/root/scripts/.eve_offset"
   ES="https://10.10.12.11:9200/suricata-eve/_bulk"

   LAST=$(cat "$OFFSET_FILE" 2>/dev/null || echo 0)
   TOTAL=$(wc -l < "$EVE" | tr -d ' ')
   [ "$TOTAL" -lt "$LAST" ] && LAST=0          # log rotated

   tail -n +$((LAST + 1)) "$EVE" | head -n $((TOTAL - LAST)) \
     | grep '"event_type":"alert"' \
     | awk '{print "{\"index\":{}}"; print}' > /tmp/eve_bulk.ndjson

   if [ -s /tmp/eve_bulk.ndjson ]; then
     curl -s --cacert /root/elastic_ca.crt -u "<USER>:<PASSWORD>" \
       -H "Content-Type: application/x-ndjson" \
       -X POST "$ES" --data-binary @/tmp/eve_bulk.ndjson > /dev/null
   fi
   echo "$TOTAL" > "$OFFSET_FILE"
   ```

   If your Elasticsearch runs without TLS (the trigger's `base_url` is `http://10.10.12.11:9200`), drop `--cacert` and use the `http://` URL.

4. Schedule it every minute: install the `Cron` package, then add the job under **Services > Cron**.
5. In Kibana, create a data view for `suricata-eve*` with `timestamp` as the time field.

Reference: [Elasticsearch Bulk API](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-bulk)

## 4. Velociraptor server (10.10.12.22)

1. Download the latest `velociraptor-vX.Y.Z-linux-amd64` from [Velociraptor releases](https://github.com/Velocidex/velociraptor/releases).
2. Generate config and build the server package:

   ```bash
   chmod +x velociraptor-*-linux-amd64
   ./velociraptor-*-linux-amd64 config generate -i
   # Self Signed SSL; public DNS/IP = 10.10.12.22
   # Frontend (client) port 8000; GUI port 8889; API (gRPC) port 8001
   ./velociraptor-*-linux-amd64 debian server --config ./server.config.yaml
   sudo dpkg -i velociraptor_server_*_amd64.deb
   ```

3. In `/etc/velociraptor/server.config.yaml`, set the `GUI`, `Frontend` and `API` bind addresses to `0.0.0.0` as needed for the lab subnet, then `sudo systemctl restart velociraptor_server`.
4. Open `https://10.10.12.22:8889`.
5. Create the API client used by the trigger script (`api.config.yaml`, gRPC on port 8001):

   ```bash
   sudo -u velociraptor velociraptor --config /etc/velociraptor/server.config.yaml \
     config api_client --name soar --role administrator,api /etc/velociraptor/api.config.yaml
   ```

   `api.config.yaml` contains the client private key — do not commit it.

References: [Quickstart Guide](https://docs.velociraptor.app/docs/deployment/quickstart/), [Self-Signed SSL deployment](https://docs.velociraptor.app/docs/deployment/self-signed/), [Server Deployment](https://docs.velociraptor.app/docs/deployment/server/), [Security Configuration](https://docs.velociraptor.app/docs/deployment/security/)

## 5. Windows victim endpoint (10.10.12.20)

1. Static IP `10.10.12.20/24`, gateway and DNS `10.10.12.2`.
2. **Sysmon** (built-in feature *or* standalone Sysinternals — they cannot coexist):
   - Built-in (recent Win10/11): `Enable-WindowsOptionalFeature -Online -FeatureName Sysmon`, then `sysmon -i C:\Sysmon\sysmonconfig.xml`
   - Standalone: download from [Sysinternals Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon), then `sysmon64.exe -accepteula -i sysmonconfig.xml`
   - Config: [olafhartong/sysmon-modular](https://github.com/olafhartong/sysmon-modular) maps events to MITRE ATT&CK techniques (e.g. T1036 Masquerading).
3. **Velociraptor client:** in the GUI, run the `Server.Utils.CreateMSI` artifact, download the repacked MSI from **Uploaded Files**, install it as Administrator. The client connects to the frontend at `https://10.10.12.22:8000`. Confirm it appears under **Search clients**.
4. (Optional) forward Sysmon and Windows event logs into Elastic with [Elastic Agent / Winlogbeat](https://www.elastic.co/docs/reference/beats/winlogbeat) so endpoint telemetry sits alongside the Suricata alerts.

References: [Enable and configure Sysmon in Windows](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/how-to-enable-sysmon), [Velociraptor client deployment](https://docs.velociraptor.app/docs/deployment/clients/)

## 6. Attacker / C2 host (192.168.1.7) — out of scope

The attacker box (Kali running Mythic C2) is what you are **detecting**, so this guide does not reproduce payload build or endpoint-evasion steps. Set it up from the framework's own documentation, on the isolated network only, and only against VMs you own:

- [Mythic C2 official documentation](https://docs.mythic-c2.net/) and [installation guide](https://docs.mythic-c2.net/installation)
- [Kali Linux installation](https://www.kali.org/docs/installation/)

For the detection lab you only need the C2 endpoint (192.168.1.7, HTTP listener on 443) to write the Suricata rule and confirm the beacon appears in the PCAP and endpoint telemetry.

---

# Automation and analysis

## Trigger script: suricata_velociraptor.py

### Requirements

```bash
pip3 install pyvelociraptor grpcio requests pyyaml
```

An API client configuration is required from the Velociraptor server (see build step 4):

```bash
velociraptor --config server.config.yaml config api_client \
    --name soar --role administrator api.config.yaml
```

Place `api.config.yaml` next to the script. It contains the client private key, so do not commit it.

### Configuration

Edit the `CONFIG` dictionary at the top of the script:

| Key | Default | Description |
|---|---|---|
| `elasticsearch.base_url` | `http://10.10.12.11:9200` | Elasticsearch endpoint |
| `elasticsearch.index` | `suricata-eve*` | Index written by the pfSense shipper |
| `victim_ip` | `10.10.12.20` | Only alerts involving this IP are handled |
| `max_severity` | `None` | Set to 1 or 2 to handle only high-severity alerts |
| `velociraptor.api_endpoint` | `10.10.12.22:8001` | Velociraptor gRPC API |
| `velociraptor.artifact` | `Windows.Memory.Acquisition` | Artifact collected on alert |
| `cooldown_minutes` | `30` | New alerts in this window are attached to the open incident instead of triggering another acquisition |
| `flow_timeout_minutes` | `45` | Flows running longer are marked TIMEOUT |

### Usage

```bash
python3 suricata_velociraptor.py --test      # check Elasticsearch, Velociraptor API and client lookup
python3 suricata_velociraptor.py --dry-run   # full loop without triggering acquisition
python3 suricata_velociraptor.py --once      # single cycle
python3 suricata_velociraptor.py             # continuous mode
```

### Incident log

`incidents.jsonl` records one JSON object per event: `TRIGGERED`, `ALERT_ATTACHED`, `FINISHED`, `ERROR`, `TIMEOUT`, `TRIGGER_FAILED`, `DRY_RUN`. Each record carries the incident ID, the Velociraptor flow ID and the Suricata alert summary (signature, source and destination, `flow_id`, `community_id`), which links the network alert to the memory image.

## Memory acquisition record

Metadata of a collected image from `Windows.Memory.Acquisition`:

| Field | Value |
|---|---|
| Stored name | `PhysicalMemory.dd` |
| Size | 5,368,709,120 bytes (5 GiB) |
| SHA256 | `efa461225a760f95244952188a3c442531cad117a59598ea0701ac855108f8fd` |
| MD5 | `fb357c6474c4b42b8a528fd2d06c90de` |
| NtBuildNumber | 17763 (Windows Server 2019 / Windows 10 1809) |
| Temporary image on endpoint | `C:\Windows\TEMP\tmp523269964.pmem` |

The physical memory runs add up to 4,293,959,680 bytes. The image is 5 GiB because the physical address space extends to `0x140000000` and the gaps are zero-filled.

The temporary `.pmem` file is an artifact created by the acquisition itself and should be noted in the report.

Verify the image before analysis:

```bash
sha256sum PhysicalMemory.dd                        # Linux
Get-FileHash PhysicalMemory.dd -Algorithm SHA256   # Windows
```

The hash shown in the Velociraptor download panel is the hash of the exported ZIP, not of the memory image.

## Analysis workflow

### Network (Wireshark)

A PCAP does not contain process or file names. It identifies the C2 endpoint through:

- DNS queries: `dns`
- TLS SNI: `tls.handshake.type == 1`
- HTTP requests: `http.request` (Host, URI, User-Agent)
- TLS certificates and JA3/JA4 fingerprints, which help identify the C2 framework
- Beacon timing and packet size regularity

### Memory (Volatility 3)

Install: `pip install volatility3` ([docs](https://volatility3.readthedocs.io/), [repo](https://github.com/volatilityfoundation/volatility3)).

Correlation path: C2 IP and timestamp from the alert or PCAP, then `netscan` for the PID, then `pstree` and `cmdline` for the process name and path, then `dumpfiles` for the binary.

```bash
vol -f PhysicalMemory.dd windows.info
vol -f PhysicalMemory.dd windows.netscan
vol -f PhysicalMemory.dd windows.pstree
vol -f PhysicalMemory.dd windows.cmdline  --pid <PID>
vol -f PhysicalMemory.dd windows.dlllist  --pid <PID>
vol -f PhysicalMemory.dd windows.handles  --pid <PID>
vol -f PhysicalMemory.dd windows.malfind  --pid <PID>
vol -f PhysicalMemory.dd -o dump windows.dumpfiles --pid <PID>
```

Notes:

- `ImageFileName` in `pslist` and `pstree` is truncated to 15 characters. Use `cmdline` or `dlllist` for the full name and path.
- The image also contains the legitimate Velociraptor client and the acquisition process. Use the PID that owns the connection to the C2 IP to tell them apart.
- On Windows, set `PYTHONUTF8=1` before piping Volatility output. Otherwise the cp1252 console encoding fails on Unicode file names.
- Save `filescan` output to a file once and search the file, since the plugin scans the whole image.

### Endpoint telemetry

- Sysmon Event ID 1 (process creation) and Event ID 3 (network connection) give the image path and PID for the C2 connection.
- Velociraptor `Windows.Network.Netstat` gives the live PID to connection mapping.
- In this lab, Sysmon flagged a process masquerading as ScreenConnect as MITRE ATT&CK T1036 (Masquerading) while connecting to the C2 domain.

## MITRE ATT&CK coverage

| Stage | Technique | Detection source |
|---|---|---|
| Initial access | T1566.001 Spearphishing Attachment | Endpoint telemetry |
| Execution | T1204.002 Malicious File | Sysmon Event ID 1 |
| Defense evasion | T1036 Masquerading | Sysmon |
| Command and control | T1071.001 Web Protocols | Suricata on pfSense |

---

## Recommended build order

1. VMware networks (VMnet1)
2. pfSense (WAN/LAN, NAT)
3. Confirm the existing Elasticsearch + Kibana stack (10.10.12.11) is reachable
4. Suricata + eve.json shipper -> verify alerts land in Kibana (`suricata-eve*`)
5. Velociraptor server + Windows client + Sysmon
6. `suricata_velociraptor.py` trigger + tcpdump automation (test with `--test`, then `--dry-run`)
7. Attacker host, then run one controlled beacon end-to-end and validate every stage
