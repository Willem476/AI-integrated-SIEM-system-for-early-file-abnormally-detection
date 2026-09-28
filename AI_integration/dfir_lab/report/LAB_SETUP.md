# Lab Setup Guide

This guide explains how to build the phishing-to-C2 DFIR lab shown in `dfir_pipeline.png`. The focus is the **defensive / detection-and-response** stack: firewall IDS, SIEM, endpoint telemetry, and automated evidence collection.

> **Isolation is mandatory.** Build this only on a host-only network you own and control. Keep the lab off any production or internet-facing segment. Snapshot every VM before running malware samples.

## 1. Topology

| Host | Role | OS | Network | IP |
|---|---|---|---|---|
| Physical PC | Hypervisor host | Windows + VMware Workstation | Home LAN | 192.168.1.3 |
| pfSense VM | Firewall, NAT, Suricata IDS, packet capture | pfSense CE | WAN (VMware NAT) / LAN (VMnet1) | WAN 192.168.166.131, LAN 10.10.12.2 |
| Windows VM | Victim endpoint (Sysmon, Velociraptor client) | Windows 10/11 | VMnet1 | 10.10.12.20 |
| Ubuntu VM | Elasticsearch + Kibana (existing) | Ubuntu Server 24.04 LTS | VMnet1 | 10.10.12.11 |
| Ubuntu VM | Velociraptor server | Ubuntu Server 24.04 LTS | VMnet1 | 10.10.12.22 |
| Laptop | Attacker / C2 (out of scope here) | Kali Linux | Home LAN | 192.168.1.7 |

Optional pfSense interfaces: OPT1 10.10.13.2 and OPT2 10.10.14.2.

Traffic path under test: Windows VM -> pfSense LAN -> pfSense WAN (NAT) -> host network -> attacker host (192.168.1.7).

### VMware network setup

1. In VMware Workstation, open **Edit > Virtual Network Editor**.
2. Set **VMnet1** to host-only, subnet `10.10.12.0/24`, with the VMware DHCP service disabled (pfSense and static IPs handle addressing).
3. Give the pfSense VM two NICs: NIC 1 on **NAT (VMnet8)** for WAN, NIC 2 on **VMnet1** for LAN.
4. Give every other lab VM a single NIC on **VMnet1**, with gateway and DNS set to `10.10.12.2`.

Reference: [VMware Workstation Pro documentation](https://techdocs.broadcom.com/us/en/vmware-cis/desktop-hypervisors/workstation-pro.html)

## 2. pfSense CE

1. Download the installer from [pfSense CE download](https://www.pfsense.org/download/) (Netgate Installer, AMD64).
2. Follow the [Installation Walkthrough](https://docs.netgate.com/pfsense/en/latest/install/install-walkthrough.html). Allocate 2 vCPU, 2 GB RAM, 20 GB disk.
3. Assign interfaces from the console: WAN on the NAT NIC (DHCP), LAN on the VMnet1 NIC set to `10.10.12.2/24`.
4. Open the web GUI at `https://10.10.12.2`. Default credentials are `admin` / `pfsense`; change them in the setup wizard.
5. Confirm **Firewall > NAT > Outbound** is set to automatic so LAN hosts reach the host network through WAN.
6. On the WAN interface, clear **Block private networks** and **Block bogon networks** (the WAN side is itself a private network here).

References: [Installing and Upgrading](https://docs.netgate.com/pfsense/en/latest/install/index.html), [Download Installation Media](https://docs.netgate.com/pfsense/en/latest/install/download-installer-image.html)

## 3. Suricata on pfSense

1. **System > Package Manager > Available Packages**, install `suricata`.
2. **Services > Suricata > Global Settings**: enable **ETOpen Emerging Threats** rules, set an update interval, then run **Updates > Update**.
3. **Services > Suricata > Interfaces**: add the **LAN** interface. Run Suricata on LAN, not WAN, so each alert keeps the endpoint's real pre-NAT IP (10.10.12.20). That IP is what lets an alert be correlated with the Velociraptor client.
4. In the LAN interface settings:
   - Enable **EVE JSON Log**, **EVE Output Type** = `FILE`.
   - Log alerts plus HTTP, TLS, and DNS metadata for context.
5. **LAN Categories**: enable the ET categories you need (at minimum `emerging-malware`, `emerging-trojan`, `emerging-policy`).
6. Start Suricata on LAN. Alerts are written to `/var/log/suricata/suricata_<LAN_IF><ID>/eve.json`.

> **Note on encrypted C2:** beacons over HTTPS are encrypted, so signature rules often match only on metadata (JA3/JA4 hashes, TLS SNI, destination, timing). Treat the Suricata alert as detection of the **network stage only** — the delivery and execution stages are covered by endpoint telemetry (Sysmon + Velociraptor), not Suricata.

References: [pfSense Package Manager](https://docs.netgate.com/pfsense/en/latest/packages/manager.html), [Suricata EVE JSON output](https://docs.suricata.io/en/latest/output/eve/eve-json-output.html), [Suricata rule format](https://docs.suricata.io/en/latest/rules/intro.html), [pfELK: Suricata on pfSense](https://github.com/pfelk/pfelk/wiki/How-To:-Suricata-on-pfSense)

## 4. Shipping eve.json to Elasticsearch

This assumes the existing Elasticsearch + Kibana stack at `10.10.12.11`. Filebeat does not run on pfSense's FreeBSD base, so alerts are sent with a shell script and `curl` to the Elasticsearch Bulk API.

1. Copy `/etc/elasticsearch/certs/http_ca.crt` from the Elastic VM to `/root/elastic_ca.crt` on pfSense.
2. Create a dedicated Kibana user (**Stack Management > Users**) with write access to `suricata-*`. Do not use `elastic` for ingest.
3. Deploy a shipper script on pfSense (e.g. `/root/scripts/eve_shipper.sh`) that tails new alert lines, wraps them for the Bulk API, and POSTs them:

   ```sh
   #!/bin/sh
   EVE="/var/log/suricata/suricata_<LAN_IF><ID>/eve.json"
   OFFSET_FILE="/root/scripts/.eve_offset"
   ES="https://10.10.12.11:9200/suricata-alerts/_bulk"

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

4. Schedule it every minute: install the `Cron` package, then add the job under **Services > Cron**.
5. In Kibana, create a data view for `suricata-alerts*` with `timestamp` as the time field.

Reference: [Elasticsearch Bulk API](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-bulk)

## 5. Velociraptor server (10.10.12.22)

1. Download the latest `velociraptor-vX.Y.Z-linux-amd64` from [Velociraptor releases](https://github.com/Velocidex/velociraptor/releases).
2. Generate config and build the server package:

   ```bash
   chmod +x velociraptor-*-linux-amd64
   ./velociraptor-*-linux-amd64 config generate -i
   # Choose: Self Signed SSL; public DNS/IP = 10.10.12.22; frontend port 8000; GUI port 8889
   ./velociraptor-*-linux-amd64 debian server --config ./server.config.yaml
   sudo dpkg -i velociraptor_server_*_amd64.deb
   ```

3. In `/etc/velociraptor/server.config.yaml`, set `GUI.bind_address` and `API.bind_address` to `0.0.0.0`, then `sudo systemctl restart velociraptor_server`.
4. Open `https://10.10.12.22:8889`.
5. Create an API client for the automation trigger:

   ```bash
   sudo -u velociraptor velociraptor --config /etc/velociraptor/server.config.yaml \
     config api_client --name dfir_trigger --role administrator,api /etc/velociraptor/api.config.yaml
   ```

References: [Quickstart Guide](https://docs.velociraptor.app/docs/deployment/quickstart/), [Self-Signed SSL deployment](https://docs.velociraptor.app/docs/deployment/self-signed/), [Server Deployment](https://docs.velociraptor.app/docs/deployment/server/), [Security Configuration](https://docs.velociraptor.app/docs/deployment/security/)

## 6. Windows victim endpoint (10.10.12.20)

1. Static IP `10.10.12.20/24`, gateway and DNS `10.10.12.2`.
2. **Sysmon** (built-in feature *or* standalone Sysinternals — they cannot coexist):
   - Built-in (recent Win10/11): `Enable-WindowsOptionalFeature -Online -FeatureName Sysmon`, then `sysmon -i C:\Sysmon\sysmonconfig.xml`
   - Standalone: download from [Sysinternals Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon), then `sysmon64.exe -accepteula -i sysmonconfig.xml`
   - Config: [olafhartong/sysmon-modular](https://github.com/olafhartong/sysmon-modular) maps events to MITRE ATT&CK techniques (e.g. T1036 Masquerading).
3. **Velociraptor client:** in the GUI, run the `Server.Utils.CreateMSI` artifact, download the repacked MSI from **Uploaded Files**, install it as Administrator. The client connects to `https://10.10.12.22:8000`. Confirm it appears under **Search clients**.
4. (Optional) forward Sysmon and Windows event logs into Elastic with [Elastic Agent / Winlogbeat](https://www.elastic.co/docs/reference/beats/winlogbeat) so endpoint telemetry sits alongside the Suricata alerts.

References: [Enable and configure Sysmon in Windows](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/how-to-enable-sysmon), [Velociraptor client deployment](https://docs.velociraptor.app/docs/deployment/clients/)

## 7. Attacker / C2 host (192.168.1.7) — out of scope

The attacker box (Kali running a C2 framework such as Mythic) is what you are **detecting**, so this guide does not reproduce payload build or endpoint-evasion steps. Set it up from the framework's own documentation, on the isolated network only, and only against VMs you own:

- [Mythic C2 official documentation](https://docs.mythic-c2.net/) and [installation guide](https://docs.mythic-c2.net/installation)
- [Kali Linux installation](https://www.kali.org/docs/installation/)

For the detection lab you only need to know the C2 endpoint (192.168.1.7, listener on 443) so you can write the Suricata rule and confirm the beacon appears in the PCAP and endpoint telemetry.

## 8. Automated evidence collection (trigger)

A trigger script watches for new Suricata alerts (tailing `eve.json`, or querying the `suricata-alerts` index) and, on a match, launches two collections in parallel:

- **pfSense:** an alert-triggered `tcpdump` on the LAN interface writing `traffic.pcap`.
- **Velociraptor:** a client collection (via the `dfir_trigger` API client from step 5) that acquires a memory image (`memory.dmp`) and the suspicious file, using artifacts such as `Windows.Memory.Acquisition` and `Windows.Collection.File`.

Per-incident evidence set: `alert.json`, `traffic.pcap`, `memory.dmp`, `suspicious_file`.

References: [Velociraptor VQL / artifacts](https://docs.velociraptor.app/docs/vql/), [tcpdump manual](https://www.tcpdump.org/manpages/tcpdump.1.html)

## 9. Forensic analysis

| Evidence | Tool | Install / docs |
|---|---|---|
| `traffic.pcap` | Wireshark | [wireshark.org](https://www.wireshark.org/download.html) |
| `memory.dmp` | Volatility 3 (`pip install volatility3`) | [volatilityfoundation/volatility3](https://github.com/volatilityfoundation/volatility3), [docs](https://volatility3.readthedocs.io/) |
| `suspicious_file` | Static analysis: hashes, `strings`, PE headers, threat-intel lookup | [pefile](https://github.com/erocarrera/pefile), [YARA](https://virustotal.github.io/yara/), [MITRE ATT&CK](https://attack.mitre.org/) |

Combine the findings with the Elastic endpoint telemetry into an incident report with a timeline and MITRE ATT&CK mapping.

## 10. Recommended build order

1. VMware networks (VMnet1)
2. pfSense (WAN/LAN, NAT)
3. Confirm the existing Elasticsearch + Kibana stack (10.10.12.11) is reachable
4. Suricata + eve.json shipper -> verify alerts land in Kibana
5. Velociraptor server + Windows client + Sysmon
6. Trigger / automation
7. Attacker host, then run one controlled beacon end-to-end and validate every stage
