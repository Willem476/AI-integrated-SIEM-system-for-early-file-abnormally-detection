# Phishing-to-C2 DFIR Lab

An extension of the AI-integrated SIEM that covers the network stage of an intrusion. A phishing attachment runs on a Windows endpoint and opens a C2 channel. Suricata on pfSense detects the C2 traffic, the alert lands in Elasticsearch, and an automation script triggers memory acquisition on the endpoint through Velociraptor. The evidence is then analyzed offline with Wireshark and Volatility 3.

## Scope

The Suricata alert is treated as detection of the C2 (network) stage only. It is not equivalent to phishing detection. The email, attachment and execution stages are left to endpoint telemetry (Sysmon through Elastic Agent, and Velociraptor).

## Lab topology

The lab runs on two physical machines: one PC hosts pfSense and the lab VMs, and a separate laptop hosts the C2 server.

| Component | Address | Role |
|---|---|---|
| pfSense (LAN) | 10.10.12.2 | Firewall, Suricata IDS on the LAN interface |
| pfSense (WAN) | 192.168.1.7 | Upstream interface |
| pfSense (OPT1 / OPT2) | 10.10.13.2 / 10.10.14.2 | Additional lab segments |
| Windows VM | 10.10.12.20 | Victim endpoint, Sysmon, Velociraptor client |
| Ubuntu VM | 10.10.12.11 | Elasticsearch / Kibana |
| Velociraptor server | 10.10.12.22 | Endpoint collection, gRPC API on port 8001 |
| Kali (separate laptop) | 192.168.87.128 | Mythic C2 server, HTTP listener on port 443 |

The victim, pfSense LAN, Elasticsearch and Velociraptor share the VMnet1 subnet (10.10.12.0/24).

Suricata listens on the LAN interface rather than WAN, so alerts carry the endpoint's real pre-NAT IP address. This lets the alert be correlated directly with the Velociraptor client and with Sysmon events on the endpoint.

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

## Trigger script: suricata_velociraptor.py

### Requirements

```bash
pip3 install pyvelociraptor grpcio requests pyyaml
```

An API client configuration is required from the Velociraptor server:

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
