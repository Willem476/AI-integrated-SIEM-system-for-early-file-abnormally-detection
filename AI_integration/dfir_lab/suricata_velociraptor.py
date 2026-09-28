#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Suricata alert -> Velociraptor memory acquisition
=================================================
- Polls Suricata alerts (event_type=alert) from Elasticsearch
- Only handles alerts where src_ip or dest_ip is the victim host
- Triggers the Velociraptor artifact Windows.Memory.Acquisition on the victim client
- Tracks the flow until FINISHED/ERROR/TIMEOUT and records the incident in incidents.jsonl
- The memory image stays on the Velociraptor server and is downloaded from the GUI

Requirements (on the host running this script):
    pip3 install pyvelociraptor grpcio requests pyyaml

Usage:
    python3 suricata_velociraptor.py --test      # Test Elasticsearch, Velociraptor API and client lookup, then exit
    python3 suricata_velociraptor.py --dry-run   # Run the full loop without triggering acquisition
    python3 suricata_velociraptor.py             # Real-time mode
    python3 suricata_velociraptor.py --once      # Run a single cycle, then exit
"""

import argparse
import json
import signal
import sys
import time
from datetime import datetime, timezone

import grpc
import requests
import urllib3
import yaml
from pyvelociraptor import api_pb2, api_pb2_grpc

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ============================================================
# Configuration
# ============================================================
CONFIG = {
    'elasticsearch': {
        'base_url': 'http://10.10.12.11:9200',
        'index': 'suricata-eve*',          # index written by the bulk-upload script on pfSense
        'time_field': '@timestamp',        # time field of the suricata-eve data view (may be 'timestamp')
        'username': '',                     # leave empty if Elasticsearch security is disabled
        'password': '',
        'verify_ssl': False,
        'batch_size': 500,
    },

    'victim_ip': '10.10.12.20',
    # None = every alert. Set to 1 or 2 to keep only high-severity alerts (Suricata: 1 = highest)
    'max_severity': None,

    'velociraptor': {
        'api_config': 'api.config.yaml',
        # Overrides api_connection_string in api.config.yaml (default 127.0.0.1:8001).
        # Leave empty to use the value from the file. When running from another host, use '10.10.12.22:8001'.
        'api_endpoint': '10.10.12.22:8001',
        'server_name': 'VelociraptorServer',   # CN/SAN of the Frontend certificate
        'artifact': 'Windows.Memory.Acquisition',
        'client_id': '',                       # empty = resolve by victim_ip; or set C.xxxxxxxx explicitly
        'datastore_hint': r'C:\Windows\Temp',  # Datastore.location in server.config.yaml
    },

    'poll_interval': 15,          # seconds between Elasticsearch polls
    'cooldown_minutes': 30,       # do not acquire the same client again within this window
    'flow_timeout_minutes': 45,   # mark the flow as TIMEOUT if it has not finished by then
    'incident_log': 'incidents.jsonl',
}


def get_field(src, path, default=None):
    """Read a field from _source; supports nested (alert: {signature}) and flat ('alert.signature') layouts."""
    if path in src:
        return src[path]
    cur = src
    for key in path.split('.'):
        if isinstance(cur, dict) and key in cur:
            cur = cur[key]
        else:
            return default
    return cur


def now_iso():
    return datetime.now(timezone.utc).isoformat()


# ============================================================
# Elasticsearch - Suricata alerts
# ============================================================
class SuricataAlertSource:
    def __init__(self, cfg, victim_ip, max_severity):
        self.base_url = cfg['base_url'].rstrip('/')
        self.index = cfg['index']
        self.verify_ssl = cfg['verify_ssl']
        self.batch_size = cfg['batch_size']
        self.time_field = cfg.get('time_field', '@timestamp')
        self.victim_ip = victim_ip
        self.max_severity = max_severity
        self.session = requests.Session()
        self.session.headers.update({'Content-Type': 'application/json'})
        if cfg.get('username'):
            self.session.auth = (cfg['username'], cfg['password'])

    def test(self):
        try:
            r = self.session.get(f'{self.base_url}/{self.index}/_count',
                                 json={"query": {"term": {"event_type": "alert"}}},
                                 verify=self.verify_ssl, timeout=10)
            if r.status_code == 200:
                print(f"   [OK] Elasticsearch: {r.json().get('count', 0):,} alerts in '{self.index}'")
                return True
            print(f"   [FAIL] Elasticsearch HTTP {r.status_code}: {r.text[:200]}")
        except Exception as e:
            print(f"   [FAIL] Elasticsearch error: {e}")
        return False

    def pull(self, since_ms):
        """Return (hits, new_cursor). The cursor is the epoch-millis value of the newest timestamp seen."""
        filters = [
            {"term": {"event_type": "alert"}},
            {"range": {self.time_field: {"gt": since_ms, "format": "epoch_millis"}}},
            {"bool": {
                "should": [
                    {"match": {"src_ip": {"query": self.victim_ip, "operator": "and"}}},
                    {"match": {"dest_ip": {"query": self.victim_ip, "operator": "and"}}},
                ],
                "minimum_should_match": 1,
            }},
        ]
        if self.max_severity is not None:
            filters.append({"range": {"alert.severity": {"lte": self.max_severity}}})

        query = {
            "size": self.batch_size,
            "sort": [{self.time_field: {"order": "asc"}}],
            "query": {"bool": {"filter": filters}},
        }
        try:
            r = self.session.post(f'{self.base_url}/{self.index}/_search', json=query,
                                  verify=self.verify_ssl, timeout=30)
            if r.status_code != 200:
                print(f"   [FAIL] ES query HTTP {r.status_code}: {r.text[:200]}")
                return [], since_ms
            hits = r.json().get('hits', {}).get('hits', [])
        except Exception as e:
            print(f"   [FAIL] ES query error: {e}")
            return [], since_ms

        # Advance the cursor over ALL returned hits (including ones filtered out below) so they are not re-queried
        new_cursor = since_ms
        for h in hits:
            if h.get('sort'):
                new_cursor = max(new_cursor, int(h['sort'][0]))

        # Exact re-check in Python, in case a text mapping makes the match query too loose
        hits = [h for h in hits
                if self.victim_ip in (get_field(h['_source'], 'src_ip'), get_field(h['_source'], 'dest_ip'))]
        return hits, new_cursor

    @staticmethod
    def summarize(hit):
        s = hit['_source']
        return {
            'es_id': hit.get('_id'),
            'timestamp': get_field(s, 'timestamp') or get_field(s, '@timestamp'),
            'signature': get_field(s, 'alert.signature'),
            'signature_id': get_field(s, 'alert.signature_id'),
            'severity': get_field(s, 'alert.severity'),
            'category': get_field(s, 'alert.category'),
            'src': f"{get_field(s, 'src_ip')}:{get_field(s, 'src_port')}",
            'dest': f"{get_field(s, 'dest_ip')}:{get_field(s, 'dest_port')}",
            'proto': get_field(s, 'proto'),
            'app_proto': get_field(s, 'app_proto'),
            'suricata_flow_id': get_field(s, 'flow_id'),
            'community_id': get_field(s, 'community_id'),
        }


# ============================================================
# Velociraptor API client (gRPC + mTLS)
# ============================================================
class VelociraptorAPI:
    def __init__(self, cfg):
        with open(cfg['api_config'], 'r', encoding='utf-8') as f:
            api = yaml.safe_load(f)
        creds = grpc.ssl_channel_credentials(
            root_certificates=api['ca_certificate'].encode('utf-8'),
            private_key=api['client_private_key'].encode('utf-8'),
            certificate_chain=api['client_cert'].encode('utf-8'),
        )
        options = (('grpc.ssl_target_name_override', cfg['server_name']),)
        self.endpoint = cfg.get('api_endpoint') or api['api_connection_string']
        self.channel = grpc.secure_channel(self.endpoint, creds, options)
        self.stub = api_pb2_grpc.APIStub(self.channel)

    def query(self, vql, env=None, timeout=60):
        req = api_pb2.VQLCollectorArgs(
            max_wait=1,
            max_row=1000,
            Query=[api_pb2.VQLRequest(Name='q', VQL=vql)],
            env=[api_pb2.VQLEnv(key=k, value=str(v)) for k, v in (env or {}).items()],
        )
        rows = []
        for resp in self.stub.Query(req, timeout=timeout):
            if resp.Response:
                rows.extend(json.loads(resp.Response))
        return rows

    def test(self):
        try:
            rows = self.query("SELECT Hostname, OS FROM info()", timeout=15)
            host = rows[0].get('Hostname') if rows else 'unknown'
            print(f"   [OK] Velociraptor API: {self.endpoint} (server host: {host})")
            return True
        except grpc.RpcError as e:
            print(f"   [FAIL] Velociraptor API {self.endpoint}: {e.code().name} - {e.details()}")
        except Exception as e:
            print(f"   [FAIL] Velociraptor API error: {e}")
        return False

    def find_client(self, ip):
        """Resolve client_id from last_ip (format 'IP:port')."""
        rows = self.query(
            "SELECT client_id, os_info.hostname AS hostname, last_ip, last_seen_at FROM clients()")
        matches = [r for r in rows if str(r.get('last_ip', '')).split(':')[0] == ip]
        if not matches:
            return None, None
        matches.sort(key=lambda r: r.get('last_seen_at') or 0, reverse=True)
        return matches[0]['client_id'], matches[0].get('hostname')

    def collect(self, client_id, artifact):
        rows = self.query(
            "SELECT collect_client(client_id=ClientId, artifacts=Artifact).flow_id AS FlowId FROM scope()",
            env={'ClientId': client_id, 'Artifact': artifact},
        )
        return rows[0].get('FlowId') if rows else None

    def flow_status(self, client_id, flow_id):
        rows = self.query(
            "SELECT state, status, total_uploaded_bytes, total_uploaded_files "
            "FROM flows(client_id=ClientId, flow_id=FlowId)",
            env={'ClientId': client_id, 'FlowId': flow_id},
        )
        return rows[0] if rows else {}


# ============================================================
# Trigger engine
# ============================================================
class TriggerEngine:
    def __init__(self, source, velo, config, dry_run=False):
        self.source = source
        self.velo = velo
        self.cfg = config
        self.vcfg = config['velociraptor']
        self.dry_run = dry_run
        self.running = True
        self.client_id = self.vcfg.get('client_id') or None
        self.hostname = None
        self.active = None       # open incident (inside the cooldown window)
        self.pending = {}        # incident_id -> incident waiting for its flow to finish
        self.stats = {'cycles': 0, 'alerts': 0, 'dumps': 0, 'finished': 0, 'failed': 0}
        signal.signal(signal.SIGINT, self._stop)
        signal.signal(signal.SIGTERM, self._stop)

    def _stop(self, signum, frame):
        print(f"\nSignal {signum} received, stopping...")
        self.running = False

    def log(self, record):
        record['logged_at'] = now_iso()
        with open(self.cfg['incident_log'], 'a', encoding='utf-8') as f:
            f.write(json.dumps(record, ensure_ascii=False, default=str) + '\n')

    def resolve_client(self):
        if self.client_id:
            return True
        cid, host = self.velo.find_client(self.cfg['victim_ip'])
        if cid:
            self.client_id, self.hostname = cid, host
            print(f"   Victim {self.cfg['victim_ip']} -> {cid} ({host})")
            return True
        print(f"   [FAIL] No Velociraptor client with last_ip = {self.cfg['victim_ip']}. "
              f"Check that the client is enrolled, or set client_id manually in CONFIG.")
        return False

    def uploads_path(self, flow_id):
        return (f"{self.vcfg['datastore_hint']}\\clients\\{self.client_id}"
                f"\\collections\\{flow_id}\\uploads")

    # ---------- alert handling ----------
    def handle_alerts(self, hits):
        alerts = [SuricataAlertSource.summarize(h) for h in hits]
        self.stats['alerts'] += len(alerts)
        for a in alerts:
            print(f"   ALERT [sev {a['severity']}] {a['signature']} | {a['src']} -> {a['dest']}")

        cooldown = self.cfg['cooldown_minutes'] * 60
        if self.active and time.time() - self.active['started'] < cooldown:
            self.active['alert_count'] += len(alerts)
            self.log({'event': 'ALERT_ATTACHED', 'incident_id': self.active['incident_id'],
                      'velociraptor_flow_id': self.active.get('flow_id'), 'alerts': alerts})
            left = int((cooldown - (time.time() - self.active['started'])) / 60)
            print(f"   Cooldown active ({left} min left): attached {len(alerts)} alert(s) to "
                  f"{self.active['incident_id']}, no new acquisition")
            return

        if not self.resolve_client():
            self.log({'event': 'TRIGGER_FAILED', 'reason': 'client_not_found', 'alerts': alerts})
            return

        incident_id = f"INC-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        incident = {
            'incident_id': incident_id,
            'client_id': self.client_id,
            'hostname': self.hostname,
            'victim_ip': self.cfg['victim_ip'],
            'artifact': self.vcfg['artifact'],
            'started': time.time(),
            'alert_count': len(alerts),
            'first_alert_ts': alerts[0]['timestamp'],
            'flow_id': None,
        }

        if self.dry_run:
            print(f"   DRY-RUN: would trigger {self.vcfg['artifact']} on {self.client_id} ({incident_id})")
            self.active = incident
            self.log({'event': 'DRY_RUN', **incident, 'alerts': alerts})
            return

        try:
            flow_id = self.velo.collect(self.client_id, self.vcfg['artifact'])
        except grpc.RpcError as e:
            print(f"   [FAIL] collect_client: {e.code().name} - {e.details()}")
            self.log({'event': 'TRIGGER_FAILED', 'incident_id': incident_id,
                      'reason': f'{e.code().name}: {e.details()}', 'alerts': alerts})
            return

        if not flow_id:
            print("   [FAIL] collect_client returned no flow_id")
            self.log({'event': 'TRIGGER_FAILED', 'incident_id': incident_id,
                      'reason': 'no_flow_id', 'alerts': alerts})
            return

        incident['flow_id'] = flow_id
        self.active = incident
        self.pending[incident_id] = incident
        self.stats['dumps'] += 1
        print(f"   TRIGGERED {self.vcfg['artifact']} | {incident_id} | client {self.client_id} | flow {flow_id}")
        self.log({'event': 'TRIGGERED', 'incident_id': incident_id, 'client_id': self.client_id,
                  'hostname': self.hostname, 'velociraptor_flow_id': flow_id,
                  'artifact': self.vcfg['artifact'], 'alerts': alerts})

    # ---------- flow tracking ----------
    def check_pending(self):
        timeout = self.cfg['flow_timeout_minutes'] * 60
        for inc_id, inc in list(self.pending.items()):
            try:
                st = self.velo.flow_status(inc['client_id'], inc['flow_id'])
            except grpc.RpcError as e:
                print(f"   [WARN] Cannot read status of flow {inc['flow_id']}: {e.code().name}")
                continue

            state = str(st.get('state', 'UNKNOWN')).upper()
            size = st.get('total_uploaded_bytes') or 0
            elapsed = int(time.time() - inc['started'])

            if state == 'FINISHED':
                self.stats['finished'] += 1
                print(f"   [OK] {inc_id} FINISHED after {elapsed}s - {size:,} bytes "
                      f"({size / 1024 ** 3:.2f} GiB)")
                print(f"        Path: {self.uploads_path(inc['flow_id'])}")
                print(f"        GUI:  Clients > {inc['client_id']} > Collected > {inc['flow_id']} > Uploaded Files")
                self.log({'event': 'FINISHED', 'incident_id': inc_id,
                          'velociraptor_flow_id': inc['flow_id'], 'uploaded_bytes': size,
                          'uploads_path': self.uploads_path(inc['flow_id']), 'elapsed_s': elapsed,
                          'alert_count': inc['alert_count']})
                del self.pending[inc_id]
            elif state == 'ERROR':
                self.stats['failed'] += 1
                print(f"   [FAIL] {inc_id} ERROR: {st.get('status')}")
                self.log({'event': 'ERROR', 'incident_id': inc_id,
                          'velociraptor_flow_id': inc['flow_id'], 'status': st.get('status')})
                del self.pending[inc_id]
            elif elapsed > timeout:
                self.stats['failed'] += 1
                print(f"   [TIMEOUT] {inc_id} after {elapsed}s (state={state}), check the GUI")
                self.log({'event': 'TIMEOUT', 'incident_id': inc_id,
                          'velociraptor_flow_id': inc['flow_id'], 'last_state': state})
                del self.pending[inc_id]
            else:
                print(f"   {inc_id} {state} - {elapsed}s, {size:,} bytes uploaded")

    # ---------- main loop ----------
    def run(self, once=False):
        interval = self.cfg['poll_interval']
        since_ms = int((time.time() - 60) * 1000)
        print("\n" + "=" * 60)
        print("SURICATA -> VELOCIRAPTOR TRIGGER STARTED")
        print(f"   ES:        {self.source.base_url}/{self.source.index}")
        print(f"   Victim:    {self.cfg['victim_ip']}")
        print(f"   Artifact:  {self.vcfg['artifact']}")
        print(f"   Poll:      {interval}s | Cooldown: {self.cfg['cooldown_minutes']} min")
        print(f"   Mode:      {'DRY-RUN' if self.dry_run else 'LIVE'}{' / ONE-SHOT' if once else ''}")
        print("=" * 60)

        while self.running:
            self.stats['cycles'] += 1
            t0 = time.time()
            print(f"\n--- Cycle #{self.stats['cycles']} | {datetime.now():%H:%M:%S} ---")

            if self.pending:
                self.check_pending()

            hits, since_ms = self.source.pull(since_ms)
            if hits:
                self.handle_alerts(hits)
            else:
                print("   No new alerts for the victim")

            if once:
                break
            sleep_left = max(0, interval - (time.time() - t0))
            for _ in range(int(sleep_left)):
                if not self.running:
                    break
                time.sleep(1)

        print(f"\nCycles: {self.stats['cycles']} | Alerts: {self.stats['alerts']} | "
              f"Acquisitions triggered: {self.stats['dumps']} | Finished: {self.stats['finished']} | "
              f"Failed/Timeout: {self.stats['failed']}")
        if self.pending:
            print(f"[WARN] {len(self.pending)} flow(s) still running on Velociraptor, follow up in the GUI:")
            for inc in self.pending.values():
                print(f"   {inc['incident_id']} -> flow {inc['flow_id']}")


# ============================================================
# Main
# ============================================================
def main():
    p = argparse.ArgumentParser(description='Suricata alert -> Velociraptor memory acquisition')
    p.add_argument('--test', action='store_true', help='Test Elasticsearch, Velociraptor and client lookup, then exit')
    p.add_argument('--dry-run', action='store_true', help='Do not trigger acquisition, log only')
    p.add_argument('--once', action='store_true', help='Run a single cycle, then exit')
    p.add_argument('--interval', type=int, default=CONFIG['poll_interval'])
    p.add_argument('--max-severity', type=int, default=CONFIG['max_severity'])
    args = p.parse_args()

    CONFIG['poll_interval'] = args.interval
    CONFIG['max_severity'] = args.max_severity

    print("Checking connectivity...")
    source = SuricataAlertSource(CONFIG['elasticsearch'], CONFIG['victim_ip'], CONFIG['max_severity'])
    velo = VelociraptorAPI(CONFIG['velociraptor'])
    es_ok = source.test()
    velo_ok = velo.test()
    if not (es_ok and velo_ok):
        sys.exit(1)

    engine = TriggerEngine(source, velo, CONFIG, dry_run=args.dry_run)
    if not engine.resolve_client() and args.test:
        sys.exit(1)
    if args.test:
        print("\nAll checks passed.")
        return

    engine.run(once=args.once)


if __name__ == '__main__':
    main()
