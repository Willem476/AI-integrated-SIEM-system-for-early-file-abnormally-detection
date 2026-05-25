#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
🛡️ COMMAND LINE DETECTION - REAL-TIME ELASTICSEARCH VERSION v5
===============================================================
- Train model từ dataset local (data2/command_line_AI_2_labeled.csv)
- Pull log từ Elasticsearch theo thời gian thực
- 28 features (10 ML + 8 IOC + 10 MITRE)
- COMPOSITE RISK SCORE: ML(50%) + IOC(20%) + MITRE(30%)
- Aggregation: aggregation_window=0 → gửi alert NGAY (latency ~3s)
                aggregation_window>0 → gộp alert trong window

Cấu trúc thư mục:
    ~/kltn/
    ├── data/
    ├── data2/
    │   └── command_line_AI_10pct_labeled.csv
    └── command_detection_local.py

Cách chạy:
    python3 command_detection_local.py                # Real-time (default poll 3s, no aggregation)
    python3 command_detection_local.py --interval 10  # Poll mỗi 10s
    python3 command_detection_local.py --once
    python3 command_detection_local.py --no-alert
    python3 command_detection_local.py --show-payload
"""

import pandas as pd
import numpy as np
import re
import math
import requests
import json
import time
import sys
import os
import argparse
import signal
import urllib3
import warnings
from datetime import datetime, timezone, timedelta
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    confusion_matrix, f1_score, accuracy_score,
    precision_score, recall_score
)
from scipy.sparse import hstack, csr_matrix

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings('ignore')
np.random.seed(42)
import random
random.seed(42)

# ============================================================
# ⚙️ CẤU HÌNH
# ============================================================
CONFIG = {
    'dataset_file': 'data2/command_line_AI_10pct_labeled.csv',

    'shuffle_webhook_url': 'http://10.10.10.34:3001/api/v1/hooks/webhook_f9fb0551-8cb6-480e-8ae5-2971c80aeedf',

    'elasticsearch': {
        'base_url': 'http://10.10.10.34:9200',
        'api_key': '∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎',
        'username': '∎∎∎∎∎∎∎',
        'password': '∎∎∎∎∎∎∎',
        'index_pattern': 'logs-endpoint.events.process-*',
        'auth_method': 'basic',
        'verify_ssl': False,
    },

    # ⚡ REALTIME TUNING
    'poll_interval':       10,    # poll mỗi 10 giây
    'batch_size':          1000,
    'aggregation_window':  0,    # 0 = NGAY (no aggregation), >0 = gộp trong N giây

    'test_size':     0.20,    # 20% test (giữ riêng cho đánh giá cuối)
    'val_size':      0.20,    # 20% validation (tune model trong khi train)
    'random_state':  42,
    'n_estimators':  100,
    'max_depth':     15,

    'risk_weights': {
        'ml_score':    0.50,
        'ioc_score':   0.20,
        'mitre_score': 0.30,
    },
    'risk_thresholds': {
        'CRITICAL': 80,
        'HIGH':     60,
        'MEDIUM':   40,
        'LOW':      20,
    },
    'min_alert_level': 'LOW',
}


# ============================================================
# 🔍 FEATURE EXTRACTORS - 28 features (10 ML + 8 IOC + 10 MITRE)
# ============================================================
def extract_ml_features(cmdlines):
    feats = pd.DataFrame()
    feats['ml_cmd_length']      = cmdlines.str.len()
    feats['ml_num_args']        = cmdlines.str.count(r'\s+')                                # Đếm số nhóm khoảng trắng = số khoảng cách giữa các từ ≈ số argument.
    feats['ml_num_special']     = cmdlines.str.count(r'[\\/:;|&<>]')
    feats['ml_num_digits']      = cmdlines.str.count(r'\d')                                 # Đếm bao nhiêu số trong 1 câu lệnh
    feats['ml_num_uppercase']   = cmdlines.str.count(r'[A-Z]')
    feats['ml_has_quotes']      = cmdlines.str.contains('"', regex=False).astype(int)       # Kiểm tra xem có dấu "" hay không
    feats['ml_starts_with_nt']  = cmdlines.str.startswith('\\??\\').astype(int)
    feats['ml_word_count']      = cmdlines.str.split().str.len().fillna(0).astype(int)      # Đếm số từ / số token trong mỗi command line
    feats['ml_avg_word_length'] = cmdlines.apply(
        lambda s: np.mean([len(w) for w in s.split()]) if s.split() else 0)
    def shannon(s):
        if not s: return 0
        freq = {c: s.count(c)/len(s) for c in set(s)}
        return -sum(p*math.log2(p) for p in freq.values() if p>0)       # Biểu thức toán học: ký tự lặp nhiều → entropy thấp, ký tự random hơn → entropy cao
    feats['ml_entropy'] = cmdlines.apply(shannon)
    return feats

IOC_PATTERNS = {
    'ioc_has_url':          r'https?://',
    'ioc_malicious_domain': r'(mega\.nz|mediafire|anonfiles|gofile|pastebin|discordapp\.com|raw\.githubusercontent|transfer\.sh|bit\.ly|tinyurl)',
    'ioc_malware_tool':     r'(mimikatz|procdump|psexec|nc\.exe|ncat|netcat|pchunter|processhacker)',
    'ioc_encoded_payload':  r'[A-Za-z0-9+/=]{30,}', # https://www.linkedin.com/pulse/regex-digital-forensics-cyberthreat-intelligence-guide-james-henning-aqrde
    'ioc_archive_op':       r'(7z|7-zip|winrar|unzip).*\.(rar|zip|7z|tar|gz)',
    'ioc_ip_address':       r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
    'ioc_com_object':       r'new-object\s+-com',   # detect command PowerShell tạo COM Object (Cơ chế giúp các phần mềm giao tiếp với nhau trên windows)
    'ioc_downloadcradle':   r'(downloadstring|downloadfile|invoke-webrequest|iwr\s)',
    'ioc_credential_hunt':  r'(findstr.*password|findstr.*passwd|select-string.*password|grep.*password|cmdkey\s+/list)',
}
def extract_ioc_features(cmdlines):
    feats = pd.DataFrame()
    cl = cmdlines.str.lower()
    for name, pat in IOC_PATTERNS.items():
        feats[name] = cl.str.contains(pat, regex=True, na=False).astype(int)
    return feats

MITRE_PATTERNS = {
    'mitre_t1059_001': r'powershell(\.exe)?\s+',
    'mitre_t1059_003': r'cmd(\.exe)?\s+/c',
    'mitre_t1218':     r'(mshta|regsvr32|rundll32|installutil|msiexec|cmstp|odbcconf|hh|mavinject)\.exe', # lợi dụng binary hợp pháp có sẵn trên Windows để thực thi mã độc
    'mitre_t1105':     r'(certutil\s+.*-urlcache|bitasdmin\s+/transfer|invoke-webrequest|iwr\s|downloadstring|downloadfile|curl\.exe\s+-|wget\.exe)', # attacker chuyển tool/payload từ bên ngoài vào máy nạn nhân.
    'mitre_t1003_001': r'(lsass.*\.dmp|comsvcs\.dll.*minidump|sekurlsa|-ma\s+lsass)', #  LSASS lưu trữ các thông tin đăng nhập trong bộ nhớ
    'mitre_t1087':     r'\b(whoami(\s+/all)?|net\s+(user|group|localgroup)|nltest|quser)\b',
    'mitre_t1082':     r'(systeminfo|wmic\s+os|get-wmiobject.*win32_computersystem|hostname\.exe)',
    'mitre_t1057':     r'(get-process\b|tasklist(\.exe)?\b)',   # Liệt kê process đang chạy.
    'mitre_t1497':     r'(get-wmiobject.*computersystem|get-ciminstance.*bios|vmware|virtualbox|vbox)',
    'mitre_t1027':     r'(-nop\b|-noprofile|-w\s+hidden|-windowstyle\s+hidden|-executionpolicy\s+bypass|-ep\s+bypass|iex\s*\(|frombase64string)',   # Attacker cố che giấu hoặc làm khó phân tích command/script.
    'mitre_t1552_001':     r'(findstr.*\*\.(txt|xml|config|ini|conf|json|yml|yaml|properties)|select-string.*-pattern.*pass|gci.*-recurse.*\.(config|xml).*\|.*select-string)',
}
def extract_mitre_features(cmdlines):       # Kiểm tra command line có trùng mitre nào ko
    feats = pd.DataFrame()
    cl = cmdlines.str.lower()
    for name, pat in MITRE_PATTERNS.items():
        feats[name] = cl.str.contains(pat, regex=True, na=False).astype(int)
    return feats

def build_features(cmdlines):
    ml    = extract_ml_features(cmdlines)
    ioc   = extract_ioc_features(cmdlines)
    mitre = extract_mitre_features(cmdlines)
    X = hstack([
        csr_matrix(ml.values.astype(float)),
        csr_matrix(ioc.values.astype(float)),
        csr_matrix(mitre.values.astype(float)),
    ]).tocsr()
    return X, ml, ioc, mitre

# ============================================================
# 📊 RISK SCORE CALCULATOR
# ============================================================
class RiskScoreCalculator:
    def __init__(self, weights, thresholds):
        self.weights    = weights
        self.thresholds = thresholds

    def calculate(self, ml_prob, ioc_count, mitre_count):
        ml_score = ml_prob * 100
        ioc_score = 0
        if ioc_count > 0:
            ioc_score = 30 + min(ioc_count * 20, 70)
        mitre_score = min(mitre_count * 25, 100)

        risk_score = (
            ml_score    * self.weights['ml_score']    +
            ioc_score   * self.weights['ioc_score']   +
            mitre_score * self.weights['mitre_score']
        )

        if (ioc_score > 0 and mitre_score > 0) and risk_score < 20:
            risk_score = 20

        t = self.thresholds
        if   risk_score >= t['CRITICAL']: risk_level = 'CRITICAL'
        elif risk_score >= t['HIGH']:     risk_level = 'HIGH'
        elif risk_score >= t['MEDIUM']:   risk_level = 'MEDIUM'
        elif risk_score >= t['LOW']:      risk_level = 'LOW'
        else:                             risk_level = 'SAFE'

        return {
            'risk_score': round(risk_score, 2),
            'risk_level': risk_level,
            'breakdown': {
                'ml_score':    round(ml_score, 2),
                'ioc_score':   round(ioc_score, 2),
                'mitre_score': round(mitre_score, 2),
            },
        }


# ============================================================
# 📡 ELASTICSEARCH CLIENT
# ============================================================
class ElasticsearchClient:
    def __init__(self, config):
        self.base_url      = config['base_url'].rstrip('/')
        self.api_key       = config.get('api_key', '')
        self.username      = config.get('username', '')
        self.password      = config.get('password', '')
        self.index_pattern = config.get('index_pattern', 'logs-endpoint.events.process-*')
        self.auth_method   = config.get('auth_method', 'basic')
        self.verify_ssl    = config.get('verify_ssl', False)
        self.session = requests.Session()
        self._setup_auth()

    def _setup_auth(self):
        if self.auth_method == 'api_key':
            self.session.headers.update({
                'Authorization': f'ApiKey {self.api_key}',
                'Content-Type': 'application/json',
            })
        else:
            self.session.auth = (self.username, self.password)
            self.session.headers.update({'Content-Type': 'application/json'})

    def test_connection(self):
        try:
            r = self.session.get(f'{self.base_url}/', verify=self.verify_ssl, timeout=10)
            if r.status_code == 200:
                info = r.json()
                print(f"   ✅ Connected to Elasticsearch {info.get('version', {}).get('number', '?')}")
                print(f"   📍 Cluster: {info.get('cluster_name', '?')}")
                return True
            if r.status_code == 401 and self.auth_method == 'api_key':
                print("   🔄 API key failed, fallback Basic Auth...")
                self.auth_method = 'basic'
                self.session.headers.pop('Authorization', None)
                self._setup_auth()
                return self.test_connection()
            print(f"   ❌ HTTP {r.status_code}")
            return False
        except Exception as e:
            print(f"   ❌ {e}")
            return False

    def pull_logs(self, since_ts, batch_size=1000):
        query = {
            "size": batch_size,
            "sort": [{"@timestamp": {"order": "asc"}}],
            "query": {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": {
                            "gt": since_ts, "format": "strict_date_optional_time"}}},
                        {"exists": {"field": "process.command_line"}},
                        {"exists": {"field": "process.name"}},
                    ]
                }
            },
            "_source": [
                "@timestamp", "host.name", "host.hostname",
                "process.name", "process.command_line",
                "process.parent.name", "user.name",
                "event.action", "event.code",
            ],
        }
        try:
            url = f'{self.base_url}/{self.index_pattern}/_search'
            r = self.session.post(url, data=json.dumps(query),          # Kéo log về model
                                  verify=self.verify_ssl, timeout=30)
            if r.status_code != 200:
                return []
            return [self._flatten(h) for h in r.json().get('hits', {}).get('hits', [])]
        except Exception as e:
            print(f"   ❌ Pull error: {e}")
            return []

    @staticmethod
    def _flatten(hit):
        src = hit.get('_source', {})
        def g(d, path, default=''):
            cur = d
            for k in path.split('.'):
                if isinstance(cur, dict) and k in cur:
                    cur = cur[k]
                else:
                    return default
            return cur if cur is not None else default
        return {
            '_id':                  hit.get('_id', ''),
            '@timestamp':           g(src, '@timestamp'),
            'host.name':            g(src, 'host.name') or g(src, 'host.hostname'),
            'process.name':         g(src, 'process.name'),
            'process.command_line': g(src, 'process.command_line'),
            'process.parent.name':  g(src, 'process.parent.name'),
            'user.name':            g(src, 'user.name'),
            'event.action':         g(src, 'event.action'),
            'event.code':           g(src, 'event.code'),
        }


# ============================================================
# 🚨 SHUFFLE SOAR ALERTER
# ============================================================
class ShuffleAlerter:
    def __init__(self, webhook_url):
        self.webhook_url = webhook_url

    def send(self, payload):
        try:
            r = requests.post(self.webhook_url, json=payload, timeout=10, verify=False)
            return r.status_code in (200, 201)
        except Exception as e:
            print(f"   ❌ Shuffle: {e}")
            return False


# ============================================================
# 🔗 ALERT AGGREGATOR
# ============================================================
class AlertAggregator:
    """
    Gộp các alert cùng host+user trong window thời gian.
    Nếu window=0 → KHÔNG gộp, trả về alert ngay.
    """

    def __init__(self, window_seconds=60):
        self.window = window_seconds
        self.groups = {}

    def _parse_ts(self, ts_str):
        try:
            return datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
        except:
            return datetime.now(timezone.utc)

    def add(self, alert):
        # Mode realtime: gửi ngay không gộp
        if self.window == 0:
            return self._build_single(alert)

        key = (alert.get('host.name', ''), alert.get('user.name', ''))
        ts = self._parse_ts(alert.get('@timestamp', ''))

        flushed = None
        if key in self.groups:
            first_ts = self.groups[key]['first_ts']
            if (ts - first_ts).total_seconds() > self.window:
                flushed = self._build_aggregated(key)
                del self.groups[key]

        if key not in self.groups:
            self.groups[key] = {'first_ts': ts, 'alerts': []}
        self.groups[key]['alerts'].append(alert)
        return flushed

    def flush_old(self, now=None):
        if self.window == 0 or not self.groups:
            return []
        if now is None:
            now = datetime.now(timezone.utc)
        result = []
        for key in list(self.groups.keys()):
            first_ts = self.groups[key]['first_ts']
            if (now - first_ts).total_seconds() > self.window:
                agg = self._build_aggregated(key)
                if agg:
                    result.append(agg)
                del self.groups[key]
        return result

    def flush_all(self):
        result = []
        for key in list(self.groups.keys()):
            agg = self._build_aggregated(key)
            if agg:
                result.append(agg)
        self.groups.clear()
        return result

    def _build_single(self, alert):
        """Wrap 1 alert thành format giống aggregated cho consistent"""
        return {
            'primary':       alert,
            'count':         1,
            'all_iocs':      alert['matched_iocs'],
            'all_mitre':     alert['matched_mitre'],
            'process_chain': [{
                'timestamp':       alert.get('@timestamp', ''),
                'parent':          alert.get('process.parent.name', ''),
                'process':         alert.get('process.name', ''),
                'cmdline':         alert.get('process.command_line', ''),
                'risk_score':      alert['risk_score'],
                'risk_level':      alert['risk_level'],
                'breakdown':       alert['breakdown'],
                'matched_iocs':    alert.get('matched_iocs', []),
                'matched_mitre':   alert.get('matched_mitre', []),
                'top_ml_features': alert.get('top_ml_features', []),
            }],
            'first_seen':    alert.get('@timestamp', ''),
            'last_seen':     alert.get('@timestamp', ''),
            'max_risk':      alert['risk_score'],
        }

    def _build_aggregated(self, key):
        if key not in self.groups:
            return None
        alerts = self.groups[key]['alerts']
        if not alerts:
            return None

        primary = max(alerts, key=lambda a: a['risk_score'])
        all_iocs  = sorted(set(i for a in alerts for i in a['matched_iocs']))
        all_mitre = sorted(set(m for a in alerts for m in a['matched_mitre']))
        process_chain = [{
            'timestamp':       a.get('@timestamp', ''),
            'parent':          a.get('process.parent.name', ''),
            'process':         a.get('process.name', ''),
            'cmdline':         a.get('process.command_line', ''),
            'risk_score':      a['risk_score'],
            'risk_level':      a['risk_level'],
            'breakdown':       a['breakdown'],
            'matched_iocs':    a.get('matched_iocs', []),
            'matched_mitre':   a.get('matched_mitre', []),
            'top_ml_features': a.get('top_ml_features', []),
        } for a in sorted(alerts, key=lambda x: x.get('@timestamp', ''))]

        return {
            'primary':       primary,
            'count':         len(alerts),
            'all_iocs':      all_iocs,
            'all_mitre':     all_mitre,
            'process_chain': process_chain,
            'first_seen':    min(a.get('@timestamp', '') for a in alerts),
            'last_seen':     max(a.get('@timestamp', '') for a in alerts),
            'max_risk':      max(a['risk_score'] for a in alerts),
        }


# ============================================================
# 🛡️ COMMAND DETECTOR
# ============================================================
class CommandDetector:
    def __init__(self, config):
        self.config = config
        self.model = None
        # ML feature metadata cho explanation
        self.ml_feature_names = None
        self.ml_feature_max   = None
        self.ml_importances   = None
        self.risk_calc = RiskScoreCalculator(
            weights=config['risk_weights'],
            thresholds=config['risk_thresholds'])

    def _get_top_ml_features(self, ml_row, top_n=3):
        """Trả về top-N ML features đóng góp nhiều nhất cho prediction này.
        Dựa trên: feature_importance × normalized_value (so với max của training set).
        Chỉ giữ feature có giá trị > 0 và contribution đáng kể."""
        if self.ml_feature_names is None or self.ml_feature_max is None or self.ml_importances is None:
            return []
        values = ml_row.values.astype(float)
        # Normalize 0..1 theo max của training set, tránh chia 0
        norm = np.divide(values, self.ml_feature_max,
                         out=np.zeros_like(values, dtype=float),
                         where=self.ml_feature_max != 0)
        norm = np.clip(norm, 0.0, 1.0)      # Nếu giá trị < 0 → thành 0, nếu giá trị > 1 → thành 1
        contributions = norm * self.ml_importances

        top_idx = np.argsort(contributions)[::-1][:top_n]   # Phần chọn ra các feature có “độ đóng góp” cao nhất
        return [
            (self.ml_feature_names[j], float(values[j]))
            for j in top_idx
            if contributions[j] > 0.001 and values[j] > 0
        ]

    def train(self):
        print("\n" + "=" * 60)
        print("📊 LOADING TRAINING DATA")
        print("=" * 60)
        path = self.config['dataset_file']
        if not os.path.exists(path):
            print(f"❌ Không tìm thấy: {path}")
            sys.exit(1)

        print(f"\n⏳ Loading: {path}")
        df = pd.read_csv(path)
        df['process.command_line'] = df['process.command_line'].fillna('').astype(str)
        df = df[df['process.command_line'].str.len() > 0].reset_index(drop=True)
        print(f"   ✅ Total : {len(df):,}")
        print(f"   🟢 Benign   : {(df['label']==0).sum():,}")
        print(f"   🔴 Malicious: {(df['label']==1).sum():,}")
        print(f"   📈 Positive : {df['label'].mean()*100:.2f}%")

        print("\n" + "=" * 60)
        print("🔍 BUILDING FEATURES (30 features)")
        print("=" * 60)
        X, ml, ioc, mitre = build_features(df['process.command_line'])
        y = df['label'].values
        print(f"   ML: {ml.shape[1]}  |  IOC: {ioc.shape[1]}  |  MITRE: {mitre.shape[1]}")
        print(f"   TOTAL: {X.shape[1]} features")

        # Lưu ML feature metadata phục vụ explanation lúc predict
        self.ml_feature_names = ml.columns.tolist()
        self.ml_feature_max   = ml.max().values.astype(float)

        print("\n" + "=" * 60)
        print("🎯 TRAINING RANDOM FOREST")
        print("=" * 60)

        # Chia dataset 60/20/20 (Train / Validation / Test) với stratify
        # stratify=y đảm bảo TỶ LỆ MALWARE giữ nguyên ở cả 3 set
        # Lần 1: tách 20% test ra trước (giữ riêng cho đánh giá cuối)
        X_temp, X_te, y_temp, y_te = train_test_split(
            X, y, test_size=self.config['test_size'],
            random_state=self.config['random_state'], stratify=y)

        # Lần 2: từ 80% còn lại, tách 25% (= 20% tổng) làm validation
        # 80% × 0.25 = 20% tổng → 60% train + 20% val
        val_ratio_of_temp = self.config['val_size'] / (1 - self.config['test_size'])
        X_tr, X_val, y_tr, y_val = train_test_split(
            X_temp, y_temp, test_size=val_ratio_of_temp,
            random_state=self.config['random_state'], stratify=y_temp)

        total = X.shape[0]
        # In thông tin chia dataset + tỷ lệ malware (verify stratification)
        print(f"\n   📊 Dataset split (stratified - tỷ lệ malware giữ nguyên ở cả 3 set):")
        print(f"   {'Set':<12} {'Samples':>10} {'Malware':>10} {'Ratio':>8}")
        print(f"   {'-' * 45}")
        for name, y_set in [('Train', y_tr), ('Validation', y_val), ('Test', y_te)]:
            n_total = len(y_set)
            n_mal = int((y_set == 1).sum())
            pct = n_mal / n_total * 100
            print(f"   {name:<12} {n_total:>10,} {n_mal:>10,} {pct:>7.2f}%")
        print(f"   ⏳ Fitting...")
        self.model = RandomForestClassifier(
            n_estimators=self.config['n_estimators'],
            max_depth=self.config['max_depth'],
            n_jobs=-1,
            random_state=self.config['random_state'],
            class_weight='balanced')
        self.model.fit(X_tr, y_tr)

        # 10 importance đầu = ML features (ML đứng trước IOC, MITRE trong build_features)
        self.ml_importances = self.model.feature_importances_[:len(self.ml_feature_names)].astype(float)

        # Đánh giá trên validation set (dùng để monitor overfitting)
        y_val_pred = self.model.predict(X_val)
        print(f"\n📊 Validation results (20%):")
        print(f"   Accuracy : {accuracy_score(y_val, y_val_pred):.4f}")
        print(f"   Precision: {precision_score(y_val, y_val_pred):.4f}")
        print(f"   Recall   : {recall_score(y_val, y_val_pred):.4f}")
        print(f"   F1-Score : {f1_score(y_val, y_val_pred):.4f}")

        # Đánh giá trên test set (final unbiased evaluation)
        y_pred = self.model.predict(X_te)
        cm = confusion_matrix(y_te, y_pred)
        print(f"\n📈 Test results (20%):")
        print(f"   Accuracy : {accuracy_score(y_te, y_pred):.4f}")
        print(f"   Precision: {precision_score(y_te, y_pred):.4f}")
        print(f"   Recall   : {recall_score(y_te, y_pred):.4f}")
        print(f"   F1-Score : {f1_score(y_te, y_pred):.4f}")
        print(f"\n   Confusion Matrix (Test):")
        print(f"               Pred-Benign  Pred-Mal")
        print(f"   Benign     {cm[0,0]:>10d}  {cm[0,1]:>8d}")
        print(f"   Malicious  {cm[1,0]:>10d}  {cm[1,1]:>8d}")
        print(f"\n📊 Risk Score formula:")
        w = self.config['risk_weights']
        print(f"   risk_score = ml_score × {w['ml_score']} + ioc_score × {w['ioc_score']} + mitre_score × {w['mitre_score']}")
        print(f"\n✅ Model ready")

    def predict_logs(self, logs):
        if not logs:
            return []
        df = pd.DataFrame(logs)
        df['process.command_line'] = df['process.command_line'].fillna('').astype(str)
        df = df[df['process.command_line'].str.len() > 0].reset_index(drop=True)
        if len(df) == 0:
            return []

        X, ml, ioc, mitre = build_features(df['process.command_line'])
        proba = self.model.predict_proba(X)[:, 1]

        out = []
        for i, row in df.iterrows():
            matched_iocs  = [c for c in ioc.columns   if ioc.iloc[i][c]   == 1]
            matched_mitre = [c for c in mitre.columns if mitre.iloc[i][c] == 1]
            top_ml_features = self._get_top_ml_features(ml.iloc[i])
            risk = self.risk_calc.calculate(
                ml_prob=float(proba[i]),
                ioc_count=len(matched_iocs),
                mitre_count=len(matched_mitre))
            out.append({
                **row.to_dict(),
                'ml_prob':         float(proba[i]),
                'risk_score':      risk['risk_score'],
                'risk_level':      risk['risk_level'],
                'breakdown':       risk['breakdown'],
                'matched_iocs':    matched_iocs,
                'matched_mitre':   matched_mitre,
                'top_ml_features': top_ml_features,
            })
        return out


# ============================================================
# 🔄 REAL-TIME ENGINE
# ============================================================
class RealTimeEngine:
    LEVEL_RANK = {'SAFE': 0, 'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
    SEVERITY_MAP = {'SAFE': 0, 'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
    BORDER_W   = 70

    def _print_info(self, r):
        """In log có điểm nhưng chưa đạt ngưỡng alert - chỉ hiển thị, không gửi Shuffle"""
        icons = {'SAFE': '⚪', 'LOW': '🟢'}
        icon = icons.get(r['risk_level'], '⚪')
        b = r['breakdown']
        ts = r.get('@timestamp', '')[11:19] if len(r.get('@timestamp', '')) >= 19 else r.get('@timestamp', '')
        cmd = self._trim_cmd(r.get('process.command_line', ''), max_len=120)
        ml_trig = self._fmt_ml_triggers(r.get('top_ml_features', []))

        print(f"\n   {icon} [INFO/{r['risk_level']}] {ts}  risk={r['risk_score']:.1f}/100  "
              f"(ML={b['ml_score']:.1f}{ml_trig} IOC={b['ioc_score']:.1f} MITRE={b['mitre_score']:.1f})")
        print(f"      💻 {r.get('host.name','-')}  |  👤 {r.get('user.name','-')}  "
              f"|  ⚙️ {r.get('process.parent.name','-')} → {r.get('process.name','-')}")
        if r['matched_iocs']:
            print(f"      🎯 IOC  : {', '.join(r['matched_iocs'])}")
        if r['matched_mitre']:
            print(f"      🗺️  MITRE: {', '.join(r['matched_mitre'])}")
        print(f"      ⚡ {cmd}")

    def __init__(self, detector, es, alerter, config, send_alerts=True, show_payload=False):
        self.detector     = detector
        self.es           = es
        self.alerter      = alerter
        self.config       = config
        self.send_alerts  = send_alerts
        self.show_payload = show_payload
        self.last_ts      = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
        self.min_rank     = self.LEVEL_RANK[config['min_alert_level']]
        self.aggregator   = AlertAggregator(window_seconds=config.get('aggregation_window', 0))
        self.running      = True
        signal.signal(signal.SIGINT,  self._stop)
        signal.signal(signal.SIGTERM, self._stop)

    def _stop(self, *_):
        print("\n\n🛑 Stopping... flushing remaining alerts...")
        self.running = False

    @staticmethod
    def _trim_cmd(cmd, max_len=180):
        if len(cmd) <= max_len:
            return cmd
        head = max_len - 50
        return f"{cmd[:head]}...[{len(cmd)} chars]...{cmd[-30:]}"

    @staticmethod
    def _fmt_ml_triggers(top_ml):
        """Format top ML features: [entropy=5.2, cmd_length=234, num_special=15]"""
        if not top_ml:
            return ''
        parts = []
        for name, val in top_ml:
            short = name.replace('ml_', '')
            if isinstance(val, float) and not float(val).is_integer():
                parts.append(f"{short}={val:.2f}")
            else:
                parts.append(f"{short}={int(val)}")
        return ' [' + ', '.join(parts) + ']'

    @staticmethod
    def _fmt_matched(matched, prefix):
        """Format matched IOC/MITRE: [t1218, t1003_001]"""
        if not matched:
            return ''
        return ' [' + ', '.join(c.replace(prefix, '') for c in matched) + ']'

    def _print_aggregated(self, agg):
        p = agg['primary']
        icons = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}
        icon = icons.get(p['risk_level'], '⚪')
        bar = '─' * self.BORDER_W

        # Header khác nhau cho single vs aggregated
        if agg['count'] == 1:
            header = f"  {icon}  ALERT [{p['risk_level']}]   risk={agg['max_risk']:.1f}/100"
        else:
            header = f"  {icon}  ALERT [{p['risk_level']}]   max_risk={agg['max_risk']:.1f}/100   events={agg['count']}"


        print(f"\n   ┌{bar}")
        print(f"   │{header}")
        print(f"   ├{bar}")
        if agg['count'] == 1:
            print(f"   │  🕐 Time  : {agg['first_seen']}")
        else:
            print(f"   │  🕐 First : {agg['first_seen']}")
            print(f"   │  🕐 Last  : {agg['last_seen']}")
        print(f"   │  💻 Host  : {p.get('host.name','-')}")
        print(f"   │  👤 User  : {p.get('user.name','-')}")
        if agg['all_iocs']:
            print(f"   │  🎯 IOC   : {', '.join(agg['all_iocs'])}")
        if agg['all_mitre']:
            print(f"   │  🗺️  MITRE : {', '.join(agg['all_mitre'])}")
        print(f"   ├{bar}")

        if agg['count'] == 1:
            ev = agg['process_chain'][0]
            b  = ev['breakdown']
            ml_trig    = self._fmt_ml_triggers(ev.get('top_ml_features', []))
            ioc_trig   = self._fmt_matched(ev.get('matched_iocs', []),  'ioc_')
            mitre_trig = self._fmt_matched(ev.get('matched_mitre', []), 'mitre_')
            print(f"   │  ⚙️  PROCESS: {ev['parent']}  →  {ev['process']}")
            print(f"   │  📊 breakdown:")
            print(f"   │     ML    = {b['ml_score']:5.1f}{ml_trig}")
            print(f"   │     IOC   = {b['ioc_score']:5.1f}{ioc_trig}")
            print(f"   │     MITRE = {b['mitre_score']:5.1f}{mitre_trig}")
            print(f"   ├{bar}")
            cmd = self._trim_cmd(ev['cmdline'], max_len=180)
            for j in range(0, len(cmd), 90):
                prefix = '⚡  ' if j == 0 else '    '
                print(f"   │  {prefix}{cmd[j:j+90]}")
        else:
            print(f"   │  🔗 PROCESS CHAIN ({agg['count']} events)")
            print(f"   ├{bar}")
            for i, ev in enumerate(agg['process_chain'], 1):
                ts = ev['timestamp'][11:19] if len(ev['timestamp']) >= 19 else ev['timestamp']
                b  = ev['breakdown']
                ml_trig    = self._fmt_ml_triggers(ev.get('top_ml_features', []))
                ioc_trig   = self._fmt_matched(ev.get('matched_iocs', []),  'ioc_')
                mitre_trig = self._fmt_matched(ev.get('matched_mitre', []), 'mitre_')
                print(f"   │")
                print(f"   │  [{i}] {ts}  risk={ev['risk_score']:.1f}/100  [{ev['risk_level']}]")
                print(f"   │      breakdown:")
                print(f"   │         ML    = {b['ml_score']:5.1f}{ml_trig}")
                print(f"   │         IOC   = {b['ioc_score']:5.1f}{ioc_trig}")
                print(f"   │         MITRE = {b['mitre_score']:5.1f}{mitre_trig}")
                print(f"   │      {ev['parent']}  →  {ev['process']}")
                cmd = self._trim_cmd(ev['cmdline'], max_len=180)
                for j in range(0, len(cmd), 90):
                    prefix = '⚡  ' if j == 0 else '    '
                    print(f"   │      {prefix}{cmd[j:j+90]}")
        print(f"   └{bar}")

    def _build_payload(self, agg):
        p = agg['primary']
        return {
            'alert_type':     'command_line_anomaly',
            'risk_level':     p['risk_level'],
            'severity':       self.SEVERITY_MAP.get(p['risk_level'], 0),
            'max_risk_score': round(agg['max_risk'], 2),
            'event_count':    agg['count'],
            'first_seen':     agg['first_seen'],
            'last_seen':      agg['last_seen'],
            'host':           p.get('host.name', ''),
            'user':           p.get('user.name', ''),
            'matched_iocs':   agg['all_iocs'],
            'matched_mitre':  agg['all_mitre'],
            'process_chain':  agg['process_chain'],
            'detector':       'command_detection_local',
            'detected_at':    datetime.now(timezone.utc).isoformat(),
        }

    def _send_aggregated(self, aggregated_list):
        if not aggregated_list:
            return
        for agg in aggregated_list:
            self._print_aggregated(agg)
            if self.send_alerts:
                payload = self._build_payload(agg)
                if self.show_payload:
                    print(f"\n      📤 Shuffle payload:")
                    for line in json.dumps(payload, indent=2, ensure_ascii=False).split('\n'):
                        print(f"         {line}")
                if self.alerter.send(payload):
                    label = '1 event' if agg['count'] == 1 else f"{agg['count']} events grouped"
                    print(f"      ✅ Sent to Shuffle ({label})")
                else:
                    print(f"      ❌ Shuffle send failed")

    def run_once(self):
        print(f"\n🔍 Polling logs since {self.last_ts}...")
        logs = self.es.pull_logs(self.last_ts, batch_size=self.config['batch_size'])

        if logs:
            print(f"   📥 Pulled {len(logs)} logs")
            latest = max((l.get('@timestamp', '') for l in logs if l.get('@timestamp')), default=self.last_ts)
            if latest > self.last_ts:
                self.last_ts = latest

            results = self.detector.predict_logs(logs)

            # Show MỌI detection có điểm (ML/IOC/MITRE > 0), không chỉ >= LOW
            # Chỉ show log có signal RÕ RÀNG:
            # - IOC match (rule signature, đảm bảo có evidence cụ thể)
            # - MITRE technique match
            # - Parent chain boost (suspicious process tree)
            # - HOẶC ML >= 15 (đủ cao để loại tất cả noise: 0.1, 1.0, 2.0, 5.0...)
            # Bỏ qua hoàn toàn log có ML < 15 và không có IOC/MITRE/Chain
            detected = [r for r in results
                        if r['breakdown']['ml_score']    >= 15.0
                        or r['breakdown']['ioc_score']   >  0
                        or r['breakdown']['mitre_score'] >  0
                        or r['breakdown'].get('chain_boost', 0) > 0]

            # Chia 2 nhóm: alert (>= min_rank) và info (< min_rank nhưng có điểm)
            alerts = [r for r in detected if self.LEVEL_RANK[r['risk_level']] >= self.min_rank]
            info   = [r for r in detected if self.LEVEL_RANK[r['risk_level']] <  self.min_rank]

            print(f"   📊 Scored: {len(detected)} (alerts={len(alerts)}, info={len(info)})")

            # In info-level (không gửi Shuffle, chỉ show)
            for r in info:
                self._print_info(r)

            # Alert thực sự → aggregator + send Shuffle
            ready = []
            for r in alerts:
                result = self.aggregator.add(r)
                if result:
                    ready.append(result)
            self._send_aggregated(ready)
        else:
            print(f"   (no new logs)")

        # Flush các group đã đủ window (chỉ áp dụng khi window > 0)
        flushed = self.aggregator.flush_old()
        self._send_aggregated(flushed)

    def run_forever(self, interval):
        agg_w = self.config.get('aggregation_window', 0)
        mode = "REALTIME (no aggregation)" if agg_w == 0 else f"AGGREGATED ({agg_w}s window)"
        print(f"\n🔄 Real-time mode | poll={interval}s | {mode}")
        print(f"   Ctrl+C to stop.\n")
        while self.running:
            try:
                self.run_once()
            except Exception as e:
                print(f"   ❌ Cycle error: {e}")
            for _ in range(interval):
                if not self.running: break
                time.sleep(1)
        if self.aggregator.window > 0:
            print("\n📦 Flushing remaining alerts before exit...")
            flushed = self.aggregator.flush_all()
            self._send_aggregated(flushed)


# ============================================================
# 🚀 MAIN
# ============================================================
def main():
    parser = argparse.ArgumentParser(description='Command Line Detection - Real-time')
    parser.add_argument('--interval', type=int, default=CONFIG['poll_interval'],
                        help='Poll interval (seconds)')
    parser.add_argument('--once',         action='store_true', help='Chạy 1 lần rồi thoát')
    parser.add_argument('--no-alert',     action='store_true', help='Không gửi alert đến Shuffle')
    parser.add_argument('--show-payload', action='store_true', help='In full JSON payload trước khi gửi')
    args = parser.parse_args()

    agg_w = CONFIG['aggregation_window']
    print("=" * 60)
    print("🛡️  COMMAND LINE DETECTION - REAL-TIME")
    print(f"   Started     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"   Mode        : {'ONCE' if args.once else f'LOOP (poll {args.interval}s)'}")
    print(f"   Aggregation : {'OFF (realtime)' if agg_w == 0 else f'{agg_w}s window'}")
    print(f"   Risk weights: ML={CONFIG['risk_weights']['ml_score']} IOC={CONFIG['risk_weights']['ioc_score']} MITRE={CONFIG['risk_weights']['mitre_score']}")
    print(f"   Alerts      : {'OFF (test)' if args.no_alert else 'ON (Shuffle SOAR)'}")
    print(f"   Payload log : {'ON' if args.show_payload else 'OFF'}")
    print("=" * 60)

    detector = CommandDetector(CONFIG)
    detector.train()

    print("\n" + "=" * 60)
    print("📡 CONNECTING TO ELASTICSEARCH")
    print("=" * 60)
    es = ElasticsearchClient(CONFIG['elasticsearch'])
    if not es.test_connection():
        print("❌ Không kết nối được Elasticsearch.")
        sys.exit(1)

    alerter = ShuffleAlerter(CONFIG['shuffle_webhook_url'])
    engine = RealTimeEngine(detector, es, alerter, CONFIG,
                            send_alerts=not args.no_alert,
                            show_payload=args.show_payload)
    if args.once:
        engine.run_once()
        if engine.aggregator.window > 0:
            flushed = engine.aggregator.flush_all()
            engine._send_aggregated(flushed)
    else:
        engine.run_forever(args.interval)

    print("\n👋 Done.")


if __name__ == '__main__':
    main()
