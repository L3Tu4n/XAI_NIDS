#!/usr/bin/env python3
"""
Stream Aggregator - PRODUCTION READY (FIXED LOGIC ERRORS + DEBUG LOGGING)

Critical fixes:
1. ✅ Fixed index mapping between flows_df and features_df
2. ✅ Fixed features extraction for cached flows
3. ✅ Added proper None/empty result handling
4. ✅ Fixed representative flow selection logic
5. ✅ Added thread-safe cache operations
6. ✅ Enhanced timestamp parsing (handles ms/s + debug logging)
7. ✅ Added comprehensive flow tracking debug logs

Author: ML-NIDS Team
Version: 2.1.0
"""
import os
import json
import logging
import asyncio
import signal
import hashlib
from datetime import datetime, timedelta
from collections import defaultdict
from threading import Lock

import pandas as pd
import numpy as np
import httpx
from confluent_kafka import Consumer, Producer, KafkaException
from dateutil import parser as date_parser

from feature_engineer import StreamFeatureEngineer

# Setup logging
logging.basicConfig(
    level=os.getenv('LOG_LEVEL', 'INFO'),
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)
logger = logging.getLogger('stream-aggregator')

# ==========================================
# CONFIGURATION
# ==========================================
KAFKA_BOOTSTRAP = os.getenv('KAFKA_BOOTSTRAP_SERVERS', 'kafka:9092')
INPUT_TOPIC = os.getenv('INPUT_TOPIC', 'zeek-conn')
OUTPUT_TOPIC = os.getenv('OUTPUT_TOPIC', 'ml-predictions')
XAI_QUEUE_TOPIC = os.getenv('XAI_QUEUE_TOPIC', 'xai-queue')
CONSUMER_GROUP = os.getenv('CONSUMER_GROUP', 'stream-aggregator-group')
WINDOW_SIZE_SECONDS = int(os.getenv('WINDOW_SIZE_SECONDS', '10'))
FLUSH_INTERVAL_SECONDS = int(os.getenv('FLUSH_INTERVAL_SECONDS', '5'))
MAX_BUFFER_SIZE = int(os.getenv('MAX_BUFFER_SIZE', '1000'))
ML_API_URL = os.getenv('ML_API_URL', 'http://ml-api:5000')
ENCODER_PATH = os.getenv('ENCODER_PATH', '/opt/ml-nids/models/feature_schema.pkl')

# Cache & Aggregation Settings
CACHE_TTL_SECONDS = int(os.getenv('CACHE_TTL_SECONDS', '300'))
CACHE_MIN_CONFIDENCE = float(os.getenv('CACHE_MIN_CONFIDENCE', '0.85'))
CACHE_UPDATE_CONFIDENCE = float(os.getenv('CACHE_UPDATE_CONFIDENCE', '0.90'))
MAX_UNIQUE_TRACKING = int(os.getenv('MAX_UNIQUE_TRACKING', '1000'))
XAI_SEVERITY_THRESHOLD = int(os.getenv('XAI_SEVERITY_THRESHOLD', '0'))

# ==========================================
# UTILITY FUNCTIONS
# ==========================================
def get_attack_session_id(src_ip, attack_type, time_bucket_hours=1):
    """Generate deterministic session ID for attack tracking"""
    now = datetime.utcnow()
    bucket = now.replace(minute=0, second=0, microsecond=0)
    session_string = f"{src_ip}:{attack_type}:{bucket.isoformat()}"
    session_id = hashlib.md5(session_string.encode()).hexdigest()[:16]
    return session_id


def calculate_attack_severity(group):
    """Calculate attack severity score (0-100)"""
    volume_score = min(40, (group['flow_count'] / 100) * 40)
    
    unique_targets = max(
        group.get('unique_dst_ip_count', 0),
        group.get('unique_dst_port_count', 0)
    )
    scope_score = min(30, (unique_targets / 10) * 30)
    confidence_score = group['avg_confidence'] * 20
    
    critical_types = {
        'Infiltration': 10, 'Web Attack - SQL Injection': 9,
        'Web Attack - XSS': 8, 'Web Attack - Brute Force': 7,
        'Bot': 7, 'DDoS': 6, 'DoS Hulk': 5, 'PortScan': 4,
        'SSH-Patator': 6, 'FTP-Patator': 6
    }
    type_score = critical_types.get(group['attack_type'], 3)
    
    severity = volume_score + scope_score + confidence_score + type_score
    return min(100, int(severity))


def safe_str(value):
    """Safely convert to string"""
    return str(value) if pd.notna(value) else '-'


def safe_num(value, default=0.0):
    """Safely convert to number"""
    return float(value) if pd.notna(value) else default


# ==========================================
# ENHANCED ATTACK CACHE (Thread-safe)
# ==========================================
class AttackCache:
    """Thread-safe cache with enhanced metadata tracking"""
    
    def __init__(self, ttl_seconds=CACHE_TTL_SECONDS):
        self.cache = {}
        self.ttl = ttl_seconds
        self.lock = Lock()  # ✅ Thread-safe
        self.stats = {
            'hits': 0, 'misses': 0,
            'ml_calls_saved': 0, 'unique_attackers': 0
        }
    
    def get(self, src_ip):
        """Get cached attack detection (thread-safe)"""
        with self.lock:
            if src_ip not in self.cache:
                self.stats['misses'] += 1
                return None
            
            entry = self.cache[src_ip]
            
            # Check expiration
            if (datetime.now() - entry['timestamp']).total_seconds() > self.ttl:
                del self.cache[src_ip]
                self.stats['misses'] += 1
                return None
            
            # Cache hit
            self.stats['hits'] += 1
            self.stats['ml_calls_saved'] += 1
            entry['hit_count'] += 1
            entry['last_seen'] = datetime.now()
            
            return entry.copy()  # Return copy to avoid external modification
    
    def set(self, src_ip, attack_type, confidence):
        """Cache attack detection (thread-safe)"""
        if confidence < CACHE_MIN_CONFIDENCE:
            return
        
        with self.lock:
            if src_ip not in self.cache:
                self.cache[src_ip] = {
                    'attack_type': attack_type,
                    'confidence': confidence,
                    'timestamp': datetime.now(),
                    'first_seen': datetime.now(),
                    'last_seen': datetime.now(),
                    'hit_count': 0,
                    'total_flows': 1
                }
                self.stats['unique_attackers'] += 1
                logger.warning(
                    f"🔴 NEW ATTACKER CACHED: {src_ip} → {attack_type} "
                    f"(conf={confidence:.3f})"
                )
            else:
                entry = self.cache[src_ip]
                entry['confidence'] = max(entry['confidence'], confidence)
                entry['timestamp'] = datetime.now()
                entry['total_flows'] += 1
    
    def cleanup(self):
        """Remove expired entries (thread-safe)"""
        with self.lock:
            now = datetime.now()
            expired = [
                ip for ip, e in self.cache.items()
                if (now - e['timestamp']).total_seconds() > self.ttl
            ]
            
            for ip in expired:
                logger.info(f"🧹 Expired cache for {ip}")
                del self.cache[ip]
            
            return len(expired)
    
    def get_summary(self):
        """Get cache statistics summary (thread-safe)"""
        with self.lock:
            total_requests = self.stats['hits'] + self.stats['misses']
            hit_rate = (self.stats['hits'] / total_requests * 100) \
                       if total_requests > 0 else 0
            
            return {
                'cache_size': len(self.cache),
                'hit_rate': f"{hit_rate:.1f}%",
                'ml_calls_saved': self.stats['ml_calls_saved'],
                'unique_attackers': self.stats['unique_attackers']
            }


# ==========================================
# WINDOW BUFFER (ENHANCED)
# ==========================================
class WindowBuffer:
    """Time-based window buffer for flow aggregation"""
    
    def __init__(self, window_size_seconds=10):
        self.window_size = timedelta(seconds=window_size_seconds)
        self.flows = []
        self.window_start = None
        self.window_end = None
    
    def add_flow(self, flow_dict):
        """Add flow to window buffer with enhanced debugging"""
        raw_ts = flow_dict.get('ts')
        if not raw_ts:
            logger.debug(f"❌ Flow missing 'ts' field: {list(flow_dict.keys())[:5]}")
            return False
        
        try:
            # ✅ Handle both seconds and milliseconds timestamps
            if isinstance(raw_ts, (int, float)):
                ts_float = float(raw_ts)
                if ts_float > 1e12:  # Likely milliseconds
                    ts = datetime.fromtimestamp(ts_float / 1000)
                    logger.debug(f"Converted ms timestamp: {ts_float} → {ts}")
                else:
                    ts = datetime.fromtimestamp(ts_float)
            else:
                ts = date_parser.parse(str(raw_ts))
            
            logger.debug(f"✓ Parsed timestamp: {ts} (raw: {raw_ts})")
        except Exception as e:
            logger.warning(f"❌ Timestamp parse failed: {e} (raw: {raw_ts})")
            return False
        
        flow_dict['ts'] = ts
        
        # Initialize window on first flow
        if self.window_start is None:
            self.window_start = ts
            self.window_end = ts + self.window_size
            logger.info(f"🪟 New window created: {self.window_start} → {self.window_end}")
        
        # Check if flow belongs to current window
        if ts < self.window_end:
            self.flows.append(flow_dict)
            logger.debug(f"✓ Flow added to window (total: {len(self.flows)})")
            return True
        else:
            logger.info(
                f"⏭️ Flow outside window: {ts} >= {self.window_end} "
                f"(current window has {len(self.flows)} flows)"
            )
            return False
    
    def is_ready(self):
        return len(self.flows) > 0
    
    def get_flows(self):
        return self.flows
    
    def clear(self):
        logger.debug(f"🧹 Clearing window buffer ({len(self.flows)} flows)")
        self.flows = []
        self.window_start = None
        self.window_end = None


# ==========================================
# MAIN AGGREGATOR
# ==========================================
class StreamAggregator:
    """Main Stream Aggregator with intelligent caching and aggregation"""
    
    def __init__(self):
        self.running = False
        self.consumer = None
        self.producer = None
        self.buffer = WindowBuffer(window_size_seconds=WINDOW_SIZE_SECONDS)
        
        self.feature_engineer = StreamFeatureEngineer(encoder_path=ENCODER_PATH)
        self.http_client = httpx.AsyncClient(timeout=120.0)
        
        self.attack_cache = AttackCache(ttl_seconds=CACHE_TTL_SECONDS)
        
        self.stats = {
            'consumed': 0, 'windows_processed': 0,
            'attacks_detected': 0, 'alerts_sent': 0,
            'xai_queued': 0, 'errors': 0
        }
    
    def setup_kafka(self):
        """Initialize Kafka consumer and producer"""
        conf_c = {
            'bootstrap.servers': KAFKA_BOOTSTRAP,
            'group.id': CONSUMER_GROUP,
            'auto.offset.reset': 'latest',
            'enable.auto.commit': True
        }
        self.consumer = Consumer(conf_c)
        self.consumer.subscribe([INPUT_TOPIC])
        
        self.producer = Producer({'bootstrap.servers': KAFKA_BOOTSTRAP})
        logger.info(f"✓ Kafka Connected (topic: {INPUT_TOPIC})")
    
    def compute_behavioral(self, df):
        """Compute behavioral features for window"""
        if df.empty:
            return df
        
        src_stats = df.groupby('id.orig_h').agg(
            src_conn_count=('id.orig_h', 'size'),
            src_unique_dests=('id.resp_h', 'nunique'),
            src_unique_ports=('id.resp_p', 'nunique'),
            src_service_diversity=('service', 'nunique')
        ).reset_index()
        
        dst_stats = df.groupby('id.resp_h').size().reset_index(
            name='dst_conn_count'
        )
        
        df = df.merge(src_stats, on='id.orig_h', how='left')
        df = df.merge(dst_stats, on='id.resp_h', how='left')
        
        return df.fillna(0)
    
    async def predict_batch(self, features_df):
        """Call ML API for batch prediction"""
        try:
            payload = {
                'samples': [
                    {'features': dict(zip(features_df.columns, r))}
                    for r in features_df.values.tolist()
                ]
            }
            resp = await self.http_client.post(
                f"{ML_API_URL}/predict_batch",
                json=payload
            )
            
            if resp.status_code == 200:
                return resp.json().get('predictions', [])
            else:
                logger.error(f"ML API returned {resp.status_code}")
                return None
        
        except Exception as e:
            logger.error(f"ML API Error: {e}")
            return None
       
    async def process_window(self):
        """
        ✅ FIXED: Main window processing with corrected index mapping
        """
        flows = self.buffer.get_flows()
        if not flows:
            return
        
        logger.info(
            f"📦 Window: {len(flows)} flows | "
            f"{self.attack_cache.get_summary()}"
        )
        
        try:
            # ========================================
            # STEP 1: Prepare Data
            # ========================================
            flows_df = pd.DataFrame(flows)
            
            meta_cols = [
                'ts', 'uid', 'id.orig_h', 'id.resp_h', 'id.resp_p',
                'proto', 'service', 'duration', 'orig_bytes', 'resp_bytes',
                'conn_state', 'orig_pkts', 'resp_pkts'
            ]
            for c in meta_cols:
                if c not in flows_df.columns:
                    flows_df[c] = None
            
            flows_with_behavior = self.compute_behavioral(flows_df)
            features_df_all = self.feature_engineer.extract_features(flows_with_behavior)
            # ========================================
            # STEP 2: Cache-based Routing
            # ========================================
            indices_need_ml = []
            final_results = [None] * len(flows)
            
            for i, row in flows_with_behavior.iterrows():
                src_ip = row.get('id.orig_h')
                cached = self.attack_cache.get(src_ip)
                
                if cached:
                    # CACHE HIT
                    final_results[i] = {
                        'is_attack': True,
                        'attack_type': cached['attack_type'],
                        'confidence': cached['confidence'],
                        'attack_probability': cached['confidence'],
                        'predicted_class': -1,
                        'method': 'CACHE',
                        'anomaly_score': 0.0, 'is_anomaly': False
                    }
                else:
                    # CACHE MISS
                    indices_need_ml.append(i)
            
            # ========================================
            # STEP 3: ML Prediction for Cache Misses
            # ========================================
            # ✅ FIX #1: Create index mapping for ML predictions
            index_mapping = {}  # ml_result_index -> original_flow_index
            
            if indices_need_ml:
                df_for_ml = flows_with_behavior.iloc[indices_need_ml]
                features_df = self.feature_engineer.extract_features(df_for_ml)
                
                # Create explicit mapping
                for ml_idx, original_idx in enumerate(indices_need_ml):
                    index_mapping[ml_idx] = original_idx
                
                logger.info(
                    f"🧠 Calling ML for {len(indices_need_ml)} uncached flows..."
                )
                predictions = await self.predict_batch(features_df)
                
                if predictions:
                    # ✅ FIXED: Use correct index mapping
                    for ml_idx, pred in enumerate(predictions):
                        original_idx = index_mapping[ml_idx]
                        
                        # Update cache if high-confidence attack
                        if pred['is_attack'] and \
                           pred['confidence'] > CACHE_UPDATE_CONFIDENCE:
                            ip = flows_with_behavior.iloc[original_idx].get(
                                'id.orig_h'
                            )
                            if ip:
                                self.attack_cache.set(
                                    ip,
                                    pred['attack_type'],
                                    pred['confidence']
                                )
                        
                        final_results[original_idx] = {
                            'is_attack': pred['is_attack'],
                            'attack_type': pred['attack_type'],
                            'confidence': float(pred['confidence']),
                            'attack_probability': float(
                                pred.get('attack_probability', 0)
                            ),
                            'predicted_class': pred['predicted_class'],
                            'method': 'ML',
                            'cache_metadata': None,
                            # 🌟 THÊM HAI TRƯỜNG NÀY TỪ PREDICTION
                            'anomaly_score': float(pred.get('anomaly_score', 0.0)),
                            'is_anomaly': pred.get('is_anomaly', False)
                        }
                else:
                    # ML FAILED - Fallback
                    logger.error(
                        f"ML API failed for {len(indices_need_ml)} flows"
                    )
                    for original_idx in indices_need_ml:
                        final_results[original_idx] = {
                            'is_attack': False,
                            'attack_type': 'BENIGN',
                            'confidence': 0.0,
                            'attack_probability': 0.0,
                            'predicted_class': 0,
                            'method': 'ML_FAILED',
                            'cache_metadata': None
                        }
            
            # ========================================
            # STEP 4: SMART AGGREGATION
            # ========================================
            attack_groups = {}
            benign_count = 0
            
            for i, result in enumerate(final_results):
                # ✅ FIX #3: Proper None/empty check
                if result is None or not isinstance(result, dict):
                    logger.warning(f"Invalid result at index {i}: {result}")
                    continue
                
                meta = flows_df.iloc[i]
                b_row = flows_with_behavior.iloc[i]
                
                # --- A. BENIGN: Send individual ---
                if not result.get('is_attack', False):
                    benign_count += 1
                    
                    event = {
                        'timestamp': datetime.utcnow().isoformat(),
                        'log_type': 'flow',
                        'window_start': self.buffer.window_start.isoformat(),
                        'src_ip': safe_str(meta.get('id.orig_h')),
                        'dst_ip': safe_str(meta.get('id.resp_h')),
                        'dst_port': int(safe_num(meta.get('id.resp_p'))),
                        'proto': safe_str(meta.get('proto')),
                        'service': safe_str(meta.get('service')),
                        'uid': safe_str(meta.get('uid')),
                        'duration': float(safe_num(meta.get('duration'))),
                        'orig_bytes': int(safe_num(meta.get('orig_bytes'))),
                        'resp_bytes': int(safe_num(meta.get('resp_bytes'))),
                        'conn_state': safe_str(meta.get('conn_state')),
                        'src_conn_count': int(
                            safe_num(b_row.get('src_conn_count'))
                        ),
                        'is_attack': False,
                        'attack_type': 'BENIGN',
                        'confidence': result['confidence'],
                        'detection_method': result['method'],
                        'anomaly_score': float(pred.get('anomaly_score', 0.0)),                      
                    }
                    
                    self.producer.produce(
                        OUTPUT_TOPIC,
                        json.dumps(event).encode('utf-8')
                    )
                    continue
                
                # --- B. ATTACK: Aggregate ---
                src_ip = safe_str(meta.get('id.orig_h'))
                attack_type = result['attack_type']
                key = (src_ip, attack_type)
                
                # ✅ FIX #2: Use centralized feature extraction
                encoded_features_row = features_df_all.iloc[i].to_dict()
                clean_features = {k: float(v) if isinstance(v, (np.float32, np.float64, np.integer)) else v for k, v in encoded_features_row.items()}

                # Initialize attack group
                if key not in attack_groups:
                    session_id = get_attack_session_id(src_ip, attack_type)
                    attack_groups[key] = {
                        'timestamp': datetime.utcnow().isoformat(),
                        'log_type': 'alert_summary',
                        'attack_session_id': session_id,
                        'first_seen': datetime.utcnow().isoformat(),
                        'last_updated': datetime.utcnow().isoformat(),
                        'window_start': self.buffer.window_start.isoformat(),
                        'window_end': (
                            self.buffer.window_start +
                            timedelta(seconds=WINDOW_SIZE_SECONDS)
                        ).isoformat(),
                        'src_ip': src_ip,
                        'attack_type': attack_type,
                        'is_attack': True,
                        'detection_method': result['method'],
                        'flow_count': 0,
                        'total_orig_bytes': 0,
                        'total_resp_bytes': 0,
                        'sum_duration': 0.0,
                        'avg_confidence': 0.0,
                        'sum_anomaly_score': 0.0,
                        'anomaly_flow_count': 0,
                        'protocols': set(),
                        'services': set(),
                        'target_ips_tracking': set(),
                        'target_ports_tracking': set(),
                        'target_overflow': False,
                        'sample_targets': [],
                        'best_candidate': None
                    }
                
                group = attack_groups[key]
                group['last_updated'] = datetime.utcnow().isoformat()
                
                # Accumulate metrics
                group['flow_count'] += 1
                group['total_orig_bytes'] += int(
                    safe_num(meta.get('orig_bytes'))
                )
                group['total_resp_bytes'] += int(
                    safe_num(meta.get('resp_bytes'))
                )
                group['sum_duration'] += float(safe_num(meta.get('duration')))
                if result.get('is_anomaly', False):
                    group['sum_anomaly_score'] += result.get('anomaly_score', 0.0)
                    group['anomaly_flow_count'] += 1
                # Context tracking
                proto = safe_str(meta.get('proto'))
                service = safe_str(meta.get('service'))
                if proto != '-':
                    group['protocols'].add(proto)
                if service != '-':
                    group['services'].add(service)
                
                # Target tracking with overflow protection
                dst_ip = safe_str(meta.get('id.resp_h'))
                dst_port = int(safe_num(meta.get('id.resp_p')))
                
                if len(group['target_ips_tracking']) < MAX_UNIQUE_TRACKING:
                    group['target_ips_tracking'].add(dst_ip)
                else:
                    group['target_overflow'] = True
                
                if len(group['target_ports_tracking']) < MAX_UNIQUE_TRACKING:
                    group['target_ports_tracking'].add(dst_port)
                
                # Incremental average confidence
                curr_sum = group['avg_confidence'] * (group['flow_count'] - 1)
                group['avg_confidence'] = (
                    (curr_sum + result['confidence']) / group['flow_count']
                )
                
                # Sample targets
                if len(group['sample_targets']) < 5:
                    target = f"{dst_ip}:{dst_port}"
                    if target not in group['sample_targets']:
                        group['sample_targets'].append(target)
                
                # ✅ FIX #4: Track representative flows correctly
                flow_record = {
                    'flow_id': safe_str(meta.get('uid')),
                    'timestamp': str(meta.get('ts')),
                    'dst_ip': dst_ip,
                    'dst_port': dst_port,
                    'confidence': result['confidence'],
                    'ml_features': clean_features
                }
                
                current_best = group['best_candidate']
                if current_best is None or result['confidence'] > current_best['confidence']:
                    group['best_candidate'] = flow_record
            
            # ========================================
            # STEP 5: Flush Aggregated Alerts
            # ========================================
            alerts_sent = 0
            xai_queued = 0
            
            for group in attack_groups.values():
                # Select Representatives
                best_flow = group['best_candidate']
                representative_flows = []
                
                if best_flow:
                    # Gán lý do chọn (mặc định là highest_confidence)
                    best_flow['selection_reason'] = 'highest_confidence'
                    representative_flows.append(best_flow)

                # Finalize group data
                del group['best_candidate'] # Xóa biến tạm
                group['protocols'] = list(group['protocols'])
                group['services'] = list(group['services'])
                group['unique_dst_ip_count'] = len(group['target_ips_tracking'])
                group['unique_dst_port_count'] = len(group['target_ports_tracking'])
                del group['target_ips_tracking']
                del group['target_ports_tracking']
                
                group['severity_score'] = calculate_attack_severity(group)
                group['avg_anomaly_score'] = group['sum_anomaly_score'] / group['anomaly_flow_count'] if group['anomaly_flow_count'] > 0 else 0.0
                del group['sum_anomaly_score']
                del group['anomaly_flow_count']

                # --- SPLIT PAYLOADS ---
                
                # A. Send clean summary to ES (ml-predictions)
                # Remove heavy feature data
                es_payload = group.copy()
                # (No representative features in group dict anymore to delete)
                
                self.producer.produce(OUTPUT_TOPIC, json.dumps(es_payload).encode('utf-8'))
                alerts_sent += 1
                
                # B. Send full details to XAI (xai-queue)
                if group['severity_score'] >= 0:
                    xai_payload = {
                        'session_id': group['attack_session_id'],
                        'src_ip': group['src_ip'],
                        'attack_type': group['attack_type'],
                        'severity': group['severity_score'],
                        'flow_count': group['flow_count'],
                        'avg_confidence': group['avg_confidence'],
                        'sample_targets': group['sample_targets'],
                        'timestamp': group['timestamp'],
                        # ⭐️ Only sent to XAI queue
                        'representative_flows': representative_flows 
                    }
                    self.producer.produce(XAI_QUEUE_TOPIC, json.dumps(xai_payload).encode('utf-8'))
                    xai_queued += 1
                    logger.warning(f"⚡ HIGH SEVERITY: {group['attack_type']} (Score={group['severity_score']}) -> XAI Queued")

            self.producer.flush()
            self.stats['windows_processed'] += 1
            self.stats['attacks_detected'] += len(attack_groups)
            
            if alerts_sent > 0:
                logger.warning(f"🚨 ATTACKS: {alerts_sent} alerts | Benign: {benign_count} | XAI: {xai_queued}")
            else:
                logger.info(f"✓ Clean window: {len(flows)} benign flows")
                
            if self.stats['windows_processed'] % 10 == 0:
                self.attack_cache.cleanup()

        except Exception as e:
            logger.error(f"Window processing error: {e}", exc_info=True)
            self.stats['errors'] += 1
        finally:
            self.buffer.clear()
    
    async def consume_loop(self):
        """Main Kafka consumption loop with enhanced debugging (FIXED WINDOW LOGIC)"""
        logger.info("🚀 Starting consumption loop...")
        last_flush = datetime.now()
        
        while self.running:
            
            # --- 1. Force flush on buffer overflow ---
            if len(self.buffer.flows) >= MAX_BUFFER_SIZE:
                logger.warning(
                    f"⚠️ Buffer overflow ({len(self.buffer.flows)}), "
                    f"FORCE FLUSHING..."
                )
                await self.process_window()
                last_flush = datetime.now()
                continue
            
            try:
                # --- 2. Poll Kafka Message ---
                # Poll với timeout ngắn hơn để không bỏ lỡ interval check
                msg = self.consumer.poll(0.5) 
                
                # --- 3. Periodic flush check ---
                if (datetime.now() - last_flush).total_seconds() >= \
                   FLUSH_INTERVAL_SECONDS:
                    if self.buffer.is_ready():
                        logger.info(
                            f"⏱️ Flush interval reached. Processing "
                            f"{len(self.buffer.flows)} flows..."
                        )
                        await self.process_window()
                    last_flush = datetime.now()
                
                if not msg or msg.error():
                    continue
                
                # --- 4. Decode and Parse Message ---
                try:
                    val = msg.value().decode('utf-8')
                    data = json.loads(val)
                    
                    # Handle Filebeat wrapper (như logic cũ)
                    if 'message' in data and isinstance(data['message'], str) and data['message']: # Thêm check data['message'] không rỗng
                        try:
                            log = json.loads(data['message'])
                        except json.JSONDecodeError:
                            log = data
                            logger.debug("Filebeat message field is not JSON, using outer data.")
                    else:
                        log = data
                    
                    # DEBUG: Log first few flows
                    if self.stats['consumed'] < 5:
                        logger.info(f"🔍 Sample flow #{self.stats['consumed']+1}:")
                        logger.info(f"    - ts: {log.get('ts')}")
                        logger.info(f"    - src: {log.get('id.orig_h')}")
                        logger.info(f"    - dst: {log.get('id.resp_h')}:{log.get('id.resp_p')}")
                        logger.info(f"    - proto: {log.get('proto')}")
                        
                    self.stats['consumed'] += 1
                    
                    # --- 5. CORE LOGIC FIX: Try adding flow ---
                    added = self.buffer.add_flow(log)
                    
                    if not added:
                        # Flow không thuộc về cửa sổ hiện tại (quá muộn/quá sớm)
                        logger.info(
                            f"⏭️ Flow ts outside current window. Attempting flush..."
                        )
                        
                        # Chỉ process window hiện tại nếu nó CÓ data
                        if self.buffer.is_ready():
                            await self.process_window()
                        
                        # Sau khi process/clear, thử thêm flow này lại lần nữa.
                        # Lần này flow sẽ tạo cửa sổ mới
                        added_retry = self.buffer.add_flow(log)
                        
                        if added_retry:
                            logger.debug(
                                f"✓ Flow successfully added to new window after flush."
                            )
                        else:
                            # Nếu lần 2 vẫn fail, khả năng cao do timestamp bị lỗi
                            logger.warning(
                                f"⚠️ Flow rejected twice! Invalid TS or parsing error: {log.get('ts')}"
                            )
                        
                        last_flush = datetime.now()
                        
                except json.JSONDecodeError:
                    logger.warning(f"❌ Could not parse JSON message: {msg.value().decode('utf-8')[:100]}...")
                    self.stats['errors'] += 1
                except Exception as e:
                    logger.error(f"Error processing flow: {e}", exc_info=True)
                    self.stats['errors'] += 1
                        
            except KafkaException as e:
                if e.args[0].code() != KafkaException._TIMEDOUT:
                    logger.error(f"Kafka error: {e}")
                await asyncio.sleep(0.5)
            except Exception as e:
                logger.error(f"Consume loop unexpected error: {e}", exc_info=True)
                await asyncio.sleep(1)

    async def start(self):
        """Start aggregator"""
        self.running = True
        logger.info("="*60)
        logger.info("STREAM AGGREGATOR v2.1.0 - DEBUG MODE")
        logger.info("="*60)
        logger.info(f"Window size: {WINDOW_SIZE_SECONDS}s")
        logger.info(f"Flush interval: {FLUSH_INTERVAL_SECONDS}s")
        logger.info(f"Cache TTL: {CACHE_TTL_SECONDS}s")
        logger.info(f"Input topic: {INPUT_TOPIC}")
        logger.info(f"Output topic: {OUTPUT_TOPIC}")
        logger.info(f"ML API: {ML_API_URL}")
        logger.info("="*60)
        
        self.setup_kafka()
        await self.consume_loop()

    async def stop(self):
        """Graceful shutdown"""
        self.running = False
        logger.info("Stopping aggregator...")
        
        if self.consumer:
            self.consumer.close()
        
        await self.http_client.aclose()
        
        # Final stats
        logger.info("="*60)
        logger.info("FINAL STATISTICS")
        logger.info("="*60)
        logger.info(f"Flows consumed: {self.stats['consumed']}")
        logger.info(f"Windows processed: {self.stats['windows_processed']}")
        logger.info(f"Attacks detected: {self.stats['attacks_detected']}")
        logger.info(f"Cache summary: {self.attack_cache.get_summary()}")
        logger.info("="*60)


# ==========================================
# MAIN ENTRY POINT
# ==========================================
async def main():
    agg = StreamAggregator()
    loop = asyncio.get_running_loop()
    
    def shutdown():
        asyncio.create_task(agg.stop())
    
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, shutdown)
    
    await agg.start()


if __name__ == '__main__':
    asyncio.run(main())
