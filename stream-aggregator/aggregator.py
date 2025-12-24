#!/usr/bin/env python3
"""
Stream Aggregator - SMART CACHE INVALIDATION (v7.10)
Updates:
- ✅ LOGIC: Detect Attack Switching (e.g., PortScan -> SSH).
- ✅ FIX: Invalidate old cache & Start fresh session on switch.
- ✅ FIX: Force Detailed Alert for the switch event.
"""
import os
import json
import logging
import asyncio
import signal
import time
import math
import random
import hashlib
from datetime import datetime, timedelta
from threading import Lock
from collections import defaultdict

import pandas as pd
import numpy as np
import httpx
from confluent_kafka import Consumer, Producer, KafkaException
from dateutil import parser as date_parser

try:
    from feature_engineer import NIDSFeatureEngineer
except ImportError:
    print("❌ Error: Missing 'feature_engineering.py'")
    exit(1)

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
INPUT_TOPIC = os.getenv('INPUT_TOPIC', 'zeek-raw')
OUTPUT_TOPIC = os.getenv('OUTPUT_TOPIC', 'ml-predictions')
XAI_QUEUE_TOPIC = os.getenv('XAI_QUEUE_TOPIC', 'xai-queue')
CONSUMER_GROUP = os.getenv('CONSUMER_GROUP', 'stream-aggregator-group')

WINDOW_SIZE_SECONDS = int(os.getenv('WINDOW_SIZE_SECONDS', '10'))
MAX_BUFFER_SIZE = int(os.getenv('MAX_BUFFER_SIZE', '5000'))
FLUSH_INTERVAL_SECONDS = 5

ML_API_URL = os.getenv('ML_API_URL', 'http://ml-api:5000')
ENCODER_PATH = os.getenv('ENCODER_PATH', '/opt/ml-nids/models/feature_schema_lgbm.pkl')

# Cache & Session Settings
CACHE_TTL_SECONDS = 300 
CACHE_MIN_CONFIDENCE = 0.90
CACHE_REVERIFY_RATE = float(os.getenv('CACHE_REVERIFY_RATE', '0.1'))
MAX_ACTIVE_SESSIONS = 50000 

DROP_FIELDS = ['agent', 'host', 'ecs', 'error', 'message', 'input', 'log', 'tags', '@version', '@metadata']

# ==========================================
# UTILITY
# ==========================================
def get_attack_session_id(src_ip, attack_type):
    now = datetime.utcnow()
    time_bucket = now.strftime('%Y-%m-%d-%H')
    raw_str = f"{src_ip}-{attack_type}-{time_bucket}"
    return hashlib.md5(raw_str.encode()).hexdigest()

# ==========================================
# 1. SMART ATTACK CACHE
# ==========================================
class AttackCache:
    def __init__(self, ttl_seconds=60, max_hits=1000, min_conf=0.90):
        self.cache = {} 
        self.ttl = ttl_seconds
        self.max_hits = max_hits
        self.min_conf = min_conf
        self.lock = Lock()
    
    def get(self, src_ip):
        with self.lock:
            if src_ip in self.cache:
                entry = self.cache[src_ip]
                now = time.time()
                if now > entry['expiry']:
                    del self.cache[src_ip]
                    return None
                entry['hits'] += 1
                return entry['data'].copy()
        return None

    def set(self, src_ip, result):
        if not result.get('is_attack') or result.get('confidence', 0) < self.min_conf:
            return
        
        session_id = result.get('session_id')
        if not session_id:
            session_id = get_attack_session_id(src_ip, result['attack_type'])
        
        cache_data = {
            'is_attack': True,
            'attack_type': result['attack_type'],
            'confidence': result['confidence'],
            'session_id': session_id,
            'verdict': 'Cached Attack',
            'from_cache': True 
        }

        with self.lock:
            self.cache[src_ip] = {
                'data': cache_data,
                'expiry': time.time() + self.ttl,
                'hits': 0
            }

    # [NEW] Hàm xóa cache cụ thể
    def invalidate(self, src_ip):
        with self.lock:
            if src_ip in self.cache:
                del self.cache[src_ip]
                return True
        return False

    def cleanup(self):
        with self.lock:
            now = time.time()
            expired = [ip for ip, e in self.cache.items() if now > e['expiry']]
            for ip in expired: del self.cache[ip]
            if expired:
                logger.info(f"🧹 Cache Cleanup: Removed {len(expired)} expired IPs")

# ==========================================
# 2. CONTEXT MANAGER
# ==========================================
class FlowContextManager:
    def __init__(self):
        self.buffer = {} 
        self.last_cleanup = time.time()
        
    def add_context(self, uid, log_type, data):
        if uid not in self.buffer:
            self.buffer[uid] = {'timestamp': time.time()}
        if log_type == 'dns':
            if 'query' in data: self.buffer[uid]['query'] = data['query']
        elif log_type == 'http':
            if 'uri' in data: self.buffer[uid]['uri'] = data['uri']
            if 'method' in data: self.buffer[uid]['method'] = data['method']
            
    def pop_context(self, uid):
        return self.buffer.pop(uid, {})

    def cleanup(self):
        now = time.time()
        if now - self.last_cleanup < 60: return 
        expired = [uid for uid, ctx in self.buffer.items() if now - ctx['timestamp'] > 60]
        for uid in expired: del self.buffer[uid]
        self.last_cleanup = now

# ==========================================
# 3. MAIN STREAM AGGREGATOR
# ==========================================
class StreamAggregator:
    def __init__(self):
        self.running = False
        self.consumer = None
        self.producer = None
        self.flow_buffer = [] 
        self.active_flow_indices = {} 
        self.context_manager = FlowContextManager()
        
        self.feature_engineer = NIDSFeatureEngineer(
            time_window=f"{WINDOW_SIZE_SECONDS}s",
            encoder_path=ENCODER_PATH,
            model_type='if' 
        )
        
        try:
            lgbm_feats = self.feature_engineer.FEATURES_LGBM
            if_feats = self.feature_engineer.FEATURES_IF
            hybrid_features = list(set(lgbm_feats + if_feats))
            self.feature_engineer.feature_columns = hybrid_features
            self.lgbm_features_list = lgbm_feats
            logger.info(f"🔧 Hybrid Mode Enabled: {len(hybrid_features)} features")
        except AttributeError:
            logger.error("❌ Feature Engineer Error: Update feature_engineering.py")
            exit(1)

        self.http_client = httpx.AsyncClient(timeout=30.0)
        self.attack_cache = AttackCache(ttl_seconds=CACHE_TTL_SECONDS, min_conf=CACHE_MIN_CONFIDENCE)
        
        self.active_sessions = {}
        self.stats = {'consumed': 0, 'cache_hits': 0, 'reverified': 0, 'suppressed': 0, 'api_calls': 0, 'summaries': 0}
        self.last_cleanup = time.time()

    def setup_kafka(self):
        conf = {
            'bootstrap.servers': KAFKA_BOOTSTRAP,
            'group.id': CONSUMER_GROUP,
            'auto.offset.reset': 'latest'
        }
        self.consumer = Consumer(conf)
        self.consumer.subscribe([INPUT_TOPIC])
        self.producer = Producer({'bootstrap.servers': KAFKA_BOOTSTRAP})
        logger.info(f"✅ Kafka Connected. Topic: {INPUT_TOPIC}")

    async def predict_batch(self, features_df):
        try:
            missing_cols = set(self.lgbm_features_list) - set(features_df.columns)
            if missing_cols:
                logger.error(f"❌ Missing columns: {missing_cols}")
                for c in missing_cols: features_df[c] = 0

            api_df = features_df[self.lgbm_features_list].copy()
            api_df = api_df.replace([np.inf, -np.inf], 0).fillna(0)
            
            for col in api_df.columns:
                if pd.api.types.is_datetime64_any_dtype(api_df[col]):
                    api_df[col] = api_df[col].astype(str)

            features_list = api_df.to_dict(orient='records')
            payload = {'samples': [{'features': f} for f in features_list]}
            
            resp = await self.http_client.post(f"{ML_API_URL}/predict_batch", json=payload)
            
            if resp.status_code == 200:
                return resp.json().get('predictions', [])
            else:
                return None
        except Exception as e:
            logger.error(f"ML API Error: {e}")
            return None

    def clean_payload(self, payload):
        for field in DROP_FIELDS: payload.pop(field, None)
        return payload

    def sanitize_for_json(self, data):
        if isinstance(data, dict): return {k: self.sanitize_for_json(v) for k, v in data.items()}
        elif isinstance(data, list): return [self.sanitize_for_json(v) for v in data]
        elif isinstance(data, (np.bool_, bool)): return bool(data)
        elif isinstance(data, (np.integer, int)): return int(data)
        elif isinstance(data, (np.floating, float)): 
            if math.isnan(data) or math.isinf(data): return 0.0
            return float(data)
        elif isinstance(data, np.ndarray): return self.sanitize_for_json(data.tolist())
        return data

    def ensure_iso_timestamp(self, ts_value):
        try:
            if isinstance(ts_value, (int, float)): return datetime.fromtimestamp(ts_value).isoformat()
            if isinstance(ts_value, datetime): return ts_value.isoformat()
            if isinstance(ts_value, str): return ts_value.replace(' ', 'T') 
            return datetime.utcnow().isoformat() 
        except:
            return datetime.utcnow().isoformat()

    def cleanup_states(self):
        now = time.time()
        if now - self.last_cleanup > 60: 
            self.attack_cache.cleanup()
            current_time = datetime.utcnow()
            
            if len(self.active_sessions) > MAX_ACTIVE_SESSIONS:
                sorted_sessions = sorted(self.active_sessions.items(), key=lambda item: item[1] or datetime.min)
                cutoff = int(MAX_ACTIVE_SESSIONS * 0.8)
                self.active_sessions = dict(sorted_sessions[-cutoff:])

            expired_sessions = [
                sid for sid, last_seen in self.active_sessions.items()
                if last_seen and (current_time - last_seen).total_seconds() > 3600
            ]
            for sid in expired_sessions:
                del self.active_sessions[sid]
            
            self.last_cleanup = now

    async def process_window(self):
        if not self.flow_buffer: return
        
        window_stats = {
            'flows': len(self.flow_buffer),
            'hits': 0, 'reverified': 0, 'api_calls': 0, 'suppressed': 0, 'summaries': 0
        }
        
        current_flows = list(self.flow_buffer)
        self.flow_buffer = []
        self.active_flow_indices = {} 
        
        logger.info(f"📦 Processing Window: {len(current_flows)} flows")
        
        flows_to_predict = []
        indices_to_predict = []
        final_results = [None] * len(current_flows)
        
        cache_aggregator = defaultdict(lambda: {
            'count': 0, 'bytes': 0, 'first_ts': None, 'last_ts': None, 
            'src_ip': None, 'attack_type': None, 'confidence': 0.0
        })

        # --- 1. CACHE FILTERING & RE-VERIFY ---
        for idx, flow in enumerate(current_flows):
            src_ip = flow.get('id.orig_h')
            cached_result = self.attack_cache.get(src_ip)
            
            should_reverify = False
            if cached_result:
                if random.random() < CACHE_REVERIFY_RATE:
                    should_reverify = True
                    window_stats['reverified'] += 1
                    # Lưu lại state cũ để so sánh
                    flow['_prev_session_id'] = cached_result.get('session_id')
                    flow['_prev_attack_type'] = cached_result.get('attack_type')
                
                flow['_was_cached'] = True

            if cached_result and not should_reverify:
                session_id = cached_result.get('session_id')
                if session_id:
                    self.active_sessions[session_id] = datetime.utcnow()

                agg = cache_aggregator[session_id]
                agg['count'] += 1
                bytes_in = flow.get('orig_bytes', 0) or 0
                if isinstance(bytes_in, (int, float)): agg['bytes'] += bytes_in
                
                ts = flow.get('ts')
                if agg['first_ts'] is None: agg['first_ts'] = ts
                agg['last_ts'] = ts
                
                agg['src_ip'] = src_ip
                agg['attack_type'] = cached_result['attack_type']
                agg['confidence'] = cached_result['confidence']
                
                final_results[idx] = cached_result
                window_stats['hits'] += 1
                
            else:
                flows_to_predict.append(flow)
                indices_to_predict.append(idx)

        # --- 2. ML INFERENCE ---
        df_all_raw = pd.DataFrame(current_flows)
        df_all_features = self.feature_engineer.extract_all_features(df_all_raw)
        
        if flows_to_predict:
            df_predict_features = df_all_features.iloc[indices_to_predict]
            predictions = await self.predict_batch(df_predict_features)
            window_stats['api_calls'] += 1
            
            if predictions:
                for i, pred in enumerate(predictions):
                    original_idx = indices_to_predict[i]
                    flow = current_flows[original_idx]
                    
                    pred['from_cache'] = False 
                    pred['_first_alert'] = False
                    
                    if pred.get('is_attack'):
                        src_ip = flows_to_predict[i].get('id.orig_h')
                        attack_type = pred['attack_type']
                        
                        # --- [NEW] DETECT SWITCHING ---
                        # Nếu flow này trước đó được cache, và loại tấn công thay đổi
                        if flow.get('_was_cached'):
                            prev_type = flow.get('_prev_attack_type')
                            if prev_type and prev_type != attack_type:
                                logger.warning(f"🔄 Attack Switch Detected: {src_ip} ({prev_type} -> {attack_type})")
                                # 1. Xóa cache cũ
                                self.attack_cache.invalidate(src_ip)
                                # 2. Force Session mới (sẽ được tạo ở dưới)
                                # Logic bên dưới sẽ tự tạo session_id mới vì attack_type khác
                        
                        # Generate ID (New or Existing)
                        session_id = get_attack_session_id(src_ip, attack_type)
                        pred['session_id'] = session_id
                        
                        if session_id not in self.active_sessions:
                            # NEW ATTACK SESSION
                            self.active_sessions[session_id] = datetime.utcnow()
                            pred['_first_alert'] = True 
                            logger.warning(f"🚨 New Attack Session: {attack_type} from {src_ip}")
                        else:
                            # EXISTING SESSION
                            self.active_sessions[session_id] = datetime.utcnow()
                            pred['_first_alert'] = False
                        
                        self.attack_cache.set(src_ip, pred)
                    
                    final_results[original_idx] = pred
            else:
                for idx in indices_to_predict:
                    final_results[idx] = {'is_attack': False, 'verdict': 'ML_ERROR', 'from_cache': False}

        # --- 3. MERGE & PRODUCE ---
        for i, result in enumerate(final_results):
            if result is None: continue 
            
            is_attack = result.get('is_attack') or result.get('is_anomaly')
            is_from_cache = result.get('from_cache', False)
            is_first_alert = result.get('_first_alert', False)
            
            # --- SUPPRESSION LOGIC ---
            # Suppress nếu: (Là Attack) VÀ (Từ Cache HOẶC (Session cũ VÀ Không phải alert đầu))
            if is_attack and (is_from_cache or not is_first_alert):
                window_stats['suppressed'] += 1
                
                # Cộng dồn vào Aggregator nếu là flow mới detect (nhưng thuộc session cũ)
                if not is_from_cache: 
                    session_id = result.get('session_id')
                    if session_id:
                        agg = cache_aggregator[session_id]
                        agg['count'] += 1
                        bytes_in = current_flows[i].get('orig_bytes', 0) or 0
                        if isinstance(bytes_in, (int, float)): agg['bytes'] += bytes_in
                        
                        if agg['src_ip'] is None:
                            agg['src_ip'] = current_flows[i].get('id.orig_h')
                            agg['attack_type'] = result.get('attack_type')
                            agg['confidence'] = result.get('confidence')
                            agg['first_ts'] = current_flows[i].get('ts') 
                        agg['last_ts'] = current_flows[i].get('ts')
                
                continue 
            
            # --- PRODUCE SINGLE ALERT (New Attack/Session or Benign) ---
            flow_data = current_flows[i]
            
            # Lazy convert features
            features_series = df_all_features.iloc[i]
            features_dict = {}
            for col, val in features_series.items():
                if isinstance(val, (pd.Timestamp, datetime)):
                    features_dict[col] = str(val)
                else:
                    features_dict[col] = val
            
            enriched_flow = {**flow_data, **features_dict, **result}
            enriched_flow = self.clean_payload(enriched_flow)

            ts_source = enriched_flow.get('timestamp') or enriched_flow.get('ts')
            enriched_flow['timestamp'] = self.ensure_iso_timestamp(ts_source)
            if 'ts' in enriched_flow: enriched_flow['ts'] = enriched_flow['timestamp']
            
            enriched_flow = self.sanitize_for_json(enriched_flow)

            # A. Output Topic (Detailed Log)
            es_payload = enriched_flow.copy()
            es_payload.pop('features_vector', None)
            self.producer.produce(OUTPUT_TOPIC, json.dumps(es_payload).encode('utf-8'))
            
            # B. XAI Queue (First Alert of Attack)
            if is_attack and is_first_alert:
                self.producer.produce(XAI_QUEUE_TOPIC, json.dumps(enriched_flow).encode('utf-8'))

        # --- 4. PRODUCE SUMMARIES ---
        for session_id, agg in cache_aggregator.items():
            if agg['count'] == 0: continue
            
            last_ts = agg['last_ts'] or datetime.utcnow()
            first_ts = agg['first_ts'] or last_ts

            summary_log = {
                'timestamp': self.ensure_iso_timestamp(last_ts),
                'window_start': self.ensure_iso_timestamp(first_ts),
                'log_type': 'flow_summary',
                'id.orig_h': agg['src_ip'],
                'attack_type': agg['attack_type'],
                'is_attack': True,
                'verdict': 'Cached Attack Summary',
                'flow_count': agg['count'],
                'total_bytes': agg['bytes'],
                'session_id': session_id,
                'confidence': agg['confidence'],
                'detection_method': 'CACHE_AGGREGATED'
            }
            
            summary_log = self.sanitize_for_json(summary_log)
            self.producer.produce(OUTPUT_TOPIC, json.dumps(summary_log).encode('utf-8'))
            window_stats['summaries'] += 1

        self.producer.flush()
        logger.info(
            f"✅ Window Done. Flows: {window_stats['flows']} | "
            f"Hits: {window_stats['hits']} | "
            f"Suppressed: {window_stats['suppressed']} | "
            f"Summaries: {window_stats['summaries']}"
        )

        self.stats['consumed'] += window_stats['flows']
        self.stats['cache_hits'] += window_stats['hits']
        self.stats['suppressed'] += window_stats['suppressed']

    async def consume_loop(self):
        logger.info("🚀 Starting Consumption Loop...")
        last_flush = time.time()
        
        while self.running:
            now = time.time()
            if (now - last_flush) >= FLUSH_INTERVAL_SECONDS or len(self.flow_buffer) >= MAX_BUFFER_SIZE:
                await self.process_window()
                last_flush = now
                self.context_manager.cleanup()
                self.cleanup_states()

            msg = self.consumer.poll(0.5)
            if msg is None: continue
            if msg.error():
                if msg.error().code() != KafkaException._TIMEDOUT:
                    logger.error(f"Kafka Error: {msg.error()}")
                continue

            try:
                raw_val = msg.value().decode('utf-8')
                record = json.loads(raw_val)
                data = record.get('message', record)
                if isinstance(data, str): 
                    try: data = json.loads(data)
                    except: data = record

                uid = data.get('uid')
                if 'ts' in data:
                    try:
                        ts_raw = data['ts']
                        if isinstance(ts_raw, (int, float)):
                            data['ts'] = datetime.fromtimestamp(float(ts_raw))
                        else:
                            data['ts'] = date_parser.parse(str(ts_raw))
                    except:
                        data['ts'] = datetime.utcnow()

                log_type = 'unknown'
                if 'id.orig_h' in data and 'duration' in data: log_type = 'conn'
                elif 'query' in data: log_type = 'dns'
                elif 'uri' in data: log_type = 'http'
                
                if uid:
                    if log_type == 'conn':
                        context = self.context_manager.pop_context(uid)
                        merged_flow = {**data, **context}
                        self.flow_buffer.append(merged_flow)
                        self.active_flow_indices[uid] = len(self.flow_buffer) - 1
                    elif log_type in ['dns', 'http']:
                        if uid in self.active_flow_indices:
                            idx = self.active_flow_indices[uid]
                            if idx < len(self.flow_buffer):
                                if log_type == 'dns' and 'query' in data:
                                    self.flow_buffer[idx]['query'] = data['query']
                                elif log_type == 'http' and 'uri' in data:
                                    self.flow_buffer[idx]['uri'] = data['uri']
                        else:
                            self.context_manager.add_context(uid, log_type, data)
                self.stats['consumed'] += 1
            except Exception as e:
                logger.error(f"Consume Error: {e}")

    async def start(self):
        self.running = True
        self.setup_kafka()
        await self.consume_loop()

    async def stop(self):
        self.running = False
        if self.consumer: self.consumer.close()
        await self.http_client.aclose()
        logger.info("🛑 Aggregator Stopped")

if __name__ == '__main__':
    agg = StreamAggregator()
    loop = asyncio.get_event_loop()
    def signal_handler(): asyncio.create_task(agg.stop())
    for sig in (signal.SIGINT, signal.SIGTERM): loop.add_signal_handler(sig, signal_handler)
    loop.run_until_complete(agg.start())