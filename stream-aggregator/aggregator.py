#!/usr/bin/env python3
"""
Stream Aggregator - BEHAVIORAL INTELLIGENCE (v7.13)

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
from concurrent.futures import ThreadPoolExecutor

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

CACHE_TTL_SECONDS = 300 
CACHE_MIN_CONFIDENCE = 0.45
CACHE_REVERIFY_RATE = 0.1 # 10% ngẫu nhiên
FORCE_VERIFY_EVERY = 50   # Ép buộc sau 50 packets từ cùng 1 IP
MAX_ACTIVE_SESSIONS = 50000

DROP_FIELDS = ['agent', 'host', 'ecs', 'error', 'message', 'input', 'log', 'tags', '@version', '@metadata']

# ==========================================
# UTILITY
# ==========================================
def get_attack_session_id(src_ip, attack_type):
    time_bucket = datetime.utcnow().strftime('%Y-%m-%d-%H')
    raw_str = f"{src_ip}-{attack_type}-{time_bucket}"
    return hashlib.md5(raw_str.encode()).hexdigest()

# ==========================================
# 1. SMART ATTACK CACHE (BEHAVIORAL)
# ==========================================
class AttackCache:
    def __init__(self, ttl_seconds, min_conf):
        self.cache = {} 
        self.ttl = ttl_seconds
        self.min_conf = min_conf
        self.lock = Lock()
    
    def get(self, src_ip, current_port=None, current_proto=None):
        with self.lock:
            if src_ip in self.cache:
                entry = self.cache[src_ip]
                now = time.time()
                
                # 1. Check TTL
                if now > entry['expiry']:
                    del self.cache[src_ip]
                    return None
                
                # 2. Check Hit-count (Ép buộc kiểm tra lại định kỳ)
                entry['hits'] += 1
                if entry['hits'] % FORCE_VERIFY_EVERY == 0:
                    return None 

                # 3. Check Behavioral Change (Đổi Port hoặc Protocol)
                # Nếu IP đang quét port này mà nhảy sang port khác -> Cần ML check lại
                if current_port and entry.get('last_port') != current_port:
                    return None
                if current_proto and entry.get('last_proto') != current_proto:
                    return None

                return entry['data'].copy()
        return None

    def set(self, src_ip, result, port=None, proto=None):
        if not result.get('is_attack') or result.get('confidence', 0) < self.min_conf:
            return
        
        session_id = result.get('session_id') or get_attack_session_id(src_ip, result['attack_type'])
        cache_data = {
            'is_attack': True, 'attack_type': result['attack_type'],
            'confidence': result['confidence'], 'session_id': session_id,
            'verdict': 'Cached Attack', 'from_cache': True 
        }
        with self.lock:
            self.cache[src_ip] = {
                'data': cache_data, 
                'expiry': time.time() + self.ttl, 
                'hits': 0,
                'last_port': port,
                'last_proto': proto
            }

    def invalidate(self, src_ip):
        with self.lock:
            return self.cache.pop(src_ip, None) is not None

    def cleanup(self):
        with self.lock:
            now = time.time()
            expired = [ip for ip, e in self.cache.items() if now > e['expiry']]
            for ip in expired: del self.cache[ip]

# ==========================================
# 2. CONTEXT MANAGER (Giữ nguyên)
# ==========================================
class FlowContextManager:
    def __init__(self):
        self.buffer = {} 
        self.last_cleanup = time.time()
        
    def add_context(self, uid, log_type, data):
        if uid not in self.buffer: self.buffer[uid] = {'timestamp': time.time()}
        if log_type == 'dns': self.buffer[uid]['query'] = data.get('query')
        elif log_type == 'http': self.buffer[uid].update({'uri': data.get('uri'), 'method': data.get('method')})
            
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
        self.executor = ThreadPoolExecutor(max_workers=os.cpu_count())
        
        self.feature_engineer = NIDSFeatureEngineer(
            time_window=f"{WINDOW_SIZE_SECONDS}s",
            encoder_path=ENCODER_PATH, model_type='if' 
        )
        lgbm_feats = self.feature_engineer.FEATURES_LGBM
        self.lgbm_features_list = lgbm_feats
        self.feature_engineer.feature_columns = list(set(lgbm_feats + self.feature_engineer.FEATURES_IF))

        self.http_client = httpx.AsyncClient(timeout=30.0)
        self.attack_cache = AttackCache(ttl_seconds=CACHE_TTL_SECONDS, min_conf=CACHE_MIN_CONFIDENCE)
        self.active_sessions = {}
        self.stats = {'consumed': 0, 'cache_hits': 0, 'reverified': 0, 'suppressed': 0, 'api_calls': 0, 'summaries': 0}
        self.last_cleanup = time.time()

    def setup_kafka(self):
        conf = {'bootstrap.servers': KAFKA_BOOTSTRAP, 'group.id': CONSUMER_GROUP, 'auto.offset.reset': 'latest'}
        self.consumer = Consumer(conf)
        self.consumer.subscribe([INPUT_TOPIC])
        self.producer = Producer({'bootstrap.servers': KAFKA_BOOTSTRAP})
        logger.info(f"✅ Kafka Connected. Topic: {INPUT_TOPIC}")

    def _extract_features_sync(self, flows):
        df_raw = pd.DataFrame(flows)
        return self.feature_engineer.extract_all_features(df_raw)

    async def predict_batch(self, features_df):
        try:
            api_df = features_df.reindex(columns=self.lgbm_features_list, fill_value=0)
            api_df = api_df.replace([np.inf, -np.inf], 0).fillna(0)
            for col in api_df.columns:
                if pd.api.types.is_datetime64_any_dtype(api_df[col]): api_df[col] = api_df[col].astype(str)
            payload = {'samples': [{'features': f} for f in api_df.to_dict(orient='records')]}
            resp = await self.http_client.post(f"{ML_API_URL}/predict_batch", json=payload)
            return resp.json().get('predictions', []) if resp.status_code == 200 else None
        except Exception as e:
            logger.error(f"ML API Error: {e}"); return None

    def clean_payload(self, payload):
        for f in DROP_FIELDS: payload.pop(f, None)
        return payload

    def sanitize_for_json(self, data):
        if isinstance(data, dict): return {k: self.sanitize_for_json(v) for k, v in data.items()}
        elif isinstance(data, list): return [self.sanitize_for_json(v) for v in data]
        elif isinstance(data, (pd.Timestamp, datetime, np.datetime64)): return str(data)
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
        except: return datetime.utcnow().isoformat()

    def cleanup_states(self):
        now = time.time()
        if now - self.last_cleanup > 60: 
            self.attack_cache.cleanup()
            current_time = datetime.utcnow()
            if len(self.active_sessions) > MAX_ACTIVE_SESSIONS:
                sorted_sessions = sorted(self.active_sessions.items(), key=lambda item: item[1] or datetime.min)
                self.active_sessions = dict(sorted_sessions[-int(MAX_ACTIVE_SESSIONS * 0.8):])
            expired = [sid for sid, last_seen in self.active_sessions.items() if (current_time - last_seen).total_seconds() > 3600]
            for sid in expired: del self.active_sessions[sid]
            self.last_cleanup = now

    async def process_window(self):
        if not self.flow_buffer: return
        
        window_stats = {'flows': len(self.flow_buffer), 'hits': 0, 'reverified': 0, 'api_calls': 0, 'suppressed': 0, 'summaries': 0}
        current_flows = list(self.flow_buffer)
        self.flow_buffer, self.active_flow_indices = [], {}
        
        logger.info(f"📦 Processing Window: {len(current_flows)} flows")
        
        flows_to_predict, indices_to_predict = [], []
        final_results = [None] * len(current_flows)
        cache_aggregator = defaultdict(lambda: {'count': 0, 'bytes': 0, 'first_ts': None, 'last_ts': None, 'src_ip': None, 'attack_type': None, 'confidence': 0.0})

        # --- 1. LỌC CACHE (BEHAVIORAL CHECK) ---
        for idx, flow in enumerate(current_flows):
            src_ip = flow.get('id.orig_h')
            dest_port = flow.get('id.resp_p')
            proto = flow.get('proto')
            
            # CẢI TIẾN: Gửi thêm Port và Proto vào Cache check
            cached = self.attack_cache.get(src_ip, current_port=dest_port, current_proto=proto)
            
            # Re-verify ngẫu nhiên (Duy trì 10% để check thay đổi nhỏ)
            reverify = (cached and random.random() < CACHE_REVERIFY_RATE)

            if cached and not reverify:
                sid = cached.get('session_id')
                if sid:
                    self.active_sessions[sid] = datetime.utcnow()
                    agg = cache_aggregator[sid]
                    agg.update({'count': agg['count']+1, 'bytes': agg['bytes']+(flow.get('orig_bytes', 0) or 0), 'src_ip': src_ip, 'attack_type': cached['attack_type'], 'confidence': cached['confidence']})
                    if agg['first_ts'] is None: agg['first_ts'] = flow.get('ts')
                    agg['last_ts'] = flow.get('ts')
                final_results[idx] = cached
                window_stats['hits'] += 1
            else:
                # Nếu không có trong cache HOẶC đổi port/proto HOẶC hit-count đạt ngưỡng -> Predict
                if reverify: window_stats['reverified'] += 1
                flows_to_predict.append(flow); indices_to_predict.append(idx)

        # --- 2. XỬ LÝ ML (THREADPOOL) ---
        if flows_to_predict:
            loop = asyncio.get_event_loop()
            df_features = await loop.run_in_executor(self.executor, self._extract_features_sync, flows_to_predict)
            predictions = await self.predict_batch(df_features)
            window_stats['api_calls'] += 1
            
            if predictions:
                for i, pred in enumerate(predictions):
                    orig_idx = indices_to_predict[i]
                    src_ip = flows_to_predict[i].get('id.orig_h')
                    dest_port = flows_to_predict[i].get('id.resp_p')
                    proto = flows_to_predict[i].get('proto')
                    new_atk = pred.get('attack_type')
                    
                    if pred.get('is_attack'):
                        curr_cache = self.attack_cache.get(src_ip)
                        is_fresh = not curr_cache or curr_cache['attack_type'] != new_atk
                        
                        if is_fresh and curr_cache:
                            logger.warning(f"🔄 Attack Changed: {src_ip} ({curr_cache['attack_type']} -> {new_atk})")
                            self.attack_cache.invalidate(src_ip)
                        
                        sid = get_attack_session_id(src_ip, new_atk)
                        pred.update({'session_id': sid, '_first_alert': is_fresh or sid not in self.active_sessions, 'from_cache': False})
                        
                        if pred['_first_alert']:
                            logger.warning(f"🚨 FRESH ALERT: {new_atk} from {src_ip}")
                        
                        self.active_sessions[sid] = datetime.utcnow()
                        # CẬP NHẬT: Lưu cả port và proto vào cache mới
                        self.attack_cache.set(src_ip, pred, port=dest_port, proto=proto)
                    
                    final_results[orig_idx] = pred
                    flows_to_predict[i]['_features'] = df_features.iloc[i].to_dict()

        # --- 3. MERGE & PRODUCE ---
        for i, result in enumerate(final_results):
            if not result: continue
            is_attack = result.get('is_attack')
            is_first_alert = result.get('_first_alert', False)
            
            if is_attack and (result.get('from_cache', False) or not is_first_alert):
                window_stats['suppressed'] += 1
                continue
            
            flow_data = current_flows[i]
            feats = flow_data.pop('_features', {})
            enriched = self.sanitize_for_json({**flow_data, **feats, **result})
            enriched['timestamp'] = self.ensure_iso_timestamp(enriched.get('ts') or time.time())
            
            p_bytes = json.dumps(self.clean_payload(enriched)).encode('utf-8')
            self.producer.produce(OUTPUT_TOPIC, p_bytes)
            if is_attack and is_first_alert: self.producer.produce(XAI_QUEUE_TOPIC, p_bytes)

        # --- 4. PRODUCE SUMMARIES ---
        for sid, agg in cache_aggregator.items():
            if agg['count'] == 0: continue
            summary = self.sanitize_for_json({'@timestamp': self.ensure_iso_timestamp(agg['last_ts']), 'log_type': 'flow_summary', 'id.orig_h': agg['src_ip'], 'attack_type': agg['attack_type'], 'is_attack': True, 'flow_count': agg['count'], 'session_id': sid, 'verdict': 'Cached Attack Summary'})
            self.producer.produce(OUTPUT_TOPIC, json.dumps(summary).encode('utf-8'))
            window_stats['summaries'] += 1

        self.producer.flush()
        logger.info(f"✅ Window Done. Flows: {window_stats['flows']} | Hits: {window_stats['hits']} | Suppressed: {window_stats['suppressed']} | Summaries: {window_stats['summaries']}")

    async def consume_loop(self):
        logger.info("🚀 Starting Consumption Loop...")
        last_flush = time.time()
        while self.running:
            now = time.time()
            if (now - last_flush) >= FLUSH_INTERVAL_SECONDS or len(self.flow_buffer) >= MAX_BUFFER_SIZE:
                await self.process_window(); last_flush = now; self.context_manager.cleanup(); self.cleanup_states()
            msg = self.consumer.poll(0.5)
            if msg is None: continue
            if msg.error():
                if msg.error().code() != KafkaException._TIMEDOUT: logger.error(f"Kafka Error: {msg.error()}")
                continue
            try:
                record = json.loads(msg.value().decode('utf-8'))
                data = record.get('message', record)
                if isinstance(data, str): 
                    try: data = json.loads(data)
                    except: data = record
                uid = data.get('uid')
                if 'ts' in data:
                    try: ts_raw = data['ts']; data['ts'] = datetime.fromtimestamp(float(ts_raw)) if isinstance(ts_raw, (int, float)) else date_parser.parse(str(ts_raw))
                    except: data['ts'] = datetime.utcnow()
                log_type = 'conn' if 'duration' in data else 'dns' if 'query' in data else 'http' if 'uri' in data else 'unknown'
                if uid:
                    if log_type == 'conn':
                        self.flow_buffer.append({**data, **self.context_manager.pop_context(uid)})
                        self.active_flow_indices[uid] = len(self.flow_buffer) - 1
                    elif log_type in ['dns', 'http']:
                        if uid in self.active_flow_indices:
                            idx = self.active_flow_indices[uid]
                            if idx < len(self.flow_buffer):
                                if log_type == 'dns': self.flow_buffer[idx]['query'] = data.get('query')
                                else: self.flow_buffer[idx].update({'uri': data.get('uri'), 'method': data.get('method')})
                        else: self.context_manager.add_context(uid, log_type, data)
            except Exception as e: logger.error(f"Consume Error: {e}")

    async def start(self):
        self.running = True; self.setup_kafka(); await self.consume_loop()

    async def stop(self):
        self.running = False
        if self.consumer: self.consumer.close()
        await self.http_client.aclose(); self.executor.shutdown(wait=True)
        logger.info("🛑 Aggregator Stopped")

if __name__ == '__main__':
    agg = StreamAggregator()
    loop = asyncio.get_event_loop()
    for sig in (signal.SIGINT, signal.SIGTERM): loop.add_signal_handler(sig, lambda: asyncio.create_task(agg.stop()))
    try: loop.run_until_complete(agg.start())
    except KeyboardInterrupt: pass
