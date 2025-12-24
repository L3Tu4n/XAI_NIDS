#!/usr/bin/env python3
"""
XAI + LLM Worker - SESSION ID ENABLED (v7.3 - Retry Fix)
Updates:
- ✅ FIX RACE CONDITION: Retry ES update if doc not found (Wait for indexing).
- ✅ Uses 'session_id' for deduplication.
- ✅ Fixed SHAP Dtypes.
"""
import os
import json
import logging
import asyncio
import signal
import time  # Import time for sleep
from datetime import datetime, timedelta
import joblib
import shap
import pandas as pd
import numpy as np
from confluent_kafka import Consumer
from elasticsearch import Elasticsearch
import google.generativeai as genai

# Setup logging
logging.basicConfig(
    level=os.getenv('LOG_LEVEL', 'INFO'),
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)
logger = logging.getLogger('xai-worker')

# CONFIGURATION
KAFKA_BOOTSTRAP = os.getenv('KAFKA_BOOTSTRAP_SERVERS', 'kafka:9092')
INPUT_TOPIC = os.getenv('INPUT_TOPIC', 'xai-queue')
CONSUMER_GROUP = os.getenv('CONSUMER_GROUP', 'xai-worker-group')
MODEL_DIR = os.getenv('MODEL_DIR', '/opt/ml-nids/models')
ES_HOSTS = os.getenv('ES_HOSTS', 'https://192.168.63.134:9200')
ES_INDEX = os.getenv('ES_INDEX', 'ml-nids-alerts')
ES_USERNAME = os.getenv('ES_USERNAME', 'elastic')
ES_PASSWORD = os.getenv('ES_PASSWORD', 'changeme')
GEMINI_API_KEY = os.getenv('GEMINI_API_KEY', '')
MAX_SHAP_FEATURES = 10
XAI_DEDUP_HOURS = 1

# ==========================================
# HELPERS
# ==========================================
class SHAPExplainer:
    def __init__(self, model_path, metadata_path):
        logger.info(f"Loading models from {model_path}")
        self.models = joblib.load(model_path)
        with open(metadata_path, 'r') as f:
            self.metadata = json.load(f)
        self.feature_names = self.metadata.get('feature_names', [])
        
        # [FIX] Dtypes
        self.cat_cols = [c for c in self.feature_names if 'encoded' in c or 'numeric' in c]
        logger.info(f"Categorical columns identified: {self.cat_cols}")
        
        self.explainers = [shap.TreeExplainer(model) for model in self.models]
    
    def explain(self, features_dict, top_n=10):
        try:
            # 1. Extract values
            ordered_features = []
            for name in self.feature_names:
                try: val = float(features_dict.get(name, 0))
                except: val = 0.0
                ordered_features.append(val)

            # 2. Create DF & Enforce Dtypes
            feature_vector = pd.DataFrame([ordered_features], columns=self.feature_names)
            for col in self.cat_cols:
                if col in feature_vector.columns:
                    feature_vector[col] = feature_vector[col].fillna(0).astype(int).astype('category')

            # 3. Calculate SHAP
            shap_list = []
            for explainer in self.explainers:
                sv = explainer.shap_values(feature_vector)
                if isinstance(sv, list): sv = np.mean(sv, axis=0)
                if sv.ndim == 2: sv = sv[0]
                elif sv.ndim > 2: sv = sv.reshape(-1, len(self.feature_names))[0]
                shap_list.append(sv)
            
            avg_shap = np.mean(np.array(shap_list), axis=0)
            
            # 4. Rank Features
            feature_importance = []
            for i, name in enumerate(self.feature_names):
                val = float(avg_shap[i])
                feature_importance.append({
                    'feature': name,
                    'shap_value': val,
                    'abs_shap_value': abs(val),
                    'feature_value': float(ordered_features[i]), 
                    'direction': 'attack' if val > 0 else 'benign'
                })
            
            feature_importance.sort(key=lambda x: x['abs_shap_value'], reverse=True)
            return {'top_features': feature_importance[:top_n]}
        except Exception as e:
            logger.error(f"SHAP explanation error: {e}", exc_info=True)
            return None

class LLMExplainer:
    def __init__(self):
        if GEMINI_API_KEY:
            genai.configure(api_key=GEMINI_API_KEY)
            self.model = genai.GenerativeModel('gemini-2.5-flash')
            self.active = True
            logger.info("✓ Gemini API configured")
        else:
            self.active = False
            logger.warning("LLM Disabled (No Key)")

    async def generate_content(self, prompt):
        if not self.active: return None
        try:
            logger.info("Calling LLM...")
            response = await asyncio.to_thread(self.model.generate_content, prompt)
            text = response.text.strip()
            logger.info(f"✓ LLM generated ({len(text)} chars)")
            return text
        except Exception as e:
            logger.error(f"LLM Error: {e}")
            return None

# ==========================================
# WORKER
# ==========================================
class XAIWorker:
    def __init__(self):
        self.running = False
        self.consumer = None
        self.es = None
        
        self.shap = SHAPExplainer(
            os.path.join(MODEL_DIR, 'nids_tri_lgbm_v1.joblib'),
            os.path.join(MODEL_DIR, 'nids_tri_lgbm_v1_metadata.json')
        )
        self.llm = LLMExplainer()
        
        # Deduplication Cache
        self.processed_sessions = set()
        self.stats = {'processed': 0, 'explained': 0, 'skipped': 0, 'errors': 0}

    def setup(self):
        self.consumer = Consumer({
            'bootstrap.servers': KAFKA_BOOTSTRAP,
            'group.id': CONSUMER_GROUP,
            'auto.offset.reset': 'latest'
        })
        self.consumer.subscribe([INPUT_TOPIC])
        
        import urllib3
        urllib3.disable_warnings()
        self.es = Elasticsearch(
            [ES_HOSTS], basic_auth=(ES_USERNAME, ES_PASSWORD),
            verify_certs=False, ssl_show_warn=False, request_timeout=30
        )
        if self.es.ping(): logger.info("✓ Connected to Elasticsearch")

    async def process_alert(self, data):
        session_id = data.get('session_id')
        attack_type = data.get('attack_type', 'Unknown')
        src_ip = data.get('src_ip', data.get('id.orig_h', 'Unknown'))
        
        logger.info(f"Processing session: {session_id} | {attack_type} from {src_ip}")
        
        # 1. Deduplication by Session ID
        if session_id and session_id in self.processed_sessions:
            logger.info(f"Skipping duplicate session: {session_id}")
            self.stats['skipped'] += 1
            return
        
        # 2. SHAP
        logger.info("Running SHAP analysis...")
        shap_res = self.shap.explain(data)
        if not shap_res: return

        # 3. LLM Explanation
        prompt = f"""Explain this network attack:
        Type: {attack_type}
        Source: {src_ip}
        Top Features: {json.dumps(shap_res['top_features'][:3])}
        Risk & Mitigation? concise."""
        
        explanation = await self.llm.generate_content(prompt)
        
        # 4. LLM Rule
        rule_prompt = f"""Generate Suricata rule for {attack_type} based on:
        {json.dumps(shap_res['top_features'][:2])}
        Return ONLY the rule string."""
        rule = await self.llm.generate_content(rule_prompt)

        # 5. Update Elasticsearch by Session ID (WITH RETRY)
        if session_id:
            updated = 0
            retries = 3  # Thử lại 3 lần
            
            # [FIX] Vòng lặp Retry
            for attempt in range(retries):
                try:
                    logger.info(f"Updating Elasticsearch (Attempt {attempt+1}/{retries})...")
                    
                    query = {
                        "script": {
                            "source": "ctx._source.xai_explanation = params.exp; ctx._source.xai_rule = params.rule; ctx._source.xai_shap = params.shap; ctx._source.xai_processed = true",
                            "params": {
                                "exp": explanation or "N/A",
                                "rule": rule or "N/A",
                                "shap": shap_res['top_features']
                            }
                        },
                        "query": {"term": {"session_id.keyword": session_id}} # Dùng session_id
                    }
                    
                    resp = self.es.update_by_query(
                        index=f"{ES_INDEX}-*", 
                        body=query,
                        wait_for_completion=True,
                        refresh=True # Force refresh để tìm thấy ngay
                    )
                    updated = resp.get('updated', 0)
                    
                    if updated > 0:
                        logger.info(f"✓ Updated {updated} docs in SIEM successfully for session {session_id}")
                        self.processed_sessions.add(session_id)
                        self.stats['explained'] += 1
                        break # Thành công -> Thoát vòng lặp
                    else:
                        logger.warning(f"⚠ Attempt {attempt+1}: No documents found for session {session_id}. Waiting...")
                        await asyncio.sleep(2) # Đợi 2s để ES Consumer kịp index
                        
                except Exception as e:
                    logger.error(f"ES Update Error (Attempt {attempt+1}): {e}")
                    await asyncio.sleep(2)

            if updated == 0:
                logger.error(f"❌ Failed to update session {session_id} after {retries} retries. Document might be missing.")
                self.stats['errors'] += 1

    async def run(self):
        self.setup()
        logger.info("🚀 XAI Worker Started (Session-Based + Retry)")
        while self.running:
            msg = self.consumer.poll(1.0)
            if msg and not msg.error():
                try:
                    data = json.loads(msg.value().decode('utf-8'))
                    self.stats['processed'] += 1
                    await self.process_alert(data)
                    
                    if self.stats['processed'] % 10 == 0:
                        logger.info(f"Stats: {self.stats}")
                except Exception as e:
                    logger.error(f"Consume Error: {e}")

    def start(self):
        self.running = True
        asyncio.run(self.run())

    def stop(self):
        self.running = False

if __name__ == '__main__':
    worker = XAIWorker()
    loop = asyncio.get_event_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, worker.stop)
    worker.start()