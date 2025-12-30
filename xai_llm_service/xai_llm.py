#!/usr/bin/env python3
<<<<<<< HEAD
=======
"""
XAI + LLM Worker - SESSION ID ENABLED (v7.3 - Retry Fix)
Updates:
- ✅ FIX RACE CONDITION: Retry ES update if doc not found (Wait for indexing).
- ✅ Uses 'session_id' for deduplication.
- ✅ Fixed SHAP Dtypes.
"""
>>>>>>> 0256bb75b84656b7b323e070c4d129eb9a6d1f6b
import os
import json
import logging
import asyncio
import signal
<<<<<<< HEAD
import hashlib
import time
import yaml
from datetime import datetime, timedelta

import numpy as np
import pandas as pd
import joblib
import shap
from confluent_kafka import Consumer
from elasticsearch import Elasticsearch
from groq import AsyncGroq
=======
import time  # Import time for sleep
from datetime import datetime, timedelta
import joblib
import shap
import pandas as pd
import numpy as np
from confluent_kafka import Consumer
from elasticsearch import Elasticsearch
import google.generativeai as genai
>>>>>>> 0256bb75b84656b7b323e070c4d129eb9a6d1f6b

# Setup logging
logging.basicConfig(
    level=os.getenv('LOG_LEVEL', 'INFO'),
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)
logger = logging.getLogger('xai-worker-llama')

<<<<<<< HEAD
# ==========================================
# 1. CONFIGURATION
# ==========================================
KAFKA_BOOTSTRAP = os.getenv('KAFKA_BOOTSTRAP_SERVERS', 'kafka:9092')
INPUT_TOPIC = os.getenv('INPUT_TOPIC', 'xai-queue')
CONSUMER_GROUP = os.getenv('CONSUMER_GROUP', 'xai-worker-v5-stable')

=======
# CONFIGURATION
KAFKA_BOOTSTRAP = os.getenv('KAFKA_BOOTSTRAP_SERVERS', 'kafka:9092')
INPUT_TOPIC = os.getenv('INPUT_TOPIC', 'xai-queue')
CONSUMER_GROUP = os.getenv('CONSUMER_GROUP', 'xai-worker-group')
>>>>>>> 0256bb75b84656b7b323e070c4d129eb9a6d1f6b
MODEL_DIR = os.getenv('MODEL_DIR', '/opt/ml-nids/models')
ES_HOSTS = os.getenv('ES_HOSTS', 'https://192.168.63.134:9200')
ES_INDEX = os.getenv('ES_INDEX', 'ml-nids-alerts')
ES_USERNAME = os.getenv('ES_USERNAME', 'elastic')
<<<<<<< HEAD
ES_PASSWORD = os.getenv('ES_PASSWORD', '')

GROQ_API_KEY = os.getenv('GROQ_API_KEY', '')
XAI_DEDUP_HOURS = int(os.getenv('XAI_DEDUP_HOURS', '1'))
PROMPT_CONFIG_PATH = os.getenv('PROMPT_CONFIG_PATH', 'xai_llm_prompts.yaml')
# ==========================================
# 2. XAI EXPLAINER (SHAP)
=======
ES_PASSWORD = os.getenv('ES_PASSWORD', 'changeme')
GEMINI_API_KEY = os.getenv('GEMINI_API_KEY', '')
MAX_SHAP_FEATURES = 10
XAI_DEDUP_HOURS = 1

# ==========================================
# HELPERS
>>>>>>> 0256bb75b84656b7b323e070c4d129eb9a6d1f6b
# ==========================================
class SHAPExplainer:
    def __init__(self, model_path, metadata_path):
        logger.info(f"Loading models from {model_path}")
        self.models = joblib.load(model_path)
        with open(metadata_path, 'r') as f:
            self.metadata = json.load(f)
        self.feature_names = self.metadata.get('feature_names', [])
<<<<<<< HEAD
        self.cat_cols = [c for c in self.feature_names if 'encoded' in c or 'numeric' in c]
        self.explainers = [shap.TreeExplainer(model) for model in self.models]

    def explain(self, features_dict, top_n=10):
        try:
            ordered_vals = []
            for name in self.feature_names:
                val = features_dict.get(name, 0)
                ordered_vals.append(float(val) if val is not None else 0.0)

            df = pd.DataFrame([ordered_vals], columns=self.feature_names)
            
            for col in self.cat_cols:
                if col in df.columns:
                    df[col] = df[col].fillna(0).astype(int).astype('category')

            shap_list = []
            for explainer in self.explainers:
                sv = explainer.shap_values(df)
                if isinstance(sv, list): sv = np.mean(sv, axis=0)
                if sv.ndim == 2: sv = sv[0]
                elif sv.ndim > 2: sv = sv.reshape(-1, len(self.feature_names))[0]
                shap_list.append(sv)

            avg_shap = np.mean(np.array(shap_list), axis=0)
            feat_imp = []
            for i, name in enumerate(self.feature_names):
                val = float(avg_shap[i])
                feat_imp.append({
                    'feature': name, 'shap_value': val, 'abs_shap_value': abs(val),
                    'feature_value': float(ordered_vals[i]),
                    'direction': 'attack' if val > 0 else 'benign'
                })
            feat_imp.sort(key=lambda x: x['abs_shap_value'], reverse=True)
            return {'top_features': feat_imp[:top_n], 'prediction_score': float(avg_shap.sum())}
        except Exception as e:
            logger.error(f"SHAP Error: {e}"); return None

# ==========================================
# 3. LLM EXPLAINER (Giữ nguyên)
# ==========================================
class LLMExplainer:
    def __init__(self, prompt_path):
        self.client = AsyncGroq(api_key=GROQ_API_KEY)
        self.model_name = "llama-3.3-70b-versatile"
        self.system_instruction = self._load_prompt_from_yaml(prompt_path)
    
    def _load_prompt_from_yaml(self, path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)
                prompt = config.get('system_instruction')
                logger.info(f"✅ Loaded SYSTEM_INSTRUCTION from {path}")
                return prompt
        except Exception as e:
            logger.error(f"❌ Failed to load YAML prompt: {e}. Fallingback to default.")
            return "You are a Tier-3 SOC Analyst. Explain the alert in Vietnamese."

    async def generate_defense_artifacts(self, alert_data, shap_data):
        top_features = shap_data.get('top_features', [])[:10]

        # Tách SHAP theo vai trò (rất quan trọng)
        shap_features = {
            feat['feature']: feat['feature_value']
            for feat in top_features
        }

        llm_input = {
            "alert_context": {
                "model_prediction": alert_data.get('attack_type'),
                "confidence_score": alert_data.get('confidence'),
                "is_anomaly": alert_data.get('is_anomaly')
            },
            "network_telemetry": {
                # Truyền mọi thông số có trong log của bạn
                "protocol_info": {
                    "proto": alert_data.get('proto'),
                    "service": alert_data.get('service'),
                    "conn_state": alert_data.get('conn_state'),
                    "history": alert_data.get('history')
                },
                "addressing": {
                    "src": alert_data.get('id.orig_h'),
                    "dst": alert_data.get('id.resp_h'),
                    "src_p": alert_data.get('id.orig_p'),
                    "dst_p": alert_data.get('id.resp_p')
                },
                "traffic_behavior": {
                    "counts": {
                        "connections": alert_data.get('src_conn_count'),
                        "unique_dst_ports": alert_data.get('src_unique_ports'),
                        "unique_dst_ips": alert_data.get('src_unique_dests')
                    },
                    "volumetric": {
                        "bytes_per_sec": alert_data.get('bytes_per_sec'),
                        "pkts_per_sec": alert_data.get('pkts_per_sec'),
                        "payload_ratio": alert_data.get('pkt_ratio')
                    },
                    "outliers": {
                        "dns_entropy": alert_data.get('dns_entropy'),
                        "duration": alert_data.get('duration')
                    }
                }
            },
            "xai_evidence": top_features # Những đặc trưng khiến model AI đưa ra quyết định
        }

        try:
            response = await self.client.chat.completions.create(
                model=self.model_name,
                messages=[
                    {"role": "system", "content": self.system_instruction},
                    {
                        "role": "user",
                        "content": (
                            "Analyze the following network evidence and XAI explanation. "
                            "Infer the attacker behavior and generate IDS artifacts.\n\n"
                            f"{json.dumps(llm_input, ensure_ascii=False)}"
                        )
                    }
                ],
                temperature=0.1,
                response_format={"type": "json_object"}
            )
            return json.loads(response.choices[0].message.content)

        except Exception as e:
            logger.error(f"Llama API Error: {e}")
            return None

# ==========================================
# 4. XAI WORKER
=======
        
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
>>>>>>> 0256bb75b84656b7b323e070c4d129eb9a6d1f6b
# ==========================================
class XAIWorker:
    def __init__(self):
        self.running = False
        self.consumer = None
        self.es = None
<<<<<<< HEAD
        m_path = os.path.join(MODEL_DIR, 'nids_tri_lgbm_v1.joblib')
        meta_path = os.path.join(MODEL_DIR, 'nids_tri_lgbm_v1_metadata.json')
        self.shap_explainer = SHAPExplainer(m_path, meta_path)
        self.llm_explainer = LLMExplainer(PROMPT_CONFIG_PATH)
        self.explained_sessions = {}
        self.stats = {'processed': 0, 'explained': 0, 'errors': 0}
        self.last_cleanup = time.time()
=======
        
        self.shap = SHAPExplainer(
            os.path.join(MODEL_DIR, 'nids_tri_lgbm_v1.joblib'),
            os.path.join(MODEL_DIR, 'nids_tri_lgbm_v1_metadata.json')
        )
        self.llm = LLMExplainer()
        
        # Deduplication Cache
        self.processed_sessions = set()
        self.stats = {'processed': 0, 'explained': 0, 'skipped': 0, 'errors': 0}
>>>>>>> 0256bb75b84656b7b323e070c4d129eb9a6d1f6b

    def setup(self):
        self.consumer = Consumer({
            'bootstrap.servers': KAFKA_BOOTSTRAP,
            'group.id': CONSUMER_GROUP,
<<<<<<< HEAD
            'auto.offset.reset': 'latest',
            'enable.auto.commit': True
=======
            'auto.offset.reset': 'latest'
>>>>>>> 0256bb75b84656b7b323e070c4d129eb9a6d1f6b
        })
        self.consumer.subscribe([INPUT_TOPIC])
        
        import urllib3
        urllib3.disable_warnings()
        self.es = Elasticsearch(
            [ES_HOSTS], basic_auth=(ES_USERNAME, ES_PASSWORD),
<<<<<<< HEAD
            verify_certs=False, request_timeout=30
        )

    # --- FIX 2: CƠ CHẾ TỰ DỌN DẸP explained_sessions ---
    def _cleanup_old_explanations(self):
        now = datetime.now()
        cutoff = now - timedelta(hours=XAI_DEDUP_HOURS)
        expired = [sid for sid, timestamp in self.explained_sessions.items() if timestamp < cutoff]
        for sid in expired:
            del self.explained_sessions[sid]
        if expired:
            logger.info(f"🧹 XAI Cache Cleanup: Removed {len(expired)} old sessions from memory.")

    async def process_alert(self, alert_data):
        session_id = str(alert_data.get('session_id', '')).strip()
        attack_type = alert_data.get('attack_type', 'Unknown')
        if not session_id: return

        dedup_key = f"{session_id}_{attack_type}"
        if dedup_key in self.explained_sessions: return

        logger.info(f"🚀 XAI Start: {attack_type} | Session: {session_id}")

        try:
            shap_res = self.shap_explainer.explain(alert_data)
            if not shap_res: return
            artifacts = await self.llm_explainer.generate_defense_artifacts(alert_data, shap_res)
            if not artifacts: return

            actual_query = {"term": {"session_id.keyword": session_id}}

            # POLLING (Đợi bản ghi xuất hiện trên ES)
            found = False
            for attempt in range(10):
                resp = self.es.search(index=f"{ES_INDEX}-*", body={"query": actual_query}, size=1)
                if resp['hits']['total']['value'] > 0:
                    found = True; break
                await asyncio.sleep(3)

            if not found:
                logger.error(f"❌ Timeout: Session {session_id} not found on ES."); return

            # CẬP NHẬT ES
            query_body = {
                "query": actual_query,
                "script": {
                    "source": """
                        ctx._source.xai_processed = true;
                        ctx._source.xai_timestamp = params.now;
                        ctx._source.xai_explanation = params.exp;
                        ctx._source.xai_shap = params.shap;
                        ctx._source.genai_suricata_rule = params.rule;
                        ctx._source.genai_zeek_script = params.zeek;
                        ctx._source.genai_provider = params.provider;
                    """,
                    "params": {
                        "now": datetime.utcnow().isoformat(),
                        "exp": artifacts.get('analysis'),
                        "shap": shap_res,
                        "rule": artifacts.get('suricata_rule'),
                        "zeek": artifacts.get('zeek_script'),
                        "provider": f"Groq-{self.llm_explainer.model_name}"
                    },
                    "lang": "painless"
                }
            }

            # --- FIX 1: XỬ LÝ LỖI refresh=True ---
            # Xóa refresh=True, sử dụng default hoặc wait_for_completion=True
            update_resp = self.es.update_by_query(
                index=f"{ES_INDEX}-*",
                body=query_body,
                wait_for_completion=True,
                conflicts="proceed"
            )
            
            logger.info(f"✨ SIEM Updated: {session_id}")
            self.explained_sessions[dedup_key] = datetime.now()
            self.stats['explained'] += 1

        except Exception as e:
            logger.error(f"❌ XAI Processing Error: {e}")
            self.stats['errors'] += 1

    async def start(self):
        self.setup()
        self.running = True
        logger.info("🔥 XAI Worker is running...")
        while self.running:
            # Dọn dẹp định kỳ mỗi 10 phút
            if time.time() - self.last_cleanup > 600:
                self._cleanup_old_explanations()
                self.last_cleanup = time.time()

            msg = self.consumer.poll(1.0)
            if msg is None or msg.error(): continue
            try:
                data = json.loads(msg.value().decode('utf-8'))
                self.stats['processed'] += 1
                await self.process_alert(data)
            except Exception as e:
                logger.error(f"Loop error: {e}")

    def stop(self, *args): self.running = False
=======
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
>>>>>>> 0256bb75b84656b7b323e070c4d129eb9a6d1f6b

if __name__ == '__main__':
    worker = XAIWorker()
    loop = asyncio.get_event_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, worker.stop)
<<<<<<< HEAD
    try: loop.run_until_complete(worker.start())
    except KeyboardInterrupt: pass
=======
    worker.start()
>>>>>>> 0256bb75b84656b7b323e070c4d129eb9a6d1f6b
