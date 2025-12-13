#!/usr/bin/env python3
"""
XAI + LLM Worker for ML-NIDS
- Consumes high-severity attacks from Kafka
- Explains predictions using SHAP
- Generates human-readable explanations using LLM
- Creates detection rules
"""
import os
import json
import logging
import asyncio
import signal
from datetime import datetime
from collections import defaultdict

import numpy as np
import pandas as pd
import joblib
import shap
from confluent_kafka import Consumer, KafkaException
from elasticsearch import Elasticsearch, helpers
import google.generativeai as genai  # For Gemini
# from openai import OpenAI  # Alternative: OpenAI

# Setup logging
logging.basicConfig(
    level=os.getenv('LOG_LEVEL', 'INFO'),
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)
logger = logging.getLogger('xai-worker')

# ==========================================
# CONFIGURATION
# ==========================================
KAFKA_BOOTSTRAP = os.getenv('KAFKA_BOOTSTRAP_SERVERS', 'kafka:9092')
INPUT_TOPIC = os.getenv('INPUT_TOPIC', 'xai-queue')
CONSUMER_GROUP = os.getenv('CONSUMER_GROUP', 'xai-worker-group')

# Model paths
MODEL_DIR = os.getenv('MODEL_DIR', '/opt/ml-nids/models')
MODEL_NAME = os.getenv('MODEL_NAME', 'nids_tri_lgbm_v1_trilgbm')

# Elasticsearch
ES_HOSTS = os.getenv('ES_HOSTS', 'https://192.168.63.134:9200')
ES_INDEX = os.getenv('ES_INDEX', 'ml-nids-alerts')
ES_USERNAME = os.getenv('ES_USERNAME', 'elastic')
ES_PASSWORD = os.getenv('ES_PASSWORD', '')

# LLM Config
LLM_PROVIDER = os.getenv('LLM_PROVIDER', 'gemini')  # 'gemini' or 'openai'
GEMINI_API_KEY = os.getenv('GEMINI_API_KEY', '')
OPENAI_API_KEY = os.getenv('OPENAI_API_KEY', '')

# XAI Config
XAI_DEDUP_HOURS = int(os.getenv('XAI_DEDUP_HOURS', '1'))
MAX_SHAP_FEATURES = int(os.getenv('MAX_SHAP_FEATURES', '10'))


# ==========================================
# XAI EXPLAINER
# ==========================================
class SHAPExplainer:
    """
    SHAP-based explanation for LightGBM predictions
    """
    
    def __init__(self, model_path, metadata_path):
        """
        Args:
            model_path: Path to .joblib file (3 models)
            metadata_path: Path to metadata JSON
        """
        logger.info(f"Loading models from {model_path}")
        
        # Load 3 models
        self.models = joblib.load(model_path)
        
        # Load metadata
        with open(metadata_path, 'r') as f:
            self.metadata = json.load(f)
        
        self.feature_names = self.metadata['feature_names']
        
        # Create SHAP explainers (one for each model)
        logger.info("Initializing SHAP explainers...")
        self.explainers = [
            shap.TreeExplainer(model) for model in self.models
        ]
        
        logger.info(f"✓ SHAP explainers ready ({len(self.explainers)} models)")
    
    def explain(self, features_dict, top_n=10):
        """
        Explain prediction using SHAP
        
        Args:
            features_dict: Dict with 24 ML features
            top_n: Number of top features to return
            
        Returns:
            Dict with SHAP values and feature importance
        """
        try:
            # Convert dict to DataFrame
            feature_vector = pd.DataFrame([features_dict])
            
            # Ensure feature order
            feature_vector = feature_vector[self.feature_names]
            
            # Get SHAP values from all 3 models
            shap_values_list = []
            
            for explainer in self.explainers:
                shap_values = explainer.shap_values(feature_vector)
                
                # Handle different SHAP value formats
                if isinstance(shap_values, list):
                    # Multiclass: shap_values is list of arrays [class0, class1, class2, ...]
                    # Each array is shape (n_samples, n_features)
                    # Stack and take mean across classes
                    shap_values = np.mean(shap_values, axis=0)
                
                # Now shap_values should be (n_samples, n_features)
                # Take first sample (we only have 1 sample)
                if shap_values.ndim == 2:
                    shap_values = shap_values[0]  # Get first row -> (n_features,)
                elif shap_values.ndim > 2:
                    # Reshape to (n_samples, n_features) if needed
                    shap_values = shap_values.reshape(-1, len(self.feature_names))
                    shap_values = shap_values[0]
                
                # Final check: should be 1D array with length = n_features
                if shap_values.shape[0] == len(self.feature_names):
                    shap_values_list.append(shap_values)
                else:
                    logger.warning(
                        f"Skipping explainer: SHAP shape {shap_values.shape} "
                        f"doesn't match {len(self.feature_names)} features"
                    )
            
            # Average SHAP values across 3 models
            if not shap_values_list:
                logger.error("No valid SHAP values from any explainer")
                return None
            
            # Convert to numpy array first
            shap_values_array = np.array(shap_values_list)
            
            # Average along model axis (axis=0)
            avg_shap_values = np.mean(shap_values_array, axis=0)
            
            # Debug: log shapes
            logger.debug(f"Number of explainers used: {len(shap_values_list)}")
            logger.debug(f"SHAP values array shape: {shap_values_array.shape}")
            logger.debug(f"Average SHAP values shape: {avg_shap_values.shape}")
            logger.debug(f"Feature names count: {len(self.feature_names)}")
            
            # Verify dimensions match
            if len(avg_shap_values) != len(self.feature_names):
                logger.error(
                    f"Dimension mismatch: {len(avg_shap_values)} SHAP values "
                    f"vs {len(self.feature_names)} features"
                )
                return None
            
            # Create feature importance ranking
            feature_importance = []
            for i, feature_name in enumerate(self.feature_names):
                # Extract scalar value safely
                shap_val = avg_shap_values[i]
                
                # Convert to Python scalar if it's a numpy type
                if isinstance(shap_val, (np.ndarray, np.generic)):
                    shap_val = float(shap_val.item())
                else:
                    shap_val = float(shap_val)
                
                feature_importance.append({
                    'feature': feature_name,
                    'shap_value': shap_val,
                    'abs_shap_value': abs(shap_val),
                    'feature_value': float(feature_vector[feature_name].iloc[0]),
                    'direction': 'attack' if shap_val > 0 else 'benign'
                })
            
            # Sort by absolute SHAP value
            feature_importance.sort(key=lambda x: x['abs_shap_value'], reverse=True)
            
            # Return top N
            top_features = feature_importance[:top_n]
            
            # Calculate base value safely
            base_values = []
            for exp in self.explainers:
                base_val = exp.expected_value
                # Handle multiclass expected values
                if isinstance(base_val, (list, np.ndarray)):
                    base_val = np.mean(base_val)
                base_values.append(float(base_val))
            
            return {
                'top_features': top_features,
                'base_value': float(np.mean(base_values)),
                'prediction_score': float(avg_shap_values.sum()),
                'all_features': feature_importance
            }
        
        except Exception as e:
            logger.error(f"SHAP explanation error: {e}", exc_info=True)
            logger.error(f"avg_shap_values type: {type(avg_shap_values)}")
            logger.error(f"avg_shap_values shape: {getattr(avg_shap_values, 'shape', 'N/A')}")
            return None


# ==========================================
# LLM EXPLAINER
# ==========================================
class LLMExplainer:
    """
    LLM-based human-readable explanation generator
    """
    
    def __init__(self, provider='gemini'):
        """
        Args:
            provider: 'gemini' or 'openai'
        """
        self.provider = provider
        
        if provider == 'gemini':
            if not GEMINI_API_KEY:
                raise ValueError("GEMINI_API_KEY not set!")
            
            genai.configure(api_key=GEMINI_API_KEY)
            self.model = genai.GenerativeModel('gemini-2.5-flash')
            logger.info("✓ Gemini API configured")
        
        elif provider == 'openai':
            if not OPENAI_API_KEY:
                raise ValueError("OPENAI_API_KEY not set!")
            
            # self.client = OpenAI(api_key=OPENAI_API_KEY)
            logger.info("✓ OpenAI API configured")
        
        else:
            raise ValueError(f"Unknown LLM provider: {provider}")
    
    def _build_prompt(self, alert_data, shap_explanation):
        """
        Build optimized prompt for LLM
        
        Args:
            alert_data: Attack alert from Kafka
            shap_explanation: SHAP explanation results
        """
        # Extract key information
        attack_type = alert_data.get('attack_type', 'Unknown')
        src_ip = alert_data.get('src_ip', 'Unknown')
        flow_count = alert_data.get('flow_count', 0)
        total_bytes = alert_data.get('total_orig_bytes', 0)
        unique_targets = alert_data.get('unique_dst_ip_count', 0)
        severity = alert_data.get('severity_score', 0)
        
        # Format top SHAP features
        top_features = shap_explanation['top_features'][:5]
        features_text = "\n".join([
            f"- {f['feature']}: {f['feature_value']:.2f} "
            f"(SHAP: {f['shap_value']:+.4f}, pushes toward {f['direction']})"
            for f in top_features
        ])
        
        # Build prompt
        prompt = f"""You are a cybersecurity expert explaining network intrusion detection results to a SOC analyst.

ATTACK DETECTED:
- Type: {attack_type}
- Source IP: {src_ip}
- Severity: {severity}/100
- Volume: {flow_count} network flows
- Total Traffic: {total_bytes:,} bytes
- Unique Targets: {unique_targets}

TOP 5 CONTRIBUTING FACTORS (from ML model analysis):
{features_text}

TASK:
Write a concise, professional explanation (3-4 sentences) that:
1. Explains WHY this was classified as {attack_type}
2. Highlights the most suspicious behaviors from the contributing factors
3. Assesses the threat level and potential impact
4. Uses clear, non-technical language suitable for a security analyst

Format: Plain text paragraph, no bullet points."""

        return prompt
    
    async def explain(self, alert_data, shap_explanation):
        """
        Generate human-readable explanation using LLM
        
        Args:
            alert_data: Attack alert dict
            shap_explanation: SHAP results
            
        Returns:
            Dict with explanation and metadata
        """
        try:
            # Build prompt
            prompt = self._build_prompt(alert_data, shap_explanation)
            
            logger.info("Calling LLM for explanation...")
            
            if self.provider == 'gemini':
                # Call Gemini API
                response = await asyncio.to_thread(
                    self.model.generate_content, prompt
                )
                explanation_text = response.text
            
            elif self.provider == 'openai':
                # Call OpenAI API
                # response = await asyncio.to_thread(
                #     self.client.chat.completions.create,
                #     model="gpt-4o-mini",
                #     messages=[{"role": "user", "content": prompt}],
                #     temperature=0.3,
                #     max_tokens=300
                # )
                # explanation_text = response.choices[0].message.content
                pass
            
            logger.info(f"✓ LLM explanation generated ({len(explanation_text)} chars)")
            
            return {
                'explanation': explanation_text.strip(),
                'provider': self.provider,
                'timestamp': datetime.utcnow().isoformat(),
                'prompt_tokens': len(prompt.split()),  # Approximate
                'response_tokens': len(explanation_text.split())
            }
        
        except Exception as e:
            logger.error(f"LLM explanation error: {e}", exc_info=True)
            return None
    
    async def generate_detection_rule(self, alert_data, shap_explanation):
        """
        Generate Suricata detection rule using LLM
        
        Args:
            alert_data: Attack alert dict
            shap_explanation: SHAP results
            
        Returns:
            Suricata rule string
        """
        try:
            attack_type = alert_data.get('attack_type', 'Unknown')
            src_ip = alert_data.get('src_ip', 'Unknown')
            top_features = shap_explanation['top_features'][:3]
            
            # Build rule generation prompt
            prompt = f"""You are a Suricata rule expert. Generate a Suricata detection rule for this attack.

ATTACK DETAILS:
- Type: {attack_type}
- Source IP: {src_ip}
- Key Indicators:
{chr(10).join([f"  * {f['feature']}: {f['feature_value']}" for f in top_features])}

REQUIREMENTS:
1. Create a Suricata rule that detects similar attacks
2. Use appropriate protocol, ports, and flow characteristics
3. Include meaningful metadata (sid, classtype, reference)
4. Keep the rule specific but not overfitted

OUTPUT FORMAT: Return ONLY the Suricata rule, no explanation.
Example: alert tcp any any -> $HOME_NET any (msg:"..."; flow:...; sid:1000001; classtype:trojan-activity;)"""

            if self.provider == 'gemini':
                response = await asyncio.to_thread(
                    self.model.generate_content, prompt
                )
                rule_text = response.text.strip()
            
            # Clean up rule (remove markdown if present)
            rule_text = rule_text.replace('```', '').strip()
            
            logger.info(f"✓ Detection rule generated")
            
            return rule_text
        
        except Exception as e:
            logger.error(f"Rule generation error: {e}", exc_info=True)
            return None


# ==========================================
# XAI WORKER
# ==========================================
class XAIWorker:
    """
    Main XAI worker that processes high-severity attacks
    """
    
    def __init__(self):
        """Initialize XAI worker"""
        self.running = False
        self.consumer = None
        self.es = None
        
        # Load models and explainers
        model_path = os.path.join(MODEL_DIR, f'nids_tri_lgbm_v1_trilgbm.joblib')
        metadata_path = os.path.join(MODEL_DIR, f'nids_tri_lgbm_v1_metadata.json')
        
        self.shap_explainer = SHAPExplainer(model_path, metadata_path)
        self.llm_explainer = LLMExplainer(provider=LLM_PROVIDER)
        
        # Deduplication tracking
        self.explained_sessions = {}  # session_id -> timestamp
        
        # Statistics
        self.stats = {
            'processed': 0,
            'explained': 0,
            'skipped_duplicate': 0,
            'errors': 0
        }
    
    def setup_kafka(self):
        """Initialize Kafka consumer"""
        conf = {
            'bootstrap.servers': KAFKA_BOOTSTRAP,
            'group.id': CONSUMER_GROUP,
            'auto.offset.reset': 'latest',
            'enable.auto.commit': True
        }
        
        self.consumer = Consumer(conf)
        self.consumer.subscribe([INPUT_TOPIC])
        
        logger.info(f"✓ Kafka consumer initialized (topic: {INPUT_TOPIC})")
    
    def setup_elasticsearch(self):
        """Initialize Elasticsearch client (Insecure HTTPS Fix)"""
        # 1. Import và tắt cảnh báo bảo mật (QUAN TRỌNG)
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        # 2. Khởi tạo client với verify_certs=False
        self.es = Elasticsearch(
            [ES_HOSTS],
            basic_auth=(ES_USERNAME, ES_PASSWORD),
            
            # ⭐️ CẤU HÌNH BỎ QUA SSL CHECK ⭐️
            verify_certs=False, 
            ssl_show_warn=False,
            request_timeout=30
        )
        
        # 3. Test kết nối ngay lập tức
        if self.es.ping():
            logger.info("✓ Connected to Elasticsearch (Insecure HTTPS)")
        else:
            # Log lỗi nhưng không raise exception để tránh crash vòng lặp nếu mạng chập chờn
            logger.error("❌ Failed to connect to Elasticsearch. Will retry later.")
    
    def should_explain(self, session_id):
        """
        Check if session should be explained (deduplication)
        
        Args:
            session_id: Attack session ID
            
        Returns:
            bool: True if should explain
        """
        # Check if already explained recently
        if session_id in self.explained_sessions:
            last_explained = self.explained_sessions[session_id]
            hours_since = (datetime.now() - last_explained).total_seconds() / 3600
            
            if hours_since < XAI_DEDUP_HOURS:
                logger.info(f"Session {session_id} already explained {hours_since:.1f}h ago. Skipping.")
                self.stats['skipped_duplicate'] += 1
                return False
        
        return True
    
    async def process_alert(self, alert_data):
        """
        Process single alert with XAI + LLM
        
        Args:
            alert_data: Attack alert dict from Kafka
        """
        try:
            session_id = alert_data.get('session_id')
            attack_type = alert_data.get('attack_type', 'Unknown')
            src_ip = alert_data.get('src_ip', 'Unknown')
            
            logger.info(f"Processing alert: {attack_type} from {src_ip}")
            
            # Check deduplication
            if not self.should_explain(session_id):
                return
            
            # Get representative flow features
            rep_flows = alert_data.get('representative_flows', [])
            
            if not rep_flows:
                logger.warning("No representative flows found. Skipping.")
                return
            
            # Use highest confidence flow for explanation
            highest_conf_flow = next(
                (f for f in rep_flows if f.get('selection_reason') == 'highest_confidence'),
                rep_flows[0]
            )
            
            features = highest_conf_flow.get('ml_features', {})
            
            if not features:
                logger.warning("No ML features found. Skipping.")
                return
            
            # ===== STEP 1: SHAP Explanation =====
            logger.info("Running SHAP analysis...")
            shap_result = self.shap_explainer.explain(
                features, top_n=MAX_SHAP_FEATURES
            )
            
            if not shap_result:
                logger.error("SHAP analysis failed")
                self.stats['errors'] += 1
                return
            
            # ===== STEP 2: LLM Human Explanation =====
            logger.info("Generating LLM explanation...")
            llm_result = await self.llm_explainer.explain(
                alert_data, shap_result
            )
            
            if not llm_result:
                logger.error("LLM explanation failed")
                # Continue anyway, save SHAP results
            
            # ===== STEP 3: Generate Detection Rule =====
            logger.info("Generating detection rule...")
            detection_rule = await self.llm_explainer.generate_detection_rule(
                alert_data, shap_result
            )
            
            # ===== STEP 4: Update Elasticsearch =====
            logger.info("Updating Elasticsearch...")
            
            # Prepare explanation document
            explanation_doc = {
                'xai_processed': True,
                'xai_timestamp': datetime.utcnow().isoformat(),
                'xai_shap': {
                    'top_features': shap_result['top_features'],
                    'prediction_score': shap_result['prediction_score']
                },
                # ⭐️ Bổ sung kết quả từ LLM vào đây
                'xai_explanation': llm_result['explanation'] if llm_result else "LLM failed to generate explanation.",
                'xai_detection_rule': detection_rule,
                'xai_provider': LLM_PROVIDER
            }
            
            # Update document in ES
            # Use session_id to find and update the document
            try:
                # Search for document by session_id
                search_query = {
                    "query": {
                        "term": {"attack_session_id": session_id}
                    }
                }
                target_index = f"{ES_INDEX}-*"
                response = self.es.search(index=target_index, body=search_query, size=1)
                
                if response['hits']['total']['value'] > 0:
                    doc_id = response['hits']['hits'][0]['_id']
                    found_index = response['hits']['hits'][0]['_index']
                    # Update document
                    self.es.update(
                        index=found_index,
                        id=doc_id,
                        body={'doc': explanation_doc}
                    )
                    
                    logger.info(f"✓ Updated ES document {doc_id}")
                else:
                    logger.warning(f"No ES document found for session {session_id}")
            
            except Exception as e:
                logger.error(f"ES update error: {e}")
            
            # Mark as explained
            self.explained_sessions[session_id] = datetime.now()
            self.stats['explained'] += 1
            
            # Log summary
            logger.info(f"✓ XAI complete for {attack_type}")
            logger.info(f"  Top feature: {shap_result['top_features'][0]['feature']}")
            if llm_result:
                logger.info(f"  Explanation: {llm_result['explanation'][:100]}...")
        
        except Exception as e:
            logger.error(f"Error processing alert: {e}", exc_info=True)
            self.stats['errors'] += 1
    
    async def consume_loop(self):
        """Main consumption loop"""
        logger.info("🚀 Starting XAI worker...")
        
        while self.running:
            try:
                msg = self.consumer.poll(1.0)
                
                if msg is None:
                    # Cleanup old sessions periodically
                    if self.stats['processed'] % 100 == 0:
                        self._cleanup_old_sessions()
                    continue
                
                if msg.error():
                    logger.error(f"Kafka error: {msg.error()}")
                    continue
                
                # Parse message
                try:
                    alert_data = json.loads(msg.value().decode('utf-8'))
                    
                    self.stats['processed'] += 1
                    
                    # Process alert
                    await self.process_alert(alert_data)
                    
                    # Log progress
                    if self.stats['processed'] % 10 == 0:
                        logger.info(f"Stats: {self.stats}")
                
                except json.JSONDecodeError as e:
                    logger.error(f"JSON decode error: {e}")
            
            except Exception as e:
                logger.error(f"Consume loop error: {e}", exc_info=True)
                await asyncio.sleep(1)
    
    def _cleanup_old_sessions(self):
        """Remove old session entries"""
        now = datetime.now()
        expired = [
            sid for sid, ts in self.explained_sessions.items()
            if (now - ts).total_seconds() / 3600 > XAI_DEDUP_HOURS * 2
        ]
        
        for sid in expired:
            del self.explained_sessions[sid]
        
        if expired:
            logger.info(f"Cleaned up {len(expired)} old session entries")
    
    async def start(self):
        """Start worker"""
        self.running = True
        
        logger.info("="*60)
        logger.info("XAI + LLM WORKER")
        logger.info("="*60)
        logger.info(f"LLM Provider: {LLM_PROVIDER}")
        logger.info(f"Input Topic: {INPUT_TOPIC}")
        logger.info(f"ES Index: {ES_INDEX}")
        logger.info(f"Dedup Window: {XAI_DEDUP_HOURS}h")
        logger.info("="*60)
        
        self.setup_kafka()
        self.setup_elasticsearch()
        
        await self.consume_loop()
    
    async def stop(self):
        """Graceful shutdown"""
        self.running = False
        logger.info("Stopping XAI worker...")
        
        if self.consumer:
            self.consumer.close()
        
        if self.es:
            self.es.close()
        
        logger.info("="*60)
        logger.info("FINAL STATISTICS")
        logger.info("="*60)
        logger.info(f"Processed: {self.stats['processed']}")
        logger.info(f"Explained: {self.stats['explained']}")
        logger.info(f"Skipped (duplicate): {self.stats['skipped_duplicate']}")
        logger.info(f"Errors: {self.stats['errors']}")
        logger.info("="*60)


# ==========================================
# MAIN ENTRY POINT
# ==========================================
async def main():
    """Main entry point"""
    worker = XAIWorker()
    loop = asyncio.get_running_loop()
    
    def shutdown():
        asyncio.create_task(worker.stop())
    
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, shutdown)
    
    await worker.start()


if __name__ == '__main__':
    asyncio.run(main())