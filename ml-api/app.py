#!/usr/bin/env python3
"""
ML API Service - HYBRID VERSION (Fixed Boolean Serialization)
Fixes:
- Strict Schema Enforcement: Force dtypes before prediction to match training metadata.
- Fix 'train and valid dataset categorical_feature do not match'.
"""
from flask import Flask, request, jsonify
import joblib
import numpy as np
import pandas as pd
import json
from pathlib import Path
import logging
from datetime import datetime
import os

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Global Service Instance
ml_service = None

class NIDSMLService:
    """Service class quản lý Model và Inference"""
    
    def __init__(self, model_dir):
        self.model_dir = Path(model_dir)
        logger.info(f"📂 Loading resources from {self.model_dir}...")
        
        # 1. LOAD LIGHTGBM
        lgbm_path = self.model_dir / 'nids_tri_lgbm_v1.joblib'
        lgbm_meta_path = self.model_dir / 'nids_tri_lgbm_v1_metadata.json'
        
        if not lgbm_path.exists():
            raise FileNotFoundError(f"❌ LGBM model missing: {lgbm_path}")
            
        self.models = joblib.load(lgbm_path)
        
        with open(lgbm_meta_path, 'r') as f:
            self.lgbm_meta = json.load(f)
            self.lgbm_features = self.lgbm_meta.get('feature_names') or self.lgbm_meta.get('feature_columns')
            if not self.lgbm_features:
                raise ValueError("❌ LGBM Metadata missing feature list")
            
        logger.info(f"✅ Loaded Tri-LGBM. Features: {len(self.lgbm_features)}")
        
        # Xác định cột category từ tên feature (để ép kiểu sau này)
        self.cat_cols = [col for col in self.lgbm_features if 'encoded' in col or 'numeric' in col]
        logger.info(f"    Categorical columns to enforce: {self.cat_cols}")
        
        # 2. LOAD ISOLATION FOREST
        if_path = self.model_dir / 'isolation_forest.joblib'
        if_scaler_path = self.model_dir / 'if_scaler.joblib'
        if_meta_path = self.model_dir / 'isolation_forest_metadata.json'
        
        self.anomaly_model = None
        self.if_scaler = None
        
        if if_path.exists() and if_scaler_path.exists():
            try:
                self.anomaly_model = joblib.load(if_path)
                self.if_scaler = joblib.load(if_scaler_path)
                
                with open(if_meta_path, 'r') as f:
                    self.if_meta = json.load(f)
                    self.if_features = self.if_meta.get('feature_names') or self.if_meta.get('feature_columns')
                    self.if_threshold = self.if_meta.get('threshold', -0.05)
                    
                logger.info(f"✅ Loaded IF Model & Scaler. Threshold: {self.if_threshold}")
            except Exception as e:
                logger.error(f"❌ Failed to load IF resources: {e}")
        else:
            logger.warning(f"⚠️ Isolation Forest files missing")

        # 3. MAP CLASSES
        try:
            self.model_classes = self.models[0].classes_
            self.class_to_idx = {label: idx for idx, label in enumerate(self.model_classes)}
        except AttributeError:
            self.class_to_idx = {0: 0, 1: 1}

        self.label_to_attack = {
            0: 'BENIGN', 1: 'DoS Hulk', 2: 'PortScan', 3: 'DDoS',
            4: 'DoS GoldenEye', 5: 'FTP-Patator', 6: 'SSH-Patator',
            7: 'DoS slowloris', 8: 'DoS Slowhttptest', 9: 'Bot',
            10: 'Web Attack - Brute Force', 11: 'Web Attack - XSS',
            12: 'Web Attack - SQL Injection', 13: 'Infiltration', 14: 'Heartbleed'
        }

    def _prepare_dataframe(self, features_list, required_features):
        """
        Prepare DataFrame and FORCE correct dtypes
        """
        df = pd.DataFrame(features_list)
        
        # 1. Ensure all columns exist
        for feature in required_features:
            if feature not in df.columns: df[feature] = 0
            
        # 2. Select and Clean
        df = df[required_features].copy()
        df.replace([np.inf, -np.inf], 0, inplace=True)
        df.fillna(0, inplace=True)
        
        # 3. [FIX] Enforce Categorical Types for LightGBM
        # Đây là bước quan trọng để khớp với metadata lúc train
        for col in self.cat_cols:
            if col in df.columns:
                try:
                    # Ép về int trước (tránh lỗi float 1.0 != 1)
                    df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0).astype(int)
                    # Sau đó ép về category
                    df[col] = df[col].astype('category')
                except Exception as e:
                    # Fallback nếu lỗi, log warning nhưng không crash
                    pass

        return df

    def predict_batch_optimized(self, features_list):
        def tri_training_vote(preds):
            counts = np.bincount(preds.astype(int))
            if len(counts) == 0: return 0
            top_class = counts.argmax()
            if counts[top_class] >= 2: return top_class
            return preds[0]

        try:
            if not features_list: return []
            
            # Predict LGBM
            # Hàm _prepare_dataframe đã được vá lỗi dtypes
            X_lgbm = self._prepare_dataframe(features_list, self.lgbm_features)
            
            all_preds = np.array([model.predict(X_lgbm) for model in self.models])
            all_probas = np.array([model.predict_proba(X_lgbm) for model in self.models])
            
            # Predict IF
            anomaly_scores = None
            if self.anomaly_model:
                # IF dùng RobustScaler nên cũng cần ép kiểu số (không cần category)
                # Nhưng dùng chung _prepare_dataframe vẫn an toàn
                X_if = self._prepare_dataframe(features_list, self.if_features)
                
                # Scaler expect DataFrame with correct names
                X_if_scaled = self.if_scaler.transform(X_if)
                anomaly_scores = self.anomaly_model.decision_function(X_if_scaled)
            
            results = []
            n_samples = len(features_list)
            
            for i in range(n_samples):
                # LGBM Result
                sample_preds = all_preds[:, i] 
                maj_vote = tri_training_vote(sample_preds)
                
                class_idx = self.class_to_idx.get(maj_vote, 0)
                avg_proba = np.mean(all_probas[:, i, :], axis=0)
                confidence = float(avg_proba[class_idx]) if class_idx < len(avg_proba) else 0.0
                
                benign_idx = self.class_to_idx.get(0, 0)
                attack_prob = float(1.0 - avg_proba[benign_idx]) if benign_idx < len(avg_proba) else 0.0
                
                # 🛠️ FIX: Ép kiểu bool() rõ ràng
                is_attack = bool(maj_vote != 0)
                attack_type = self.label_to_attack.get(maj_vote, f'Class_{maj_vote}')
                
                # IF Result
                anomaly_score = 0.0
                anomaly_distance = 0.0
                is_anomaly = False
                
                if anomaly_scores is not None:
                    anomaly_score = float(anomaly_scores[i])
                    if anomaly_score < self.if_threshold:
                        is_anomaly = True
                    if self.if_threshold != 0:
                        anomaly_distance = max(0.0, (self.if_threshold - anomaly_score) / abs(self.if_threshold))

                # Hybrid Decision
                final_verdict = "Clean"
                if is_attack:
                    final_verdict = f"Known Attack: {attack_type}"
                elif is_anomaly:
                    is_attack = True
                    attack_type = "Zero-Day / Unknown Attack"
                    final_verdict = "Suspicious (Anomaly Detected)"
                    if attack_prob < 0.5: attack_prob = 0.65

                # 🛠️ FIX: Đảm bảo toàn bộ giá trị là native Python types
                results.append({
                    'is_attack': bool(is_attack),       # Explicit bool conversion
                    'attack_type': str(attack_type),
                    'verdict': str(final_verdict),
                    'predicted_class': int(maj_vote),   # Explicit int conversion
                    'confidence': round(confidence, 4),
                    'attack_probability': round(attack_prob, 4),
                    'anomaly_score': round(anomaly_score, 4),
                    'anomaly_distance': round(anomaly_distance, 4),
                    'is_anomaly': bool(is_anomaly),     # Explicit bool conversion
                    'timestamp': datetime.utcnow().isoformat()
                })
            
            return results
            
        except Exception as e:
            logger.error(f"Batch inference error: {e}", exc_info=True)
            return []

def init_service():
    global ml_service
    try:
        env_model_dir = os.getenv('MODEL_DIR')
        if env_model_dir:
            base_dir = Path(env_model_dir).resolve()
        else:
            base_dir = Path('./models').resolve()
        
        logger.info(f"Init Service from: {base_dir}")
        if not base_dir.exists():
             logger.error(f"❌ Directory not found: {base_dir}")
             return

        ml_service = NIDSMLService(base_dir)
        logger.info("🚀 ML API Initialized Successfully!")
    except Exception as e:
        logger.error(f"❌ FATAL: Initialization failed: {e}")

init_service()

@app.route('/health', methods=['GET'])
def health_check():
    global ml_service
    status = 200 if ml_service else 503
    return jsonify({'status': 'healthy' if ml_service else 'error'}), status

@app.route('/model_info', methods=['GET'])
def model_info():
    if not ml_service: return jsonify({'error': 'Not initialized'}), 503
    return jsonify({
        'lgbm_features': ml_service.lgbm_features,
        'if_features': ml_service.if_features,
        'threshold': ml_service.if_threshold
    }), 200

@app.route('/predict_batch', methods=['POST'])
def predict_batch():
    if not ml_service: return jsonify({'error': 'Model not loaded'}), 503
    try:
        data = request.get_json()
        if not data or 'samples' not in data:
            return jsonify({'error': 'Missing "samples"'}), 400
        
        features_list = [item.get('features', {}) for item in data['samples']]
        results = ml_service.predict_batch_optimized(features_list)
        return jsonify({'predictions': results, 'count': len(results)}), 200
        
    except Exception as e:
        logger.error(f"Request error: {e}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)