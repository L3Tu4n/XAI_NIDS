#!/usr/bin/env python3
"""
ML API Service - HYBRID VERSION (Tri-LGBM + Anomaly Detection)
Features:
- Tri-Training Majority Voting
- Isolation Forest Anomaly Scoring (Zero-day detection)
"""
from flask import Flask, request, jsonify
import joblib
import numpy as np
import pandas as pd
import json
import pickle
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
    
    def __init__(self, model_path, metadata_path, encoder_path, anomaly_model_path=None):
        logger.info("📂 Loading resources...")
        
        # --- A. LOAD MAIN MODEL (Tri-LGBM) ---
        if not Path(model_path).exists():
            raise FileNotFoundError(f"❌ Main model missing: {model_path}")
        self.models = joblib.load(model_path)
        logger.info(f"✅ Loaded Tri-LGBM: {Path(model_path).name} (Count: {len(self.models)})")
        
        # --- B. LOAD ANOMALY MODEL (Isolation Forest) ---
        self.anomaly_model = None
        if anomaly_model_path and Path(anomaly_model_path).exists():
            try:
                self.anomaly_model = joblib.load(anomaly_model_path)
                logger.info(f"✅ Loaded Anomaly Detector: {Path(anomaly_model_path).name}")
            except Exception as e:
                logger.error(f"❌ Failed to load Anomaly Detector: {e}")
        else:
            logger.warning(f"⚠️ No Anomaly Model found at {anomaly_model_path}. Zero-day detection disabled.")

        # --- C. LOAD METADATA ---
        if not Path(metadata_path).exists():
            raise FileNotFoundError(f"❌ Metadata missing: {metadata_path}")
        with open(metadata_path, 'r') as f:
            self.metadata = json.load(f)
        
        # Hỗ trợ key cũ và mới
        self.feature_names = self.metadata.get('feature_names') or self.metadata.get('feature_columns')
        if not self.feature_names: raise ValueError("Metadata missing feature list")
            
        self.num_classes = self.metadata.get('num_classes', 15)
        logger.info(f"✅ Loaded Metadata. Input Features: {len(self.feature_names)}")
        
        # --- D. LOAD ENCODER ---
        if not Path(encoder_path).exists():
             logger.warning(f"⚠️ Encoder file missing at {encoder_path}")
             self.encoders = {}
        else:
            try:
                with open(encoder_path, 'rb') as f:
                    self.encoders = pickle.load(f)
                logger.info(f"✅ Loaded Encoders: {Path(encoder_path).name}")
            except Exception as e:
                logger.error(f"❌ Failed to load encoder: {e}")
                self.encoders = {}
        
        # --- E. MAP CLASSES ---
        # Lấy class map từ model đầu tiên
        try:
            self.model_classes = self.models[0].classes_
            self.class_to_idx = {label: idx for idx, label in enumerate(self.model_classes)}
        except AttributeError:
            logger.warning("Could not detect model classes, using default.")
            self.class_to_idx = {0: 0, 1: 1} # Fallback

        # Mapping Attack Types (CIC-IDS-2017)
        self.label_to_attack = {
            0: 'BENIGN', 1: 'DoS Hulk', 2: 'PortScan', 3: 'DDoS',
            4: 'DoS GoldenEye', 5: 'FTP-Patator', 6: 'SSH-Patator',
            7: 'DoS slowloris', 8: 'DoS Slowhttptest', 9: 'Bot',
            10: 'Web Attack - Brute Force', 11: 'Web Attack - XSS',
            12: 'Web Attack - SQL Injection', 13: 'Infiltration', 14: 'Heartbleed'
        }

    def _prepare_dataframe(self, features_data):
        if isinstance(features_data, dict):
            features_data = [features_data]
        df = pd.DataFrame(features_data)
        
        # Fill missing cols
        for feature in self.feature_names:
            if feature not in df.columns: df[feature] = 0
        
        # Select & Clean
        df = df[self.feature_names]
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        df.fillna(0, inplace=True)
        
        # Ensure Numeric
        for col in df.columns:
             if df[col].dtype == 'object':
                 df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)
                 
        return df

    def predict_batch_optimized(self, features_list):
        """
        Dự đoán Batch kết hợp Anomaly Detection
        """
        try:
            if not features_list: return []
            X = self._prepare_dataframe(features_list)
            
            # 1. TRI-TRAINING PREDICTION (Supervised)
            all_preds = np.array([model.predict(X) for model in self.models])
            all_probas = np.array([model.predict_proba(X) for model in self.models])
            
            # 2. ANOMALY DETECTION (Unsupervised)
            anomaly_scores = None
            if self.anomaly_model:
                # decision_function trả về số thực. 
                # Càng thấp (âm) = Càng bất thường. Càng cao (dương) = Càng bình thường.
                anomaly_scores = self.anomaly_model.decision_function(X)
            
            results = []
            n_samples = X.shape[0]
            
            # Ngưỡng Zero-day (Cần tinh chỉnh tùy dataset, ví dụ -0.15)
            ANOMALY_THRESHOLD = -0.15 
            
            for i in range(n_samples):
                # --- A. Supervised Logic ---
                sample_preds = all_preds[:, i] 
                maj_vote = int(np.bincount(sample_preds.astype(int)).argmax())
                
                class_idx = self.class_to_idx.get(maj_vote, 0)
                avg_proba = np.mean(all_probas[:, i, :], axis=0)
                
                try:
                    confidence = float(avg_proba[class_idx])
                except IndexError:
                    confidence = 0.0

                benign_idx = self.class_to_idx.get(0, 0)
                try:
                    attack_prob = float(1.0 - avg_proba[benign_idx])
                except IndexError:
                    attack_prob = 0.0
                
                is_attack = (maj_vote != 0)
                attack_type = self.label_to_attack.get(maj_vote, f'Class_{maj_vote}')
                
                # --- B. Anomaly Logic (Zero-day check) ---
                anomaly_score = 0.0
                is_anomaly = False
                
                if anomaly_scores is not None:
                    anomaly_score = float(anomaly_scores[i])
                    # Nếu điểm thấp hơn ngưỡng -> Bất thường
                    if anomaly_score < ANOMALY_THRESHOLD:
                        is_anomaly = True
                
                # --- C. Hybrid Decision ---
                # Nếu model chính bảo SẠCH, nhưng model Anomaly bảo RẤT LẠ -> Cảnh báo Zero-day
                if not is_attack and is_anomaly:
                    is_attack = True
                    attack_type = "Potential Zero-Day"
                    # Gán confidence thấp hơn một chút để biết là phỏng đoán
                    confidence = 0.75 
                    attack_prob = 0.75

                results.append({
                    'is_attack': is_attack,
                    'attack_type': attack_type,
                    'predicted_class': maj_vote,
                    'confidence': round(confidence, 4),
                    'attack_probability': round(attack_prob, 4),
                    'anomaly_score': round(anomaly_score, 4), # Thêm điểm bất thường vào kết quả
                    'is_anomaly': is_anomaly,
                    'timestamp': datetime.utcnow().isoformat()
                })
            return results
            
        except Exception as e:
            logger.error(f"Batch inference error: {e}", exc_info=True)
            return []

def init_service():
    """Hàm khởi tạo Service"""
    global ml_service
    try:
        base_dir = Path('/opt/ml-nids/models')
        
        # ⚠️ SỬA TÊN FILE CHO KHỚP VỚI LỆNH LS CỦA BẠN
        # 1. Main Model (Tri-LGBM)
        model_path = base_dir / 'nids_tri_lgbm_v1_trilgbm.joblib' 
        
        # 2. Metadata
        metadata_path = base_dir / 'nids_tri_lgbm_v1_metadata.json'
        
        # 3. Anomaly Model (Isolation Forest)
        anomaly_path = base_dir / 'nids_tri_lgbm_v1_isolforest.joblib'
        
        # 4. Encoder
        encoder_path = base_dir / 'feature_schema.pkl'
        
        logger.info(f"Init Service with: {model_path.name}")
        
        ml_service = NIDSMLService(
            str(model_path), 
            str(metadata_path), 
            str(encoder_path),
            str(anomaly_path)
        )
        logger.info("🚀 ML API Initialized Successfully!")
        
    except Exception as e:
        logger.error(f"❌ FATAL: Initialization failed: {e}")
        
    except Exception as e:
        logger.error(f"❌ FATAL: Initialization failed: {e}")

# Init ngay khi import
init_service()

# --- FLASK ROUTES ---
@app.route('/health', methods=['GET'])
def health_check():
    global ml_service
    if ml_service is None: init_service()
    status = 200 if ml_service else 503
    return jsonify({'status': 'healthy' if ml_service else 'error'}), status

@app.route('/model_info', methods=['GET'])
def model_info():
    if not ml_service: return jsonify({'error': 'Not initialized'}), 503
    return jsonify({
        'feature_names': ml_service.feature_names,
        'num_models': len(ml_service.models),
        'has_anomaly_detector': ml_service.anomaly_model is not None,
        'classes': [int(c) for c in ml_service.model_classes]
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