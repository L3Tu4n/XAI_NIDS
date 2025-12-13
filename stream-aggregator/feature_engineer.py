#!/usr/bin/env python3
"""
Simplified Feature Engineer - FINAL
"""
import pandas as pd
import numpy as np
import pickle
import logging
from pathlib import Path

logger = logging.getLogger('feature-engineer')

class StreamFeatureEngineer:
    def __init__(self, encoder_path):
        self.encoder_path = Path(encoder_path)
        self.encoders = {}
        self.feature_columns = []
        self._load_encoders()
    
    def _load_encoders(self):
        if not self.encoder_path.exists():
            # Chỉ warn, không crash để debug dễ hơn
            logger.warning(f"Encoder not found: {self.encoder_path}. Categorical features will be invalid.")
            return
        
        try:
            with open(self.encoder_path, 'rb') as f:
                self.encoders = pickle.load(f)
            logger.info(f"Loaded encoders: {list(self.encoders.keys())}")
        except Exception as e:
            logger.error(f"Failed to load pickle: {e}")
    
    def _transform_categorical(self, data_series, encoder_name):
        if encoder_name not in self.encoders:
            return np.full(len(data_series), -1, dtype=np.int32)
        
        try:
            # OrdinalEncoder expects 2D array
            data = data_series.fillna('MISSING').astype(str).to_frame()
            encoded = self.encoders[encoder_name].transform(data).ravel()
            return encoded.astype(np.int32)
        except Exception:
            return np.full(len(data_series), -1, dtype=np.int32)
    
    def extract_features(self, df):
        features = df.copy()
        
        # 1. Basic features (Ensure numeric)
        basic_cols = [
            'duration', 'orig_bytes', 'resp_bytes', 'missed_bytes',
            'orig_pkts', 'orig_ip_bytes', 'resp_pkts', 'resp_ip_bytes'
        ]
        
        for col in basic_cols:
            if col not in features.columns:
                features[col] = 0
            features[col] = pd.to_numeric(features[col], errors='coerce').fillna(0)
        
        # Derived features (Tính toán trực tiếp trên cột đã chuẩn hóa)
        features['total_bytes'] = features['orig_bytes'] + features['resp_bytes']
        features['total_pkts'] = features['orig_pkts'] + features['resp_pkts']
        
        # Safe Division
        features['bytes_per_sec'] = np.where(features['duration'] > 0, features['total_bytes'] / features['duration'], 0)
        features['pkts_per_sec'] = np.where(features['duration'] > 0, features['total_pkts'] / features['duration'], 0)
        features['bytes_per_pkt'] = np.where(features['total_pkts'] > 0, features['total_bytes'] / features['total_pkts'], 0)
        
        features['byte_ratio'] = np.where(features['resp_bytes'] > 0, features['orig_bytes'] / features['resp_bytes'], 0)
        features['pkt_ratio'] = np.where(features['resp_pkts'] > 0, features['orig_pkts'] / features['resp_pkts'], 0)
        
        # 2. Protocol features
        if 'ip_proto' in features.columns:
            features['proto_numeric'] = pd.to_numeric(features['ip_proto'], errors='coerce').fillna(0).astype(np.int32)
        else:
            features['proto_numeric'] = 0
            
        features['proto_str_encoded'] = self._transform_categorical(features.get('proto'), 'proto_str')
        features['service_encoded'] = self._transform_categorical(features.get('service'), 'service')
        features['conn_state_encoded'] = self._transform_categorical(features.get('conn_state'), 'conn_state')
        
        # 3. Behavioral features (Đã được merge ở Aggregator, chỉ cần fillna)
        behavioral_cols = ['src_conn_count', 'src_unique_dests', 'src_unique_ports', 'src_service_diversity', 'dst_conn_count']
        for col in behavioral_cols:
            if col not in features.columns:
                features[col] = 1
            features[col] = features[col].fillna(1).astype(np.int32)
            
        # 4. Final Selection
        self.final_cols = [
            'duration', 'orig_bytes', 'resp_bytes', 'missed_bytes',
            'orig_pkts', 'orig_ip_bytes', 'resp_pkts', 'resp_ip_bytes',
            'total_bytes', 'total_pkts', 'bytes_per_sec', 'pkts_per_sec',
            'bytes_per_pkt', 'byte_ratio', 'pkt_ratio',
            'proto_numeric', 'proto_str_encoded', 'service_encoded', 'conn_state_encoded',
            'src_conn_count', 'src_unique_dests', 'src_unique_ports',
            'src_service_diversity', 'dst_conn_count'
        ]
        
        # Tạo DataFrame kết quả chỉ chứa các cột cần thiết
        X = pd.DataFrame()
        for col in self.final_cols:
            if col in features.columns:
                X[col] = features[col]
            else:
                X[col] = 0
                
        # Clean final X
        X.replace([np.inf, -np.inf], 0, inplace=True)
        X.fillna(0, inplace=True)
        
        return X