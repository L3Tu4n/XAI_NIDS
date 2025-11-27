#!/usr/bin/env python3
"""
Feature Engineering cho NIDS - PRODUCTION READY VERSION
Fixes:
1. OrdinalEncoder categories handling
2. Consistent encoding behavior
3. Better NaN handling
4. Proper inference mode logic
"""
import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.preprocessing import OrdinalEncoder
import warnings
import json
import pickle
import os

warnings.filterwarnings('ignore')

class NIDSFeatureEngineer:
    """
    Feature Engineer với OrdinalEncoder cho categorical variables
    Support cả training và inference modes
    """
    
    def __init__(self, time_window='10s', encoder_path=None):
        """
        Args:
            time_window: Time window cho behavioral features
            encoder_path: Path tới encoder pickle file (cho inference mode)
        """
        self.time_window = time_window
        self.feature_columns = []
        self.encoders = {}
        self.encoder_path = encoder_path
        
        # OrdinalEncoder configuration
        self.OE_CONFIG = {
            'handle_unknown': 'use_encoded_value',
            'unknown_value': -1,
            'dtype': 'int32'
        }
        
        # Load encoders nếu có (inference mode)
        if self.encoder_path and os.path.exists(self.encoder_path):
            with open(self.encoder_path, 'rb') as f:
                self.encoders = pickle.load(f)
            print(f"[✓] Loaded encoders from {self.encoder_path}")
            print(f"    Available encoders: {list(self.encoders.keys())}")

    def _fit_or_transform_encoder(self, data_series, col_name, training_mode=True):
        """
        FIX: Cải thiện logic fit/transform với better error handling
        
        Args:
            data_series: Pandas Series data
            col_name: Column name (dùng làm key cho encoder)
            training_mode: True = fit_transform, False = transform only
            
        Returns:
            Encoded array
        """
        # Chuẩn bị data: fill NaN -> convert to string
        data = data_series.fillna('MISSING').astype(str).to_frame()
        
        if col_name in self.encoders:
            # INFERENCE MODE: Transform with existing encoder
            try:
                encoded = self.encoders[col_name].transform(data).ravel()
                return encoded
            except Exception as e:
                print(f"[!] Warning: Transform error for '{col_name}': {e}")
                # Fallback: return safe values
                return np.zeros(len(data), dtype=np.int32)
        
        elif training_mode:
            # TRAINING MODE: Fit new encoder
            oe = OrdinalEncoder(**self.OE_CONFIG)
            encoded = oe.fit_transform(data).ravel()
            self.encoders[col_name] = oe
            
            # Log categories
            categories = oe.categories_[0]
            print(f"    Fitted encoder '{col_name}': {len(categories)} unique values")
            
            return encoded
        
        else:
            # ERROR: Inference mode but no encoder found
            raise ValueError(
                f"Encoder for '{col_name}' not found. "
                f"Available encoders: {list(self.encoders.keys())}"
            )

    def extract_basic_features(self, df):
        """
        Extract basic connection features từ Zeek conn.log
        
        Features:
        - Duration, bytes, packets
        - Derived features: rates, ratios
        """
        print("[*] Extracting basic connection features...")
        features = df.copy()
        
        # Basic numeric columns từ Zeek
        basic_cols = [
            'duration', 'orig_bytes', 'resp_bytes',
            'orig_pkts', 'resp_pkts', 'missed_bytes',
            'orig_ip_bytes', 'resp_ip_bytes'
        ]
        
        # Fill missing values với 0
        for col in basic_cols:
            if col in features.columns:
                features[col] = pd.to_numeric(features[col], errors='coerce').fillna(0)
        
        # Derived features
        features['total_bytes'] = features['orig_bytes'] + features['resp_bytes']
        features['total_pkts'] = features['orig_pkts'] + features['resp_pkts']
        
        # Rate features (safe division)
        features['bytes_per_sec'] = np.where(
            features['duration'] > 0,
            features['total_bytes'] / features['duration'],
            0
        )
        
        features['pkts_per_sec'] = np.where(
            features['duration'] > 0,
            features['total_pkts'] / features['duration'],
            0
        )
        
        features['bytes_per_pkt'] = np.where(
            features['total_pkts'] > 0,
            features['total_bytes'] / features['total_pkts'],
            0
        )
        
        # Ratio features (asymmetry)
        features['byte_ratio'] = np.where(
            features['resp_bytes'] > 0,
            features['orig_bytes'] / features['resp_bytes'],
            0
        )
        
        features['pkt_ratio'] = np.where(
            features['resp_pkts'] > 0,
            features['orig_pkts'] / features['resp_pkts'],
            0
        )
        
        print(f"    Created {len(basic_cols) + 7} basic features")
        return features
        
    def extract_protocol_features(self, df):
        """
        FIX: Improved protocol feature extraction
        
        Features:
        - proto_numeric: từ ip_proto (numeric, không cần encode)
        - service_encoded: OrdinalEncoder
        - conn_state_encoded: OrdinalEncoder
        - proto_str_encoded: OrdinalEncoder cho proto string (nếu có)
        """
        print("[*] Extracting protocol features...")
        features = df.copy()
        training_mode = not bool(self.encoders)
        
        # 1. IP Protocol Number (numeric từ Zeek)
        if 'ip_proto' in features.columns:
            # FIX: Đảm bảo numeric và rename rõ ràng
            features['proto_numeric'] = pd.to_numeric(
                features['ip_proto'], 
                errors='coerce'
            ).fillna(0).astype(np.int32)
            print("    Created: proto_numeric (from ip_proto)")
        
        # 2. Protocol String (nếu có cột 'proto' dạng string: tcp/udp/icmp)
        if 'proto' in features.columns:
            encoded = self._fit_or_transform_encoder(
                features['proto'], 
                'proto_str',  # FIX: Key name khác với 'proto' để tránh confusion
                training_mode=training_mode
            )
            features['proto_str_encoded'] = encoded
            print("    Created: proto_str_encoded")
        
        # 3. Service (http, dns, ssl, ssh, etc.)
        if 'service' in features.columns:
            encoded = self._fit_or_transform_encoder(
                features['service'],
                'service',
                training_mode=training_mode
            )
            features['service_encoded'] = encoded
            print("    Created: service_encoded")
        
        # 4. Connection State (SF, S0, REJ, etc.)
        if 'conn_state' in features.columns:
            encoded = self._fit_or_transform_encoder(
                features['conn_state'],
                'conn_state',
                training_mode=training_mode
            )
            features['conn_state_encoded'] = encoded
            print("    Created: conn_state_encoded")
        
        # Count protocol features
        new_cols = [
            col for col in features.columns 
            if col.endswith('_encoded') or col == 'proto_numeric'
        ]
        print(f"    Total protocol features: {len(new_cols)}")
        
        return features
        
    def extract_behavioral_features(self, df):
        """
        FIX: Optimized behavioral features với better aggregation
        
        Time-window based features:
        - Connection counts per source/destination
        - Unique destinations/ports per source
        - Service diversity
        """
        print(f"[*] Extracting behavioral features (window={self.time_window})...")
        features = df.copy()
        
        # Check required columns
        required_cols = ['ts', 'id.orig_h', 'id.resp_h', 'id.resp_p', 'service']
        missing_cols = [col for col in required_cols if col not in features.columns]
        
        if missing_cols:
            print(f"[!] Missing columns: {missing_cols}. Skipping behavioral features.")
            return features
        
        # FIX: Ensure proper sorting với uid nếu có
        sort_cols = ['ts', 'uid'] if 'uid' in features.columns else ['ts']
        features = features.sort_values(sort_cols).reset_index(drop=True)
        
        # Create time bins
        features['time_group'] = features['ts'].dt.floor(self.time_window)
        
        # SOURCE IP STATISTICS
        # Group by source IP + time window
        grouped_src = features.groupby(['id.orig_h', 'time_group'])
        
        # FIX: Aggregation với explicit column names
        src_stats = grouped_src.agg(
            src_conn_count=('id.orig_h', 'size'),  # Total connections
            src_unique_dests=('id.resp_h', 'nunique'),  # Unique destinations
            src_unique_ports=('id.resp_p', 'nunique'),  # Unique ports
            src_service_diversity=('service', 'nunique')  # Service diversity
        ).reset_index()
        
        # DESTINATION IP STATISTICS
        grouped_dst = features.groupby(['id.resp_h', 'time_group'])
        dst_stats = grouped_dst.size().reset_index(name='dst_conn_count')
        
        # Merge statistics back to features
        features = features.merge(
            src_stats,
            on=['id.orig_h', 'time_group'],
            how='left'
        )
        
        features = features.merge(
            dst_stats,
            on=['id.resp_h', 'time_group'],
            how='left'
        )
        
        # FIX: Fill NaN với 1 (not 0) vì mỗi connection tối thiểu có 1 count
        behavioral_cols = [
            'src_conn_count', 'src_unique_dests', 'src_unique_ports',
            'src_service_diversity', 'dst_conn_count'
        ]
        
        for col in behavioral_cols:
            if col in features.columns:
                features[col] = features[col].fillna(1).astype(np.int32)
        
        print(f"    Created {len(behavioral_cols)} behavioral features")
        
        # Cleanup
        features.drop('time_group', axis=1, inplace=True, errors='ignore')
        
        return features
        
    def extract_all_features(self, df):
        """
        Main feature extraction pipeline
        
        Returns:
            DataFrame with all features
        """
        # Determine mode
        training_mode = not bool(self.encoders)
        mode_str = "TRAINING" if training_mode else "INFERENCE"
        
        print("="*60)
        print(f"FEATURE ENGINEERING - {mode_str} MODE")
        print("="*60)
        
        # Ensure timestamp is datetime
        if 'ts' in df.columns and df['ts'].dtype != 'datetime64[ns]':
            df['ts'] = pd.to_datetime(df['ts'], errors='coerce')
        
        # Extract features step by step
        features = self.extract_basic_features(df)
        features = self.extract_protocol_features(features)
        features = self.extract_behavioral_features(features)
        
        # Define feature columns (exclude metadata)
        excluded_cols = [
            # Metadata
            'ts', 'uid', 'source_file', 'pcap_source', 'conn_key',
            # Original columns (before encoding)
            'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p',
            'proto', 'service', 'conn_state', 'ip_proto',
            # Zeek specific
            'local_orig', 'local_resp', 'history', 'tunnel_parents',
            # Labels
            'attack_type', 'label'
        ]
        
        # FIX: Only select columns that actually exist
        self.feature_columns = [
            col for col in features.columns 
            if col not in excluded_cols
        ]
        
        print("\n" + "="*60)
        print(f"[✓] Feature engineering complete!")
        print(f"    Mode: {mode_str}")
        print(f"    Total features: {len(self.feature_columns)}")
        print(f"    Features: {self.feature_columns}")
        print("="*60)
        
        return features
        
    def get_feature_matrix(self, df):
        """
        Get feature matrix X and label vector y
        
        Returns:
            X (DataFrame), y (Series)
        """
        if not self.feature_columns:
            raise ValueError("Run extract_all_features() first!")
        
        # FIX: Handle case where 'label' might not exist (inference)
        X = df[self.feature_columns].copy()
        
        if 'label' in df.columns:
            y = df['label'].copy()
        else:
            y = None  # Inference mode without labels
        
        # Final cleaning
        X.replace([np.inf, -np.inf], 0, inplace=True)
        X.fillna(0, inplace=True)
        
        # FIX: Ensure all numeric
        for col in X.columns:
            if X[col].dtype == 'object':
                print(f"[!] Warning: Column '{col}' is object type, converting to numeric")
                X[col] = pd.to_numeric(X[col], errors='coerce').fillna(0)
        
        return X, y
        
    def save_feature_schema(self, output_path):
        """
        Save feature schema và encoders
        
        Args:
            output_path: Path tới JSON schema file
        """
        # Schema metadata
        schema = {
            'feature_columns': self.feature_columns,
            'time_window': self.time_window,
            'num_features': len(self.feature_columns),
            'encoder_config': self.OE_CONFIG,
            'encoders': list(self.encoders.keys())  # FIX: Track encoder names
        }
        
        # Save JSON schema
        with open(output_path, 'w') as f:
            json.dump(schema, f, indent=2)
        
        print(f"[✓] Saved feature schema to {output_path}")
        
        # Save encoders (pickle)
        if self.encoders:
            encoder_path = Path(output_path).with_suffix('.pkl')
            with open(encoder_path, 'wb') as f:
                pickle.dump(self.encoders, f)
            
            print(f"[✓] Saved {len(self.encoders)} encoders to {encoder_path}")
            
            # FIX: Log encoder details
            for name, encoder in self.encoders.items():
                n_cats = len(encoder.categories_[0])
                print(f"    - {name}: {n_cats} categories")
        else:
            print("[!] No encoders to save (inference mode?)")
    
    def load_feature_schema(self, schema_path):
        """
        Load feature schema (for validation)
        
        Args:
            schema_path: Path tới JSON schema file
        """
        with open(schema_path, 'r') as f:
            schema = json.load(f)
        
        # Validate
        if schema['feature_columns'] != self.feature_columns:
            print("[!] Warning: Feature columns mismatch!")
            print(f"    Expected: {len(schema['feature_columns'])} features")
            print(f"    Got: {len(self.feature_columns)} features")
        
        return schema


if __name__ == "__main__":
    import sys
    
    # Paths
    INPUT_FILE = "./CIC-IDS-2017/labeled_conn_logs.parquet"
    OUTPUT_FILE = "./CIC-IDS-2017/featured_dataset.parquet"
    SCHEMA_FILE = "./CIC-IDS-2017/feature_schema.json"
    ENCODER_PKL = Path(SCHEMA_FILE).with_suffix('.pkl')
    
    # =================================================================
    # MODE 1: TRAINING - Fit encoders và save
    # =================================================================
    print("\n" + "="*60)
    print("MODE 1: TRAINING")
    print("="*60)
    
    print("\n[*] Loading labeled data...")
    df = pd.read_parquet(INPUT_FILE)
    print(f"[✓] Loaded {len(df)} records")
    print(f"    Columns: {list(df.columns)}")
    
    # Initialize engineer (training mode - no encoder_path)
    engineer = NIDSFeatureEngineer(time_window='10s')
    
    # Extract features
    featured_df = engineer.extract_all_features(df)
    
    # Get feature matrix
    X, y = engineer.get_feature_matrix(featured_df)
    
    print(f"\n[*] Feature matrix shape: {X.shape}")
    print(f"[*] Feature dtypes:")
    print(X.dtypes.value_counts())
    
    if y is not None:
        print(f"\n[*] Label distribution:")
        print(y.value_counts())
    
    # Save featured dataset
    print(f"\n[*] Saving featured dataset...")
    featured_df.to_parquet(OUTPUT_FILE, index=False, compression='snappy')
    print(f"[✓] Saved to {OUTPUT_FILE}")
    
    # Save schema và encoders
    engineer.save_feature_schema(SCHEMA_FILE)
    
    # =================================================================
    # MODE 2: INFERENCE - Load encoders và transform
    # =================================================================
    print("\n\n" + "="*60)
    print("MODE 2: INFERENCE (DEMO)")
    print("="*60)
    
    # Simulate new data (sample from existing)
    inference_df = df.sample(n=100, random_state=42).copy()
    print(f"\n[*] Simulating inference on {len(inference_df)} samples...")
    
    # Initialize engineer (inference mode - WITH encoder_path)
    inference_engineer = NIDSFeatureEngineer(
        time_window='2s',
        encoder_path=ENCODER_PKL
    )
    
    # Extract features (transform only)
    inference_featured_df = inference_engineer.extract_all_features(inference_df)
    
    # Get feature matrix
    X_inf, y_inf = inference_engineer.get_feature_matrix(inference_featured_df)
    
    print(f"\n[✓] Inference feature shape: {X_inf.shape}")
    print(f"[✓] Feature columns match: {X_inf.columns.equals(X.columns)}")
    
    # Validate features match
    if not X_inf.columns.equals(X.columns):
        print("\n[!] ERROR: Feature mismatch!")
        print(f"Training features: {list(X.columns)}")
        print(f"Inference features: {list(X_inf.columns)}")
        sys.exit(1)
    
    print("\n" + "="*60)
    print("[✓] ALL TESTS PASSED!")
    print("="*60)
    print(f"\nReady for:")
    print(f"  1. Model training with: {OUTPUT_FILE}")
    print(f"  2. Production inference with: {ENCODER_PKL}")
    print("="*60)