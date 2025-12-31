#!/usr/bin/env python3
"""
Feature Engineering cho NIDS - MULTI-MODEL VERSION
- Isolation Forest: Sử dụng DNS features (dns_query_len, dns_entropy) để phát hiện DNS tunneling
- LightGBM: Không sử dụng DNS features (để tránh bias từ normal traffic không có DNS)
"""
import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.preprocessing import OrdinalEncoder
from scipy.stats import entropy
import warnings
import json
import pickle
import os

warnings.filterwarnings('ignore')

class NIDSFeatureEngineer:
    """
    Feature Engineer với hỗ trợ 2 feature sets:
    - IF_FEATURES: Bao gồm DNS features (dns_query_len, dns_entropy)
    - LGBM_FEATURES: Không có DNS features
    """
    
    # Feature set definitions
    FEATURES_LGBM = [
        'duration', 'orig_bytes', 'resp_bytes', 'orig_pkts', 'resp_pkts',
        'bytes_per_sec', 'pkts_per_sec', 'bytes_per_pkt', 
        'byte_ratio', 'pkt_ratio',
        'service_encoded', 'conn_state_encoded', # Categorical OK cho Tree Gradient Boosting
        'src_conn_count', 'src_unique_dests', 'src_unique_ports',
        'src_service_diversity', 'dst_conn_count',
        'proto_numeric',
        'service_intensity', 'port_usage_ratio'  # New Features
    ]
    FEATURES_IF = [
        'duration', 'orig_bytes', 'resp_bytes', 'orig_pkts', 'resp_pkts',
        'bytes_per_sec', 'pkts_per_sec', 'bytes_per_pkt', 
        'byte_ratio', 'pkt_ratio',
        'src_conn_count', 'src_unique_dests', 'src_unique_ports',
        'src_service_diversity', 'dst_conn_count',
        'proto_numeric', 'service_intensity', 'port_usage_ratio', # New Features
        'dns_query_len', 'dns_entropy' # Đặc biệt quan trọng cho IF
    ]
    
    DNS_FEATURES = ['dns_query_len', 'dns_entropy']
    
    def __init__(self, time_window='10s', encoder_path=None, model_type='lgbm'):
        """
        Args:
            time_window: Time window cho behavioral features
            encoder_path: Path tới encoder pickle file (cho inference mode)
            model_type: 'if' hoặc 'lgbm' - xác định feature set nào dùng
        """
        self.time_window = time_window
        self.model_type = model_type.lower()
        self.feature_columns = []
        self.encoders = {}
        self.encoder_path = encoder_path
        
        # Validate model type
        if self.model_type not in ['if', 'lgbm']:
            raise ValueError(f"model_type must be 'if' or 'lgbm', got '{self.model_type}'")
        
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
        Fit hoặc transform encoder với error handling
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
        - duration, orig_bytes, resp_bytes, orig_pkts, resp_pkts
        - bytes_per_sec, pkts_per_sec, bytes_per_pkt
        - byte_ratio, pkt_ratio
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
        
        features['byte_ratio'] = (
            np.log1p(features['orig_bytes']) -
            np.log1p(features['resp_bytes'])
        )

        features['pkt_ratio'] = (
            np.log1p(features['orig_pkts']) -
            np.log1p(features['resp_pkts'])
        )
        
        print(f"    Created 10 basic features")
        return features
        
    def extract_protocol_features(self, df):
        """
        Extract protocol features
        
        Features:
        - proto_numeric: từ ip_proto (TCP=6, UDP=17, ICMP=1)
        - service_encoded: OrdinalEncoder
        - conn_state_encoded: OrdinalEncoder
        """
        print("[*] Extracting protocol features...")
        features = df.copy()
        training_mode = self.encoder_path is None

        
        # 1. IP Protocol Number (numeric từ Zeek)
        if 'ip_proto' in features.columns:
            features['proto_numeric'] = pd.to_numeric(
                features['ip_proto'], 
                errors='coerce'
            ).fillna(0).astype(np.int32)
            print("    Created: proto_numeric")
        elif 'proto' in features.columns:
            # Fallback: Map string proto to numeric
            proto_map = {'tcp': 6, 'udp': 17, 'icmp': 1}
            features['proto_numeric'] = features['proto'].map(proto_map).fillna(0).astype(np.int32)
            print("    Created: proto_numeric (from proto string)")
        
        # 2. Service (http, dns, ssl, ssh, etc.)
        if 'service' in features.columns:
            encoded = self._fit_or_transform_encoder(
                features['service'],
                'service',
                training_mode=training_mode
            )
            features['service_encoded'] = encoded
            print("    Created: service_encoded")
        
        # 3. Connection State (SF, S0, REJ, etc.)
        if 'conn_state' in features.columns:
            encoded = self._fit_or_transform_encoder(
                features['conn_state'],
                'conn_state',
                training_mode=training_mode
            )
            features['conn_state_encoded'] = encoded
            print("    Created: conn_state_encoded")
        
        print(f"    Total protocol features: 3")
        return features
    
    def extract_dns_features(self, df):
        """
        NEW: Extract DNS-based features (CHỈ CHO ISOLATION FOREST)
        
        Features:
        - dns_query_len: Độ dài DNS query (phát hiện DNS tunneling)
        - dns_entropy: Entropy của DNS query (phát hiện random domains trong tunneling)
        
        DNS Tunneling characteristics:
        - Query dài bất thường (>50 chars)
        - Entropy cao (random strings)
        """
        print("[*] Extracting DNS features (for Isolation Forest)...")
        features = df.copy()
        
        if 'query' not in features.columns:
            print("    [!] 'query' column not found, creating default values")
            features['dns_query_len'] = 0
            features['dns_entropy'] = 0.0
            return features
        
        # DNS Query Length
        features['dns_query_len'] = features['query'].fillna('').astype(str).str.len()
        
        # DNS Entropy
        def calculate_entropy(text):
            """Calculate Shannon entropy of text"""
            if pd.isna(text) or text == '':
                return 0.0
            
            text = str(text).lower()
            # Tính xác suất xuất hiện (probabilities) thay vì đếm số lượng (counts)
            probs = pd.Series(list(text)).value_counts(normalize=True) 
            return entropy(probs, base=2)
        
        features['dns_entropy'] = features['query'].apply(calculate_entropy)
        
        # Handle inf/nan
        features['dns_entropy'].replace([np.inf, -np.inf], 0, inplace=True)
        features['dns_entropy'].fillna(0, inplace=True)
        if 'service' in features.columns:
            is_dns = features['service'] == 'dns'
            features.loc[~is_dns, ['dns_query_len', 'dns_entropy']] = 0
        print(f"    Created 2 DNS features")
        print(f"    DNS query length stats: mean={features['dns_query_len'].mean():.2f}, max={features['dns_query_len'].max()}")
        print(f"    DNS entropy stats: mean={features['dns_entropy'].mean():.2f}, max={features['dns_entropy'].max():.2f}")
        
        return features
        
    def extract_behavioral_features(self, df):
        """
        Time-window based behavioral features
        
        Features:
        - src_conn_count, src_unique_dests, src_unique_ports, src_service_diversity
        - dst_conn_count
        """

        print(f"[*] Extracting behavioral features (window={self.time_window})...")
        features = df.copy()
        if not pd.api.types.is_datetime64_any_dtype(features['ts']):
            features['ts'] = pd.to_datetime(features['ts'], errors='coerce')
        # Check required columns
        required_cols = ['ts', 'id.orig_h', 'id.resp_h', 'id.resp_p', 'service']
        missing_cols = [col for col in required_cols if col not in features.columns]
        
        if missing_cols:
            print(f"[!] Missing columns: {missing_cols}. Creating default values.")
            features['src_conn_count'] = 1
            features['src_unique_dests'] = 1
            features['src_unique_ports'] = 1
            features['src_service_diversity'] = 1
            features['dst_conn_count'] = 1
            features['port_usage_ratio'] = 0
            features['service_intensity'] = 0
            return features
        
        # Ensure proper sorting
        sort_cols = ['ts', 'uid'] if 'uid' in features.columns else ['ts']
        features = features.sort_values(sort_cols).reset_index(drop=True)
        
        # Create time bins
        features['time_group'] = features['ts'].dt.floor(self.time_window)
        
        # SOURCE IP STATISTICS
        grouped_src = features.groupby(['id.orig_h', 'time_group'])
        
        src_stats = grouped_src.agg(
            src_conn_count=('id.orig_h', 'size'),
            src_unique_dests=('id.resp_h', 'nunique'),
            src_unique_ports=('id.resp_p', 'nunique'),
            src_service_diversity=('service', 'nunique')
        ).reset_index()
        
        # DESTINATION IP STATISTICS
        grouped_dst = features.groupby(['id.resp_h', 'time_group'])
        dst_stats = grouped_dst.size().reset_index(name='dst_conn_count')
        
        # Merge statistics back
        features = features.merge(src_stats, on=['id.orig_h', 'time_group'], how='left')
        features = features.merge(dst_stats, on=['id.resp_h', 'time_group'], how='left')
        
        # Fill NaN với 1
        behavioral_cols = [
            'src_conn_count', 'src_unique_dests', 'src_unique_ports',
            'src_service_diversity', 'dst_conn_count'
        ]

        features['port_usage_ratio'] = features['src_unique_ports'] / (features['src_conn_count'] + 1.0)
        for col in behavioral_cols:
            if col in features.columns:
                features[col] = features[col].fillna(1).astype(np.int32)

        if 'service' in features.columns:
            # Dùng chuỗi gốc: 'http', 'dns'...
            features['service_intensity'] = features.groupby(['id.orig_h', 'service'])['src_conn_count'].transform('mean')
        elif 'service_encoded' in features.columns:
            # Fallback dùng encoded nếu raw bị drop trước đó
            features['service_intensity'] = features.groupby(['id.orig_h', 'service_encoded'])['src_conn_count'].transform('mean')
        else:
            features['service_intensity'] = 0.0
            
        features['service_intensity'] = features['service_intensity'].fillna(0)
        print(f"    Created 7 behavioral features")
        
        # Cleanup
        features.drop('time_group', axis=1, inplace=True, errors='ignore')
        
        return features
        
    def extract_all_features(self, df):
        """
        Main feature extraction pipeline
        Tự động chọn feature set dựa trên model_type
        
        Returns:
            DataFrame with all features
        """
        # Determine mode
        training_mode = self.encoder_path is None
        mode_str = "TRAINING" if training_mode else "INFERENCE"

        
        print("="*60)
        print(f"FEATURE ENGINEERING - {mode_str} MODE")
        print(f"Model Type: {self.model_type.upper()}")
        print("="*60)
        
        # Ensure timestamp is datetime
        if 'ts' in df.columns and df['ts'].dtype != 'datetime64[ns]':
            df['ts'] = pd.to_datetime(df['ts'], errors='coerce')
        
        # Extract features step by step
        features = self.extract_basic_features(df)
        features = self.extract_protocol_features(features)
        features = self.extract_behavioral_features(features)
        
        # DNS features CHỈ cho Isolation Forest
        if self.model_type == 'if':
            features = self.extract_dns_features(features)
            print("[✓] DNS features included (Isolation Forest mode)")
        else:
            print("[✓] DNS features excluded (LightGBM mode)")
        
        # Define feature columns based on model type
        if self.model_type == 'if':
            self.feature_columns = self.FEATURES_IF.copy()
        else:
            self.feature_columns = self.FEATURES_LGBM.copy()
        
        # Filter only existing columns
        self.feature_columns = [col for col in self.feature_columns if col in features.columns]
        
        print("\n" + "="*60)
        print(f"[✓] Feature engineering complete!")
        print(f"    Mode: {mode_str}")
        print(f"    Model: {self.model_type.upper()}")
        print(f"    Total features: {len(self.feature_columns)}")
        print(f"    Features: {self.feature_columns}")
        print("="*60)
        
        return features
        
    def get_feature_matrix(self, df):
        """
        Get feature matrix X and label vector y
        
        Returns:
            X (DataFrame), y (Series or None)
        """
        if not self.feature_columns:
            raise ValueError("Run extract_all_features() first!")
        
        # Get feature matrix
        X = df[self.feature_columns].copy()
        # Final cleaning
        X.replace([np.inf, -np.inf], 0, inplace=True)
        X.fillna(0, inplace=True)


        cat_cols = ['service_encoded', 'conn_state_encoded', 'proto_numeric']
        for col in cat_cols:
            if col in X.columns:
                X[col] = X[col].astype('category')

                
        # Get labels if exist
        if 'label' in df.columns:
            y = df['label'].copy()
        else:
            y = None  # Inference mode without labels
        

        
        # Ensure all numeric
        for col in X.columns:
            if X[col].dtype == 'object':
                print(f"[!] Warning: Column '{col}' is object type, converting to numeric")
                X[col] = pd.to_numeric(X[col], errors='coerce').fillna(0)
        
        return X, y
        
    def save_feature_schema(self, output_path):
        """
        Save feature schema và encoders
        """
        schema = {
            'model_type': self.model_type,
            'feature_columns': self.feature_columns,
            'time_window': self.time_window,
            'num_features': len(self.feature_columns),
            'encoder_config': self.OE_CONFIG,
            'encoders': list(self.encoders.keys()),
            'core_features': (
                self.FEATURES_IF if self.model_type == 'if'
                else self.FEATURES_LGBM
            ),
            'dns_features': self.DNS_FEATURES if self.model_type == 'if' else []
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
            
            for name, encoder in self.encoders.items():
                n_cats = len(encoder.categories_[0])
                print(f"    - {name}: {n_cats} categories")
        else:
            print("[!] No encoders to save (inference mode?)")
    
    def load_feature_schema(self, schema_path):
        """Load and validate feature schema"""
        with open(schema_path, 'r') as f:
            schema = json.load(f)
        
        # Validate
        if schema.get('model_type') != self.model_type:
            print(f"[!] Warning: Model type mismatch!")
            print(f"    Expected: {self.model_type}")
            print(f"    Got: {schema.get('model_type')}")
        
        if schema['feature_columns'] != self.feature_columns:
            print("[!] Warning: Feature columns mismatch!")
            print(f"    Expected: {len(schema['feature_columns'])} features")
            print(f"    Got: {len(self.feature_columns)} features")
        
        return schema


if __name__ == "__main__":
    import sys
    
    # Paths
    BASE_DIR = Path("./CIC-IDS-2017")
    
    # Input files
    LABELED_ATTACK = BASE_DIR / "labeled_conn_for_semi_supervised.parquet"  # Attack traffic (LightGBM)
    LABELED_NORMAL = BASE_DIR / "labeled_conn_normal_only.parquet"  # Normal traffic (IF)
    
    # Output files
    OUTPUT_LGBM = BASE_DIR / "featured_lgbm.parquet"
    OUTPUT_IF = BASE_DIR / "featured_if.parquet"
    
    SCHEMA_LGBM = BASE_DIR / "feature_schema_lgbm.json"
    SCHEMA_IF = BASE_DIR / "feature_schema_if.json"
    
    print("\n" + "="*80)
    print("FEATURE ENGINEERING - DUAL MODE")
    print("="*80)
    
    # =================================================================
    # PART 1: LIGHTGBM FEATURES (Attack Traffic, NO DNS)
    # =================================================================
    print("\n" + "="*80)
    print("PART 1: LIGHTGBM FEATURE ENGINEERING (Attack Traffic)")
    print("="*80)
    
    if LABELED_ATTACK.exists():
        print(f"\n[*] Loading attack traffic data...")
        df_attack = pd.read_parquet(LABELED_ATTACK)
        print(f"[✓] Loaded {len(df_attack)} attack records")
        
        # Initialize for LightGBM (no DNS features)
        engineer_lgbm = NIDSFeatureEngineer(time_window='10s', model_type='lgbm')
        
        # Extract features
        featured_lgbm = engineer_lgbm.extract_all_features(df_attack)
        
        # Get feature matrix
        X_lgbm, y_lgbm = engineer_lgbm.get_feature_matrix(featured_lgbm)
        
        print(f"\n[*] LightGBM feature matrix shape: {X_lgbm.shape}")
        print(f"[*] Feature dtypes:\n{X_lgbm.dtypes.value_counts()}")
        
        if y_lgbm is not None:
            print(f"\n[*] Label distribution:\n{y_lgbm.value_counts()}")
        
        # Save
        print(f"\n[*] Saving LightGBM features...")
        featured_lgbm.to_parquet(OUTPUT_LGBM, index=False, compression='snappy')
        print(f"[✓] Saved to {OUTPUT_LGBM}")
        
        engineer_lgbm.save_feature_schema(SCHEMA_LGBM)
        
        print("\n[✓] LightGBM processing complete!")
    else:
        print(f"\n[!] Attack traffic file not found: {LABELED_ATTACK}")
    
    # =================================================================
    # PART 2: ISOLATION FOREST FEATURES (Normal Traffic, WITH DNS)
    # =================================================================
    print("\n\n" + "="*80)
    print("PART 2: ISOLATION FOREST FEATURE ENGINEERING (Normal Traffic)")
    print("="*80)
    
    if LABELED_NORMAL.exists():
        print(f"\n[*] Loading normal traffic data...")
        df_normal = pd.read_parquet(LABELED_NORMAL)
        print(f"[✓] Loaded {len(df_normal)} normal records")
        
        # Initialize for Isolation Forest (with DNS features)
        engineer_if = NIDSFeatureEngineer(time_window='10s', model_type='if')
        
        # Extract features
        featured_if = engineer_if.extract_all_features(df_normal)
        
        # Get feature matrix
        X_if, y_if = engineer_if.get_feature_matrix(featured_if)
        
        print(f"\n[*] Isolation Forest feature matrix shape: {X_if.shape}")
        print(f"[*] Feature dtypes:\n{X_if.dtypes.value_counts()}")
        
        # DNS feature stats
        if 'dns_query_len' in X_if.columns:
            print(f"\n[*] DNS feature statistics:")
            print(f"    Query length - mean: {X_if['dns_query_len'].mean():.2f}, max: {X_if['dns_query_len'].max()}")
            print(f"    Query entropy - mean: {X_if['dns_entropy'].mean():.2f}, max: {X_if['dns_entropy'].max():.2f}")
        
        # Save
        print(f"\n[*] Saving Isolation Forest features...")
        featured_if.to_parquet(OUTPUT_IF, index=False, compression='snappy')
        print(f"[✓] Saved to {OUTPUT_IF}")
        
        engineer_if.save_feature_schema(SCHEMA_IF)
        
        print("\n[✓] Isolation Forest processing complete!")
    else:
        print(f"\n[!] Normal traffic file not found: {LABELED_NORMAL}")
    
    # =================================================================
    # SUMMARY
    # =================================================================
    print("\n\n" + "="*80)
    print("FEATURE ENGINEERING SUMMARY")
    print("="*80)
    
    print("\n📊 Feature Sets:")
    print(f"  LightGBM: {len(NIDSFeatureEngineer.FEATURES_LGBM)} features (NO DNS)")
    print(f"  Isolation Forest: {len(NIDSFeatureEngineer.FEATURES_IF)} features (WITH DNS)")
    
    print("\n📁 Output Files:")
    if OUTPUT_LGBM.exists():
        size_mb = OUTPUT_LGBM.stat().st_size / 1024**2
        print(f"  ✓ LightGBM: {OUTPUT_LGBM} ({size_mb:.2f} MB)")
    if OUTPUT_IF.exists():
        size_mb = OUTPUT_IF.stat().st_size / 1024**2
        print(f"  ✓ Isolation Forest: {OUTPUT_IF} ({size_mb:.2f} MB)")
    
    print("\n🎯 Next Steps:")
    print("  1. Train LightGBM model with featured_lgbm.parquet")
    print("  2. Train Isolation Forest with featured_if.parquet")
    print("  3. Use feature_schema_*.json for production inference")
    
    print("\n" + "="*80)
    print("[✓] ALL PROCESSING COMPLETE!")
    print("="*80)