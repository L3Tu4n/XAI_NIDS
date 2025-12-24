#!/usr/bin/env python3
"""
NIDS Feature Engineering - STREAMING PRODUCTION VERSION (v6.1)
Updates:
- ✅ FIX: Expose self.FEATURES_IF and self.FEATURES_LGBM for Aggregator
- Synced with Training Logic (port_usage_ratio, service_intensity)
"""

import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.preprocessing import OrdinalEncoder
from scipy.stats import entropy
import warnings
import pickle
import os
import logging

# Setup Logger
logger = logging.getLogger('feature-engineer')
warnings.filterwarnings("ignore")

class NIDSFeatureEngineer:

    def __init__(self, time_window="10s", encoder_path=None, model_type='lgbm'):
        self.time_window = time_window
        self.encoder_path = encoder_path
        self.model_type = model_type
        self.encoders = {}

        # Cấu hình Encoder
        self.OE_CONFIG = {
            "handle_unknown": "use_encoded_value",
            "unknown_value": -1,
            "dtype": "int32",
        }

        # Load Encoders
        if self.encoder_path:
            path = Path(self.encoder_path)
            if path.exists():
                try:
                    with open(path, "rb") as f:
                        self.encoders = pickle.load(f)
                    logger.info(f"✅ Loaded encoders from {path}")
                except Exception as e:
                    logger.error(f"❌ Failed to load encoders: {e}")
            else:
                if model_type == 'lgbm':
                    logger.warning(f"⚠️ Encoder file not found at {path}")

        # === ĐỊNH NGHĨA FEATURE COMPONENTS ===
        
        # 1. Common Features
        self.COMMON_FEATURES = [
            "duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts",
            "bytes_per_sec", "pkts_per_sec", "bytes_per_pkt", 
            "byte_ratio", "pkt_ratio",
            "src_conn_count", "src_unique_dests", "src_unique_ports",
            "src_service_diversity", "dst_conn_count",
            "proto_numeric", 
            "service_intensity", "port_usage_ratio"
        ]

        # 2. Specific Features
        self.LGBM_SPECIFIC = ["service_encoded", "conn_state_encoded"]
        self.IF_SPECIFIC = ["dns_query_len", "dns_entropy"]

        # === [FIX] EXPOSE FULL FEATURE LISTS FOR AGGREGATOR ===
        # Aggregator cần gọi 2 biến này để tạo danh sách Hybrid
        self.FEATURES_LGBM = self.COMMON_FEATURES + self.LGBM_SPECIFIC
        self.FEATURES_IF = self.COMMON_FEATURES + self.IF_SPECIFIC

        # === CHỌN ACTIVE FEATURE LIST ===
        if self.model_type == 'if':
            self.feature_columns = self.FEATURES_IF
        else:
            self.feature_columns = self.FEATURES_LGBM

        logger.info(f"🔧 Initialized FeatureEngineer for '{self.model_type}'. Features: {len(self.feature_columns)}")

    def _encode(self, series, key):
        """Hàm encode sử dụng Encoder đã train"""
        if key not in self.encoders:
            return np.full(len(series), -1)
        
        data = series.fillna("MISSING").astype(str).to_frame()
        try:
            return self.encoders[key].transform(data).ravel()
        except Exception:
            return np.full(len(series), -1)

    def extract_all_features(self, df):
        """
        Main Extraction Pipeline
        """
        if df.empty: return pd.DataFrame(columns=self.feature_columns)
        
        f = df.copy()
        
        # --- 0. PRE-CHECK CRITICAL COLUMNS ---
        required_cols = ["service", "id.orig_h", "id.resp_h", "id.resp_p", "conn_state", "history", "proto"]
        for col in required_cols:
            if col not in f.columns:
                f[col] = "MISSING"
        
        f["service"] = f["service"].fillna("-")

        # --- 1. BASIC PREPROCESSING ---
        if "ts" in f.columns:
            if not pd.api.types.is_datetime64_any_dtype(f['ts']):
                f["ts"] = pd.to_numeric(f["ts"], errors='coerce')
                f["ts"] = pd.to_datetime(f["ts"], unit='s', errors='coerce')

        num_cols = ["duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts"]
        for c in num_cols:
            if c in f.columns:
                f[c] = pd.to_numeric(f[c], errors="coerce").fillna(0)
            else:
                f[c] = 0

        # --- 2. DERIVED STATS ---
        f["total_bytes"] = f["orig_bytes"] + f["resp_bytes"]
        f["total_pkts"] = f["orig_pkts"] + f["resp_pkts"]
        
        f["bytes_per_sec"] = np.where(f["duration"] > 0, f["total_bytes"] / f["duration"], 0)
        f["pkts_per_sec"] = np.where(f["duration"] > 0, f["total_pkts"] / f["duration"], 0)
        f["bytes_per_pkt"] = np.where(f["total_pkts"] > 0, f["total_bytes"] / f["total_pkts"], 0)
        
        f["byte_ratio"] = np.log1p(f["orig_bytes"]) - np.log1p(f["resp_bytes"])
        f["pkt_ratio"] = np.log1p(f["orig_pkts"]) - np.log1p(f["resp_pkts"])

        # --- 3. PROTOCOL ---
        if "proto" in f.columns:
            proto_map = {'tcp': 6, 'udp': 17, 'icmp': 1}
            f["proto_numeric"] = f["proto"].str.lower().map(proto_map).fillna(0).astype(int)
        else:
            f["proto_numeric"] = 0

        # --- 4. CONDITIONAL FEATURES ---
        
        # A. LightGBM (Encode)
        # Lưu ý: Aggregator cần 'service_encoded' nên ta luôn tính nếu có encoder, dù mode là IF
        if self.encoders: 
             for col in ["service", "conn_state"]:
                f[f"{col}_encoded"] = self._encode(f[col], col)
        elif self.model_type != 'if': # Fallback nếu không có encoder nhưng đang chạy mode LGBM
             for col in ["service", "conn_state"]:
                f[f"{col}_encoded"] = -1

        # B. Isolation Forest (DNS)
        # Aggregator cần tính DNS luôn nên ta kích hoạt nếu mode là IF hoặc nếu cần Hybrid
        if self.model_type == 'if' or hasattr(self, 'FEATURES_IF'): 
            if "query" in f.columns:
                f["dns_query_len"] = f["query"].fillna("").astype(str).str.len()
                
                def calc_entropy(text):
                    if not text: return 0.0
                    text = str(text).lower()
                    probs = pd.Series(list(text)).value_counts(normalize=True)
                    return entropy(probs, base=2)
                
                f["dns_entropy"] = f["query"].apply(calc_entropy)
            else:
                f["dns_query_len"] = 0
                f["dns_entropy"] = 0.0

        # --- 5. BEHAVIORAL AGGREGATION ---
        if "ts" in f.columns and not f.empty:
            f["time_group"] = f["ts"].dt.floor(self.time_window)
            
            src_stats = f.groupby(["id.orig_h", "time_group"]).agg(
                src_conn_count=("ts", "size"),
                src_unique_dests=("id.resp_h", "nunique"),
                src_unique_ports=("id.resp_p", "nunique"),
                src_service_diversity=("service", "nunique") 
            ).reset_index()
            
            dst_stats = f.groupby(["id.resp_h", "time_group"]).size().reset_index(name="dst_conn_count")
            
            f = f.merge(src_stats, on=["id.orig_h", "time_group"], how="left")
            f = f.merge(dst_stats, on=["id.resp_h", "time_group"], how="left")
            
            fill_cols = ["src_conn_count", "src_unique_dests", "src_unique_ports", 
                         "src_service_diversity", "dst_conn_count"]
            f[fill_cols] = f[fill_cols].fillna(1)

            # === TÍNH TOÁN FEATURE MỚI ===
            f['port_usage_ratio'] = f['src_unique_ports'] / (f['src_conn_count'] + 1.0)

            # Service Intensity (Ưu tiên dùng raw string)
            if 'service' in f.columns:
                f['service_intensity'] = f.groupby(['id.orig_h', 'service'])['src_conn_count'].transform('mean')
            elif 'service_encoded' in f.columns:
                f['service_intensity'] = f.groupby(['id.orig_h', 'service_encoded'])['src_conn_count'].transform('mean')
            else:
                f['service_intensity'] = 0.0
            
            f['service_intensity'] = f['service_intensity'].fillna(0)

        else:
            cols = ["src_conn_count", "src_unique_dests", "src_unique_ports", 
                    "src_service_diversity", "dst_conn_count"]
            for c in cols: f[c] = 1
            f['port_usage_ratio'] = 0.0
            f['service_intensity'] = 0.0

        return f

    def get_feature_matrix(self, df):
        """
        Trả về ma trận features đúng thứ tự cột
        """
        X = pd.DataFrame()
        for c in self.feature_columns:
            if c in df.columns:
                X[c] = df[c]
            else:
                X[c] = 0 
        
        # [FIX] Clean Data First
        X.replace([np.inf, -np.inf], 0, inplace=True)
        X.fillna(0, inplace=True)
        
        # [FIX] Convert Categories Only if needed (LGBM)
        if self.model_type != 'if':
            cat_cols = ['service_encoded', 'conn_state_encoded', 'proto_numeric']
            for col in cat_cols:
                if col in X.columns:
                    try:
                        X[col] = X[col].astype(int).astype('category')
                    except:
                        pass

        # [FIX] Convert Numeric
        for col in X.columns:
            if not isinstance(X[col].dtype, pd.CategoricalDtype):
                X[col] = pd.to_numeric(X[col], errors='coerce').fillna(0)
            
        return X