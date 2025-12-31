#!/usr/bin/env python3
"""
Training Script - Isolation Forest for Zero-day Detection
UPGRADE VERSION:
- RobustScaler
- contamination='auto'
- Percentile-based threshold (deployable)
"""

import pandas as pd
import numpy as np
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import RobustScaler
import joblib
import json
from pathlib import Path
import warnings

warnings.filterwarnings('ignore')


class IsolationForestTrainer:
    def __init__(self, data_dir="./CIC-IDS-2017", model_dir="./models"):
        self.data_dir = Path(data_dir)
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(parents=True, exist_ok=True)

        # Input
        self.data_path = self.data_dir / "featured_if.parquet"
        self.schema_path = self.data_dir / "feature_schema_if.json"

        # Output
        self.model_path = self.model_dir / "isolation_forest.joblib"
        self.scaler_path = self.model_dir / "if_scaler.joblib"
        self.metadata_path = self.model_dir / "isolation_forest_metadata.json"

        self.model = None
        self.scaler = None
        self.feature_names = None
        self.threshold = None
        self.threshold_percentile = None

    # ==========================================================
    # LOAD DATA
    # ==========================================================
    def load_data(self):
        print(f"[*] Loading data from {self.data_path}")

        with open(self.schema_path, 'r') as f:
            schema = json.load(f)
            self.feature_names = schema["feature_columns"]

        df = pd.read_parquet(self.data_path)

        X = df[self.feature_names].copy()
        X.replace([np.inf, -np.inf], 0, inplace=True)
        X.fillna(0, inplace=True)

        print(f"[✓] Data loaded: {X.shape}")
        print(f"    Features: {len(self.feature_names)}")

        return X

    # ==========================================================
    # TRAIN MODEL
    # ==========================================================
    def train(self, X, threshold_percentile=5):
        print("\n" + "=" * 70)
        print("STEP 1: ROBUST SCALING")
        print("=" * 70)
        cat_cols = [col for col in self.feature_names if 'encoded' in col or 'numeric' in col]
        num_cols = [col for col in self.feature_names if col not in cat_cols]
        self.scaler = RobustScaler()

        self.scaler = ColumnTransformer([
            ('num', RobustScaler(), num_cols),
            ('cat', 'passthrough', cat_cols) # Giữ nguyên các cột encoded
        ])
        X_scaled = self.scaler.fit_transform(X)

        joblib.dump(self.scaler, self.scaler_path)
        print(f"[✓] Scaler saved: {self.scaler_path}")

        print("\n" + "=" * 70)
        print("STEP 2: TRAIN ISOLATION FOREST")
        print("=" * 70)

        self.model = IsolationForest(
            n_estimators=200,
            contamination="auto",      # 🔥 CRITICAL FIX
            max_features=0.8,          # Better subspace anomaly detection
            bootstrap=False,
            n_jobs=-1,
            random_state=42
        )

        self.model.fit(X_scaled)
        print("[✓] Isolation Forest training complete")

        # ======================================================
        # THRESHOLD COMPUTATION (DEPLOYABLE)
        # ======================================================
        scores = self.model.decision_function(X_scaled)

        self.threshold_percentile = threshold_percentile
        self.threshold = np.percentile(scores, threshold_percentile)

        anomalies = (scores < self.threshold).sum()

        print("\n[*] Training statistics:")
        print(f"    Samples: {len(scores)}")
        print(f"    Threshold percentile: {threshold_percentile}%")
        print(f"    Threshold value: {self.threshold:.6f}")
        print(f"    Anomalies detected: {anomalies} ({anomalies/len(scores)*100:.2f}%)")
        print(f"    Mean score: {scores.mean():.6f}")
        print(f"    Min score: {scores.min():.6f}")

    # ==========================================================
    # SAVE MODEL + METADATA
    # ==========================================================
    def save(self):
        print("\n[*] Saving model & metadata")

        joblib.dump(self.model, self.model_path)

        metadata = {
            "model_type": "Isolation Forest",
            "purpose": "Zero-day & DNS tunneling detection",
            "feature_names": self.feature_names,
            "scaler": str(self.scaler_path),
            "threshold": float(self.threshold),
            "threshold_percentile": self.threshold_percentile,
            "decision_rule": "score < threshold => anomaly",
            "notes": "RobustScaler + percentile-based threshold"
        }

        with open(self.metadata_path, "w") as f:
            json.dump(metadata, f, indent=2)

        print(f"[✓] Model saved: {self.model_path}")
        print(f"[✓] Metadata saved: {self.metadata_path}")

    # ==========================================================
    # PIPELINE
    # ==========================================================
    def run(self):
        X = self.load_data()
        self.train(X, threshold_percentile=5)
        self.save()
        print("\n[✓] ISOLATION FOREST READY FOR DEPLOYMENT")


# ==========================================================
# MAIN
# ==========================================================
if __name__ == "__main__":
    trainer = IsolationForestTrainer()
    try:
        trainer.run()
    except Exception as e:
        print(f"[!] ERROR: {e}")
