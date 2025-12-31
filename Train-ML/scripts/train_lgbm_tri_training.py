#!/usr/bin/env python3
"""
Train LightGBM Model cho NIDS - TRI-TRAINING FIXED VERSION (v3.1)
Fixes:
- Strict Schema Enforcement: Force dtypes before every predict/fit call.
- Fix 'train and valid dataset categorical_feature do not match'.
"""
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report, confusion_matrix, 
    accuracy_score, f1_score, precision_recall_fscore_support
)
from sklearn.utils import resample
from imblearn.over_sampling import SMOTE
from lightgbm import LGBMClassifier
from collections import defaultdict
import joblib
import json
from pathlib import Path
import matplotlib.pyplot as plt
import seaborn as sns
import warnings
import copy

warnings.filterwarnings('ignore')

class NIDSTriTrainer:
    """
    Tri-Training Implementation for NIDS
    Based on: Zhou & Li (2005) "Tri-Training: Exploiting Unlabeled Data Using Three Classifiers"
    """
    
    # Configuration
    MAX_ADD_PER_ITER = 50000
    MAX_ADD_PER_CLASS = 40000
    PREDICT_BATCH = 50000
    MAX_ITER = 10
    
    def __init__(self, model_dir='./models', encoder_path=None):
        """
        Args:
            model_dir: Directory để save models
            encoder_path: Path tới file encoder.pkl (Dùng để lưu tham chiếu)
        """
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(parents=True, exist_ok=True)
        
        self.models = None  # List of 3 LGBMClassifiers
        self.feature_names = None
        self.error_rates = None  # Track error rates for stopping criterion
        self.encoder_path = encoder_path # LƯU ĐƯỜNG DẪN ENCODER
        self.cat_cols = [] # Store categorical columns
        
    def load_data(self, parquet_path, feature_schema_path):
        """Load dataset and feature schema"""
        print("[*] Loading dataset...")
        df = pd.read_parquet(parquet_path)
        
        with open(feature_schema_path, 'r') as f:
            schema = json.load(f)
            
        self.feature_names = schema['feature_columns']
        
        # Extract features
        X = df[self.feature_names].copy()
        y = df['label'].copy()
        
        # Clean data
        X.replace([np.inf, -np.inf], 0, inplace=True)
        X.fillna(0, inplace=True)
        
        print(f"[✓] Loaded dataset: {X.shape}")
        print(f"    Features: {len(self.feature_names)}")
        print(f"    Samples: {len(X)}")
        
        # Label distribution
        print(f"\n    Label distribution:")
        for label, count in y.value_counts().sort_index().items():
            pct = count / len(y) * 100
            print(f"      Class {label}: {count} ({pct:.2f}%)")
            
        # Xác định cột category để xử lý sau này
        self.cat_cols = [col for col in self.feature_names if 'encoded' in col or 'numeric' in col]
        print(f"    Categorical columns: {self.cat_cols}")
        
        return X, y
    
    def prepare_df_dtypes(self, X):
        """
        Hàm helper quan trọng: Ép kiểu dữ liệu nghiêm ngặt
        """
        # Nếu là numpy array hoặc list, chuyển thành DataFrame
        if not isinstance(X, pd.DataFrame):
            X = pd.DataFrame(X, columns=self.feature_names)
            
        # Copy để tránh warning SettingWithCopy
        X = X.copy()
        
        # Ép kiểu cho từng cột category
        for col in self.cat_cols:
            if col in X.columns:
                try:
                    # Ép về int trước để tránh lỗi float (1.0 != 1)
                    X[col] = pd.to_numeric(X[col], errors='coerce').fillna(0).astype(int)
                    X[col] = X[col].astype('category')
                except:
                    X[col] = X[col].astype('category')
        return X

    def handle_imbalance(self, X, y, method='smote'):
        """Handle class imbalance với SMOTE"""
        if method == 'none':
            return self.prepare_df_dtypes(X), y
            
        if method == 'smote':
            print("[*] Applying SMOTE for class balancing...")
            
            min_samples = y.value_counts().min()
            k_neighbors = min(5, max(1, min_samples - 1))
            
            smote = SMOTE(random_state=42, k_neighbors=k_neighbors)
            X_resampled, y_resampled = smote.fit_resample(X, y)
            
            print(f"[✓] SMOTE applied:")
            print(f"    Before: {X.shape}")
            print(f"    After: {X_resampled.shape}")
            
            # ✅ QUAN TRỌNG: Fix lại dtypes sau khi SMOTE làm hỏng
            X_resampled = self.prepare_df_dtypes(X_resampled)
            
            return X_resampled, y_resampled
        
        return X, y
    
    def _create_base_classifier(self, seed, n_classes):
        """
        Tạo classifier với proper configuration
        """
        return LGBMClassifier(
            n_estimators=300,
            max_depth=10,
            learning_rate=0.05,
            subsample=0.8,
            colsample_bytree=0.7,
            min_child_samples=20,
            reg_alpha=0.5,
            reg_lambda=0.8,
            random_state=seed,
            is_unbalance=False,      
            class_weight='balanced', 
            categorical_feature='auto', # Để auto vì data đã chuẩn category
            importance_type='gain',
            verbose=-1,
            n_jobs=-1
        )
    
    def _bootstrap_sample(self, X, y, seed):
        """
        Bootstrap sampling để tạo diversity giữa 3 models
        """
        n_samples = len(X)
        indices = np.random.RandomState(seed).choice(
            n_samples, 
            size=n_samples, 
            replace=True
        )
        return X.iloc[indices], y.iloc[indices]
    
    def _measure_error(self, model_i, model_j, X_val, y_val):
        """
        Measure error rate của model_i trên samples mà model_j đồng ý
        """
        # Đảm bảo X_val đúng schema trước khi predict
        X_val_safe = self.prepare_df_dtypes(X_val)
        
        pred_i = model_i.predict(X_val_safe)
        pred_j = model_j.predict(X_val_safe)
        
        agree_mask = (pred_i == pred_j)
        
        if agree_mask.sum() == 0:
            return 1.0
        
        agreed_preds = pred_i[agree_mask]
        agreed_true = y_val[agree_mask]
        
        error_rate = 1.0 - accuracy_score(agreed_true, agreed_preds)
        
        return error_rate
    
    def train_tri_training(self, X_labeled, y_labeled, X_unlabeled, 
                           X_val, y_val, use_smote=True):
        """
        Proper Tri-Training Implementation
        """
        print("\n" + "="*60)
        print("TRI-TRAINING WITH ERROR RATE TRACKING")
        print("="*60)
        
        # 1. Xử lý imbalance ban đầu
        if use_smote:
            X_L, y_L = self.handle_imbalance(
                X_labeled, y_labeled, method='smote'
            )
        else:
            X_L = self.prepare_df_dtypes(X_labeled)
            y_L = y_labeled
            
        # Chuẩn hóa dtypes cho Unlabeled và Validation
        X_U = self.prepare_df_dtypes(X_unlabeled).reset_index(drop=True)
        X_val = self.prepare_df_dtypes(X_val)
        y_val_np = y_val.values if isinstance(y_val, pd.Series) else y_val
        
        n_classes = len(np.unique(y_L))
        
        print(f"\n[*] Initial data: Labeled: {len(X_L)}, Unlabeled: {len(X_U)}, Classes: {n_classes}")
        
        # 2. Initialize 3 models với BOOTSTRAP SAMPLES
        print("\n[*] Initializing 3 models with bootstrap diversity...")
        self.models = []
        
        for i, seed in enumerate([42, 52, 62]):
            X_boot, y_boot = self._bootstrap_sample(X_L, y_L, seed)
            # Safety cast
            X_boot = self.prepare_df_dtypes(X_boot) 
            
            model = self._create_base_classifier(seed, n_classes)
            model.fit(X_boot, y_boot)
            self.models.append(model)
            
            val_acc = accuracy_score(y_val_np, model.predict(X_val))
            print(f"    Model {i+1}: Validation accuracy = {val_acc:.4f}")
        
        # 3. Initialize error rates
        self.error_rates = np.zeros((3, 3))
        
        for i in range(3):
            for j in range(3):
                if i != j:
                    self.error_rates[i][j] = self._measure_error(
                        self.models[i], self.models[j], X_val, y_val_np
                    )
        
        print("\n[*] Initial error rates:")
        print(self.error_rates)
        
        # 4. Tri-Training iterations
        best_val_acc = 0
        best_models = None
        patience = 3
        patience_counter = 0
        
        for iteration in range(self.MAX_ITER):
            print(f"\n{'='*60}")
            print(f"ITERATION {iteration + 1}/{self.MAX_ITER}")
            print(f"{'='*60}")
            
            any_updated = False
            
            for i in range(3):
                j, k = (i + 1) % 3, (i + 2) % 3
                
                print(f"\n[*] Updating Model {i+1} using agreement from Models {j+1} & {k+1}...")
                
                if len(X_U) == 0:
                    print("    No unlabeled data remaining.")
                    continue
                
                # Batch prediction
                pred_j_list, pred_k_list = [], []
                prob_j_list, prob_k_list = [], []
                
                for start in range(0, len(X_U), self.PREDICT_BATCH):
                    end = min(len(X_U), start + self.PREDICT_BATCH)
                    # ✅ FIX: Ép kiểu lại cho batch để đảm bảo khớp schema
                    batch = self.prepare_df_dtypes(X_U.iloc[start:end])
                    
                    pred_j_list.append(self.models[j].predict(batch))
                    pred_k_list.append(self.models[k].predict(batch))
                    prob_j_list.append(self.models[j].predict_proba(batch))
                    prob_k_list.append(self.models[k].predict_proba(batch))
                
                pred_j = np.concatenate(pred_j_list)
                pred_k = np.concatenate(pred_k_list)
                prob_j = np.vstack(prob_j_list)
                prob_k = np.vstack(prob_k_list)
                
                # 6. Find agreements
                agree_mask = (pred_j == pred_k)
                agree_indices = np.where(agree_mask)[0]
                
                if len(agree_indices) == 0:
                    print(f"    No agreements found between Models {j+1} & {k+1}")
                    continue
                
                print(f"    Found {len(agree_indices)} agreements ({len(agree_indices)/len(X_U)*100:.2f}%)")
                
                # 7. Confidence filtering
                avg_conf = (np.max(prob_j[agree_indices], axis=1) + 
                           np.max(prob_k[agree_indices], axis=1)) / 2
                
                conf_threshold = 0.90 - iteration * 0.03
                conf_threshold = max(0.75, conf_threshold)
                
                high_conf_mask = avg_conf >= conf_threshold
                confident_indices = agree_indices[high_conf_mask]
                
                if len(confident_indices) == 0:
                    print(f"    No confident agreements (threshold={conf_threshold:.2f})")
                    continue
                
                print(f"    Confident agreements: {len(confident_indices)} (conf >= {conf_threshold:.2f})")
                
                # 8. Measure error rate on validation
                new_error = self._measure_error(self.models[i], self.models[j], X_val, y_val_np)
                old_error = self.error_rates[i][j]
                
                print(f"    Error rate: {old_error:.4f} -> {new_error:.4f}")
                
                if new_error > old_error + 0.05:
                    print(f"    Error increased too much. Skip update.")
                    continue
                
                # 9. Select samples to add (per-class balancing)
                pseudo_labels = pred_j[confident_indices]
                pseudo_conf = avg_conf[high_conf_mask]
                
                # Sort by confidence
                sort_order = np.argsort(pseudo_conf)[::-1]
                
                selected_local_indices = []
                class_counts = defaultdict(int)
                
                for idx in sort_order:
                    # idx là chỉ số tương đối trong confident_indices
                    label = int(pseudo_labels[idx])
                    if class_counts[label] < self.MAX_ADD_PER_CLASS:
                        selected_local_indices.append(idx)
                        class_counts[label] += 1
                    
                    if len(selected_local_indices) >= self.MAX_ADD_PER_ITER:
                        break
                
                if len(selected_local_indices) == 0:
                    continue
                
                # Mapping lại index
                indices_to_use = confident_indices[selected_local_indices]

                # 10. Add to training set and retrain model i
                X_new = X_U.iloc[indices_to_use]
                y_new = pred_j[indices_to_use]
                
                # ✅ FIX: Concatenate và ép kiểu cho tập train mới
                X_i_train = pd.concat([X_L, X_new], axis=0, ignore_index=True)
                X_i_train = self.prepare_df_dtypes(X_i_train)
                y_i_train = np.hstack([y_L, y_new])
                
                print(f"    Adding {len(selected_local_indices)} pseudo-labeled samples")
                print(f"    New training size for Model {i+1}: {len(X_i_train)}")
                
                # Retrain model i
                self.models[i] = self._create_base_classifier(42 + i*10, n_classes)
                self.models[i].fit(X_i_train, y_i_train)
                
                # Update error rate
                self.error_rates[i][j] = new_error
                
                any_updated = True
                
                # Remove selected samples from unlabeled pool
                X_U = X_U.drop(index=indices_to_use).reset_index(drop=True)
                # ✅ FIX: Ép kiểu lại cho X_U sau khi drop
                X_U = self.prepare_df_dtypes(X_U)
                
                print(f"    Remaining unlabeled: {len(X_U)}")
            
            # 11. Validation check (Majority vote)
            # Predict val cũng cần ép kiểu
            X_val_safe = self.prepare_df_dtypes(X_val)
            val_preds = np.array([m.predict(X_val_safe) for m in self.models])
            maj_vote = np.apply_along_axis(
                lambda x: np.bincount(x).argmax(), 
                axis=0, 
                arr=val_preds
            )
            val_acc = accuracy_score(y_val_np, maj_vote)
            
            print(f"\n[*] Validation accuracy (Majority): {val_acc:.4f}")
            
            if val_acc > best_val_acc:
                best_val_acc = val_acc
                best_models = copy.deepcopy(self.models)
                patience_counter = 0
                print(f"    New best! Saved checkpoint.")
            else:
                patience_counter += 1
                print(f"    No improvement. Patience: {patience_counter}/{patience}")
            
            if patience_counter >= patience:
                print("\n[*] Early stopping triggered.")
                break
            
            if not any_updated:
                print("\n[*] No models updated. Converged.")
                break
            
            if len(X_U) == 0:
                print("\n[*] No unlabeled data remaining.")
                break
        
        if best_models is not None:
            self.models = best_models
            print(f"\n[✓] Restored best models (val_acc={best_val_acc:.4f})")
        
        print("\n" + "="*60)
        print("[✓] TRI-TRAINING COMPLETE!")
        print(f"    Best validation accuracy: {best_val_acc:.4f}")
        print("="*60)
        
        return self.models
    
    def evaluate(self, X_test, y_test):
        """
        Evaluate với majority voting
        """
        if self.models is None or len(self.models) != 3:
            raise ValueError("Models not trained!")
        
        print("\n" + "="*60)
        print("MODEL EVALUATION (Majority Vote)")
        print("="*60)
        
        X_test_safe = self.prepare_df_dtypes(X_test)
        y_test_np = y_test.values if isinstance(y_test, pd.Series) else y_test
        
        preds = np.array([m.predict(X_test_safe) for m in self.models])
        
        y_pred = np.apply_along_axis(
            lambda x: np.bincount(x).argmax(), 
            axis=0, 
            arr=preds
        )
        
        accuracy = accuracy_score(y_test_np, y_pred)
        f1 = f1_score(y_test_np, y_pred, average='weighted')
        
        print(f"\n[*] Overall Metrics:")
        print(f"    Accuracy: {accuracy:.4f}")
        print(f"    F1-Score (weighted): {f1:.4f}")
        
        precision, recall, f1_per_class, support = precision_recall_fscore_support(
            y_test_np, y_pred, average=None
        )
        
        print(f"\n[*] Per-Class Metrics:")
        for i in range(len(precision)):
            print(f"    Class {i}: P={precision[i]:.4f}, R={recall[i]:.4f}, "
                  f"F1={f1_per_class[i]:.4f}, Support={support[i]}")
        
        print(f"\n[*] Classification Report:")
        print(classification_report(y_test_np, y_pred, digits=4))
        
        cm = confusion_matrix(y_test_np, y_pred)
        print(f"\n[*] Confusion Matrix:")
        print(cm)
        
        self._plot_confusion_matrix(cm)
        
        print(f"\n[*] Individual Model Accuracies:")
        for i, model in enumerate(self.models):
            acc = accuracy_score(y_test_np, model.predict(X_test_safe))
            print(f"    Model {i+1}: {acc:.4f}")
        
        return {
            'accuracy': accuracy,
            'f1_score': f1,
            'confusion_matrix': cm.tolist(),
            'precision': precision.tolist(),
            'recall': recall.tolist()
        }
    
    def _plot_confusion_matrix(self, cm):
        """Plot confusion matrix"""
        plt.figure(figsize=(10, 8))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues')
        plt.title('Confusion Matrix')
        plt.ylabel('True Label')
        plt.xlabel('Predicted Label')
        
        cm_path = self.model_dir / 'confusion_matrix.png'
        plt.savefig(cm_path, dpi=150, bbox_inches='tight')
        print(f"[✓] Saved confusion matrix to {cm_path}")
        plt.close()
    
    def save_model(self, model_name='nids_tri_lgbm'):
        """Save 3 models và metadata"""
        if self.models is None:
            raise ValueError("No models to save!")
        
        # Save models
        model_path = self.model_dir / f'{model_name}.joblib'
        joblib.dump(self.models, str(model_path))
        print(f"[✓] Saved 3 models to {model_path}")
        
        # Save metadata
        metadata = {
            'feature_names': self.feature_names,
            'num_features': len(self.feature_names),
            'model_type': 'Tri-Training LightGBM',
            'num_classifiers': 3,
            'num_classes': self.models[0].n_classes_,
            'error_rates': self.error_rates.tolist() if self.error_rates is not None else None,
            'encoder_reference_path': str(self.encoder_path) if hasattr(self, 'encoder_path') and self.encoder_path else 'N/A'
        }
        
        metadata_path = self.model_dir / f'{model_name}_metadata.json'
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        print(f"[✓] Saved metadata to {metadata_path}")
        if hasattr(self, 'encoder_path') and self.encoder_path:
            print(f"    Encoder reference saved: {self.encoder_path.name}")
    
    def load_model(self, model_name='nids_tri_lgbm'):
        """Load saved models"""
        model_path = self.model_dir / f'{model_name}.joblib'
        metadata_path = self.model_dir / f'{model_name}_metadata.json'
        
        self.models = joblib.load(str(model_path))
        
        with open(metadata_path, 'r') as f:
            metadata = json.load(f)
        
        self.feature_names = metadata['feature_names']
        self.error_rates = np.array(metadata['error_rates']) if metadata['error_rates'] else None
        
        print(f"[✓] Loaded 3 models from {model_path}")


if __name__ == "__main__":
    from sklearn.model_selection import train_test_split
    
    # Paths
    DATASET_PATH = "./CIC-IDS-2017/featured_lgbm.parquet"
    SCHEMA_PATH = "./CIC-IDS-2017/feature_schema_lgbm.json"
    MODEL_DIR = "./models"
    ENCODER_PKL_PATH = Path("./CIC-IDS-2017/feature_schema_lgbm.pkl")
    
    # Initialize trainer
    trainer = NIDSTriTrainer(model_dir=MODEL_DIR, encoder_path=ENCODER_PKL_PATH)
    
    # Load data
    X, y = trainer.load_data(DATASET_PATH, SCHEMA_PATH)
    
    # =================================================================
    # CUSTOM DATA SPLITTING STRATEGY (FIX FOR RARE CLASSES)
    # =================================================================
    print("\n" + "="*60)
    print("DATA SPLITTING FOR TRI-TRAINING (Robust Mode)")
    print("="*60)
    
    # 1. Tách Test Set (20%) - Giữ nguyên Stratify
    try:
        X_temp, X_test, y_temp, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
    except ValueError:
        print("[!] Warning: Stratified split failed. Switching to random split.")
        X_temp, X_test, y_temp, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42
        )

    # 2. Tách Labeled / Unlabeled thủ công
    labeled_indices = []
    unlabeled_indices = []
    
    RARE_THRESHOLD = 100 
    LABELED_RATIO_FOR_COMMON = 0.125 
    
    unique_classes = np.unique(y_temp)
    print(f"\n[*] Splitting Labeled/Unlabeled (Rare Threshold={RARE_THRESHOLD})...")
    
    for cls in unique_classes:
        cls_indices = np.where(y_temp == cls)[0]
        n_samples = len(cls_indices)
        
        if n_samples < RARE_THRESHOLD:
            # [CASE HIẾM]: Giữ TOÀN BỘ vào Labeled
            labeled_indices.extend(cls_indices)
            print(f"    Class {cls}: {n_samples} samples -> Keep ALL in Labeled")
        else:
            # [CASE THƯỜNG]: Chia theo tỷ lệ
            n_labeled = int(n_samples * LABELED_RATIO_FOR_COMMON)
            np.random.seed(42)
            np.random.shuffle(cls_indices)
            
            labeled_indices.extend(cls_indices[:n_labeled])
            unlabeled_indices.extend(cls_indices[n_labeled:])
    
    X_labeled = X_temp.iloc[labeled_indices]
    y_labeled = y_temp.iloc[labeled_indices]
    X_unlabeled = X_temp.iloc[unlabeled_indices]
    
    # 3. Tách Train / Validation từ Labeled (20%)
    try:
        X_train, X_val, y_train, y_val = train_test_split(
            X_labeled, y_labeled,
            test_size=0.2,
            stratify=y_labeled,
            random_state=42
        )
    except ValueError:
         print("    [!] Warning: Stratify failed for Train/Val split. Using random split.")
         X_train, X_val, y_train, y_val = train_test_split(
            X_labeled, y_labeled,
            test_size=0.2,
            random_state=42
        )

    print(f"\n[✓] Final Data Distribution:")
    print(f"    Labeled (Train): {len(X_train)}")
    print(f"    Labeled (Val):   {len(X_val)}")
    print(f"    Unlabeled:       {len(X_unlabeled)}")
    print(f"    Test:            {len(X_test)}")
    
    # Train Tri-Training
    print("\n[*] Starting Tri-Training...")
    trainer.train_tri_training(
        X_train, y_train, 
        X_unlabeled,
        X_val, y_val,
        use_smote=True
    )
    
    # Evaluate
    metrics = trainer.evaluate(X_test, y_test)
    
    # Save models
    trainer.save_model(model_name='nids_tri_lgbm_v1')
    
    print("\n" + "="*60)
    print("[✓] TRAINING COMPLETE!")
    print(f"    Test Accuracy: {metrics['accuracy']:.4f}")
    print(f"    Test F1-Score: {metrics['f1_score']:.4f}")
    print(f"    Models saved to: {MODEL_DIR}")
    print("="*60)