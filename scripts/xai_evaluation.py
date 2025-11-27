#!/usr/bin/env python3
"""
Comprehensive Model Evaluation cho NIDS
- Metrics: Accuracy, Precision, Recall, F1, ROC-AUC, FPR
- Train vs Test comparison (Overfitting detection)
- Threshold optimization
- XAI: SHAP và LIME explanations
"""
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path
import json
import joblib
import warnings
from sklearn.model_selection import train_test_split
warnings.filterwarnings('ignore')

# Metrics
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, roc_curve, auc, # Các imports cũ
    confusion_matrix, classification_report,
    precision_recall_curve, average_precision_score,
    # 💡 FIX: Thêm hàm bị thiếu này
    precision_recall_fscore_support 
)

# XAI Libraries
import shap
from lime import lime_tabular

class NIDSModelEvaluator:
    """
    Comprehensive evaluator cho NIDS models
    """
    
    def __init__(self, models, feature_names, label_encoder=None, output_dir='./evaluation_results'):
        # ... (Các dòng khởi tạo giữ nguyên)

        self.models = models
        self.feature_names = feature_names
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        # ⚠️ FIX: Lấy danh sách nhãn số thực tế mà mô hình đã học (theo thứ tự của y_proba)
        # Ví dụ: model_classes_learned = [0, 2, 3, 9]
        model_classes_learned = models[0].classes_ 
        
        # Khai báo ánh xạ đầy đủ (để tra cứu tên)
        cic_mapping_full = {
            0: 'BENIGN', 1: 'DoS Hulk', 2: 'PortScan', 3: 'DDoS', 4: 'DoS GoldenEye',
            5: 'FTP-Patator', 6: 'SSH-Patator', 7: 'DoS slowloris', 8: 'DoS Slowhttptest', 
            9: 'Bot', 10: 'Web Attack - Brute Force', 11: 'Web Attack - XSS', 
            12: 'Web Attack - SQL Injection', 13: 'Infiltration', 14: 'Heartbleed'
        }

        self.label_names = {}
        
        # Lặp qua vị trí chỉ mục (0, 1, 2, 3) và tìm nhãn số thực tế
        for idx, class_id_learned in enumerate(model_classes_learned):
            name = cic_mapping_full.get(class_id_learned, f'Class_{class_id_learned}')
            self.label_names[class_id_learned] = name
            if not hasattr(self, 'report_target_names'):
                self.report_target_names = {}
            
            self.report_target_names[idx] = name 

        print(f"[*] Label mapping derived from model classes ({len(self.label_names)} classes):")
        for k, v in self.label_names.items():
            print(f"    {k} → {v}")
        print(f"[*] Report Index Mapping: {self.report_target_names}")

        # For binary classification
        self.binary_label_names = {0: 'BENIGN', 1: 'ATTACK'}
    def _predict_proba_ensemble(self, X):
        """
        Get ensemble probability predictions (average of 3 models)
        
        Returns:
            Array of shape (n_samples, n_classes)
        """
        X_np = X.values if isinstance(X, pd.DataFrame) else X
        
        # Get probabilities from each model
        probs = np.array([model.predict_proba(X_np) for model in self.models])
        
        # Average probabilities
        avg_probs = np.mean(probs, axis=0)
        
        return avg_probs
    
    def _predict_ensemble(self, X, threshold=0.5):
        """
        Ensemble prediction với custom threshold (for binary)
        
        For multiclass: use majority voting
        For binary: use threshold on probability
        """
        X_np = X.values if isinstance(X, pd.DataFrame) else X
        
        # Get predictions from each model
        preds = np.array([model.predict(X_np) for model in self.models])
        
        # Majority voting
        maj_vote = np.apply_along_axis(
            lambda x: np.bincount(x).argmax(),
            axis=0,
            arr=preds
        )
        
        return maj_vote
    
    def evaluate_basic_metrics(self, X, y, dataset_name='Dataset'):
        """
        Evaluate basic classification metrics
        """
        print(f"\n{'='*60}")
        print(f"BASIC METRICS - {dataset_name}")
        print(f"{'='*60}")
        
        y_true = y.values if isinstance(y, pd.Series) else y
        y_pred = self._predict_ensemble(X)
        y_proba = self._predict_proba_ensemble(X)
        roc_auc = None
        # Basic metrics
        accuracy = accuracy_score(y_true, y_pred)
        
        # Multiclass metrics
        precision_macro = precision_score(y_true, y_pred, average='macro', zero_division=0)
        recall_macro = recall_score(y_true, y_pred, average='macro', zero_division=0)
        f1_macro = f1_score(y_true, y_pred, average='macro', zero_division=0)
        
        precision_weighted = precision_score(y_true, y_pred, average='weighted', zero_division=0)
        recall_weighted = recall_score(y_true, y_pred, average='weighted', zero_division=0)
        f1_weighted = f1_score(y_true, y_pred, average='weighted', zero_division=0)
        
        print(f"\n[*] Overall Metrics:")
        print(f"    Accuracy:              {accuracy:.4f}")
        print(f"    Precision (macro):   {precision_macro:.4f}")
        print(f"    Recall (macro):        {recall_macro:.4f}")
        print(f"    F1-Score (macro):    {f1_macro:.4f}")
        print(f"    Precision (weighted): {precision_weighted:.4f}")
        print(f"    Recall (weighted):    {recall_weighted:.4f}")
        print(f"    F1-Score (weighted):  {f1_weighted:.4f}")
        
        # ⚠️ FIX: Tính toán tất cả metrics per-class cùng lúc
        precision_per_class, recall_per_class, f1_per_class, support = precision_recall_fscore_support(
            y_true, y_pred, average=None, zero_division=0
        )
        
        # Lấy các nhãn số thực tế đã được LGBM sắp xếp
        model_classes_learned = self.models[0].classes_
        
        # 2. FIX: Per-Class Metrics (Hiển thị tên lớp đúng)
        print(f"\n[*] Per-Class Metrics:")
        
        # Lặp qua các chỉ mục (0, 1, 2, 3) của mảng Metrics
        for idx in range(len(precision_per_class)):
            # Nhãn số thực tế (0, 2, 3, hoặc 9)
            class_id = model_classes_learned[idx] 
            
            # Tên nhãn đã được ánh xạ (BENIGN, PortScan, DDoS, Bot)
            class_name = self.label_names.get(class_id, f'Class_{class_id}')
            
            # Lấy Support và Metrics theo index
            current_support = support[idx] # <-- Đã fix lỗi NameError cho support
            
            # In ra metrics
            print(f"    {class_name:25s}: P={precision_per_class[idx]:.4f}, "
                f"R={recall_per_class[idx]:.4f}, F1={f1_per_class[idx]:.4f}, "
                f"Support={current_support}")
        
        # Confusion Matrix
        cm = confusion_matrix(y_true, y_pred)
        
        # ... (Phần ROC-AUC, FPR giữ nguyên) ...
        tn = cm[0, 0]
        fp = cm[0, 1:].sum()
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
        
        print(f"\n[*] NIDS-Specific Metrics:")
        print(f"    False Positive Rate: {fpr:.4f} ({fpr*100:.2f}%)")
        print(f"    True Negatives:      {tn}")
        print(f"    False Positives:     {fp}")
        
        # 3. FIX: Classification Report (Sử dụng ánh xạ đúng)
        print(f"\n[*] Classification Report:")
        target_names = [self.label_names.get(cid, f'Class_{cid}') 
                        for cid in model_classes_learned]
        print(classification_report(y_true, y_pred, target_names=target_names, zero_division=0))
        
        # ... (Phần return giữ nguyên) ...
        
        return {
            'accuracy': accuracy,
            'precision_macro': precision_macro,
            'recall_macro': recall_macro,
            'f1_macro': f1_macro,
            'precision_weighted': precision_weighted,
            'recall_weighted': recall_weighted,
            'f1_weighted': f1_weighted,
            'roc_auc': roc_auc,
            'fpr': fpr,
            'confusion_matrix': cm,
            'y_true': y_true,
            'y_pred': y_pred,
            'y_proba': y_proba
        }
    
    def compare_train_test_overfitting(self, X_train, y_train, X_test, y_test):
        """
        So sánh performance trên train vs test để detect overfitting
        """
        print(f"\n{'='*60}")
        print("OVERFITTING DETECTION: TRAIN vs TEST")
        print(f"{'='*60}")
        
        # Evaluate on train
        train_metrics = self.evaluate_basic_metrics(X_train, y_train, 'TRAIN SET')
        
        # Evaluate on test
        test_metrics = self.evaluate_basic_metrics(X_test, y_test, 'TEST SET')
        
        # Compare
        print(f"\n{'='*60}")
        print("COMPARISON: TRAIN vs TEST")
        print(f"{'='*60}")
        
        metrics_to_compare = [
            ('Accuracy', 'accuracy'),
            ('Precision (macro)', 'precision_macro'),
            ('Recall (macro)', 'recall_macro'),
            ('F1 (macro)', 'f1_macro'),
            ('ROC-AUC', 'roc_auc'),
            ('FPR', 'fpr')
        ]
        
        comparison = []
        
        for metric_name, key in metrics_to_compare:
            train_val = train_metrics.get(key)
            test_val = test_metrics.get(key)
            
            if train_val is not None and test_val is not None:
                gap = train_val - test_val
                gap_pct = (gap / train_val * 100) if train_val != 0 else 0
                
                # Overfitting warning
                warning = ""
                if key == 'fpr':
                    # Lower is better for FPR
                    if test_val > train_val * 1.5:
                        warning = "⚠️ HIGH GAP"
                else:
                    # Higher is better for other metrics
                    if gap > 0.05 or gap_pct > 10:
                        warning = "⚠️ OVERFITTING"
                
                comparison.append({
                    'metric': metric_name,
                    'train': train_val,
                    'test': test_val,
                    'gap': gap,
                    'gap_pct': gap_pct,
                    'warning': warning
                })
                
                print(f"{metric_name:20s}: Train={train_val:.4f}, Test={test_val:.4f}, "
                      f"Gap={gap:+.4f} ({gap_pct:+.1f}%) {warning}")
        
        # Save comparison
        comparison_df = pd.DataFrame(comparison)
        comparison_path = self.output_dir / 'train_test_comparison.csv'
        comparison_df.to_csv(comparison_path, index=False)
        print(f"\n[✓] Saved comparison to {comparison_path}")
        
        # Visualization
        self._plot_train_test_comparison(comparison_df)
        
        return train_metrics, test_metrics, comparison_df
    
    def _plot_train_test_comparison(self, comparison_df):
        """Plot train vs test metrics"""
        fig, ax = plt.subplots(figsize=(12, 6))
        
        metrics = comparison_df['metric'].values
        train_vals = comparison_df['train'].values
        test_vals = comparison_df['test'].values
        
        x = np.arange(len(metrics))
        width = 0.35
        
        ax.bar(x - width/2, train_vals, width, label='Train', alpha=0.8)
        ax.bar(x + width/2, test_vals, width, label='Test', alpha=0.8)
        
        ax.set_xlabel('Metrics')
        ax.set_ylabel('Score')
        ax.set_title('Train vs Test Performance')
        ax.set_xticks(x)
        ax.set_xticklabels(metrics, rotation=45, ha='right')
        ax.legend()
        ax.grid(axis='y', alpha=0.3)
        
        plt.tight_layout()
        plot_path = self.output_dir / 'train_test_comparison.png'
        plt.savefig(plot_path, dpi=150, bbox_inches='tight')
        print(f"[✓] Saved plot to {plot_path}")
        plt.close()
    
    def threshold_optimization(self, X, y, thresholds=np.arange(0.5, 0.95, 0.05)):
        """
        Test với các threshold khác nhau (for binary attack detection)
        
        Convert multiclass to binary: 0=BENIGN, 1=ATTACK
        """
        print(f"\n{'='*60}")
        print("THRESHOLD OPTIMIZATION")
        print(f"{'='*60}")
        
        y_true = y.values if isinstance(y, pd.Series) else y
        
        # Convert to binary
        y_true_binary = (y_true > 0).astype(int)  # 0=BENIGN, >0=ATTACK
        
        # Get probabilities
        y_proba = self._predict_proba_ensemble(X)
        
        # Probability of attack (sum of all attack classes)
        y_proba_attack = 1 - y_proba[:, 0]  # 1 - P(BENIGN)
        
        results = []
        
        print(f"\n[*] Testing thresholds: {thresholds}")
        print(f"\nThreshold  | Accuracy | Precision | Recall  | F1-Score | FPR")
        print("-" * 70)
        
        for threshold in thresholds:
            # Predict with threshold
            y_pred_binary = (y_proba_attack >= threshold).astype(int)
            
            # Calculate metrics
            acc = accuracy_score(y_true_binary, y_pred_binary)
            prec = precision_score(y_true_binary, y_pred_binary, zero_division=0)
            rec = recall_score(y_true_binary, y_pred_binary, zero_division=0)
            f1 = f1_score(y_true_binary, y_pred_binary, zero_division=0)
            
            # FPR
            cm = confusion_matrix(y_true_binary, y_pred_binary)
            tn, fp = cm[0, 0], cm[0, 1]
            fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
            
            results.append({
                'threshold': threshold,
                'accuracy': acc,
                'precision': prec,
                'recall': rec,
                'f1': f1,
                'fpr': fpr
            })
            
            print(f"{threshold:.2f}       | {acc:.4f}   | {prec:.4f}    | {rec:.4f}  | {f1:.4f}   | {fpr:.4f}")
        
        results_df = pd.DataFrame(results)
        
        # Find optimal threshold (maximize F1, minimize FPR)
        # Composite score: F1 - FPR
        results_df['composite_score'] = results_df['f1'] - results_df['fpr']
        best_idx = results_df['composite_score'].idxmax()
        best_threshold = results_df.loc[best_idx, 'threshold']
        
        print(f"\n[✓] Optimal threshold: {best_threshold:.2f}")
        print(f"    F1-Score: {results_df.loc[best_idx, 'f1']:.4f}")
        print(f"    FPR:      {results_df.loc[best_idx, 'fpr']:.4f}")
        
        # Save results
        results_path = self.output_dir / 'threshold_optimization.csv'
        results_df.to_csv(results_path, index=False)
        print(f"\n[✓] Saved results to {results_path}")
        
        # Plot
        self._plot_threshold_optimization(results_df)
        
        return results_df, best_threshold
    
    def _plot_threshold_optimization(self, results_df):
        """Plot threshold optimization results"""
        fig, axes = plt.subplots(2, 2, figsize=(14, 10))
        
        thresholds = results_df['threshold']
        
        # Plot 1: Accuracy, Precision, Recall, F1
        ax = axes[0, 0]
        ax.plot(thresholds, results_df['accuracy'], 'o-', label='Accuracy', linewidth=2)
        ax.plot(thresholds, results_df['precision'], 's-', label='Precision', linewidth=2)
        ax.plot(thresholds, results_df['recall'], '^-', label='Recall', linewidth=2)
        ax.plot(thresholds, results_df['f1'], 'd-', label='F1-Score', linewidth=2)
        ax.set_xlabel('Threshold')
        ax.set_ylabel('Score')
        ax.set_title('Metrics vs Threshold')
        ax.legend()
        ax.grid(alpha=0.3)
        
        # Plot 2: FPR
        ax = axes[0, 1]
        ax.plot(thresholds, results_df['fpr'], 'o-', color='red', linewidth=2)
        ax.set_xlabel('Threshold')
        ax.set_ylabel('False Positive Rate')
        ax.set_title('FPR vs Threshold (Lower is Better)')
        ax.grid(alpha=0.3)
        
        # Plot 3: Precision-Recall tradeoff
        ax = axes[1, 0]
        ax.plot(results_df['recall'], results_df['precision'], 'o-', linewidth=2)
        for i, thresh in enumerate(thresholds):
            if i % 2 == 0:  # Annotate every other point
                ax.annotate(f'{thresh:.2f}', 
                           (results_df['recall'].iloc[i], results_df['precision'].iloc[i]),
                           fontsize=8)
        ax.set_xlabel('Recall')
        ax.set_ylabel('Precision')
        ax.set_title('Precision-Recall Curve')
        ax.grid(alpha=0.3)
        
        # Plot 4: Composite score
        ax = axes[1, 1]
        ax.plot(thresholds, results_df['composite_score'], 'o-', linewidth=2, color='green')
        best_idx = results_df['composite_score'].idxmax()
        ax.axvline(results_df['threshold'].iloc[best_idx], 
                   color='red', linestyle='--', label='Optimal')
        ax.set_xlabel('Threshold')
        ax.set_ylabel('Composite Score (F1 - FPR)')
        ax.set_title('Composite Score vs Threshold')
        ax.legend()
        ax.grid(alpha=0.3)
        
        plt.tight_layout()
        plot_path = self.output_dir / 'threshold_optimization.png'
        plt.savefig(plot_path, dpi=150, bbox_inches='tight')
        print(f"[✓] Saved plot to {plot_path}")
        plt.close()
    
    def explain_with_shap(self, X_sample, sample_size=100):
        """
        Explain model decisions using SHAP
        
        Args:
            X_sample: Sample data for explanation
            sample_size: Number of samples to explain
        """
        print(f"\n{'='*60}")
        print("SHAP EXPLANATION")
        print(f"{'='*60}")
        
        X_np = X_sample.values if isinstance(X_sample, pd.DataFrame) else X_sample
        
        # Use first model for SHAP (representative)
        model = self.models[0]
        
        # Sample data
        if len(X_np) > sample_size:
            indices = np.random.choice(len(X_np), sample_size, replace=False)
            X_explain = X_np[indices]
        else:
            X_explain = X_np
        
        print(f"[*] Explaining {len(X_explain)} samples...")
        print(f"[*] X_explain shape: {X_explain.shape}")
        print(f"[*] Number of features: {len(self.feature_names)}")
        
        # Create SHAP explainer
        # Use TreeExplainer for LightGBM
        explainer = shap.TreeExplainer(model)
        
        # Calculate SHAP values
        print("[*] Calculating SHAP values...")
        shap_values = explainer.shap_values(X_explain)
        
        # SHAP values shape: (n_classes, n_samples, n_features) for multiclass
        # Or (n_samples, n_features) for binary
        
        print(f"[✓] SHAP values calculated. Shape: {np.array(shap_values).shape}")
        
        # Plot 1: Summary plot (all classes)
        print("[*] Generating SHAP summary plot...")
        plt.figure(figsize=(12, 8))
        
        if isinstance(shap_values, list):  # Multiclass
            # Plot for class 0 (BENIGN) vs rest
            shap.summary_plot(
                shap_values[1],  # Attack class (or any non-benign)
                X_explain,
                feature_names=self.feature_names,
                show=False,
                max_display=20
            )
        else:  # Binary
            shap.summary_plot(
                shap_values,
                X_explain,
                feature_names=self.feature_names,
                show=False,
                max_display=20
            )
        
        plt.tight_layout()
        summary_path = self.output_dir / 'shap_summary_plot.png'
        plt.savefig(summary_path, dpi=150, bbox_inches='tight')
        print(f"[✓] Saved SHAP summary plot to {summary_path}")
        plt.close()
        
        # Plot 2: Feature importance (mean absolute SHAP)
        print("[*] Generating SHAP feature importance...")
        
        if isinstance(shap_values, list):
            # List of arrays, each (n_samples, n_features) for each class
            # Average across classes and samples
            shap_mean = np.mean([np.abs(sv).mean(axis=0) for sv in shap_values], axis=0)
        else:
            # Single array
            # Check shape
            if shap_values.ndim == 3:
                # Shape: (n_samples, n_features, n_classes)
                # Average across samples and classes
                shap_mean = np.abs(shap_values).mean(axis=(0, 2))
            elif shap_values.ndim == 2:
                # Shape: (n_samples, n_features)
                # Average across samples only
                shap_mean = np.abs(shap_values).mean(axis=0)
            else:
                raise ValueError(f"Unexpected SHAP values shape: {shap_values.shape}")
        
        print(f"[*] shap_mean shape after processing: {shap_mean.shape}")
        print(f"[*] feature_names length: {len(self.feature_names)}")
        
        # FIX: Ensure 1D array
        if shap_mean.ndim > 1:
            print(f"[!] WARNING: shap_mean is {shap_mean.ndim}D, flattening by averaging...")
            shap_mean = shap_mean.mean(axis=tuple(range(1, shap_mean.ndim)))
        
        # Ensure same length
        min_length = min(len(self.feature_names), len(shap_mean))
        
        if len(self.feature_names) != len(shap_mean):
            print(f"[!] WARNING: Feature names ({len(self.feature_names)}) and SHAP values ({len(shap_mean)}) length mismatch!")
            print(f"[!] Using first {min_length} features only.")
        
        importance_df = pd.DataFrame({
            'feature': self.feature_names[:min_length],
            'importance': shap_mean[:min_length]
        }).sort_values('importance', ascending=False)
        
        # Plot top 20
        plt.figure(figsize=(10, 8))
        top_features = importance_df.head(20)
        plt.barh(range(len(top_features)), top_features['importance'])
        plt.yticks(range(len(top_features)), top_features['feature'])
        plt.xlabel('Mean |SHAP value|')
        plt.title('Top 20 Feature Importances (SHAP)')
        plt.gca().invert_yaxis()
        plt.tight_layout()
        
        importance_path = self.output_dir / 'shap_feature_importance.png'
        plt.savefig(importance_path, dpi=150, bbox_inches='tight')
        print(f"[✓] Saved SHAP importance to {importance_path}")
        plt.close()
        
        # Save importance
        importance_csv = self.output_dir / 'shap_feature_importance.csv'
        importance_df.to_csv(importance_csv, index=False)
        
        print(f"\n[*] Top 10 Important Features (SHAP):")
        for idx, row in importance_df.head(10).iterrows():
            print(f"    {row['feature']:30s}: {row['importance']:.4f}")
        
        return shap_values, importance_df
    
    def explain_with_lime(self, X_sample, y_sample, n_samples=5):
        """
        Explain individual predictions using LIME
        
        Args:
            X_sample: Sample data
            y_sample: True labels
            n_samples: Number of samples to explain
        """
        print(f"\n{'='*60}")
        print("LIME EXPLANATION")
        print(f"{'='*60}")
        
        X_np = X_sample.values if isinstance(X_sample, pd.DataFrame) else X_sample
        y_np = y_sample.values if isinstance(y_sample, pd.Series) else y_sample
        
        # Sample data
        indices = np.random.choice(len(X_np), min(n_samples, len(X_np)), replace=False)
        
        # Get number of classes from model
        n_classes = len(self.models[0].classes_)
        
        # Create LIME explainer
        explainer = lime_tabular.LimeTabularExplainer(
            X_np,
            feature_names=self.feature_names,
            class_names=[self.label_names.get(i, f'Class_{i}') for i in range(n_classes)],
            mode='classification',
            random_state=42
        )
        
        print(f"[*] Explaining {len(indices)} individual samples...")
        
        # Prediction function (ensemble average)
        def predict_fn(X):
            return self._predict_proba_ensemble(X)
        
        # Explain each sample
        explanations = []
        
        for i, idx in enumerate(indices):
            sample = X_np[idx]
            true_label = int(y_np[idx])  # Convert to Python int
            pred_label = int(self._predict_ensemble(sample.reshape(1, -1))[0])  # Convert to Python int
            
            print(f"\n[*] Sample {i+1}/{len(indices)}:")
            print(f"    True label: {self.label_names.get(true_label, true_label)}")
            print(f"    Predicted:  {self.label_names.get(pred_label, pred_label)}")
            
            try:
                # Generate explanation
                exp = explainer.explain_instance(
                    sample,
                    predict_fn,
                    num_features=10,
                    top_labels=min(3, n_classes)  # Don't ask for more labels than we have
                )
                
                explanations.append(exp)
                
                # Check if explanation exists for predicted label
                if pred_label not in exp.local_exp:
                    print(f"    [!] WARNING: No explanation for predicted label {pred_label}")
                    print(f"    Available labels in explanation: {list(exp.local_exp.keys())}")
                    # Use the first available label
                    if len(exp.local_exp) > 0:
                        pred_label = list(exp.local_exp.keys())[0]
                        print(f"    Using label {pred_label} instead")
                    else:
                        print(f"    [!] Skipping visualization for this sample")
                        continue
                
                # Save visualization
                fig = exp.as_pyplot_figure(label=pred_label)
                plt.tight_layout()
                lime_path = self.output_dir / f'lime_sample_{i+1}.png'
                plt.savefig(lime_path, dpi=150, bbox_inches='tight')
                print(f"    [✓] Saved LIME plot to {lime_path}")
                plt.close()
                
                # Print top features
                print(f"    Top features:")
                feature_weights = exp.as_list(label=pred_label)[:5]
                for feature, weight in feature_weights:
                    direction = "→ ATTACK" if weight > 0 else "→ BENIGN"
                    print(f"      {feature:40s}: {weight:+.4f} {direction}")
                    
            except Exception as e:
                print(f"    [!] ERROR explaining sample: {e}")
                print(f"    Skipping this sample...")
                continue
        
        print(f"\n[✓] Successfully explained {len(explanations)} samples")
        
        return explanations
    
    def generate_full_report(self, X_train, y_train, X_test, y_test):
        """
        Generate comprehensive evaluation report
        """
        print("\n" + "="*60)
        print("GENERATING COMPREHENSIVE EVALUATION REPORT")
        print("="*60)
        
        report = {}
        
        # 1. Train vs Test comparison
        print("\n[1/4] Comparing Train vs Test...")
        train_metrics, test_metrics, comparison = self.compare_train_test_overfitting(
            X_train, y_train, X_test, y_test
        )
        report['train_metrics'] = train_metrics
        report['test_metrics'] = test_metrics
        
        # 2. Threshold optimization
        print("\n[2/4] Optimizing threshold...")
        threshold_results, best_threshold = self.threshold_optimization(X_test, y_test)
        report['threshold_results'] = threshold_results
        report['best_threshold'] = best_threshold
        
        # 3. SHAP explanation
        print("\n[3/4] Generating SHAP explanations...")
        shap_values, shap_importance = self.explain_with_shap(X_test, sample_size=100)
        report['shap_importance'] = shap_importance
        
        # 4. LIME explanation
        print("\n[4/4] Generating LIME explanations...")
        lime_explanations = self.explain_with_lime(X_test, y_test, n_samples=5)
        
        # Save report summary
        summary = {
            'test_accuracy': float(test_metrics['accuracy']),
            'test_f1': float(test_metrics['f1_weighted']),
            'test_fpr': float(test_metrics['fpr']),
            'best_threshold': float(best_threshold),
            'top_10_features': shap_importance.head(10).to_dict('records')
        }
        
        summary_path = self.output_dir / 'evaluation_summary.json'
        with open(summary_path, 'w') as f:
            json.dump(summary, f, indent=2)
        
        print(f"\n{'='*60}")
        print("EVALUATION COMPLETE!")
        print(f"{'='*60}")
        print(f"Results saved to: {self.output_dir}")
        print(f"\nKey Findings:")
        print(f"  Test Accuracy: {summary['test_accuracy']:.4f}")
        print(f"  Test F1-Score: {summary['test_f1']:.4f}")
        print(f"  False Positive Rate: {summary['test_fpr']:.4f}")
        print(f"  Optimal Threshold: {summary['best_threshold']:.2f}")
        
        return report
    
def load_and_split_data(data_path, metadata_path, test_ratio=0.2):
    """Tải dữ liệu và chia thành Train Pool và Test Set (cho Evaluation)"""
    df = pd.read_parquet(data_path)
    
    with open(metadata_path, 'r') as f:
        metadata = json.load(f)
        
    feature_names = metadata['feature_names']
    
    # Clean data
    X = df[feature_names].copy()
    y = df['label'].copy()
    X.replace([np.inf, -np.inf], 0, inplace=True)
    X.fillna(0, inplace=True)
    
    # Tách Test Set cuối cùng
    X_pool, X_test, y_pool, y_test = train_test_split(
        X, y, test_size=test_ratio, random_state=42, stratify=y
    )
    
    # Tập Train Pool này chứa dữ liệu dùng để fit mô hình. Ta dùng nó để kiểm tra Overfitting.
    return X_pool, y_pool, X_test, y_test, feature_names

if __name__ == "__main__":
    import sys
    
    # Paths
    MODEL_PATH = './models/nids_tri_lgbm_v1.joblib'
    METADATA_PATH = './models/nids_tri_lgbm_v1_metadata.json' 
    DATASET_PATH = './CIC-IDS-2017/featured_dataset.parquet'
    SCHEMA_PATH = './CIC-IDS-2017/feature_schema.json'
    OUTPUT_DIR = './evaluation_results'
    
    # Check files
    if not Path(MODEL_PATH).exists():
        print(f"[✗] Model not found: {MODEL_PATH}")
        sys.exit(1)
    
    if not Path(METADATA_PATH).exists():
        print(f"[✗] Metadata not found: {METADATA_PATH}")
        sys.exit(1)
        
    print("[*] Loading models and data...")
    
    # Load models
    models = joblib.load(MODEL_PATH)
    
    # Load và chia dữ liệu
    X_train_pool, y_train_pool, X_test, y_test, FEATURE_NAMES = load_and_split_data(
        DATASET_PATH, METADATA_PATH, test_ratio=0.2
    )

    # Initialize evaluator
    evaluator = NIDSModelEvaluator(
        models=models, 
        feature_names=FEATURE_NAMES, 
        output_dir=OUTPUT_DIR
    )
    
    # Generate Report
    report = evaluator.generate_full_report(
        X_train=X_train_pool, 
        y_train=y_train_pool, 
        X_test=X_test, 
        y_test=y_test
    )
    
    print("\n[✓] All evaluation processes completed.")