#!/usr/bin/env python3
"""
Comprehensive Model Evaluation cho NIDS
- LGBM Ensemble: Multiclass classification
- Isolation Forest: Zero-day & Anomaly detection
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
    roc_auc_score, roc_curve, auc,
    confusion_matrix, classification_report,
    precision_recall_curve, average_precision_score,
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
        self.models = models
        self.feature_names = feature_names
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        model_classes_learned = models[0].classes_ 
        
        cic_mapping_full = {
            0: 'BENIGN', 1: 'DoS Hulk', 2: 'PortScan', 3: 'DDoS', 4: 'DoS GoldenEye',
            5: 'FTP-Patator', 6: 'SSH-Patator', 7: 'DoS slowloris', 8: 'DoS Slowhttptest', 
            9: 'Bot', 10: 'Web Attack - Brute Force', 11: 'Web Attack - XSS', 
            12: 'Web Attack - SQL Injection', 13: 'Infiltration', 14: 'Heartbleed'
        }

        self.label_names = {}
        
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

        self.binary_label_names = {0: 'BENIGN', 1: 'ATTACK'}
    
    def _predict_proba_ensemble(self, X):
        """Get ensemble probability predictions (average of 3 models)"""
        X_np = X.values if isinstance(X, pd.DataFrame) else X
        probs = np.array([model.predict_proba(X_np) for model in self.models])
        avg_probs = np.mean(probs, axis=0)
        return avg_probs
    
    def _predict_ensemble(self, X, threshold=0.5):
        """Ensemble prediction with majority voting"""
        X_np = X.values if isinstance(X, pd.DataFrame) else X
        preds = np.array([model.predict(X_np) for model in self.models])
        maj_vote = np.apply_along_axis(
            lambda x: np.bincount(x).argmax(),
            axis=0,
            arr=preds
        )
        return maj_vote
    
    def evaluate_basic_metrics(self, X, y, dataset_name='Dataset'):
        """Evaluate basic classification metrics"""
        print(f"\n{'='*60}")
        print(f"BASIC METRICS - {dataset_name}")
        print(f"{'='*60}")
        
        y_true = y.values if isinstance(y, pd.Series) else y
        y_pred = self._predict_ensemble(X)
        y_proba = self._predict_proba_ensemble(X)
        roc_auc = None
        
        accuracy = accuracy_score(y_true, y_pred)
        
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
        
        precision_per_class, recall_per_class, f1_per_class, support = precision_recall_fscore_support(
            y_true, y_pred, average=None, zero_division=0
        )
        
        model_classes_learned = self.models[0].classes_
        
        print(f"\n[*] Per-Class Metrics:")
        
        for idx in range(len(precision_per_class)):
            class_id = model_classes_learned[idx] 
            class_name = self.label_names.get(class_id, f'Class_{class_id}')
            current_support = support[idx]
            
            print(f"    {class_name:25s}: P={precision_per_class[idx]:.4f}, "
                f"R={recall_per_class[idx]:.4f}, F1={f1_per_class[idx]:.4f}, "
                f"Support={current_support}")
        
        cm = confusion_matrix(y_true, y_pred)
        
        tn = cm[0, 0]
        fp = cm[0, 1:].sum()
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
        
        print(f"\n[*] NIDS-Specific Metrics:")
        print(f"    False Positive Rate: {fpr:.4f} ({fpr*100:.2f}%)")
        print(f"    True Negatives:      {tn}")
        print(f"    False Positives:     {fp}")
        
        print(f"\n[*] Classification Report:")
        target_names = [self.label_names.get(cid, f'Class_{cid}') 
                        for cid in model_classes_learned]
        print(classification_report(y_true, y_pred, target_names=target_names, digits=4, zero_division=0))
        
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
        """So sánh performance trên train vs test để detect overfitting"""
        print(f"\n{'='*60}")
        print("OVERFITTING DETECTION: TRAIN vs TEST")
        print(f"{'='*60}")
        
        train_metrics = self.evaluate_basic_metrics(X_train, y_train, 'TRAIN SET')
        test_metrics = self.evaluate_basic_metrics(X_test, y_test, 'TEST SET')
        
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
                
                warning = ""
                if key == 'fpr':
                    if test_val > train_val * 1.5:
                        warning = "⚠️ HIGH GAP"
                else:
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
        
        comparison_df = pd.DataFrame(comparison)
        comparison_path = self.output_dir / 'train_test_comparison.csv'
        comparison_df.to_csv(comparison_path, index=False)
        print(f"\n[✓] Saved comparison to {comparison_path}")
        
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
        """Test với các threshold khác nhau (for binary attack detection)"""
        print(f"\n{'='*60}")
        print("THRESHOLD OPTIMIZATION")
        print(f"{'='*60}")
        
        y_true = y.values if isinstance(y, pd.Series) else y
        y_true_binary = (y_true > 0).astype(int)
        
        y_proba = self._predict_proba_ensemble(X)
        y_proba_attack = 1 - y_proba[:, 0]
        
        results = []
        
        print(f"\n[*] Testing thresholds: {thresholds}")
        print(f"\nThreshold  | Accuracy | Precision | Recall  | F1-Score | FPR")
        print("-" * 70)
        
        for threshold in thresholds:
            y_pred_binary = (y_proba_attack >= threshold).astype(int)
            
            acc = accuracy_score(y_true_binary, y_pred_binary)
            prec = precision_score(y_true_binary, y_pred_binary, zero_division=0)
            rec = recall_score(y_true_binary, y_pred_binary, zero_division=0)
            f1 = f1_score(y_true_binary, y_pred_binary, zero_division=0)
            
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
        results_df['composite_score'] = results_df['f1'] - results_df['fpr']
        best_idx = results_df['composite_score'].idxmax()
        best_threshold = results_df.loc[best_idx, 'threshold']
        
        print(f"\n[✓] Optimal threshold: {best_threshold:.2f}")
        print(f"    F1-Score: {results_df.loc[best_idx, 'f1']:.4f}")
        print(f"    FPR:      {results_df.loc[best_idx, 'fpr']:.4f}")
        
        results_path = self.output_dir / 'threshold_optimization.csv'
        results_df.to_csv(results_path, index=False)
        print(f"\n[✓] Saved results to {results_path}")
        
        self._plot_threshold_optimization(results_df)
        
        return results_df, best_threshold
    
    def _plot_threshold_optimization(self, results_df):
        """Plot threshold optimization results"""
        fig, axes = plt.subplots(2, 2, figsize=(14, 10))
        
        thresholds = results_df['threshold']
        
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
        
        ax = axes[0, 1]
        ax.plot(thresholds, results_df['fpr'], 'o-', color='red', linewidth=2)
        ax.set_xlabel('Threshold')
        ax.set_ylabel('False Positive Rate')
        ax.set_title('FPR vs Threshold (Lower is Better)')
        ax.grid(alpha=0.3)
        
        ax = axes[1, 0]
        ax.plot(results_df['recall'], results_df['precision'], 'o-', linewidth=2)
        for i, thresh in enumerate(thresholds):
            if i % 2 == 0:
                ax.annotate(f'{thresh:.2f}', 
                           (results_df['recall'].iloc[i], results_df['precision'].iloc[i]),
                           fontsize=8)
        ax.set_xlabel('Recall')
        ax.set_ylabel('Precision')
        ax.set_title('Precision-Recall Curve')
        ax.grid(alpha=0.3)
        
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
        """Explain model decisions using SHAP"""
        print(f"\n{'='*60}")
        print("SHAP EXPLANATION")
        print(f"{'='*60}")
        
        X_np = X_sample.values if isinstance(X_sample, pd.DataFrame) else X_sample
        model = self.models[0]
        
        if len(X_np) > sample_size:
            indices = np.random.choice(len(X_np), sample_size, replace=False)
            X_explain = X_np[indices]
        else:
            X_explain = X_np
        
        print(f"[*] Explaining {len(X_explain)} samples...")
        print(f"[*] X_explain shape: {X_explain.shape}")
        print(f"[*] Number of features: {len(self.feature_names)}")
        
        explainer = shap.TreeExplainer(model)
        
        print("[*] Calculating SHAP values...")
        shap_values = explainer.shap_values(X_explain)
        
        print(f"[✓] SHAP values calculated. Shape: {np.array(shap_values).shape}")
        
        print("[*] Generating SHAP summary plot...")
        plt.figure(figsize=(12, 8))
        
        if isinstance(shap_values, list):
            shap.summary_plot(
                shap_values[1],
                X_explain,
                feature_names=self.feature_names,
                show=False,
                max_display=20
            )
        else:
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
        
        print("[*] Generating SHAP feature importance...")
        
        if isinstance(shap_values, list):
            shap_mean = np.mean([np.abs(sv).mean(axis=0) for sv in shap_values], axis=0)
        else:
            if shap_values.ndim == 3:
                shap_mean = np.abs(shap_values).mean(axis=(0, 2))
            elif shap_values.ndim == 2:
                shap_mean = np.abs(shap_values).mean(axis=0)
            else:
                raise ValueError(f"Unexpected SHAP values shape: {shap_values.shape}")
        
        print(f"[*] shap_mean shape after processing: {shap_mean.shape}")
        print(f"[*] feature_names length: {len(self.feature_names)}")
        
        if shap_mean.ndim > 1:
            print(f"[!] WARNING: shap_mean is {shap_mean.ndim}D, flattening by averaging...")
            shap_mean = shap_mean.mean(axis=tuple(range(1, shap_mean.ndim)))
        
        min_length = min(len(self.feature_names), len(shap_mean))
        
        if len(self.feature_names) != len(shap_mean):
            print(f"[!] WARNING: Feature names ({len(self.feature_names)}) and SHAP values ({len(shap_mean)}) length mismatch!")
            print(f"[!] Using first {min_length} features only.")
        
        importance_df = pd.DataFrame({
            'feature': self.feature_names[:min_length],
            'importance': shap_mean[:min_length]
        }).sort_values('importance', ascending=False)
        
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
        
        importance_csv = self.output_dir / 'shap_feature_importance.csv'
        importance_df.to_csv(importance_csv, index=False)
        
        print(f"\n[*] Top 10 Important Features (SHAP):")
        for idx, row in importance_df.head(10).iterrows():
            print(f"    {row['feature']:30s}: {row['importance']:.4f}")
        
        return shap_values, importance_df
    
    def explain_with_lime(self, X_sample, y_sample, n_samples=5):
        print(f"\n{'='*60}")
        print("LIME EXPLANATION")
        print(f"{'='*60}")
        
        X_np = X_sample.values if isinstance(X_sample, pd.DataFrame) else X_sample
        y_np = y_sample.values if isinstance(y_sample, pd.Series) else y_sample
        
        model_classes = self.models[0].classes_
        
        indices = np.random.choice(len(X_np), min(n_samples, len(X_np)), replace=False)
        
        explainer = lime_tabular.LimeTabularExplainer(
            X_np,
            feature_names=self.feature_names,
            class_names=[self.label_names.get(i, f'Class_{i}') for i in model_classes],
            mode='classification',
            random_state=42
        )
        
        def predict_fn(X):
            return self._predict_proba_ensemble(X)
        
        explanations = []
        
        for i, idx in enumerate(indices):
            sample = X_np[idx]
            true_label_raw = int(y_np[idx])
            pred_label_raw = int(self._predict_ensemble(sample.reshape(1, -1))[0])
            
            try:
                pred_label_idx = np.where(model_classes == pred_label_raw)[0][0]
            except IndexError:
                continue

            print(f"\n[*] Sample {i+1}/{len(indices)}:")
            print(f"    True label: {self.label_names.get(true_label_raw, true_label_raw)}")
            print(f"    Predicted:  {self.label_names.get(pred_label_raw, pred_label_raw)}")
            
            try:
                exp = explainer.explain_instance(
                    sample,
                    predict_fn,
                    num_features=10,
                    top_labels=3
                )
                explanations.append(exp)
                
                if pred_label_idx in exp.local_exp:
                    target_idx = pred_label_idx
                else:
                    target_idx = list(exp.local_exp.keys())[0]
                    print(f"    [!] Warning: Using alternative label index {target_idx}")

                target_label_raw = model_classes[target_idx]
                target_name = self.label_names.get(target_label_raw, target_label_raw)
                
                fig = exp.as_pyplot_figure(label=target_idx)
                plt.tight_layout()
                lime_path = self.output_dir / f'lime_sample_{i+1}.png'
                plt.savefig(lime_path, dpi=150, bbox_inches='tight')
                plt.close()
                print(f"    [✓] Saved LIME plot to {lime_path}")
                
                feature_weights = exp.as_list(label=target_idx)[:5]
                print(f"    Top features influencing '{target_name}':")
                
                for feature, weight in feature_weights:
                    if weight > 0:
                        direction = f"→ Supports {target_name}"
                    else:
                        direction = "→ Contradicts"
                    print(f"      {feature:40s}: {weight:+.4f} {direction}")
                    
            except Exception as e:
                print(f"    [!] Error: {e}")
                continue
                
        return explanations
    
    def generate_full_report(self, X_train, y_train, X_test, y_test):
        """Generate comprehensive evaluation report"""
        print("\n" + "="*60)
        print("GENERATING COMPREHENSIVE EVALUATION REPORT - LGBM ENSEMBLE")
        print("="*60)
        
        report = {}
        
        print("\n[1/4] Comparing Train vs Test...")
        train_metrics, test_metrics, comparison = self.compare_train_test_overfitting(
            X_train, y_train, X_test, y_test
        )
        report['train_metrics'] = train_metrics
        report['test_metrics'] = test_metrics
        
        print("\n[2/4] Optimizing threshold...")
        threshold_results, best_threshold = self.threshold_optimization(X_test, y_test)
        report['threshold_results'] = threshold_results
        report['best_threshold'] = best_threshold
        
        print("\n[3/4] Generating SHAP explanations...")
        shap_values, shap_importance = self.explain_with_shap(X_test, sample_size=100)
        report['shap_importance'] = shap_importance
        
        print("\n[4/4] Generating LIME explanations...")
        lime_explanations = self.explain_with_lime(X_test, y_test, n_samples=5)
        
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
        print("LGBM EVALUATION COMPLETE!")
        print(f"{'='*60}")
        print(f"Results saved to: {self.output_dir}")
        print(f"\nKey Findings:")
        print(f"  Test Accuracy: {summary['test_accuracy']:.4f}")
        print(f"  Test F1-Score: {summary['test_f1']:.4f}")
        print(f"  False Positive Rate: {summary['test_fpr']:.4f}")
        print(f"  Optimal Threshold: {summary['best_threshold']:.2f}")
        
        return report


class IsolationForestEvaluator:
    """Evaluator cho Isolation Forest model"""
    
    def __init__(self, model, scaler, threshold, feature_names, output_dir='./evaluation_results'):
        self.model = model
        self.scaler = scaler
        self.threshold = threshold
        self.feature_names = feature_names
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        print(f"[*] Isolation Forest Evaluator initialized")
        print(f"    Threshold: {threshold:.6f}")
        print(f"    Features: {len(feature_names)}")
    
    def evaluate_anomaly_detection(self, X, y=None, dataset_name='Dataset'):
        """Evaluate IF performance on anomaly detection"""
        print(f"\n{'='*60}")
        print(f"ISOLATION FOREST EVALUATION - {dataset_name}")
        print(f"{'='*60}")
        
        # Scale data (Truyền trực tiếp DataFrame X để giữ tên cột)
        try:
            X_scaled = self.scaler.transform(X)
        except Exception as e:
            print(f"[!] Scaler transform error: {e}")
            if not isinstance(X, pd.DataFrame):
                X = pd.DataFrame(X, columns=self.feature_names)
                X_scaled = self.scaler.transform(X)
            else:
                raise e
        
        # Get anomaly scores
        scores = self.model.decision_function(X_scaled)
        
        # Predictions: 1 = normal, -1 = anomaly
        predictions = self.model.predict(X_scaled)
        
        # Binary predictions using threshold (1 = anomaly/attack)
        binary_preds = (scores < self.threshold).astype(int)
        
        # Statistics
        n_anomalies_default = (predictions == -1).sum()
        n_anomalies_threshold = binary_preds.sum()
        
        print(f"\n[*] Anomaly Detection Statistics:")
        print(f"    Total samples: {len(X_scaled)}")
        print(f"    Anomalies (default): {n_anomalies_default} ({n_anomalies_default/len(X_scaled)*100:.2f}%)")
        print(f"    Anomalies (threshold={self.threshold:.6f}): {n_anomalies_threshold} ({n_anomalies_threshold/len(X_scaled)*100:.2f}%)")
        
        metrics = {}
        per_class_results = None
        
        if y is not None:
            y_true = y.values if isinstance(y, pd.Series) else y
            # Convert to binary for metrics: 0 = BENIGN, >0 = ATTACK
            y_true_binary = (y_true > 0).astype(int)
            
            # Calculate metrics
            accuracy = accuracy_score(y_true_binary, binary_preds)
            precision = precision_score(y_true_binary, binary_preds, zero_division=0)
            recall = recall_score(y_true_binary, binary_preds, zero_division=0)
            f1 = f1_score(y_true_binary, binary_preds, zero_division=0)
            
            # Confusion matrix
            cm = confusion_matrix(y_true_binary, binary_preds)
            tn, fp, fn, tp = cm.ravel()
            fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
            
            print(f"\n[*] Performance Metrics (vs Ground Truth):")
            print(f"    Accuracy:  {accuracy:.4f}")
            print(f"    Precision: {precision:.4f}")
            print(f"    Recall:    {recall:.4f}")
            print(f"    F1-Score:  {f1:.4f}")
            print(f"    FPR:       {fpr:.4f} ({fpr*100:.2f}%)")
            
            metrics = {
                'accuracy': accuracy, 'precision': precision, 'recall': recall,
                'f1': f1, 'fpr': fpr, 'confusion_matrix': cm
            }
            
            # ✨ [FIX] Gọi hàm phân tích chi tiết từng loại tấn công
            per_class_results = self._analyze_per_attack_detection(
                scores, binary_preds, y_true
            )
        
        # Score distribution plot
        self._plot_score_distribution(scores, binary_preds, dataset_name)
        
        return {
            'scores': scores,
            'predictions': predictions,
            'binary_preds': binary_preds,
            'n_anomalies_threshold': n_anomalies_threshold,
            'metrics': metrics,
            'per_class_results': per_class_results
        }

    def _analyze_per_attack_detection(self, scores, binary_preds, y_true):
        """Analyze detection rate per attack type"""
        print(f"\n[*] Per-Attack-Type Detection Analysis:")
        
        # Attack type mapping (CIC-IDS-2017 standard)
        attack_mapping = {
            0: 'BENIGN', 1: 'DoS Hulk', 2: 'PortScan', 3: 'DDoS', 4: 'DoS GoldenEye',
            5: 'FTP-Patator', 6: 'SSH-Patator', 7: 'DoS slowloris', 8: 'DoS Slowhttptest',
            9: 'Bot', 10: 'Web Attack - Brute Force', 11: 'Web Attack - XSS',
            12: 'Web Attack - SQL Injection', 13: 'Infiltration', 14: 'Heartbleed'
        }
        
        results = []
        unique_labels = np.unique(y_true)
        
        print(f"\n    {'Attack Type':<30s} | Samples | Detected | Detection Rate | Avg Score")
        print(f"    {'-'*90}")
        
        for label in sorted(unique_labels):
            mask = (y_true == label)
            n_samples = mask.sum()
            n_detected = binary_preds[mask].sum()
            detection_rate = n_detected / n_samples if n_samples > 0 else 0
            avg_score = scores[mask].mean()
            
            # Nếu label là 1 (do bước extract trước đó gán cứng), ta hiển thị là 'Attack'
            attack_name = attack_mapping.get(label, f'Attack-Label-{label}')
            
            results.append({
                'label': int(label),
                'attack_type': attack_name,
                'n_samples': int(n_samples),
                'n_detected': int(n_detected),
                'detection_rate': float(detection_rate),
                'avg_score': float(avg_score)
            })
            
            print(f"    {attack_name:<30s} | {n_samples:7d} | {n_detected:8d} | "
                  f"{detection_rate*100:13.2f}% | {avg_score:+.6f}")
        
        # Save to CSV
        results_df = pd.DataFrame(results)
        results_path = self.output_dir / 'if_per_attack_detection.csv'
        results_df.to_csv(results_path, index=False)
        print(f"\n    [✓] Saved per-attack analysis to {results_path}")
        
        # Plot
        self._plot_per_attack_detection(results_df)
        
        return results_df

    def _plot_per_attack_detection(self, results_df):
        """Plot per-attack detection rates"""
        fig, axes = plt.subplots(1, 2, figsize=(16, 6))
        
        # Filter out BENIGN
        attack_only = results_df[results_df['label'] > 0].copy()
        
        if len(attack_only) == 0:
            return
        
        attack_only = attack_only.sort_values('detection_rate', ascending=True)
        
        # Plot 1: Detection rate
        ax = axes[0]
        colors = ['red' if r < 0.5 else 'orange' if r < 0.8 else 'green' for r in attack_only['detection_rate']]
        ax.barh(range(len(attack_only)), attack_only['detection_rate'] * 100, color=colors, alpha=0.7)
        ax.set_yticks(range(len(attack_only)))
        ax.set_yticklabels(attack_only['attack_type'], fontsize=9)
        ax.set_xlabel('Detection Rate (%)')
        ax.set_title('IF Detection Rate by Attack Type')
        ax.axvline(50, color='red', linestyle='--', alpha=0.3)
        ax.axvline(80, color='orange', linestyle='--', alpha=0.3)
        
        # Plot 2: Average score
        ax = axes[1]
        attack_sorted_score = attack_only.sort_values('avg_score', ascending=True)
        colors_score = ['green' if s < self.threshold else 'red' for s in attack_sorted_score['avg_score']]
        ax.barh(range(len(attack_sorted_score)), attack_sorted_score['avg_score'], color=colors_score, alpha=0.7)
        ax.set_yticks(range(len(attack_sorted_score)))
        ax.set_yticklabels(attack_sorted_score['attack_type'], fontsize=9)
        ax.set_xlabel('Average Anomaly Score')
        ax.set_title('Average Anomaly Score vs Threshold')
        ax.axvline(self.threshold, color='black', linestyle='--', label='Threshold')
        ax.legend()
        
        plt.tight_layout()
        plot_path = self.output_dir / 'if_per_attack_detection.png'
        plt.savefig(plot_path, dpi=150, bbox_inches='tight')
        plt.close()

    def _plot_score_distribution(self, scores, binary_preds, dataset_name):
        """Plot score distribution"""
        plt.figure(figsize=(10, 6))
        
        normal_scores = scores[binary_preds == 0]
        anomaly_scores = scores[binary_preds == 1]
        
        plt.hist(normal_scores, bins=50, alpha=0.6, color='green', label='Predicted Normal')
        plt.hist(anomaly_scores, bins=50, alpha=0.6, color='red', label='Predicted Anomaly')
        plt.axvline(self.threshold, color='black', linestyle='--', linewidth=2, label=f'Threshold {self.threshold:.4f}')
        
        plt.xlabel('Anomaly Score')
        plt.ylabel('Count')
        plt.title(f'Isolation Forest Score Distribution - {dataset_name}')
        plt.legend()
        
        plot_path = self.output_dir / f'if_score_dist_{dataset_name}.png'
        plt.savefig(plot_path, dpi=150)
        plt.close()

    def evaluate_threshold_sensitivity(self, X, y, percentiles=np.arange(1, 20, 2)):
        """Test different threshold percentiles"""
        print(f"\n{'='*60}")
        print("THRESHOLD SENSITIVITY ANALYSIS")
        print(f"{'='*60}")
        
        y_true = y.values if isinstance(y, pd.Series) else y
        y_true_binary = (y_true > 0).astype(int)
        
        # [FIX] Dùng transform trực tiếp với DataFrame
        X_scaled = self.scaler.transform(X)
        scores = self.model.decision_function(X_scaled)
        
        results = []
        print(f"\nPercentile | Threshold  | Accuracy | F1-Score | FPR")
        print("-" * 60)
        
        for pct in percentiles:
            threshold = np.percentile(scores, pct)
            binary_preds = (scores < threshold).astype(int)
            
            acc = accuracy_score(y_true_binary, binary_preds)
            f1 = f1_score(y_true_binary, binary_preds, zero_division=0)
            
            cm = confusion_matrix(y_true_binary, binary_preds)
            tn, fp = cm[0, 0], cm[0, 1]
            fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
            
            results.append({
                'percentile': pct, 'threshold': threshold,
                'accuracy': acc, 'f1': f1, 'fpr': fpr
            })
            
            print(f"{pct:3.0f}%        | {threshold:+.6f} | {acc:.4f}   | {f1:.4f}   | {fpr:.4f}")
        
        results_df = pd.DataFrame(results)
        results_df.to_csv(self.output_dir / 'if_threshold_sensitivity.csv', index=False)
        return results_df
    
    def generate_if_report(self, X_test, y_test):
        """Generate IF report"""
        print("\n" + "="*60)
        print("GENERATING ISOLATION FOREST REPORT")
        print("="*60)
        
        # Evaluate performance
        test_results = self.evaluate_anomaly_detection(X_test, y_test, 'TEST SET')
        
        # Sensitivity check
        sensitivity = self.evaluate_threshold_sensitivity(X_test, y_test)
        
        return {'test_results': test_results, 'sensitivity': sensitivity}


def load_and_split_data(data_path, metadata_path, test_ratio=0.2):
    """Tải dữ liệu và chia thành Train Pool và Test Set"""
    df = pd.read_parquet(data_path)
    
    with open(metadata_path, 'r') as f:
        metadata = json.load(f)
        
    feature_names = metadata['feature_names']
    
    X = df[feature_names].copy()
    y = df['label'].copy()
    X.replace([np.inf, -np.inf], 0, inplace=True)
    X.fillna(0, inplace=True)
    
    X_pool, X_test, y_pool, y_test = train_test_split(
        X, y, test_size=test_ratio, random_state=42, stratify=y
    )
    
    return X_pool, y_pool, X_test, y_test, feature_names


def load_if_data(data_path, schema_path):
    """Load Isolation Forest data"""
    df = pd.read_parquet(data_path)
    
    with open(schema_path, 'r') as f:
        schema = json.load(f)
        feature_names = schema['feature_columns']
    
    X = df[feature_names].copy()
    y = df['label'].copy() if 'label' in df.columns else None
    
    X.replace([np.inf, -np.inf], 0, inplace=True)
    X.fillna(0, inplace=True)
    
    return X, y, feature_names


def prepare_if_test_data(lgbm_dataset_path, if_features, test_ratio=0.2):
    """
    Prepare IF test data from full dataset (Normal + Attack)
    
    Args:
        lgbm_dataset_path: Path to full featured dataset
        if_features: List of feature names expected by IF model
        test_ratio: Test set ratio
    
    Returns:
        X_test_if, y_test_if: Test data with IF features
    """
    print("\n[*] Preparing IF test data from full dataset...")
    
    # Load full dataset
    df_full = pd.read_parquet(lgbm_dataset_path)
    
    # Check feature availability
    available_features = set(df_full.columns)
    required_features = set(if_features)
    missing_features = required_features - available_features
    
    if missing_features:
        raise ValueError(
            f"Missing features in dataset: {missing_features}\n"
            f"Available: {sorted(available_features)}\n"
            f"Required: {sorted(required_features)}"
        )
    
    # Extract IF features
    X_full = df_full[if_features].copy()
    y_full = df_full['label'].copy()
    
    # Clean data
    X_full.replace([np.inf, -np.inf], 0, inplace=True)
    X_full.fillna(0, inplace=True)
    
    # Split (use same random_state as LGBM for consistency)
    _, X_test, _, y_test = train_test_split(
        X_full, y_full, test_size=test_ratio, random_state=42, stratify=y_full
    )
    
    # Print test set composition
    print(f"[✓] IF test set prepared:")
    print(f"    Total samples: {len(y_test)}")
    print(f"    Normal (label=0): {(y_test == 0).sum()} ({(y_test == 0).sum()/len(y_test)*100:.2f}%)")
    print(f"    Attack (label>0): {(y_test > 0).sum()} ({(y_test > 0).sum()/len(y_test)*100:.2f}%)")
    
    # Show attack type distribution
    attack_counts = y_test[y_test > 0].value_counts().sort_index()
    if len(attack_counts) > 0:
        print(f"    Attack types in test set:")
        for label, count in attack_counts.items():
            print(f"      Label {label}: {count} samples ({count/len(y_test)*100:.2f}%)")
    
    return X_test, y_test


if __name__ == "__main__":
    import sys
    
    # ============================================================
    # 0. CẤU HÌNH ĐƯỜNG DẪN (PATHS CONFIGURATION)
    # ============================================================
    BASE_DIR = Path('./CIC-IDS-2017')
    MODELS_DIR = Path('./models')
    OUTPUT_DIR = Path('./evaluation_results')
    
    # Paths - LGBM (Supervised)
    LGBM_MODEL_PATH = MODELS_DIR / 'nids_tri_lgbm_v1.joblib'
    LGBM_METADATA_PATH = MODELS_DIR / 'nids_tri_lgbm_v1_metadata.json'
    # Dùng file featured_lgbm.parquet nếu có, nếu không dùng featured_dataset.parquet cũ
    LGBM_DATASET_PATH = BASE_DIR / 'featured_lgbm.parquet' 
    if not LGBM_DATASET_PATH.exists():
        LGBM_DATASET_PATH = BASE_DIR / 'featured_dataset.parquet'
    
    # Paths - Isolation Forest (Unsupervised)
    IF_MODEL_PATH = MODELS_DIR / 'isolation_forest.joblib'
    IF_SCALER_PATH = MODELS_DIR / 'if_scaler.joblib'
    IF_METADATA_PATH = MODELS_DIR / 'isolation_forest_metadata.json'
    
    # Data Sources for IF Evaluation
    # 1. Normal Data (Features ready - từ quá trình train IF)
    IF_NORMAL_DATA = BASE_DIR / 'featured_if.parquet' 
    IF_SCHEMA_PATH = BASE_DIR / 'feature_schema_if.json'
    
    # 2. Attack Data (RAW - Cần extract lại feature để có DNS)
    # File này chứa cột 'query' gốc
    RAW_ATTACK_DATA = BASE_DIR / 'labeled_conn_for_semi_supervised.parquet'

    # Biến lưu kết quả để so sánh cuối cùng
    lgbm_metrics = {}
    if_metrics = {}

    # ============================================================
    # PART 1: EVALUATE LGBM ENSEMBLE
    # ============================================================
    print("\n" + "="*70)
    print("PART 1: LGBM ENSEMBLE EVALUATION")
    print("="*70)
    
    if LGBM_MODEL_PATH.exists() and LGBM_METADATA_PATH.exists() and LGBM_DATASET_PATH.exists():
        print("[*] Loading LGBM models and data...")
        
        try:
            lgbm_models = joblib.load(LGBM_MODEL_PATH)
            # Load và chia dữ liệu (Train Pool / Test)
            X_train_pool, y_train_pool, X_test_lgbm, y_test_lgbm, LGBM_FEATURES = load_and_split_data(
                LGBM_DATASET_PATH, LGBM_METADATA_PATH, test_ratio=0.2
            )
            
            # Khởi tạo Evaluator
            lgbm_evaluator = NIDSModelEvaluator(
                models=lgbm_models, 
                feature_names=LGBM_FEATURES, 
                output_dir=OUTPUT_DIR
            )
            
            # Chạy đánh giá toàn diện
            lgbm_report = lgbm_evaluator.generate_full_report(
                X_train=X_train_pool, 
                y_train=y_train_pool, 
                X_test=X_test_lgbm, 
                y_test=y_test_lgbm
            )
            
            # Lưu metrics chính để so sánh sau
            lgbm_metrics = {
                'accuracy': lgbm_report['test_metrics']['accuracy'],
                'f1_weighted': lgbm_report['test_metrics']['f1_weighted'],
                'fpr': lgbm_report['test_metrics']['fpr']
            }
            print("\n[✓] LGBM evaluation completed.")
            
        except Exception as e:
            print(f"[!] Error during LGBM evaluation: {e}")
            import traceback
            traceback.print_exc()
    else:
        print("[!] LGBM model or data not found. Skipping Part 1.")
        if not LGBM_DATASET_PATH.exists(): print(f"    Missing: {LGBM_DATASET_PATH}")

    # ============================================================
    # PART 2: EVALUATE ISOLATION FOREST (FIXED LOGIC)
    # ============================================================
    print("\n" + "="*70)
    print("PART 2: ISOLATION FOREST EVALUATION")
    print("="*70)
    
    if IF_MODEL_PATH.exists() and IF_SCALER_PATH.exists() and IF_METADATA_PATH.exists():
        try:
            print("[*] Loading Isolation Forest resources...")
            if_model = joblib.load(IF_MODEL_PATH)
            if_scaler = joblib.load(IF_SCALER_PATH)
            
            with open(IF_METADATA_PATH, 'r') as f: 
                if_meta = json.load(f)
                if_threshold = if_meta['threshold']
                if_features = if_meta['feature_names']
                
            print(f"    Threshold: {if_threshold:.6f}")
            print(f"    Features required: {len(if_features)}")

            # --- STEP 2.1: PREPARE NORMAL TEST SET ---
            print("\n[*] Preparing Normal Test Set...")
            if IF_NORMAL_DATA.exists():
                X_normal_all, _, _ = load_if_data(IF_NORMAL_DATA, IF_SCHEMA_PATH)
                # Split 20% làm test (giống lúc train/test split của LGBM để công bằng về size)
                _, X_test_normal = train_test_split(X_normal_all, test_size=0.2, random_state=42)
                y_test_normal = pd.Series([0] * len(X_test_normal)) # 0 = Benign
                print(f"    [✓] Normal samples: {len(X_test_normal)}")
            else:
                raise FileNotFoundError(f"Normal data not found: {IF_NORMAL_DATA}")

            # --- STEP 2.2: PREPARE ATTACK TEST SET (FROM RAW) ---
            print("\n[*] Preparing Attack Test Set (Extracting from RAW)...")
            if RAW_ATTACK_DATA.exists():
                # Load file gốc (có cột query)
                print(f"    Loading raw parquet: {RAW_ATTACK_DATA}...")
                df_raw = pd.read_parquet(RAW_ATTACK_DATA)
                
                # Chỉ lấy các dòng là Attack (label != 0)
                # Lưu ý: check tên cột label trong file raw, thường là 'label' hoặc 'Label'
                if 'label' in df_raw.columns:
                    df_attack_all = df_raw[df_raw['label'] != 0].copy()
                else:
                    print("    [!] 'label' column not found, checking 'attack_type'...")
                    df_attack_all = df_raw[df_raw['attack_type'] != 'BENIGN'].copy()

                # Lấy mẫu 20% số lượng Attack để làm Test Set
                # (Dùng random_state=42 để cố định tập test)
                df_attack_test = df_attack_all.sample(frac=0.2, random_state=42)
                print(f"    Extracting features for {len(df_attack_test)} attack samples...")
                
                # --- FEATURE ENGINEERING ON-THE-FLY ---
                # Khởi tạo Engineer với chế độ 'if' (Isolation Forest) -> Có DNS
                # Cần load encoder path từ LGBM Metadata để encode service/proto nếu cần (dù IF không dùng service_encoded nhưng code có thể cần load để không lỗi)
                encoder_path = None
                if LGBM_METADATA_PATH.exists():
                    with open(LGBM_METADATA_PATH) as f:
                        lgbm_meta_json = json.load(f)
                        if 'encoder_reference_path' in lgbm_meta_json and Path(lgbm_meta_json['encoder_reference_path']).exists():
                            encoder_path = Path(lgbm_meta_json['encoder_reference_path'])
                
                # Import class FeatureEngineer tại đây để đảm bảo scope
                try:
                    from feature_engineering import NIDSFeatureEngineer
                    engineer = NIDSFeatureEngineer(time_window='10s', encoder_path=encoder_path, model_type='if')
                    
                    # Extract Features
                    feat_attack = engineer.extract_all_features(df_attack_test)
                    
                    # Lấy Matrix X chỉ với các cột IF cần
                    X_test_attack, _ = engineer.get_feature_matrix(feat_attack)
                    
                    # Double check columns
                    missing_cols = set(if_features) - set(X_test_attack.columns)
                    if missing_cols:
                        print(f"    [!] Warning: Missing columns in extracted attack data: {missing_cols}")
                        # Fill 0 cho chắc
                        for c in missing_cols: X_test_attack[c] = 0
                    
                    # Reorder columns theo đúng thứ tự lúc train IF
                    X_test_attack = X_test_attack[if_features]
                    
                    # [FIX] Lấy nhãn thực tế từ df_attack_test thay vì gán cứng là 1
                    y_test_attack = df_attack_test['label'].copy().reset_index(drop=True)
                    
                    print(f"    [✓] Attack samples extracted: {len(X_test_attack)}")
                    
                except ImportError:
                    raise ImportError("Cannot import NIDSFeatureEngineer. Check file feature_engineering.py")
            else:
                raise FileNotFoundError(f"Raw attack data not found: {RAW_ATTACK_DATA}")

            # --- STEP 2.3: COMBINE & EVALUATE ---
            print("\n[*] Combining Normal & Attack Test Sets...")
            X_test_mixed = pd.concat([X_test_normal, X_test_attack], ignore_index=True)
            y_test_mixed = pd.concat([y_test_normal, y_test_attack], ignore_index=True)
            
            print(f"    Total Test Samples: {len(X_test_mixed)}")
            print(f"    - Normal: {len(X_test_normal)}")
            print(f"    - Attack: {len(X_test_attack)}")
            
            # Initialize Evaluator
            if_evaluator = IsolationForestEvaluator(
                model=if_model,
                scaler=if_scaler,
                threshold=if_threshold,
                feature_names=if_features,
                output_dir=OUTPUT_DIR
            )
            
            # Run Evaluation
            if_report = if_evaluator.generate_if_report(X_test_mixed, y_test_mixed)
            
            if if_report['test_results']['metrics']:
                if_metrics = {
                    'accuracy': if_report['test_results']['metrics']['accuracy'],
                    'f1': if_report['test_results']['metrics']['f1'],
                    'fpr': if_report['test_results']['metrics']['fpr']
                }
            
            print("\n[✓] Isolation Forest evaluation completed.")

        except Exception as e:
            print(f"[!] Error during IF evaluation: {e}")
            import traceback
            traceback.print_exc()
    else:
        print("[!] Isolation Forest model/metadata not found. Skipping Part 2.")

    # ============================================================
    # FINAL SUMMARY COMPARISON
    # ============================================================
    if lgbm_metrics or if_metrics:
        print("\n" + "="*70)
        print("FINAL MODEL PERFORMANCE SUMMARY")
        print("="*70)
        
        # Tạo bảng so sánh
        summary_data = []
        if lgbm_metrics:
            summary_data.append({
                'Model': 'LGBM Ensemble',
                'Type': 'Supervised (Multiclass)',
                'Accuracy': lgbm_metrics['accuracy'],
                'F1-Score': lgbm_metrics['f1_weighted'],
                'FPR': lgbm_metrics['fpr']
            })
        if if_metrics:
            summary_data.append({
                'Model': 'Isolation Forest',
                'Type': 'Unsupervised (Anomaly)',
                'Accuracy': if_metrics.get('accuracy', 0),
                'F1-Score': if_metrics.get('f1', 0),
                'FPR': if_metrics.get('fpr', 0)
            })
            
        summary_df = pd.DataFrame(summary_data)
        
        # In bảng đẹp
        print(f"{'Model':<20} | {'Type':<25} | {'Accuracy':<10} | {'F1-Score':<10} | {'FPR':<10}")
        print("-" * 85)
        for _, row in summary_df.iterrows():
            print(f"{row['Model']:<20} | {row['Type']:<25} | {row['Accuracy']:.4f}     | {row['F1-Score']:.4f}     | {row['FPR']:.4f}")
        print("-" * 85)
        
        # Save summary CSV
        summary_path = Path(OUTPUT_DIR) / 'final_model_comparison.csv'
        summary_df.to_csv(summary_path, index=False)
        print(f"\n[✓] Summary saved to: {summary_path}")
        
        print("\n[*] RECOMMENDATION:")
        print("    Use 'inference_nids.py' to run the Hybrid System.")
        print("    Logic: If LGBM detects specific attack -> Alert.")
        print("           If LGBM says Benign but IF Score < Threshold -> Suspicious Alert.")
        
    print("\n[✓] Evaluation pipeline finished successfully.")