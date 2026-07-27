"""
train_model.py — Industrial-Grade Model Training Pipeline

Features:
  - 5-fold stratified cross-validation
  - Confusion matrix and classification report
  - Feature importance ranking
  - Model versioning (old model preserved as backup)
  - Supports both old 7-feature and new 10-feature schemas
  - Outputs metrics to JSON for audit trail
  - Structured logging via app_logger
"""
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report, accuracy_score, confusion_matrix,
    precision_score, recall_score, f1_score
)
import os
import shutil
import time
import joblib
import json

from app_logger import get_logger

log = get_logger("TrainModel")

# Fix: resolve paths relative to this script's folder, not the CWD
_dir = os.path.dirname(os.path.abspath(__file__))

# Try new dataset first, fall back to original
_input_10k = os.path.join(_dir, "CSV", "ml_ready_dataset_v2.csv")
_input_original = os.path.join(_dir, "CSV", "ml_ready_dataset.csv")
_input_demo = os.path.join(_dir, "stealth_demo_trainable_dataset.csv")
_model_file = os.path.join(_dir, "random_forest_model.pkl")
_metrics_file = os.path.join(_dir, "model_metrics.json")

# ── Select best available dataset ───────────────────────────────────
if os.path.exists(_input_10k):
    _input_file = _input_10k
    log.info(f"Using industrial dataset: {_input_10k}")
elif os.path.exists(_input_original):
    _input_file = _input_original
    log.info(f"Using original ML dataset: {_input_original}")
else:
    _input_file = _input_demo
    log.info(f"Using demo dataset: {_input_demo}")

# Load dataset
df = pd.read_csv(_input_file, low_memory=False)
df = df.fillna(0)
log.info(f"Loaded {len(df)} rows, {len(df.columns)} columns")

# ── Feature selection ───────────────────────────────────────────────
# 10-feature schema (industrial) — falls back to available columns
all_features = [
    "Connection_Count", "Duration", "Rate", "Unique_Ports",
    "Is_Port_Scan", "Is_Night", "Payload_Entropy", "Packet_Size",
    "Connection_Interval", "SYN_Count"
]

# Use only features that exist in the dataset
features = [f for f in all_features if f in df.columns]

# Backward compatibility: map old column names if needed
column_map = {"Packets": "Connection_Count"}
for old, new in column_map.items():
    if old in df.columns and new not in df.columns:
        df[new] = df[old]
        if new not in features:
            features.append(new)

log.info(f"Using {len(features)} features: {features}")

X = df[features]
y = df["Label"]

log.info(f"Label distribution: {dict(y.value_counts())}")

# ── Model versioning: backup existing model ─────────────────────────
if os.path.exists(_model_file):
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    backup_path = f"{_model_file}.{timestamp}.backup"
    shutil.copy2(_model_file, backup_path)
    log.info(f"Previous model backed up: {backup_path}")

# ── 5-Fold Stratified Cross-Validation ──────────────────────────────
log.info("Starting 5-FOLD STRATIFIED CROSS-VALIDATION")

model = RandomForestClassifier(
    n_estimators=200,       # More trees = more stable predictions
    max_depth=20,           # Prevent overfitting on 10K rows
    min_samples_split=5,    # Require at least 5 samples to split
    min_samples_leaf=2,     # Leaf must have at least 2 samples
    random_state=42,
    n_jobs=-1,              # Use all CPU cores
    class_weight="balanced" # Handle class imbalance (25% attack / 75% normal)
)

cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
cv_scores = cross_val_score(model, X, y, cv=cv, scoring="accuracy")

log.info(f"Cross-Validation Accuracy Scores: {[round(s, 4) for s in cv_scores]}")
log.info(f"Mean CV Accuracy:  {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")

# ── Final Train/Test Split ──────────────────────────────────────────
log.info("FINAL MODEL TRAINING (75/25 SPLIT)")

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.25, random_state=42, stratify=y
)

model.fit(X_train, y_train)
y_pred = model.predict(X_test)

# ── Results ─────────────────────────────────────────────────────────
metrics = {
    "test_accuracy": round(accuracy_score(y_test, y_pred), 4),
    "precision": round(precision_score(y_test, y_pred, zero_division=0), 4),
    "recall": round(recall_score(y_test, y_pred, zero_division=0), 4),
    "f1_score": round(f1_score(y_test, y_pred, zero_division=0), 4)
}

log.info(f"Test Accuracy: {metrics['test_accuracy']}")
log.info(f"Precision:     {metrics['precision']}")
log.info(f"Recall:        {metrics['recall']}")
log.info(f"F1 Score:      {metrics['f1_score']}")

clf_report = classification_report(y_test, y_pred, target_names=["Normal (0)", "Threat (1)"])
log.info(f"\nClassification Report:\n{clf_report}")

cm = confusion_matrix(y_test, y_pred)
log.info(f"Confusion Matrix:\n  TN={cm[0][0]:5d}  FP={cm[0][1]:5d}\n  FN={cm[1][0]:5d}  TP={cm[1][1]:5d}")

metrics["confusion_matrix"] = {
    "TN": int(cm[0][0]), "FP": int(cm[0][1]),
    "FN": int(cm[1][0]), "TP": int(cm[1][1])
}

# ── Feature Importance ──────────────────────────────────────────────
importances = sorted(zip(features, model.feature_importances_),
                     key=lambda x: x[1], reverse=True)
metrics["feature_importance"] = {name: float(importance) for name, importance in importances}

feat_str = "\nFeature Importance (ranked):\n"
for name, importance in importances:
    bar = "=" * int(importance * 50)
    feat_str += f"  {name:25s} {importance:.4f}  {bar}\n"
log.info(feat_str)

# ── Save trained model ──────────────────────────────────────────────
joblib.dump(model, _model_file)
with open(_metrics_file, "w") as f:
    json.dump(metrics, f, indent=4)

log.info(f"Model saved: {_model_file} ({os.path.getsize(_model_file) / 1024:.1f} KB)")
log.info(f"Metrics saved: {_metrics_file}")
log.info(f"Features expected at inference: {features}")
log.info("Training complete.")
