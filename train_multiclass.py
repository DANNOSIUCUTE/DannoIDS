"""
train_multiclass.py - Train Multi-class Web Attack Detection Model
Dataset: combined_dataset.csv (122k+ rows, 6 classes)
Features: 30 engineered features (v3 modern attack features)
Model: LightGBM Multi-class Classifier
"""

import os
import json
import time
import math
import re
from collections import Counter
from urllib.parse import unquote
import pandas as pd
import numpy as np
import joblib
import lightgbm as lgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, f1_score

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET_PATH = os.path.join(BASE_DIR, "combined_dataset.csv")
CACHE_PATH = os.path.join(BASE_DIR, "features_extracted.parquet")
MODELS_DIR = os.path.join(BASE_DIR, "models")
os.makedirs(MODELS_DIR, exist_ok=True)

LABEL_MAP = {
    0: "Normal",
    1: "SQL Injection",
    2: "XSS",
    3: "Command Injection",
    4: "Path Traversal / LFI",
    5: "Other Attack (SSTI/XXE/SSRF)",
}


def extract_features(url: str) -> dict:
    """Trich xuat 30 dac trung cho multi-class web attack detection."""
    original_url = str(url)
    url_decoded = unquote(original_url).lower()

    # Regex patterns
    sql_words = r'(select|union|insert|drop|where|delete|and\s|or\s|--|/\*|\*/|xp_cmdshell|update|exec|waitfor|concat|group_by|order\sby|having|information_schema|load_file|into\soutfile|benchmark|sleep|extractvalue|updatexml)'
    js_words = r'(script|alert|onerror|onload|eval|javascript:|document\.cookie|iframe|src=|img|prompt|confirm|onfocus|onmouseover|fromcharcode)'
    cmd_words = r'(bash|cmd|ping|wget|curl|chmod|cat|/bin/sh|powershell|nslookup|nc\s|netcat|whoami|\bls\b|\bid\b|/etc/passwd|/etc/shadow|sleep\s|system\()'
    path_pattern = r'(\.\.\/|\.\.\\|\%2e\%2e|\%2f|/etc/passwd|/etc/shadow|boot\.ini|win\.ini|php://|file://|data://|expect://|proc/self)'
    nosql_pattern = r'(\$gt|\$ne|\$lt|\$gte|\$lte|\$regex|\$where|\$exists|\$nin|\$or|\$and)'
    ssti_pattern = r'(\{\{|\{%|\$\{|<%=|#\{|__class__|__mro__|__subclasses__|__globals__|__builtins__)'
    xxe_pattern = r'(<!doctype|<!entity|system\s|<!--|<\?xml|cdata\[|xmlns)'
    ssrf_pattern = r'(127\.0\.0\.1|169\.254\.169\.254|0x7f|localhost|::1|metadata\.google|0177\.0\.0\.1|2130706433|gopher://|dict://)'

    length = len(url_decoded)
    special_char_count = len(re.findall(r'[!@#$%^&*()\":{}<>]', url_decoded))

    features = {
        # 14 features goc
        'length': length,
        'special_char_count': special_char_count,
        'sql_keywords': len(re.findall(sql_words, url_decoded)),
        'js_keywords': len(re.findall(js_words, url_decoded)),
        'cmd_keywords': len(re.findall(cmd_words, url_decoded)),
        'path_traversal': len(re.findall(path_pattern, url_decoded)),
        'single_quotes': url_decoded.count("'"),
        'percent_encoding': url_decoded.count('%'),
        'is_brute': 1 if ('login' in url_decoded and 'password' in url_decoded) else 0,
        'num_digits': sum(c.isdigit() for c in url_decoded),
        'num_params': url_decoded.count('&'),
        'has_encoded': 1 if '%' in url_decoded else 0,
        'has_path_traversal': 1 if '../' in url_decoded else 0,
        'has_admin': 1 if 'admin' in url_decoded else 0,
    }

    # 9 features bo sung tu v1
    char_freq = Counter(url_decoded)
    n = len(url_decoded) or 1
    entropy = -sum((c / n) * math.log2(c / n) for c in char_freq.values())
    features['entropy'] = round(entropy, 4)
    features['special_ratio'] = round(special_char_count / n, 4)

    parts = url_decoded.split('?', 1)
    features['path_length'] = len(parts[0])
    features['query_length'] = len(parts[1]) if len(parts) > 1 else 0
    features['path_depth'] = url_decoded.count('/')
    features['uppercase_ratio'] = round(
        sum(1 for c in original_url if c.isupper()) / max(len(original_url), 1), 4
    )
    params = url_decoded.split('&')
    features['avg_param_length'] = round(sum(len(p) for p in params) / max(len(params), 1), 2)
    features['double_encoded'] = 1 if '%25' in url_decoded else 0
    features['has_null_byte'] = 1 if '%00' in original_url else 0

    # 7 features hien dai moi (v2)
    features['nosql_keywords'] = len(re.findall(nosql_pattern, url_decoded))
    features['ssti_patterns'] = len(re.findall(ssti_pattern, url_decoded))
    features['xxe_patterns'] = len(re.findall(xxe_pattern, url_decoded))
    features['ssrf_patterns'] = len(re.findall(ssrf_pattern, url_decoded))
    features['has_unicode_escape'] = 1 if re.search(r'(%u[0-9a-f]{4}|\\u[0-9a-f]{4})', url_decoded) else 0

    if '?' in url_decoded:
        query = url_decoded.split('?', 1)[1]
        param_parts = query.split('&')
        param_vals = [p.split('=', 1)[1] if '=' in p else p for p in param_parts]
        features['max_param_length'] = max(len(v) for v in param_vals) if param_vals else 0
    else:
        features['max_param_length'] = 0

    features['non_ascii_count'] = sum(1 for c in url_decoded if ord(c) > 127)

    return features


def main():
    print("=" * 65)
    print("  TRAINING MULTI-CLASS WEB ATTACK DETECTION MODEL")
    print("=" * 65)

    # ── 1. Load Data / Features ──
    if os.path.exists(CACHE_PATH):
        print(f"\n[1/5] Loading cached features from {CACHE_PATH} ...")
        df_feat = pd.read_parquet(CACHE_PATH)
        print(f"      Loaded {len(df_feat):,} samples.")
    else:
        print(f"\n[1/5] Loading dataset from {DATASET_PATH} ...")
        df = pd.read_csv(DATASET_PATH)
        print(f"      Total rows: {len(df):,}")
        print("      Extracting 30 features per URL (this takes ~15-25s)...")
        t0 = time.time()
        
        # Batch extraction
        records = []
        urls = df['url'].tolist()
        labels = df['label'].tolist()
        attack_types = df['attack_type'].tolist()
        
        for i, (u, lbl, atype) in enumerate(zip(urls, labels, attack_types)):
            f_dict = extract_features(u)
            f_dict['label'] = lbl
            f_dict['attack_type'] = atype
            records.append(f_dict)
            if (i + 1) % 25000 == 0:
                print(f"      Processed {i + 1:,} / {len(urls):,} ({time.time() - t0:.1f}s)")
        
        df_feat = pd.DataFrame(records)
        print(f"      Feature extraction finished in {time.time() - t0:.2f}s")
        
        try:
            df_feat.to_parquet(CACHE_PATH, index=False)
            print(f"      Cached features saved to {CACHE_PATH}")
        except Exception as e:
            print(f"      [Notice] Could not save parquet cache: {e}")

    # ── 2. Prepare Train/Test Split ──
    print("\n[2/5] Preparing Train/Test Split (80/20 Stratified)...")
    feature_cols = [c for c in df_feat.columns if c not in ('label', 'attack_type')]
    print(f"      Features count: {len(feature_cols)}")

    X = df_feat[feature_cols]
    y = df_feat['label'].astype(int)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"      Train samples: {len(X_train):,}")
    print(f"      Test samples : {len(X_test):,}")

    # ── 3. Train LightGBM Multi-class ──
    print("\n[3/5] Training LightGBM Multi-class Classifier...")
    t0 = time.time()
    
    # Compute class weights for imbalanced classes
    classes = np.unique(y_train)
    class_counts = Counter(y_train)
    total_samples = len(y_train)
    class_weights = {c: total_samples / (len(classes) * count) for c, count in class_counts.items()}
    sample_weights = y_train.map(class_weights)

    clf = lgb.LGBMClassifier(
        objective='multiclass',
        num_class=6,
        n_estimators=150,
        learning_rate=0.08,
        num_leaves=63,
        max_depth=12,
        subsample=0.85,
        colsample_bytree=0.85,
        random_state=42,
        n_jobs=-1,
        verbose=-1
    )

    clf.fit(X_train, y_train, sample_weight=sample_weights)
    train_time = time.time() - t0
    print(f"      Training completed in {train_time:.2f}s!")

    # ── 4. Evaluate on Test Set ──
    print("\n[4/5] Evaluating on Test Set...")
    y_pred = clf.predict(X_test)
    y_probs = clf.predict_proba(X_test)

    acc = accuracy_score(y_test, y_pred)
    f1_macro = f1_score(y_test, y_pred, average='macro')
    f1_weighted = f1_score(y_test, y_pred, average='weighted')

    print(f"\n  Overall Accuracy : {acc * 100:.2f}%")
    print(f"  Macro F1-Score   : {f1_macro:.4f}")
    print(f"  Weighted F1-Score: {f1_weighted:.4f}")

    target_names = [f"{LABEL_MAP[i]} (class {i})" for i in sorted(LABEL_MAP.keys())]
    print("\n  Classification Report:")
    print(classification_report(y_test, y_pred, target_names=target_names, digits=4))

    print("  Confusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    cm_df = pd.DataFrame(cm, index=[LABEL_MAP[i] for i in range(6)], columns=[LABEL_MAP[i] for i in range(6)])
    print(cm_df.to_string())

    # Binary Attack vs Normal performance
    binary_true = (y_test != 0).astype(int)
    binary_pred = (y_pred != 0).astype(int)
    binary_acc = accuracy_score(binary_true, binary_pred)
    print(f"\n  Binary Attack vs Normal Accuracy: {binary_acc * 100:.2f}%")

    # ── 5. Save Artifacts ──
    print("\n[5/5] Exporting Models and Metadata...")
    model_path = os.path.join(MODELS_DIR, "best_model_multiclass.pkl")
    feat_path = os.path.join(MODELS_DIR, "feature_names.pkl")
    label_map_path = os.path.join(MODELS_DIR, "label_map.pkl")
    meta_path = os.path.join(MODELS_DIR, "model_metadata.json")

    joblib.dump(clf, model_path)
    joblib.dump(feature_cols, feat_path)
    joblib.dump(LABEL_MAP, label_map_path)

    metadata = {
        "model_type": "LightGBM Multi-class Classifier",
        "num_classes": 6,
        "classes": LABEL_MAP,
        "feature_count": len(feature_cols),
        "feature_names": feature_cols,
        "dataset_rows": len(df_feat),
        "test_accuracy": round(float(acc), 4),
        "test_f1_macro": round(float(f1_macro), 4),
        "binary_accuracy": round(float(binary_acc), 4),
        "training_time_sec": round(float(train_time), 2),
    }
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2, ensure_ascii=False)

    print(f"  [OK] Saved model to      : {model_path}")
    print(f"  [OK] Saved feature names  : {feat_path}")
    print(f"  [OK] Saved label map      : {label_map_path}")
    print(f"  [OK] Saved metadata       : {meta_path}")

    # Top Feature Importances
    importances = clf.feature_importances_
    top_indices = np.argsort(importances)[::-1][:10]
    print("\n  Top 10 Most Important Features:")
    for rank, idx in enumerate(top_indices, 1):
        print(f"    {rank:>2}. {feature_cols[idx]:<22}: {importances[idx]}")

    print("\n" + "=" * 65)
    print("  ALL DONE! Model ready for Web Application & Detector CLI.")
    print("=" * 65)


if __name__ == "__main__":
    main()

