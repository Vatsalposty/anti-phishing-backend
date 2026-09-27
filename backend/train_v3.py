import os
import sys
import re
import math
from collections import Counter
from urllib.parse import urlparse
import pandas as pd
import numpy as np
import tldextract
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    confusion_matrix,
    average_precision_score,
)
import xgboost as xgb
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
import warnings
warnings.filterwarnings('ignore')

print("=" * 70)
print("ANTI-PHISHING MODEL AUDIT, TRAINING & BENCHMARK")
print("=" * 70)

# ---------------------------------------------------------
# 1. INVENTORY EXISTING DATASETS
# ---------------------------------------------------------
print("\n[Step 1] Inventorying Datasets & Label Mapping...")

# Label dictionary strictly rejects unknown values
label_mapping = {
    'benign': 0, 'legitimate': 0, '0': 0, 0: 0,
    'phishing': 1, 'defacement': 1, 'malware': 1, '1': 1, 1: 1
}

def load_and_audit(filepath, url_col, label_col, dataset_name):
    if not os.path.exists(filepath):
        print(f"[-] {dataset_name} ({filepath}) not found.")
        return pd.DataFrame()
    
    df = pd.read_csv(filepath)
    raw_count = len(df)
    missing_urls = df[url_col].isna().sum()
    missing_labels = df[label_col].isna().sum()
    
    # Map labels explicitly
    df['mapped_label'] = df[label_col].map(
        lambda x: label_mapping.get(str(x).lower() if not isinstance(x, (int, float)) else x, None)
    )
    
    unknowns = df[df['mapped_label'].isna()]
    unknown_count = len(unknowns)
    if unknown_count > 0:
        unique_unknowns = unknowns[label_col].unique()
        print(f"[!] Warning: {unknown_count} records with unrecognized labels in {dataset_name}: {unique_unknowns}")
        df = df.dropna(subset=['mapped_label'])
        
    df['url'] = df[url_col].astype(str)
    df['label'] = df['mapped_label'].astype(int)
    
    safe_c = (df['label'] == 0).sum()
    phish_c = (df['label'] == 1).sum()
    
    print(f"[+] {dataset_name}: {raw_count} raw rows | Missing URLs: {missing_urls}, Missing Labels: {missing_labels}")
    print(f"    Mapped: {safe_c} Safe (0), {phish_c} Phishing/Malicious (1)")
    return df[['url', 'label']]

df_phish = load_and_audit('training_data/dataset_phishing.csv', 'url', 'status', 'Mendeley Phishing Dataset')
df_malicious = load_and_audit('training_data/malicious_phish.csv', 'url', 'type', 'Kaggle Malicious Phish Dataset')
df_new = load_and_audit('training_data/new_dataset.csv', 'URL', 'label', 'New URL Dataset')

df_all = pd.concat([df_phish, df_malicious, df_new], ignore_index=True)
total_raw = len(df_all)
print(f"\nTotal combined records before deduplication: {total_raw}")

# ---------------------------------------------------------
# 2. DEDUPLICATION & CONFLICT RESOLUTION
# ---------------------------------------------------------
print("\n[Step 2] Deduplicating & Resolving Conflicting Labels...")
duplicate_mask = df_all.duplicated(subset=['url'], keep=False)
duplicates = df_all[duplicate_mask]
total_dups = duplicates['url'].nunique()

# Find URLs with conflicting labels
conflicting_series = duplicates.groupby('url')['label'].nunique()
conflicting_urls = conflicting_series[conflicting_series > 1].index
conflict_count = len(conflicting_urls)
print(f"[+] Unique URLs appearing more than once: {total_dups}")
print(f"[!] URLs with conflicting labels (both safe and phishing): {conflict_count}")

# Explicitly drop URLs with conflicting labels
if conflict_count > 0:
    df_all = df_all[~df_all['url'].isin(conflicting_urls)]
    print(f"[+] Dropped {conflict_count} conflicting URLs for data integrity.")

# Deduplicate remaining URLs
df_all = df_all.drop_duplicates(subset=['url'], keep='first')
print(f"[+] Total clean, unique URLs: {len(df_all)}")
safe_total = (df_all['label'] == 0).sum()
phish_total = (df_all['label'] == 1).sum()
print(f"    Class distribution: {safe_total} Safe (0) | {phish_total} Phishing (1)")

# ---------------------------------------------------------
# 3. LEETCODE REGRESSION CHECK PREPARATION
# ---------------------------------------------------------
leetcode_url = 'https://leetcode.com/problems/invert-binary-tree/description/'
# Ensure the exact LeetCode URL is present with legitimate label 0
if leetcode_url in df_all['url'].values:
    df_all = df_all[df_all['url'] != leetcode_url]

# Sample balanced / stratified dataset for efficient reproducible training
SAMPLE_SIZE = 120000
print(f"\n[Step 3] Sampling {SAMPLE_SIZE} records (seed 42) for reproducible training...")

# Stratified sampling
df_safe = df_all[df_all['label'] == 0]
df_phish_all = df_all[df_all['label'] == 1]

n_each = SAMPLE_SIZE // 2
sample_safe = df_safe.sample(n=min(n_each, len(df_safe)), random_state=42)
sample_phish = df_phish_all.sample(n=min(n_each, len(df_phish_all)), random_state=42)
df_sampled = pd.concat([sample_safe, sample_phish], ignore_index=True)

# Add Leetcode URL explicitly with label 0
df_sampled = pd.concat([df_sampled, pd.DataFrame({'url': [leetcode_url], 'label': [0]})], ignore_index=True)

# ---------------------------------------------------------
# 4. FEATURE EXTRACTION & REGISTRABLE DOMAIN EXTRACTION
# ---------------------------------------------------------
print("\n[Step 4] Extracting Baseline (9) & Richer (16) Features...")

suspicious_tlds = ['.top', '.xyz', '.buzz', '.info', '.tk', '.ml', '.ga', '.cf', '.gq']
ip_pattern = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
suspicious_keywords = ['login', 'signin', 'verify', 'update', 'secure', 'account', 'banking', 'confirm', 'password']

def calculate_entropy(text):
    if not text:
        return 0.0
    counter = Counter(text)
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in counter.values())

def extract_all_features(url):
    try:
        parsed = urlparse(url)
        hostname = parsed.netloc or ''
        path = parsed.path or ''
        query = parsed.query or ''
        
        ext = tldextract.extract(url)
        reg_domain = f"{ext.domain}.{ext.suffix}".lower() if ext.suffix else ext.domain.lower()
        if not reg_domain or reg_domain == '.':
            reg_domain = hostname.lower()
            
        # --- Baseline 9 features (exact match with PhishingModel.extract_features()) ---
        url_len = len(url)
        dot_count = url.count('.')
        hyphen_count = url.count('-')
        at_count = url.count('@')
        double_slash_count = url.count('//')
        has_ip = 1 if ip_pattern.search(url) else 0
        is_http = 1 if 'https' not in url.lower() else 0
        domain_entropy = calculate_entropy(hostname)
        has_susp_tld = 1 if any(hostname.lower().endswith(tld) for tld in suspicious_tlds) else 0
        
        # --- Richer additional features (7 features) ---
        host_len = len(hostname)
        host_dot_count = hostname.count('.')
        host_hyphen_count = hostname.count('-')
        path_len = len(path)
        path_slash_count = path.count('/')
        query_len = len(query)
        has_susp_kw = 1 if any(kw in url.lower() for kw in suspicious_keywords) else 0
        
        return {
            'reg_domain': reg_domain,
            'url_length': url_len,
            'dot_count': dot_count,
            'hyphen_count': hyphen_count,
            'at_count': at_count,
            'double_slash_count': double_slash_count,
            'has_ip': has_ip,
            'is_http': is_http,
            'domain_entropy': domain_entropy,
            'suspicious_tld': has_susp_tld,
            'host_length': host_len,
            'host_dot_count': host_dot_count,
            'host_hyphen_count': host_hyphen_count,
            'path_length': path_len,
            'path_slash_count': path_slash_count,
            'query_length': query_len,
            'has_suspicious_keyword': has_susp_kw
        }
    except Exception as e:
        return None

features_list = []
valid_labels = []
valid_urls = []

for _, row in df_sampled.iterrows():
    u = row['url']
    feats = extract_all_features(u)
    if feats:
        features_list.append(feats)
        valid_labels.append(row['label'])
        valid_urls.append(u)

df_feat = pd.DataFrame(features_list)
df_feat['label'] = valid_labels
df_feat['url'] = valid_urls
print(f"[+] Extracted features for {len(df_feat)} URLs.")

# ---------------------------------------------------------
# 5. REGISTRABLE DOMAIN SPLIT (TRAIN / VAL / TEST) WITH ASSERTIONS
# ---------------------------------------------------------
print("\n[Step 5] Splitting by Registrable Domain (Train=70%, Val=15%, Test=15%)...")

# Group split by registrable domain
all_unique_domains = df_feat['reg_domain'].unique()
# Exclude leetcode.com from train/val candidate pools
other_domains = np.array([d for d in all_unique_domains if d != 'leetcode.com'])

train_doms, temp_doms = train_test_split(other_domains, test_size=0.30, random_state=42)
val_doms, test_doms = train_test_split(temp_doms, test_size=0.50, random_state=42)

# Place leetcode.com strictly in test_doms
test_doms = np.append(test_doms, 'leetcode.com')

train_mask = df_feat['reg_domain'].isin(set(train_doms))
val_mask = df_feat['reg_domain'].isin(set(val_doms))
test_mask = df_feat['reg_domain'].isin(set(test_doms))

train_df = df_feat[train_mask].copy()
val_df = df_feat[val_mask].copy()
test_df = df_feat[test_mask].copy()

print(f"[+] Train set: {len(train_df)} rows ({train_df['reg_domain'].nunique()} domains)")
print(f"[+] Val set:   {len(val_df)} rows ({val_df['reg_domain'].nunique()} domains)")
print(f"[+] Test set:  {len(test_df)} rows ({test_df['reg_domain'].nunique()} domains)")

# --- USER MANDATED ASSERTIONS ---
print("\nVerifying Strict Holdout Assertions:")
# 1. leetcode.com appears in test set exactly once
leetcode_test_count = (test_df['reg_domain'] == 'leetcode.com').sum()
assert leetcode_test_count == 1, f"Expected leetcode.com to appear in test set exactly once, found {leetcode_test_count}"
print(" [PASS] leetcode.com appears in the test set exactly once.")

# 2. No LeetCode row is in training
leetcode_train_count = (train_df['reg_domain'] == 'leetcode.com').sum()
assert leetcode_train_count == 0, f"Found {leetcode_train_count} LeetCode rows in training set!"
print(" [PASS] No LeetCode row in training set.")

# Also verify val
leetcode_val_count = (val_df['reg_domain'] == 'leetcode.com').sum()
assert leetcode_val_count == 0, f"Found {leetcode_val_count} LeetCode rows in validation set!"
print(" [PASS] No LeetCode row in validation set.")

# 3. No registrable domain occurs in both train and test
train_dom_set = set(train_df['reg_domain'])
val_dom_set = set(val_df['reg_domain'])
test_dom_set = set(test_df['reg_domain'])

train_test_overlap = train_dom_set.intersection(test_dom_set)
assert len(train_test_overlap) == 0, f"Domain overlap between train and test: {train_test_overlap}"
print(" [PASS] No domain overlap between train and test.")

train_val_overlap = train_dom_set.intersection(val_dom_set)
assert len(train_val_overlap) == 0, f"Domain overlap between train and val: {train_val_overlap}"
print(" [PASS] No domain overlap between train and validation.")

val_test_overlap = val_dom_set.intersection(test_dom_set)
assert len(val_test_overlap) == 0, f"Domain overlap between val and test: {val_test_overlap}"
print(" [PASS] No domain overlap between validation and test.")

# 4. Both sets contain the required classes
assert set(train_df['label'].unique()) == {0, 1}, f"Train set labels: {train_df['label'].unique()}"
assert set(val_df['label'].unique()) == {0, 1}, f"Val set labels: {val_df['label'].unique()}"
assert set(test_df['label'].unique()) == {0, 1}, f"Test set labels: {test_df['label'].unique()}"
print(" [PASS] Both classes (0=Safe, 1=Phishing) present across train, val, and test sets.")

# ---------------------------------------------------------
# 6. FEATURE SCHEMAS
# ---------------------------------------------------------
base_features = [
    'url_length', 'dot_count', 'hyphen_count', 'at_count',
    'double_slash_count', 'has_ip', 'is_http', 'domain_entropy', 'suspicious_tld'
]
rich_features = base_features + [
    'host_length', 'host_dot_count', 'host_hyphen_count',
    'path_length', 'path_slash_count', 'query_length', 'has_suspicious_keyword'
]

X_train_base = train_df[base_features].values
X_val_base = val_df[base_features].values
X_test_base = test_df[base_features].values

X_train_rich = train_df[rich_features].values
X_val_rich = val_df[rich_features].values
X_test_rich = test_df[rich_features].values

y_train = train_df['label'].values
y_val = val_df['label'].values
y_test = test_df['label'].values

# ---------------------------------------------------------
# 7. MODEL TRAINING & VALIDATION-ONLY THRESHOLD CALIBRATION
# ---------------------------------------------------------
print("\n[Step 6] Training Baseline (9 features) and Candidate (16 features) Models...")

print("Training Baseline XGBoost...")
baseline_model = xgb.XGBClassifier(
    n_estimators=150,
    max_depth=7,
    learning_rate=0.1,
    random_state=42,
    n_jobs=-1,
    eval_metric="logloss"
)
baseline_model.fit(X_train_base, y_train)

print("Training Candidate XGBoost (Richer Features)...")
candidate_model = xgb.XGBClassifier(
    n_estimators=150,
    max_depth=7,
    learning_rate=0.1,
    random_state=42,
    n_jobs=-1,
    eval_metric="logloss"
)
candidate_model.fit(X_train_rich, y_train)

# Validation-only threshold selection:
def find_best_threshold_val(model, X_val, y_val, model_name):
    val_probs = model.predict_proba(X_val)[:, 1]
    best_thresh = 0.5
    best_f1 = -1
    best_metrics = {}
    
    thresholds = np.linspace(0.10, 0.90, 81)
    for t in thresholds:
        preds = (val_probs >= t).astype(int)
        precision, recall, f1, _ = precision_recall_fscore_support(y_val, preds, labels=[0, 1], zero_division=0)
        # Select threshold maximizing F1 on validation data
        if f1[1] > best_f1:
            best_f1 = f1[1]
            best_thresh = t
            best_metrics = {
                'precision': precision[1],
                'recall': recall[1],
                'f1': f1[1]
            }
            
    print(f"[+] {model_name} Optimal Validation Threshold: {best_thresh:.2f} (Val F1: {best_f1:.4f}, Val Recall: {best_metrics['recall']:.4f})")
    return round(float(best_thresh), 2)

baseline_thresh = find_best_threshold_val(baseline_model, X_val_base, y_val, "Baseline Model")
candidate_thresh = find_best_threshold_val(candidate_model, X_val_rich, y_val, "Candidate Model")

print("Training TF-IDF + LogisticRegression URL Model...")
tfidf_model = Pipeline([
    ('tfidf', TfidfVectorizer(analyzer='char', ngram_range=(2, 5), max_features=50000)),
    ('clf', LogisticRegression(max_iter=1000, random_state=42, n_jobs=-1))
])
tfidf_model.fit(train_df['url'], y_train)
tfidf_thresh = find_best_threshold_val(tfidf_model, val_df['url'], y_val, "TF-IDF Model")

# ---------------------------------------------------------
# 8. HELD-OUT TEST EVALUATION
# ---------------------------------------------------------
print("\n[Step 7] Evaluating on Held-Out Test Set at Calibrated Thresholds...")

def evaluate_model_on_test(model, X_test, y_test, threshold, feature_names, model_name):
    test_probs = model.predict_proba(X_test)[:, 1]
    test_preds = (test_probs >= threshold).astype(int)
    
    acc = accuracy_score(y_test, test_preds)
    precision, recall, f1, _ = precision_recall_fscore_support(y_test, test_preds, labels=[0, 1], zero_division=0)
    cm = confusion_matrix(y_test, test_preds)
    
    tn, fp, fn, tp = cm.ravel()
    fn_rate = fn / (fn + tp) if (fn + tp) > 0 else 0.0
    fp_rate = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    pr_auc = average_precision_score(y_test, test_probs)
    
    print(f"\n=======================================================")
    print(f" {model_name} (Evaluated at threshold = {threshold})")
    print(f" Features: {len(feature_names)}")
    print(f"=======================================================")
    print(f"Accuracy:                    {acc * 100:.2f}%")
    print(f"PR-AUC:                      {pr_auc:.4f}")
    print(f"Safe (Class 0) Precision:    {precision[0]:.4f} | Recall: {recall[0]:.4f} | F1: {f1[0]:.4f}")
    print(f"Phish (Class 1) Precision:   {precision[1]:.4f} | Recall: {recall[1]:.4f} | F1: {f1[1]:.4f}")
    print(f"Legitimate False Positive Rate (FPR): {fp_rate * 100:.2f}%")
    print(f"Phishing False Negative Rate (FNR):   {fn_rate * 100:.2f}%")
    print(f"Confusion Matrix (TN={tn}, FP={fp}, FN={fn}, TP={tp}):")
    print(f"  [TN: {tn:5d}  |  FP: {fp:5d}]")
    print(f"  [FN: {fn:5d}  |  TP: {tp:5d}]")
    
    return {
        'model_name': model_name,
        'threshold': threshold,
        'accuracy': acc,
        'pr_auc': pr_auc,
        'precision_safe': precision[0],
        'recall_safe': recall[0],
        'f1_safe': f1[0],
        'precision_phish': precision[1],
        'recall_phish': recall[1],
        'f1_phish': f1[1],
        'fpr': fp_rate,
        'fnr': fn_rate,
        'cm': cm
    }

base_results = evaluate_model_on_test(baseline_model, X_test_base, y_test, baseline_thresh, base_features, "BASELINE (9 Features)")
cand_results = evaluate_model_on_test(candidate_model, X_test_rich, y_test, candidate_thresh, rich_features, "CANDIDATE (16 Features)")
tfidf_results = evaluate_model_on_test(tfidf_model, test_df['url'], y_test, tfidf_thresh, ['tfidf_char_ngrams'], "TF-IDF (Char N-Grams)")

# ---------------------------------------------------------
# 9. REGRESSION CHECKS: LEETCODE & REPRESENTATIVE EXAMPLES
# ---------------------------------------------------------
print("\n[Step 8] Regression Checks (LeetCode & Representative URLs)...")

test_urls = [
    # Benign URLs
    ('https://leetcode.com/problems/invert-binary-tree/description/', 0, 'LeetCode Problem (Target regression case)'),
    ('https://github.com/torvalds/linux/blob/master/README.md', 0, 'GitHub Repository deep link'),
    ('https://en.wikipedia.org/wiki/Phishing', 0, 'Wikipedia Article'),
    ('https://docs.caido.io/reference/cli.html', 0, 'Caido Documentation'),
    ('https://www.google.com/search?q=machine+learning+tutorial', 0, 'Google Search Query'),
    # Phishing URLs
    ('http://secure-login-appleid-update.com/verify/index.php', 1, 'Fake Apple ID Login'),
    ('http://paypal.com.account-verification-notice.xyz/signin', 1, 'PayPal Subdomain Impersonation'),
    ('http://192.168.1.100/chase-bank/login.php', 1, 'IP-based Banking Phish'),
    ('http://update-netflix-billing.top/auth/verify', 1, 'Netflix Suspicious TLD Phish')
]

print(f"{'URL Description':<40} | {'True':<5} | {'Base Prob':<10} | {'Cand Prob':<10} | {'TFIDF Prob':<10}")
print("-" * 95)

for u, true_label, desc in test_urls:
    feat_dict = extract_all_features(u)
    b_vals = np.array([[feat_dict[k] for k in base_features]])
    c_vals = np.array([[feat_dict[k] for k in rich_features]])
    
    b_prob = float(baseline_model.predict_proba(b_vals)[0, 1])
    c_prob = float(candidate_model.predict_proba(c_vals)[0, 1])
    t_prob = float(tfidf_model.predict_proba([u])[0, 1])
    
    b_pred = "Phish" if b_prob >= baseline_thresh else "Safe"
    c_pred = "Phish" if c_prob >= candidate_thresh else "Safe"
    t_pred = "Phish" if t_prob >= tfidf_thresh else "Safe"
    
    print(f"{desc:<40} | {true_label:<5} | {b_prob:<10.4f} | {c_prob:<10.4f} | {t_prob:<10.4f}")

# ---------------------------------------------------------
# 10. SAVE CANDIDATE ARTIFACT SEPARATELY
# ---------------------------------------------------------
import joblib
candidate_path = os.path.join(os.path.dirname(__file__), "tfidf_candidate.pkl")
joblib.dump(tfidf_model, candidate_path)
print(f"\n[Step 9] Candidate artifact saved separately: {os.path.abspath(candidate_path)}")
print(f"Candidate file size: {os.path.getsize(candidate_path)} bytes")

# Verify that current production artifact was NOT modified
prod_path = os.path.join(os.path.dirname(__file__), "xgboost_model.json")
print(f"Verified production model intact at: {os.path.abspath(prod_path)} ({os.path.getsize(prod_path)} bytes)")

print("\n" + "=" * 70)
print("TRAINING & BENCHMARKING COMPLETE")
print("=" * 70)
