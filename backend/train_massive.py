"""
Massive Offline Training Script for Anti-Phishing AI
This script is designed to run locally on your PC. It uses multiprocessing
to rapidly extract features from massive datasets (100k+ URLs).
"""
import os
import sys
import multiprocessing
import pandas as pd
import numpy as np
import datetime
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import accuracy_score, classification_report
from tqdm import tqdm

# Add current directory to path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(CURRENT_DIR)

from model import PhishingModel

MODEL_PATH = os.path.join(CURRENT_DIR, 'phishing_model.pkl')
EXTRACTED_FEATURES_PATH = os.path.join(CURRENT_DIR, 'massive_extracted_features.csv')

FEATURE_NAMES = [
    'url_length', 'dot_count', 'hyphen_count', 'at_count',
    'double_slash_count', 'has_ip', 'is_http', 'domain_entropy', 'suspicious_tld'
]

# Initialize globally for multiprocessing workers
pm = PhishingModel()

def extract_single(data):
    """Worker function for multiprocessing."""
    url, label = data
    try:
        features = pm.extract_features(url)
        # Return features + label
        return features + [label]
    except Exception:
        return None

def extract_features_in_parallel(df_urls, num_cores=None):
    """Use all CPU cores to extract features from URLs."""
    if num_cores is None:
        num_cores = multiprocessing.cpu_count()
        
    print(f"Starting parallel feature extraction using {num_cores} CPU cores...")
    
    data_tuples = list(zip(df_urls['url'], df_urls['label']))
    results = []
    
    # We use chunksize to make it faster
    with multiprocessing.Pool(processes=num_cores) as pool:
        # Wrap with tqdm for a nice progress bar
        for res in tqdm(pool.imap_unordered(extract_single, data_tuples, chunksize=100), total=len(data_tuples)):
            if res is not None:
                results.append(res)
                
    # Save to CSV so we don't lose progress if something crashes
    columns = FEATURE_NAMES + ['label']
    df_features = pd.DataFrame(results, columns=columns)
    df_features.to_csv(EXTRACTED_FEATURES_PATH, index=False)
    print(f"\nSaved {len(df_features)} extracted features to {EXTRACTED_FEATURES_PATH}")
    return df_features

def train_massive(csv_path="massive_dataset.csv"):
    print(f"\n{'='*60}")
    print(f"MASSIVE TRAINING STARTED: {datetime.datetime.now().isoformat()}")
    print(f"{'='*60}\n")
    
    if os.path.exists(EXTRACTED_FEATURES_PATH):
        print(f"Found existing extracted features: {EXTRACTED_FEATURES_PATH}")
        print("Skipping extraction step to save time.")
        df_features = pd.read_csv(EXTRACTED_FEATURES_PATH)
    else:
        # 1. Load Raw Dataset
        if not os.path.exists(csv_path):
            print(f"ERROR: Could not find raw dataset '{csv_path}'!")
            print("Please download a massive CSV and name it 'massive_dataset.csv'")
            return
            
        print(f"Loading massive raw dataset from {csv_path}...")
        df = pd.read_csv(csv_path)
        
        # Ensure it has 'url' and 'label' columns
        if 'url' not in df.columns or 'label' not in df.columns:
            if 'status' in df.columns:
                df['label'] = df['status'].replace({'legitimate': 0, 'phishing': 1})
            elif 'type' in df.columns:
                # Kaggle 650k dataset uses 'type': benign, defacement, phishing, malware
                print("Detected Kaggle 'type' column schema. Mapping benign->0, malicious->1.")
                df['label'] = df['type'].apply(lambda x: 0 if x == 'benign' else 1)
            else:
                print("ERROR: CSV must have 'url' and 'label' (or 'status'/'type') columns.")
                return
                
        df = df.dropna(subset=['label', 'url'])
        df['label'] = df['label'].astype(int)
        
        print(f"Loaded {len(df)} raw URLs.")
        
        # 2. Extract Features in Parallel
        df_features = extract_features_in_parallel(df)
        
    if len(df_features) == 0:
        print("ERROR: No features extracted.")
        return
        
    X = df_features[FEATURE_NAMES].values
    y = df_features['label'].values
    
    print(f"\nFeature matrix: {X.shape[0]} samples × {X.shape[1]} features")
    print(f"Label distribution: Safe={sum(y==0)}, Phishing={sum(y==1)}")
    
    # 3. Train Model
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print("\nTraining Random Forest Classifier (300 trees)...")
    model = RandomForestClassifier(
        n_estimators=200, # Decreased to keep model size under 100MB GitHub limit
        max_depth=25,
        min_samples_split=5,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1  # Use all CPU cores
    )
    model.fit(X_train, y_train)

    # 4. Evaluate
    preds = model.predict(X_test)
    acc = accuracy_score(y_test, preds)
    report = classification_report(y_test, preds, target_names=['Safe', 'Phishing'])

    print(f"\nModel Accuracy: {acc * 100:.2f}%")
    print(f"\nClassification Report:\n{report}")

    # 5. Save Model
    if os.path.exists(MODEL_PATH):
        backup_path = MODEL_PATH + '.massive_backup'
        try:
            os.replace(MODEL_PATH, backup_path)
        except OSError:
            pass

    joblib.dump(model, MODEL_PATH, compress=3)
    print(f"\nNew massive model saved to {MODEL_PATH} ({os.path.getsize(MODEL_PATH)} bytes)")
    
    print(f"\n{'='*60}")
    print(f"MASSIVE TRAINING COMPLETE!")
    print("You can now run 'git add . && git commit -m \"Massive model\" && git push' to deploy it.")
    print(f"{'='*60}\n")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Train model on massive raw URL data")
    parser.add_argument("--csv", default="massive_dataset.csv", help="Path to massive raw CSV file")
    args = parser.parse_args()
    
    train_massive(args.csv)
