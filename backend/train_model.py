"""
Anti-Phishing AI Guard — Model Training Script
Merges all available datasets for maximum training data.
Can be run standalone or triggered via the /retrain API endpoint.
"""
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import accuracy_score, classification_report
import joblib
import os
import sys
import datetime

# Add current directory to path to import model.py
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(CURRENT_DIR, 'phishing_model.pkl')
TRAINING_LOG_PATH = os.path.join(CURRENT_DIR, 'training_log.txt')

FEATURE_NAMES = [
    'url_length', 'dot_count', 'hyphen_count', 'at_count',
    'double_slash_count', 'has_ip', 'is_http', 'domain_entropy', 'suspicious_tld'
]


def load_dataset_primary():
    """Load the primary dataset (dataset_phishing.csv) — ~11,430 URLs."""
    path = os.path.join(CURRENT_DIR, 'dataset_phishing.csv')
    if not os.path.exists(path):
        print("Primary dataset not found.")
        return pd.DataFrame(columns=['url', 'label'])

    try:
        df = pd.read_csv(path)
        df = df[['url', 'status']]
        df['label'] = df['status'].replace({'legitimate': 0, 'phishing': 1})  # type: ignore
        df = df[df['label'].notna()]  # type: ignore
        df['label'] = df['label'].astype(int)
        print(f"Primary dataset: {len(df)} samples")
        return df[['url', 'label']]
    except Exception as e:
        print(f"Error loading primary dataset: {e}")
        return pd.DataFrame(columns=['url', 'label'])


def load_dataset_secondary():
    """Load the secondary dataset (Phishing_Legitimate_full.csv) — ~10,000 URLs.
    This dataset doesn't have raw URLs, only pre-extracted features.
    We can't use it for URL-based feature extraction, but we note it exists."""
    path = os.path.join(CURRENT_DIR, 'Phishing_Legitimate_full.csv')
    if not os.path.exists(path):
        print("Secondary dataset not found.")
        return None

    try:
        df = pd.read_csv(path)
        # This dataset has pre-computed features + CLASS_LABEL (0=legitimate, 1=phishing)
        # It does NOT have raw URLs, so we return it separately for direct feature use
        print(f"Secondary dataset: {len(df)} samples (pre-extracted features)")
        return df
    except Exception as e:
        print(f"Error loading secondary dataset: {e}")
        return None


def load_user_reported_urls():
    """Load user-reported phishing URLs from Firebase (if available).
    This creates a feedback loop where user reports improve the model."""
    try:
        import firebase_admin
        from firebase_admin import firestore

        # Only works if Firebase is already initialized
        if not firebase_admin._apps:
            return pd.DataFrame(columns=['url', 'label'])

        db = firestore.client()
        reports = db.collection('user_reports').stream()

        urls = []
        for doc in reports:
            data = doc.to_dict()
            if data and data.get('url'):
                urls.append({'url': data['url'], 'label': 1})  # User-reported = phishing

        if urls:
            df = pd.DataFrame(urls)
            print(f"User-reported URLs: {len(df)} samples")
            return df
        return pd.DataFrame(columns=['url', 'label'])
    except Exception:
        return pd.DataFrame(columns=['url', 'label'])


def train(n_samples=None):
    """Train the phishing detection model using all available data."""
    print(f"\n{'='*60}")
    print(f"TRAINING STARTED: {datetime.datetime.now().isoformat()}")
    print(f"{'='*60}\n")

    # Lazy import to avoid circular dependency during model loading
    from model import PhishingModel

    # --- 1. Load all datasets ---
    df_primary = load_dataset_primary()
    df_secondary = load_dataset_secondary()
    df_user = load_user_reported_urls()

    # Merge URL-based datasets
    df_urls = pd.concat([df_primary, df_user], ignore_index=True)  # type: ignore
    df_urls = df_urls[~df_urls.duplicated(subset=['url'])]

    print(f"\nTotal unique URL samples: {len(df_urls)}")
    if len(df_urls) < 10:
        print("ERROR: Not enough training data. Aborting.")
        return False

    # --- 2. Extract features from URLs ---
    print("Extracting features from URLs...")
    pm = PhishingModel()

    X_url = []
    y_url = []
    failed_count = 0

    for _, row in df_urls.iterrows():
        try:
            features = pm.extract_features(row['url'])
            X_url.append(features)
            y_url.append(int(float(str(row['label']))))
        except Exception:
            failed_count += 1

    if failed_count > 0:
        print(f"Skipped {failed_count} URLs due to extraction errors.")

    X = np.array(X_url)
    y = np.array(y_url)

    print(f"Feature matrix: {X.shape[0]} samples × {X.shape[1]} features")
    print(f"Label distribution: Safe={sum(y==0)}, Phishing={sum(y==1)}")

    # --- 3. Train model ---
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print("\nTraining Random Forest Classifier (200 trees)...")
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=20,
        min_samples_split=5,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1  # Use all CPU cores
    )
    model.fit(X_train, y_train)

    # --- 4. Evaluate ---
    preds = model.predict(X_test)
    acc = accuracy_score(y_test, preds)
    report = classification_report(y_test, preds, target_names=['Safe', 'Phishing'])

    print(f"\nModel Accuracy: {acc * 100:.2f}%")
    print(f"\nClassification Report:\n{report}")

    # Cross-validation for robustness check
    cv_scores = cross_val_score(model, X, y, cv=5, scoring='accuracy')
    print(f"5-Fold CV Accuracy: {cv_scores.mean() * 100:.2f}% (±{cv_scores.std() * 100:.2f}%)")

    # Feature importance
    print("\nFeature Importance:")
    for name, importance in sorted(zip(FEATURE_NAMES, model.feature_importances_), key=lambda x: -x[1]):
        bar = "█" * int(importance * 50)
        print(f"  {name:25s} {importance:.4f} {bar}")

    # --- 5. Save model ---
    # Backup old model
    if os.path.exists(MODEL_PATH):
        backup_path = MODEL_PATH + '.backup'
        try:
            os.replace(MODEL_PATH, backup_path)
            print(f"Previous model backed up to {backup_path}")
        except OSError:
            pass

    joblib.dump(model, MODEL_PATH)
    print(f"\nNew model saved ({os.path.getsize(MODEL_PATH)} bytes)")

    # --- 6. Log training result ---
    log_entry = (
        f"{datetime.datetime.now().isoformat()} | "
        f"Samples={X.shape[0]} | "
        f"Accuracy={acc*100:.2f}% | "
        f"CV={cv_scores.mean()*100:.2f}%\n"
    )
    try:
        with open(TRAINING_LOG_PATH, 'a') as f:
            f.write(log_entry)
    except OSError:
        pass

    print(f"\n{'='*60}")
    print(f"TRAINING COMPLETE: {datetime.datetime.now().isoformat()}")
    print(f"{'='*60}\n")
    return True


if __name__ == "__main__":
    train()
