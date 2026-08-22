import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import joblib
import argparse
import os
import time
import xgboost as xgb

def train_xgboost(csv_path="massive_extracted_features.csv"):
    start_time = time.time()
    print("=" * 60)
    print(f"XGBOOST MASSIVE TRAINING STARTED: {time.time()}")
    print("=" * 60)

    if not os.path.exists(csv_path):
        print(f"Error: {csv_path} not found. Please run train_massive.py first to generate the features.")
        return False

    print(f"\nLoading existing features from: {csv_path}")
    df = pd.read_csv(csv_path)

    # Convert features to numeric
    feature_columns = ['url_length', 'dot_count', 'hyphen_count', 'at_count', 'double_slash_count', 'has_ip', 'is_http', 'domain_entropy', 'suspicious_tld']
    for col in feature_columns:
        df[col] = pd.to_numeric(df[col], errors='coerce')

    # Drop missing values
    df = df.dropna()

    X = df[feature_columns].values
    y = df['label'].values

    # Map labels to integers for XGBoost
    # XGBoost requires labels to be strictly integers 0, 1, 2...
    # If they are already numeric, just ensure they are int
    y_mapped = np.array([int(l) if str(l).isdigit() else {"safe": 0, "phishing": 1, "suspicious": 1}.get(str(l).lower(), 1) for l in y])

    print(f"\nFeature matrix: {len(X)} samples × {X.shape[1]} features")
    safe_count = sum(y_mapped == 0)
    phishing_count = sum(y_mapped == 1)
    print(f"Label distribution: Safe={safe_count}, Phishing={phishing_count}")

    # Split dataset
    X_train, X_test, y_train, y_test = train_test_split(X, y_mapped, test_size=0.2, random_state=42)

    print("\nTraining XGBoost Classifier...")
    # Initialize XGBoost
    model = xgb.XGBClassifier(
        n_estimators=300,
        max_depth=10,
        learning_rate=0.1,
        n_jobs=-1,
        random_state=42,
        eval_metric="logloss"
    )

    model.fit(X_train, y_train)

    # Evaluate
    print("\nEvaluating model...")
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    
    print(f"\nModel Accuracy: {accuracy * 100:.2f}%")
    print("\nClassification Report:")
    target_names = ["Safe (0)", "Phishing (1)"]
    print(classification_report(y_test, y_pred, target_names=target_names))

    # Save model securely in JSON format (prevents pickle RCE vulnerabilities)
    model_path = "xgboost_model.json"
    model.save_model(model_path)
    
    file_size = os.path.getsize(model_path)
    print(f"\nNew XGBoost model saved to {os.path.abspath(model_path)} ({file_size} bytes)")
    
    print("\n" + "=" * 60)
    print("XGBOOST TRAINING COMPLETE!")
    print("=" * 60)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train XGBoost Model on Massive Dataset")
    parser.add_argument("--csv", type=str, default="massive_extracted_features.csv", help="Path to extracted features CSV")
    args = parser.parse_args()
    
    train_xgboost(args.csv)
