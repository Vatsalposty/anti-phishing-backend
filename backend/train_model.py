print("Starting training script...")
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import joblib
import os
import sys

# Add current directory to path to import model.py
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from model import PhishingModel

# --- 1. Load Real Dataset ---
def load_dataset():
    print("Loading 'dataset_phishing.csv'...")
    try:
        df = pd.read_csv('dataset_phishing.csv')
        # Expecting columns 'url' and 'status' (legitimate/phishing)
        # If the file has different properties, we might need to adjust.
        # Based on inspection: url, ..., status
        
        # Keep only necessary columns
        df = df[['url', 'status']]
        
        # Map labels: legitimate -> 0, phishing -> 1
        df['label'] = df['status'].map({'legitimate': 0, 'phishing': 1})
        
        # Drop rows where mapping failed (if any)
        df = df.dropna(subset=['label'])
        
        print(f"Loaded {len(df)} samples.")
        print(f"Distribution:\n{df['label'].value_counts()}")
        
        return df
    except Exception as e:
        print(f"Error loading CSV: {e}")
        print("Falling back to synthetic generation...")
        return generate_synthetic_dataset()

def generate_synthetic_dataset(n=100):
    # Minimal fallback just to prevent crash if CSV is missing
    data = [("http://google.com", 0), ("http://phish-secure-login.xyz", 1)]
    return pd.DataFrame(data, columns=['url', 'label'])

# --- 2. Training ---
def train(n_samples=None): # n_samples argument kept for compatibility but ignored for real data
    df = load_dataset()
    
    print("Extracting features using PhishingModel logic...")
    pm = PhishingModel()
    
    # Use the EXACT same feature extraction as the live backend
    # This prevents "feature mismatch" errors
    X = []
    y = []
    
    failed_count = 0
    for index, row in df.iterrows():
        try:
            features = pm.extract_features(row['url'])
            X.append(features)
            y.append(row['label'])
        except Exception as e:
            failed_count += 1
            
    if failed_count > 0:
        print(f"Skipped {failed_count} URLs due to extraction errors.")

    X = np.array(X)
    y = np.array(y)
    
    # Split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # Train
    print("Training Random Forest Classifier...")
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)
    
    # Validate
    preds = model.predict(X_test)
    acc = accuracy_score(y_test, preds)
    print(f"Model Accuracy: {acc * 100:.2f}%")
    print("\nClassification Report:\n", classification_report(y_test, preds))
    
    # Save
    import os
    current_dir = os.path.dirname(os.path.abspath(__file__))
    model_path = os.path.join(current_dir, 'phishing_model.pkl')
    print(f"Saving model to {model_path}...")
    joblib.dump(model, model_path)
    print("Done! Model saved.")

if __name__ == "__main__":
    train()
