print("Starting training script...")
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import joblib
import re
import random
from urllib.parse import urlparse

# --- 1. Dataset Generation (Synthetic) ---
def generate_dataset(n=2000):
    print("Generating synthetic dataset...")
    data = []
    
    # Trusted Domains
    trusted = ['google', 'facebook', 'amazon', 'youtube', 'wikipedia', 'twitter', 'linkedin', 'netflix', 'microsoft', 'apple']
    tlds = ['.com', '.org', '.net', '.edu', '.gov']
    
    # Phishing Keywords
    bad_words = ['secure', 'login', 'account', 'verify', 'update', 'banking', 'confirm', 'wallet', 'bonus']
    bad_tlds = ['.xyz', '.top', '.club', '.info', '.site']

    for _ in range(n // 2):
        # Generate Safe URL
        domain = random.choice(trusted)
        tld = random.choice(tlds)
        path = "".join(random.choices("abcdefghijklmnopqrstuvwxyz/", k=random.randint(5, 15)))
        url = f"https://www.{domain}{tld}/{path}"
        data.append((url, 0)) # 0 = Safe

    for _ in range(n // 2):
        # Generate Phishing URL
        target = random.choice(trusted) # impersonated
        bad = random.choice(bad_words)
        tld = random.choice(bad_tlds)
        
        # Structure: http://google-secure-login.xyz
        url = f"http://{target}-{bad}{tld}/login"
        data.append((url, 1)) # 1 = Phishing

    df = pd.DataFrame(data, columns=['url', 'label'])
    return df

# --- 2. Feature Extraction ---
def extract_features(url):
    features = []
    
    # 1. Length of URL
    features.append(len(url))
    
    # 2. Count of dots
    features.append(url.count('.'))
    
    # 3. Count of hyphens
    features.append(url.count('-'))
    
    # 4. Count of special chars (@, //)
    features.append(url.count('@'))
    features.append(url.count('//'))
    
    # 5. Has IP address?
    ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    features.append(1 if re.search(ip_pattern, url) else 0)
    
    # 6. Has HTTP (insecure)?
    features.append(1 if 'https' not in url else 0)
    
    return features

# --- 3. Training ---
def train(n_samples=2000):
    df = generate_dataset(n=n_samples)
    
    print("Extracting features...")
    X = np.array([extract_features(url) for url in df['url']])
    y = df['label'].values
    
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
    
    # Save
    # Save
    import os
    current_dir = os.path.dirname(os.path.abspath(__file__))
    model_path = os.path.join(current_dir, 'phishing_model.pkl')
    print(f"Saving model to {model_path}...")
    joblib.dump(model, model_path)
    print("Done!")

if __name__ == "__main__":
    train()
