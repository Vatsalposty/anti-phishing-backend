import joblib
import os
import re
import numpy as np

class PhishingModel:
    def __init__(self):
        self.model = None
        current_dir = os.path.dirname(os.path.abspath(__file__))
        model_path = os.path.join(current_dir, 'phishing_model.pkl')
        
        try:
            if os.path.exists(model_path):
                self.model = joblib.load(model_path)
                print(f"Model loaded successfully from {model_path}")
            else:
                print(f"Warning: {model_path} not found. Running in Fallback Mode.")
        except Exception as e:
            print(f"Error loading model: {e}")

    def extract_features(self, url):
        features = []
        # 1. Length of URL
        features.append(len(url))
        # 2. Count of dots
        features.append(url.count('.'))
        # 3. Count of hyphens
        features.append(url.count('-'))
        # 4. Count of special chars
        features.append(url.count('@'))
        features.append(url.count('//'))
        # 5. Has IP address?
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        features.append(1 if re.search(ip_pattern, url) else 0)
        # 6. Has HTTP (insecure)?
        features.append(1 if 'https' not in url else 0)
        return features

    def predict(self, url: str):
        url_lower = url.lower()

        # 0. Allowlist (Hardware bypass for speed and safety)
        allowlist = ['google.com', 'gmail.com', 'youtube.com', 'facebook.com', 'amazon.com', 'wikipedia.org', 'chatgpt.com', 'openai.com', 'github.com', 'render.com']
        from urllib.parse import urlparse
        try:
            domain = urlparse(url).netloc
            if domain.startswith('www.'): domain = domain[4:]
            if domain in allowlist or domain.endswith('.google.com'):
                return 'safe', 99
        except:
            pass

        # 1. Use ML Model if available
        if self.model:
            try:
                features = np.array([self.extract_features(url)])
                prediction = self.model.predict(features)[0]
                # In our training: 0=Safe, 1=Phishing
                if prediction == 1:
                    # Get probability if supported
                    try:
                        probs = self.model.predict_proba(features)[0]
                        confidence = int(probs[1] * 100)
                    except:
                        confidence = 90
                    return 'phishing', confidence
                else:
                     return 'safe', 95
            except Exception as e:
                print(f"Prediction Error: {e}")
                # Fallthrough to heuristic

        # 2. Heuristic Fallback (Simple Keywords)
        phishing_keywords = ['login', 'verify', 'account', 'secure', 'bank', 'confirm']
        for kw in phishing_keywords:
            if kw in url_lower:
                return 'suspicious', 70

        return 'safe', 80
