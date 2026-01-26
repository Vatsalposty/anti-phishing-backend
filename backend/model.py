import os
import re
import requests
import joblib
import numpy as np
import traceback
import math
from collections import Counter
from urllib.parse import urlparse

class PhishingModel:
    def __init__(self):
        self.model = None
        current_dir = os.path.dirname(os.path.abspath(__file__))
        model_path = os.path.join(current_dir, 'phishing_model.pkl')
        
        try:
            import sklearn
            print(f"DEBUG: scikit-learn version: {sklearn.__version__}")
            print(f"DEBUG: joblib version: {joblib.__version__}")
            print(f"DEBUG: numpy version: {np.__version__}")

            if os.path.exists(model_path):
                print(f"Loading model from {model_path} (Size: {os.path.getsize(model_path)} bytes)")
                self.model = joblib.load(model_path)
                print(f"Model loaded successfully from {model_path}")
            else:
                print(f"Warning: {model_path} not found. Running in Fallback Mode.")
                print(f"Directory contents: {os.listdir(current_dir)}")
        except Exception as e:
            print(f"Error loading model: {repr(e)}", flush=True)
            traceback.print_exc()
            
            # --- Self-Healing: Attempt to Retrain on Server ---
            print("Attempting to Retrain Model on Server (Self-Healing)...", flush=True)
            
            # Delete the corrupted file if it exists to prevent repeat errors
            if os.path.exists(model_path):
                try:
                    os.remove(model_path)
                    print("Deleted corrupted model file.", flush=True)
                except:
                    pass

            try:
                from train_model import train
                # Train with fewer samples for speed (500 instead of 2000)
                train(n_samples=500) 
                
                if os.path.exists(model_path):
                     print(f"Model Retrained. Size: {os.path.getsize(model_path)} bytes. Reloading...", flush=True)
                     self.model = joblib.load(model_path)
                     print("Model Reloaded Successfully!", flush=True)
                else:
                    print("Retraining finished but model file not found.", flush=True)
            except Exception as re_e:
                print(f"Retraining Failed: {re_e}", flush=True)
                traceback.print_exc()

    def calculate_entropy(self, text):
        if not text:
            return 0
        counter = Counter(text)
        length = len(text)
        entropy = -sum((count/length) * math.log2(count/length) for count in counter.values())
        return entropy

    def extract_features(self, url):
        features = []
        parsed = urlparse(url)
        domain = parsed.netloc
        
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
        
        # --- NEW FEATURES ---
        # 7. Domain Entropy (High entropy often means random/generated domains)
        features.append(self.calculate_entropy(domain))
        
        # 8. TLD Analysis (suspicious TLDs like .top, .xyz, .buzz)
        suspicious_tlds = ['.top', '.xyz', '.buzz', '.info', '.tk', '.ml', '.ga', '.cf', '.gq']
        has_susp_tld = 1 if any(domain.endswith(tld) for tld in suspicious_tlds) else 0
        features.append(has_susp_tld)
        
        return features

    def check_phishtank(self, url):
        """Checks URL against PhishTank API (Free)"""
        try:
            # Note: For high volume, use an API key from PhishTank
            api_url = "https://checkurl.phishtank.com/checkurl/"
            data = {
                'url': url,
                'format': 'json',
            }
            # Use a descriptive user agent as requested by PhishTank
            headers = {
                'User-Agent': 'phishtank/anti-phishing-ai-guard-v1'
            }
            response = requests.post(api_url, data=data, headers=headers, timeout=5)
            if response.status_code == 200:
                result = response.json()
                if result.get('results', {}).get('in_database'):
                    if result['results']['verified']:
                        print(f"PhishTank ALERT: {url} is a VERIFIED phishing site.")
                        return 'phishing'
            return None
        except Exception as e:
            print(f"PhishTank API Error: {e}")
            return None

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

        # 0.5 Check External DBs (PhishTank)
        pt_result = self.check_phishtank(url)
        if pt_result == 'phishing':
            return 'phishing', 100

        # 0.6 Keyword Heuristics (Catch-all for 'secure-login' patterns the ML might miss)
        # 1. High-risk phrases (often used in demos or blatant phishing)
        high_risk_phrases = ['secure-login', 'verify-account', 'update-password', 'login-verify']
        for phrase in high_risk_phrases:
            if phrase in url_lower:
                return 'phishing', 90
        
        # 2. Localhost/IP specific check for demos
        is_local = 'localhost' in url_lower or '127.0.0.1' in url_lower
        if is_local:
            demo_keywords = ['login', 'verify', 'secure', 'account']
            if any(k in url_lower for k in demo_keywords):
                print(f"Demo Detection: Flagging local URL {url}")
                return 'suspicious', 85

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
