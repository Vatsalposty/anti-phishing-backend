import joblib
import os
import re
import numpy as np
import traceback

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
