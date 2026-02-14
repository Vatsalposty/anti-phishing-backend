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
        
        # Load Safe Domains Dataset
        self.safe_domains = set()
        try:
            import json
            data_path = os.path.join(current_dir, 'data', 'safe_domains.json')
            if os.path.exists(data_path):
                with open(data_path, 'r') as f:
                    data = json.load(f)
                    for category in data.values():
                        self.safe_domains.update(category)
                print(f"Loaded {len(self.safe_domains)} safe domains from allowlist database.")
            else:
                print("Warning: safe_domains.json not found.")
        except Exception as e:
            print(f"Error loading safe domains: {e}")

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

    def analyze_html_content(self, url):
        """
        Fetches webpage HTML and extracts phishing-related features.
        Returns a dict with feature scores and a risk_score (0-100).
        """
        html_features = {
            'password_fields': 0,
            'hidden_inputs': 0,
            'external_forms': 0,
            'iframes': 0,
            'external_scripts': 0,
            'urgency_keywords': 0,
            'risk_score': 0,
            'fetched': False
        }
        
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            response = requests.get(url, headers=headers, timeout=5, allow_redirects=True)
            
            if response.status_code != 200:
                return html_features
            
            html = response.text.lower()
            html_features['fetched'] = True
            
            # 1. Count password fields (credential harvesting indicator)
            html_features['password_fields'] = len(re.findall(r'type\s*=\s*["\']?password', html))
            
            # 2. Count hidden inputs (often used to pass stolen data)
            html_features['hidden_inputs'] = len(re.findall(r'type\s*=\s*["\']?hidden', html))
            
            # 3. Check for forms posting to external domains
            form_actions = re.findall(r'<form[^>]*action\s*=\s*["\']?(https?://[^"\'>\s]+)', html)
            parsed_url = urlparse(url)
            for action in form_actions:
                action_domain = urlparse(action).netloc
                if action_domain and action_domain != parsed_url.netloc:
                    html_features['external_forms'] += 1
            
            # 4. Count iframes (can hide malicious content)
            html_features['iframes'] = len(re.findall(r'<iframe', html))
            
            # 5. Count external scripts
            scripts = re.findall(r'<script[^>]*src\s*=\s*["\']?(https?://[^"\'>\s]+)', html)
            for script_src in scripts:
                script_domain = urlparse(script_src).netloc
                if script_domain and script_domain != parsed_url.netloc:
                    html_features['external_scripts'] += 1
            
            # 6. Urgency/Fear keywords (psychological manipulation)
            urgency_keywords = [
                'verify your account', 'confirm your identity', 'update your password',
                'suspend', 'locked', 'unauthorized', 'expire', 'immediately',
                'click here to verify', 'confirm now', 'act now', '24 hours',
                'your account will be', 'security alert', 'unusual activity'
            ]
            for keyword in urgency_keywords:
                if keyword in html:
                    html_features['urgency_keywords'] += 1
            
            # Calculate Risk Score
            risk = 0
            risk += html_features['password_fields'] * 10  # Reduced from 15
            risk += html_features['hidden_inputs'] * 5
            risk += html_features['external_forms'] * 20   # Reduced from 25
            risk += html_features['iframes'] * 10
            risk += html_features['external_scripts'] * 5
            risk += html_features['urgency_keywords'] * 5  # Reduced from 8
            
            html_features['risk_score'] = min(risk, 100)  # Cap at 100
            
            print(f"HTML Analysis for {url}: {html_features}")
            
        except requests.exceptions.Timeout:
            print(f"HTML Analysis Timeout for {url}")
        except Exception as e:
            print(f"HTML Analysis Error for {url}: {e}")
        
        return html_features

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
        reason = "Unknown"

        # 0. Allowlist (Hardware bypass for speed and safety)
        from urllib.parse import urlparse
        try:
            domain = urlparse(url).netloc
            if domain.startswith('www.'): domain = domain[4:]
            
            if domain in self.safe_domains:
                return 'safe', 99, "Trusted Domain (Allowlist)"
            
            for trusted in self.safe_domains:
                if domain.endswith('.' + trusted):
                    return 'safe', 99, "Trusted Subdomain (Allowlist)"
        except:
            pass

        # 0.5 Check External DBs (PhishTank)
        pt_result = self.check_phishtank(url)
        if pt_result == 'phishing':
            return 'phishing', 100, "Flagged by PhishTank Database"

        # 0.6 Keyword Heuristics
        high_risk_phrases = ['secure-login', 'verify-account', 'update-password', 'login-verify']
        for phrase in high_risk_phrases:
            if phrase in url_lower:
                return 'phishing', 90, f"Suspicious Keyword: '{phrase}'"
        
        # 2. Localhost/IP specific check for demos
        is_local = 'localhost' in url_lower or '127.0.0.1' in url_lower
        if is_local:
            demo_keywords = ['login', 'verify', 'secure', 'account']
            if any(k in url_lower for k in demo_keywords):
                print(f"Demo Detection: Flagging local URL {url}")
                return 'suspicious', 85, "Local Test Detection (Demo Mode)"

        # --- NEW: HTML Content Analysis ---
        if not is_local:
            html_analysis = self.analyze_html_content(url)
            if html_analysis['fetched']:
                html_risk = html_analysis['risk_score']
                
                # High Risk: External forms + Password fields + High Risk Score
                if html_analysis['external_forms'] > 0 and html_analysis['password_fields'] > 0 and html_risk > 60:
                    print(f"HTML RED FLAG: External form + password field detected!")
                    return 'phishing', max(html_risk, 92), "External Password Form Detected"
                
                # Tuned Thresholds
                if html_risk >= 70:
                    return 'phishing', html_risk, "High Risk HTML Content"
                elif html_risk >= 45:
                    return 'suspicious', html_risk, "Suspicious HTML Elements"
        # --- End HTML Analysis ---

        # 1. Use ML Model if available
        if self.model:
            try:
                features = np.array([self.extract_features(url)])
                prediction = self.model.predict(features)[0]
                if prediction == 1:
                    try:
                        probs = self.model.predict_proba(features)[0]
                        confidence = int(probs[1] * 100)
                    except:
                        confidence = 90
                    return 'phishing', confidence, "AI Model Detection Pattern"
                else:
                     return 'safe', 95, "Safe (AI Verification)"
            except Exception as e:
                print(f"Prediction Error: {e}")

        # 2. Heuristic Fallback (Simple Keywords)
        phishing_keywords = ['login', 'verify', 'account', 'secure', 'bank', 'confirm']
        for kw in phishing_keywords:
            if kw in url_lower:
                return 'suspicious', 70, f"Suspicious Keyword: '{kw}'"

        return 'safe', 80, "No Threats Found"
