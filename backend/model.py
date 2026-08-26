import logging

logger = logging.getLogger(__name__)

import os
import re
import requests
import joblib
import numpy as np
import traceback
import math
import socket
import ipaddress
from bs4 import BeautifulSoup
from collections import Counter
from urllib.parse import urlparse
import xgboost as xgb

class PhishingModel:
    def __init__(self):
        self.model = None
        current_dir = os.path.dirname(os.path.abspath(__file__))
        model_path = os.path.join(current_dir, 'xgboost_model.json')
        
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
                logger.info(f"Loaded {len(self.safe_domains)} safe domains from allowlist database.")
            else:
                logger.info("Warning: safe_domains.json not found.")
        except Exception as e:
            logger.info(f"Error loading safe domains: {e}")

        try:
            if os.path.exists(model_path):
                self.model = xgb.XGBClassifier()
                self.model.load_model(model_path)
                logger.info("Model loaded successfully.")
            else:
                logger.info("Warning: Model file not found. Running in Fallback Mode.")
        except Exception as e:
            logger.info(f"Error loading model: {repr(e)}")
            traceback.print_exc()
            
            # --- Self-Healing: Attempt to Retrain on Server ---
            logger.info("Attempting to Retrain Model on Server (Self-Healing)...")
            
            # Delete the corrupted file if it exists to prevent repeat errors
            if os.path.exists(model_path):
                try:
                    os.remove(model_path)
                    logger.info("Deleted corrupted model file.")
                except OSError:
                    pass

            try:
                from train_xgboost import train_xgboost
                # Fallback retraining script doesn't have n_samples built into train_xgboost easily,
                # but we will just call it anyway.
                train_xgboost() 
                
                if os.path.exists(model_path):
                     logger.info(f"Model Retrained. Size: {os.path.getsize(model_path)} bytes. Reloading...")
                     self.model = xgb.XGBClassifier()
                     self.model.load_model(model_path)
                     logger.info("Model Reloaded Successfully!")
                else:
                    logger.info("Retraining finished but model file not found.")
            except Exception as re_e:
                logger.info(f"Retraining Failed: {re_e}")
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

    def is_safe_url(self, url):
        """SSRF Protection: Prevent fetching internal/private IP addresses"""
        try:
            parsed = urlparse(url)
            domain = parsed.hostname
            if not domain:
                return False
            
            # Resolve domain to IP
            ip_addr = socket.gethostbyname(domain)
            ip_obj = ipaddress.ip_address(ip_addr)
            
            # Check if IP is private, loopback, or otherwise restricted
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local:
                logger.info(f"SSRF BLOCK: Prevented request to internal IP {ip_addr} for {url}")
                return False
            return True
        except Exception as e:
            logger.info(f"SSRF Check failed for {url}: {e}")
            return False

    def analyze_html_content(self, url):
        """
        Fetches webpage HTML and extracts phishing-related features using BeautifulSoup.
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
        
        if not self.is_safe_url(url):
            return html_features
            
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            response = requests.get(url, headers=headers, timeout=5, allow_redirects=True)
            
            if response.status_code != 200:
                return html_features
            
            html_features['fetched'] = True
            soup = BeautifulSoup(response.text, 'html.parser')
            parsed_url = urlparse(url)
            
            # 1. Count password fields
            password_inputs = [inp for inp in soup.find_all('input') if isinstance(inp.get('type'), str) and str(inp.get('type')).lower() == 'password']
            html_features['password_fields'] = len(password_inputs)
            
            # 2. Count hidden inputs
            hidden_inputs = [inp for inp in soup.find_all('input') if isinstance(inp.get('type'), str) and str(inp.get('type')).lower() == 'hidden']
            html_features['hidden_inputs'] = len(hidden_inputs)
            
            # 3. Check for forms posting to external domains
            forms = soup.find_all('form', action=True)
            for form in forms:
                action = form.get('action')
                if isinstance(action, list):
                    action = action[0] if action else ''
                if isinstance(action, str) and action.startswith('http'):
                    action_domain = urlparse(action).netloc
                    if action_domain and action_domain != parsed_url.netloc:
                        html_features['external_forms'] += 1
            
            # 4. Count iframes
            html_features['iframes'] = len(soup.find_all('iframe'))
            
            # 5. Count external scripts
            scripts = soup.find_all('script', src=True)
            for script in scripts:
                src = script.get('src')
                if isinstance(src, list):
                    src = src[0] if src else ''
                if isinstance(src, str) and src.startswith('http'):
                    script_domain = urlparse(src).netloc
                    if script_domain and script_domain != parsed_url.netloc:
                        html_features['external_scripts'] += 1
            
            # 6. Urgency/Fear keywords
            html_text = soup.get_text().lower()
            urgency_keywords = [
                'verify your account', 'confirm your identity', 'update your password',
                'suspend', 'locked', 'unauthorized', 'expire', 'immediately',
                'click here to verify', 'confirm now', 'act now', '24 hours',
                'your account will be', 'security alert', 'unusual activity'
            ]
            for keyword in urgency_keywords:
                if keyword in html_text:
                    html_features['urgency_keywords'] += 1
            
            # Calculate Risk Score
            risk = 0
            risk += html_features['password_fields'] * 15
            risk += min(html_features['hidden_inputs'] * 1, 10)  # Common in modern web, cap at 10
            risk += html_features['external_forms'] * 25
            risk += min(html_features['iframes'] * 2, 10) # Cap at 10
            risk += min(html_features['external_scripts'] * 1, 10) # Cap at 10
            risk += html_features['urgency_keywords'] * 10
            
            html_features['risk_score'] = min(risk, 100)
            
            logger.info(f"HTML Analysis for {url}: {html_features}")
            
        except requests.exceptions.Timeout:
            logger.info(f"HTML Analysis Timeout for {url}")
        except Exception as e:
            logger.info(f"HTML Analysis Error for {url}: {e}")
        
        return html_features

    def check_phishtank(self, url):
        """Checks URL against PhishTank API"""
        try:
            api_url = "https://checkurl.phishtank.com/checkurl/"
            data = {
                'url': url,
                'format': 'json',
            }
            
            # Add API Key if configured
            api_key = os.environ.get("PHISHTANK_API_KEY")
            if api_key:
                data['app_key'] = api_key

            headers = {
                'User-Agent': 'phishtank/anti-phishing-ai-guard-v1'
            }
            response = requests.post(api_url, data=data, headers=headers, timeout=5)
            if response.status_code == 200:
                result = response.json()
                if result.get('results', {}).get('in_database'):
                    if result['results']['verified']:
                        logger.info(f"PhishTank ALERT: {url} is a VERIFIED phishing site.")
                        return 'phishing'
            return None
        except Exception as e:
            logger.info(f"PhishTank API Error: {e}")
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

        # 0.6 Keyword Heuristics (Very Strict)
        high_risk_phrases = ['secure-login-update', 'verify-account-info', 'update-password-now']
        for phrase in high_risk_phrases:
            if phrase in url_lower:
                return 'phishing', 90, f"Suspicious Keyword Pattern: '{phrase}'"
        
        # 2. Localhost/IP specific check for demos
        is_local = 'localhost' in url_lower or '127.0.0.1' in url_lower
        if is_local:
            demo_keywords = ['login', 'verify', 'secure', 'account']
            if any(k in url_lower for k in demo_keywords):
                logger.info(f"Demo Detection: Flagging local URL {url}")
                return 'suspicious', 85, "Local Test Detection (Demo Mode)"

        # --- NEW: HTML Content Analysis ---
        if not is_local:
            html_analysis = self.analyze_html_content(url)
            if html_analysis['fetched']:
                html_risk = html_analysis['risk_score']
                
                # High Risk: External forms + Password fields + High Risk Score
                if html_analysis['external_forms'] > 0 and html_analysis['password_fields'] > 0 and html_risk > 75:
                    logger.info(f"HTML RED FLAG: External form + password field detected!")
                    return 'phishing', max(html_risk, 92), "External Password Form Detected"
                
                # Tuned Thresholds
                if html_risk >= 95:
                    return 'phishing', html_risk, "High Risk HTML Content"
                elif html_risk >= 80:
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
                logger.info(f"Prediction Error: {e}")

        # 2. Heuristic Fallback (Simple Keywords - Lower Confidence)
        phishing_keywords = ['login', 'verify', 'account', 'secure', 'bank', 'confirm']
        kw_count = sum(1 for kw in phishing_keywords if kw in url_lower)
        if kw_count >= 3:
            return 'suspicious', 60, "Multiple Suspicious Keywords in URL"

        return 'safe', 80, "No Threats Found"
