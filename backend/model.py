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

    def analyze_domain_patterns(self, url):
        """
        AI-based suspicious domain pattern analysis.
        Catches brand-new, never-seen-before phishing domains by analyzing
        structural patterns that are common in auto-generated phishing URLs.
        Returns: (is_suspicious: bool, confidence: int, reason: str)
        """
        try:
            parsed = urlparse(url.lower())
            domain = parsed.netloc
            if domain.startswith('www.'): domain = domain[4:]
            path = parsed.path
            full_url = url.lower()
            
            score = 0
            reasons = []
            
            base_domain = domain.rsplit('.', 1)[0] if '.' in domain else domain
            
            # --- Pattern 1: Random/Auto-Generated Domain Detection ---
            # Count consonant clusters (3+ consonants in a row = likely random)
            vowels = set('aeiou')
            consonant_streak = 0
            max_consonant_streak = 0
            for ch in base_domain:
                if ch.isalpha() and ch not in vowels:
                    consonant_streak += 1
                    max_consonant_streak = max(max_consonant_streak, consonant_streak)
                else:
                    consonant_streak = 0
            if max_consonant_streak >= 4:
                score += 30
                reasons.append(f"Random character pattern ({max_consonant_streak} consonants)")
            
            # --- Pattern 2: Digit-Letter Mixing ---
            # e.g., "s3cur1ty-l0gin.com" or "bank2024verify.xyz"
            digit_count = sum(1 for c in base_domain if c.isdigit())
            letter_count = sum(1 for c in base_domain if c.isalpha())
            if digit_count >= 2 and letter_count >= 3 and digit_count / max(len(base_domain), 1) > 0.2:
                score += 20
                reasons.append("Suspicious digit-letter mixing in domain")
            
            # --- Pattern 3: Excessive Hyphens ---
            # e.g., "secure-login-verify-account-now.com"
            hyphen_count = base_domain.count('-')
            if hyphen_count >= 3:
                score += 25
                reasons.append(f"Excessive hyphens ({hyphen_count})")
            elif hyphen_count >= 2:
                score += 10
            
            # --- Pattern 4: Number-Padded Brand Names ---
            # e.g., "paypal123.com", "amazon2024.com", "netflix01.com"
            brand_keywords = ['paypal', 'netflix', 'amazon', 'microsoft', 'apple', 'google',
                            'facebook', 'instagram', 'whatsapp', 'linkedin', 'twitter',
                            'chase', 'wellsfargo', 'hdfc', 'sbi', 'icici', 'gmail',
                            'outlook', 'yahoo', 'icloud', 'uber', 'flipkart', 'paytm',
                            'phonepe', 'razorpay', 'zerodha', 'groww', 'cred', 'spotify',
                            'discord', 'telegram', 'snapchat', 'tiktok', 'binance',
                            'coinbase', 'metamask', 'opensea']
            for brand in brand_keywords:
                if brand in base_domain and base_domain != brand:
                    # Domain contains a brand but ISN'T the brand itself
                    score += 35
                    reasons.append(f"Contains brand keyword '{brand}'")
                    break
            
            # --- Pattern 5: Suspicious Keyword Combos in Domain ---
            # e.g., "secure-login.xyz", "verify-account.top"
            danger_words = ['login', 'verify', 'secure', 'account', 'update', 'confirm',
                          'password', 'banking', 'signin', 'auth', 'credential', 'unlock',
                          'suspend', 'restore', 'recover', 'wallet', 'claim', 'prize',
                          'winner', 'reward', 'urgent', 'alert', 'warning', 'helpdesk',
                          'support', 'service', 'customer', 'resolution', 'validate']
            danger_hits = sum(1 for w in danger_words if w in base_domain)
            if danger_hits >= 2:
                score += 40
                reasons.append(f"Multiple danger keywords in domain ({danger_hits})")
            elif danger_hits == 1:
                score += 15
                reasons.append("Danger keyword in domain")
            
            # --- Pattern 6: Long Domain Names ---
            # Legitimate domains are usually short (google=6, amazon=6, facebook=8)
            # Phishing domains tend to be much longer
            if len(base_domain) > 25:
                score += 20
                reasons.append(f"Unusually long domain ({len(base_domain)} chars)")
            elif len(base_domain) > 18:
                score += 10
            
            # --- Pattern 7: Suspicious Path Patterns ---
            # e.g., "/wp-admin/login.php", "/cgi-bin/", base64 in URL
            if path:
                if re.search(r'\.php|\.asp|\.cgi', path):
                    score += 10
                    reasons.append("Server-side script in path")
                if re.search(r'[A-Za-z0-9+/]{30,}={0,2}', path):
                    score += 15
                    reasons.append("Possible base64-encoded data in URL")
                if path.count('/') >= 6:
                    score += 10
                    reasons.append("Deep path nesting")
                path_danger = sum(1 for w in ['login', 'verify', 'secure', 'account', 'password', 'signin', 'auth'] if w in path)
                if path_danger >= 2:
                    score += 15
                    reasons.append("Multiple danger keywords in path")

            # --- Pattern 8: Suspicious TLD + Any Other Signal ---
            risky_tlds = ['.top', '.xyz', '.buzz', '.info', '.tk', '.ml', '.ga', '.cf', 
                         '.gq', '.pw', '.cc', '.ws', '.bid', '.click', '.link', '.loan',
                         '.online', '.site', '.work', '.life', '.icu', '.fun', '.monster',
                         '.rest', '.cam', '.surf', '.bar', '.cyou']
            has_risky_tld = any(domain.endswith(tld) for tld in risky_tlds)
            if has_risky_tld:
                score += 15
                reasons.append("High-risk TLD")
            
            # --- Pattern 9: URL contains encoded characters ---
            if '%' in full_url:
                encoded_count = full_url.count('%')
                if encoded_count >= 3:
                    score += 15
                    reasons.append(f"Multiple URL-encoded characters ({encoded_count})")
            
            # --- Determine Result ---
            if score >= 70:
                return True, min(score, 95), f"Suspicious Domain Patterns: {'; '.join(reasons[:3])}"
            elif score >= 45:
                return True, min(score, 80), f"Warning: {'; '.join(reasons[:2])}"
            
            return False, 0, ""
            
        except Exception as e:
            logger.info(f"Domain Pattern Analysis Error: {e}")
            return False, 0, ""

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
                
        # 0.7 Homoglyph & Typosquatting Detection
        try:
            import difflib
            domain_to_check = urlparse(url_lower).netloc
            if domain_to_check.startswith('www.'): domain_to_check = domain_to_check[4:]
            
            base_domain = domain_to_check.rsplit('.', 1)[0] if '.' in domain_to_check else domain_to_check
            
            # Homoglyph normalization map: characters that look alike to the human eye
            homoglyph_map = {
                '1': 'l', 'l': 'i', '0': 'o', '5': 's',
                '|': 'l', '!': 'i', '@': 'a', '$': 's',
            }
            # Multi-char homoglyphs
            multi_homoglyphs = {
                'rn': 'm', 'vv': 'w', 'cl': 'd', 'nn': 'm',
            }
            
            def normalize_homoglyphs(text):
                """Convert lookalike characters to their intended form"""
                result = text
                # Multi-char replacements first
                for fake, real in multi_homoglyphs.items():
                    result = result.replace(fake, real)
                # Single-char replacements
                normalized = ''
                for ch in result:
                    normalized += homoglyph_map.get(ch, ch)
                return normalized
            
            normalized_domain = normalize_homoglyphs(base_domain)
            
            if domain_to_check not in self.safe_domains:
                for safe_url in self.safe_domains:
                    safe_base = safe_url.rsplit('.', 1)[0] if '.' in safe_url else safe_url
                    
                    if len(base_domain) > 3 and len(safe_base) > 3:
                        # 1. Homoglyph exact match (e.g., lnstagram → instagram)
                        if normalized_domain == safe_base and base_domain != safe_base:
                            logger.info(f"Homoglyph Attack: {domain_to_check} uses lookalike chars to impersonate {safe_url}")
                            return 'phishing', 96, f"Homoglyph Attack: Impersonating {safe_url}"
                        
                        # 2. Exact same name, different TLD (e.g., google.biz vs google.com)
                        if base_domain == safe_base:
                            logger.info(f"Typosquatting Alert: {domain_to_check} mimics {safe_url}")
                            return 'phishing', 95, f"Impersonating {safe_url} (Suspicious TLD)"
                        
                        # 3. Highly similar name (e.g., goooogle.com vs google.com)
                        ratio = difflib.SequenceMatcher(None, base_domain, safe_base).ratio()
                        if 0.80 <= ratio < 1.0:
                            logger.info(f"Typosquatting Alert: {domain_to_check} is {ratio:.2f} similar to {safe_url}")
                            return 'phishing', 92, f"Typosquatting: Impersonating {safe_url}"
                        
                        # 4. Normalized similarity (catches combined homoglyph + typosquatting)
                        norm_ratio = difflib.SequenceMatcher(None, normalized_domain, safe_base).ratio()
                        if 0.80 <= norm_ratio < 1.0 and norm_ratio > ratio:
                            logger.info(f"Homoglyph+Typosquat: {domain_to_check} normalized to {normalized_domain}, {norm_ratio:.2f} similar to {safe_url}")
                            return 'phishing', 93, f"Impersonation Attack: Mimicking {safe_url}"
        except Exception as e:
            logger.info(f"Typosquatting Check Error: {e}")
        
        # 0.8 Subdomain Abuse Detection (e.g., google.com.evil-site.xyz)
        try:
            domain_full = urlparse(url_lower).netloc
            if domain_full.startswith('www.'): domain_full = domain_full[4:]
            
            for trusted in self.safe_domains:
                # Check if a trusted brand name appears as a subdomain of a DIFFERENT domain
                if trusted in domain_full and not domain_full.endswith(trusted):
                    # e.g., "paypal.com.phishing-site.xyz" contains "paypal.com" but ends with ".xyz"
                    logger.info(f"Subdomain Abuse: {domain_full} contains trusted brand '{trusted}' as subdomain")
                    return 'phishing', 94, f"Subdomain Abuse: Impersonating {trusted}"
        except Exception as e:
            logger.info(f"Subdomain Abuse Check Error: {e}")
        
        # 0.85 URL Shortener Detection
        url_shorteners = [
            'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'v.gd',
            'buff.ly', 'ow.ly', 'rebrand.ly', 'bl.ink', 'short.io',
            'cutt.ly', 'rb.gy', 'clck.ru', 'shorturl.at', 'tiny.cc'
        ]
        try:
            short_domain = urlparse(url_lower).netloc
            if short_domain.startswith('www.'): short_domain = short_domain[4:]
            if short_domain in url_shorteners:
                logger.info(f"URL Shortener detected: {short_domain}")
                return 'suspicious', 65, f"Shortened URL ({short_domain}) — Cannot verify destination"
        except:
            pass
        
        # 0.9 Excessive Subdomain Depth (e.g., login.secure.bank.verify.example.com)
        try:
            depth_domain = urlparse(url_lower).netloc
            subdomain_count = depth_domain.count('.')
            if subdomain_count >= 4:
                logger.info(f"Excessive subdomains: {depth_domain} ({subdomain_count} levels)")
                return 'suspicious', 75, f"Suspicious URL Structure ({subdomain_count} subdomain levels)"
        except:
            pass

        # 0.95 Path-Based Brand Impersonation (e.g., random-site.com/paypal/login)
        try:
            url_path = urlparse(url_lower).path.lower()
            path_domain = urlparse(url_lower).netloc
            if path_domain.startswith('www.'): path_domain = path_domain[4:]
            
            brand_names = ['paypal', 'netflix', 'amazon', 'microsoft', 'apple', 'google',
                          'facebook', 'instagram', 'whatsapp', 'linkedin', 'twitter',
                          'chase', 'wellsfargo', 'bankofamerica', 'hdfc', 'sbi', 'icici',
                          'gmail', 'outlook', 'yahoo', 'icloud']
            
            if path_domain not in self.safe_domains:
                for brand in brand_names:
                    if brand in url_path and ('login' in url_path or 'verify' in url_path or 
                                              'account' in url_path or 'secure' in url_path or
                                              'password' in url_path or 'signin' in url_path):
                        logger.info(f"Path Brand Impersonation: {url} has '{brand}' + login keyword in path")
                        return 'phishing', 88, f"Brand Impersonation: '{brand}' in URL path"
        except:
            pass
        
        # 0.96 Punycode / IDN Homograph Detection (e.g., xn--pple-43d.com = аpple.com with Cyrillic 'а')
        try:
            idn_domain = urlparse(url_lower).netloc
            if 'xn--' in idn_domain:
                logger.info(f"Punycode IDN detected: {idn_domain}")
                return 'phishing', 90, "International Domain (Punycode) — Possible Homograph Attack"
        except:
            pass
        
        # 0.97 AI-Based Suspicious Domain Pattern Analysis
        # This catches brand-new phishing domains that aren't in any database yet
        is_suspicious, pattern_confidence, pattern_reason = self.analyze_domain_patterns(url)
        if is_suspicious and pattern_confidence >= 70:
            logger.info(f"Domain Pattern Alert: {url} — {pattern_reason}")
            return 'phishing', pattern_confidence, pattern_reason
        
        # 2. Localhost/IP specific check for demos
        is_local = 'localhost' in url_lower or '127.0.0.1' in url_lower
        if is_local:
            demo_keywords = ['login', 'verify', 'secure', 'account']
            if any(k in url_lower for k in demo_keywords):
                logger.info(f"Demo Detection: Flagging local URL {url}")
                return 'suspicious', 85, "Local Test Detection (Demo Mode)"

        # --- HTML Content Analysis ---
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

        # 3. Use ML Model if available
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

        # 4. Heuristic Fallback (Expanded Keywords)
        phishing_keywords = ['login', 'verify', 'account', 'secure', 'bank', 'confirm',
                            'password', 'credential', 'suspend', 'locked', 'unauthorized',
                            'wallet', 'expire', 'ssn', 'social-security', 'update-info']
        kw_count = sum(1 for kw in phishing_keywords if kw in url_lower)
        if kw_count >= 2:
            return 'suspicious', 65, "Multiple Suspicious Keywords in URL"

        # 5. Medium-confidence domain patterns (caught earlier but below phishing threshold)
        if is_suspicious and pattern_confidence >= 45:
            return 'suspicious', pattern_confidence, pattern_reason

        return 'safe', 80, "No Threats Found"
