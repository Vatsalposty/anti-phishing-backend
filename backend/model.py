import random
import re

class PhishingModel:
    def __init__(self):
        # In a real scenario, we would load a pickle file here
        # self.model = joblib.load('model.pkl')
        print("Model initialized (Heuristic Mode)")

    def predict(self, url: str):
        """
        Returns (status, confidence)
        status: 'safe', 'suspicious', 'phishing'
        confidence: 0-100
        """
        url_lower = url.lower()

        # heuristic 1: Known bad patterns
        phishing_keywords = ['login', 'verify', 'account', 'secure', 'bank', 'confirm']
        
        # Check against a small mock blacklist
        blacklist = ['evil.com', 'phishing-test.com', 'fake-login.com']
        for bad in blacklist:
            if bad in url_lower:
                return 'phishing', 99

        # heuristic 0: Known Good Domains (Allowlist)
        # Prevent false positives for long search URLs etc.
        allowlist = ['google.com', 'gmail.com', 'youtube.com', 'facebook.com', 'amazon.com', 'wikipedia.org', 'chatgpt.com', 'openai.com']
        from urllib.parse import urlparse
        try:
            domain = urlparse(url).netloc
            # Handle www. prefix
            if domain.startswith('www.'):
                domain = domain[4:]
            
            if domain in allowlist or domain.endswith('.google.com'):
                return 'safe', 98
        except:
            pass

        # Heuristic 2: Suspicious TLDs or excessive length
        if len(url) > 75:
            return 'suspicious', 70
        
        # Heuristic 3: Keywords in non-standard domains
        # e.g. "google" in "google-secure-login.xyz"
        score = 0
        for kw in phishing_keywords:
            if kw in url_lower:
                score += 20
        
        if score > 40:
             return 'suspicious', 60 + int(random.random() * 20)

        # Heuristic 4: IP address in URL
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        if re.search(ip_pattern, url):
             return 'phishing', 85

        # Default safe
        return 'safe', 95 + int(random.random() * 5)
