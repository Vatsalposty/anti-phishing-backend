import requests
import json

API_URL = "http://localhost:8000/analyze"

def test_url(url):
    try:
        response = requests.post(API_URL, json={"url": url})
        if response.status_code == 200:
            print(f"URL: {url}")
            print(f"Result: {response.json()}\n")
        else:
            print(f"Error {response.status_code}: {response.text}")
    except Exception as e:
        print(f"Connection Failed: {e}")

if __name__ == "__main__":
    print("Testing Anti-Phishing API...\n")
    
    # Safe
    test_url("https://google.com")
    
    # Phishing (Mocked in model.py)
    test_url("http://evil.com/login")
    
    # Suspicious
    test_url("http://secure-login-verify-account-update.xyz")

    print("Done.")
