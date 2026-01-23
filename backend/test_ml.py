from model import PhishingModel

def test_inference():
    print("Initializing Model...")
    model = PhishingModel()
    
    test_urls = [
        ("https://www.google.com/search?q=test", "safe"),
        ("http://google-secure-login.xyz/login", "phishing"),
        ("https://github.com/Vatsalposty", "safe"),
        ("http://192.168.1.1/admin", "phishing")
    ]
    
    print("\n--- Running Inference Tests ---")
    for url, expected in test_urls:
        status, conf = model.predict(url)
        print(f"URL: {url}")
        print(f"  Prediction: {status} ({conf}%)")
        print(f"  Expected:   {expected}")
        print("-" * 30)

if __name__ == "__main__":
    test_inference()
