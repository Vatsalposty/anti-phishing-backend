import firebase_admin
from firebase_admin import credentials, firestore
import os
import datetime

# Configuration
CRED_PATH = os.path.join(os.path.dirname(__file__), "serviceAccountKey.json")

def test_connection():
    print(f"Checking for key at: {CRED_PATH}")
    
    if not os.path.exists(CRED_PATH):
        print("\n[ERROR] 'serviceAccountKey.json' not found!")
        print("Please download it from Firebase Console -> Project Settings -> Service Accounts.")
        return

    try:
        # Initialize
        cred = credentials.Certificate(CRED_PATH)
        # Check if already initialized to avoid errors on re-run
        if not firebase_admin._apps:
            firebase_admin.initialize_app(cred)
        
        db = firestore.client()
        
        # Test Write
        print("Attempting to write test document...")
        doc_ref = db.collection('system_checks').document('connection_test')
        doc_ref.set({
            'status': 'connected',
            'timestamp': datetime.datetime.now(),
            'message': 'Firebase integration verified successfully!'
        })
        
        print(f"\n[SUCCESS] Connected to Firebase Project!")
        print("Test document written to collection 'system_checks'.")
        
    except Exception as e:
        print(f"\n[FAILURE] Could not connect to Firebase.")
        print(f"Error details: {e}")

if __name__ == "__main__":
    test_connection()
