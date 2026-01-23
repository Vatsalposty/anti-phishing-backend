import firebase_admin
from firebase_admin import credentials, firestore
import datetime
import os

import json

# Check if credential file exists
CRED_PATH = "serviceAccountKey.json"

db = None

try:
    # 1. Try Environment Variable (Production/Render)
    firebase_creds = os.environ.get("FIREBASE_CREDENTIALS")
    
    if firebase_creds:
        print("Loading Firebase credentials from Environment Variable...")
        cred_dict = json.loads(firebase_creds)
        cred = credentials.Certificate(cred_dict)
        firebase_admin.initialize_app(cred)
        db = firestore.client()
        print("Firebase connected successfully (Env Var).")
        
    # 2. Try Local File (Development)
    elif os.path.exists(CRED_PATH):
        print(f"Loading Firebase credentials from {CRED_PATH}...")
        cred = credentials.Certificate(CRED_PATH)
        firebase_admin.initialize_app(cred)
        db = firestore.client()
        print("Firebase connected successfully (Local File).")
        
    else:
        print(f"Warning: {CRED_PATH} not found and FIREBASE_CREDENTIALS not set. Firebase logging disabled.")

except Exception as e:
    print(f"Error initializing Firebase: {e}")

def log_attempt(url, status, confidence):
    if not db:
        print(f"[MOCK-FIREBASE] Logged: {url} | {status} | {confidence}%")
        return

    try:
        doc_ref = db.collection('phishing_attempts').document()
        doc_ref.set({
            'url': url,
            'status': status,
            'confidence': confidence,
            'timestamp': datetime.datetime.now()
        })
        print(f"Logged to Firebase: {url}")
    except Exception as e:
        print(f"Error writing to Firestore: {e}")

def log_system_event(event_type, details):
    if not db:
        print(f"[MOCK-FIREBASE] System Event: {event_type} - {details}")
        return

    try:
        doc_ref = db.collection('system_events').document()
        doc_ref.set({
            'event_type': event_type,
            'details': details,
            'timestamp': datetime.datetime.now()
        })
        print(f"Logged System Event: {event_type}")
    except Exception as e:
        print(f"Error writing System Event to Firestore: {e}")
