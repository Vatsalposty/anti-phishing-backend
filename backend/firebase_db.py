import os
import json
import datetime
import hashlib
import logging
from dotenv import load_dotenv
from urllib.parse import urlparse
import firebase_admin
from firebase_admin import credentials, firestore

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Load environment variables from .env file (if it exists)
load_dotenv()

# Check if credential file exists
CRED_PATH = "serviceAccountKey.json"

db = None

try:
    # 1. Try Environment Variable (Production/Render)
    firebase_creds = os.environ.get("FIREBASE_CREDENTIALS")
    
    if firebase_creds:
        logger.info("Loading Firebase credentials from Environment Variable...")
        cred_dict = json.loads(firebase_creds)
        cred = credentials.Certificate(cred_dict)
        firebase_admin.initialize_app(cred)
        db = firestore.client()
        logger.info("Firebase connected successfully (Env Var).")
        
    # 2. Try Local File (Development)
    elif os.path.exists(CRED_PATH):
        logger.info(f"Loading Firebase credentials from {CRED_PATH}...")
        cred = credentials.Certificate(CRED_PATH)
        firebase_admin.initialize_app(cred)
        db = firestore.client()
        logger.info("Firebase connected successfully (Local File).")
        
    else:
        logger.warning(f"{CRED_PATH} not found and FIREBASE_CREDENTIALS not set. Firebase logging disabled.")

except Exception as e:
    logger.error(f"Error initializing Firebase: {e}")

def sanitize_url(url: str) -> str:
    """Removes query parameters and fragments from URL to prevent PII leakage."""
    try:
        parsed = urlparse(url)
        # Reconstruct URL without query and fragment
        sanitized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        return sanitized.rstrip('/')
    except Exception:
        return url

def log_attempt(url, status, confidence):
    sanitized_url = sanitize_url(url)
    if not db:
        logger.info(f"[MOCK-FIREBASE] Logged: {sanitized_url} | {status} | {confidence}%")
        return

    try:
        # Use URL hash as distinct ID to avoid duplicates
        doc_id = hashlib.sha256(sanitized_url.encode('utf-8')).hexdigest()[:32]
        doc_ref = db.collection('phishing_attempts').document(doc_id)
        
        doc_ref.set({
            'url': sanitized_url,
            'status': status,
            'confidence': confidence,
            'last_seen': datetime.datetime.now(),
            'count': firestore.Increment(1)
        }, merge=True)
        logger.info(f"Logged/Updated Firebase: {sanitized_url}")
    except Exception as e:
        logger.error(f"Error writing to Firestore: {e}")

def log_system_event(event_type, details):
    if not db:
        logger.info(f"[MOCK-FIREBASE] System Event: {event_type} - {details}")
        return

    try:
        doc_ref = db.collection('system_events').document()
        doc_ref.set({
            'event_type': event_type,
            'details': details,
            'timestamp': datetime.datetime.now()
        })
        logger.info(f"Logged System Event: {event_type}")
    except Exception as e:
        logger.error(f"Error writing System Event to Firestore: {e}")

def log_user_report(url, reason="user_report"):
    sanitized_url = sanitize_url(url)
    if not db:
        logger.info(f"[MOCK-FIREBASE] User Report: {sanitized_url} | {reason}")
        return

    try:
        # Use URL hash to separate unique reports
        doc_id = hashlib.sha256(sanitized_url.encode('utf-8')).hexdigest()[:32]
        doc_ref = db.collection('user_reports').document(doc_id)
        
        doc_ref.set({
            'url': sanitized_url,
            'reason': reason,
            'last_reported': datetime.datetime.now(),
            'status': 'pending_review',
            'report_count': firestore.Increment(1)
        }, merge=True)
        logger.info(f"Logged/Updated User Report: {sanitized_url}")
    except Exception as e:
        logger.error(f"Error writing User Report to Firestore: {e}")
