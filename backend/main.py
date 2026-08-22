from fastapi import FastAPI, HTTPException, Request, BackgroundTasks
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from model import PhishingModel
from firebase_db import log_attempt, log_system_event, log_user_report
import uvicorn
import logging
import os
from contextlib import asynccontextmanager

# Setup Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Backend starting up...")
    log_system_event("startup", "Backend server started")
    yield
    logger.info("Backend shutting down...")
    log_system_event("shutdown", "Backend server stopped")

limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title="Anti-Phishing Backend API", lifespan=lifespan)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Configure CORS to restrict to extension if ID is provided
extension_id = os.environ.get("CHROME_EXTENSION_ID")
allowed_origins = [f"chrome-extension://{extension_id}"] if extension_id else ["*"]

# Allow CORS (important for Extension to talk to backend)
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.api_route("/", methods=["GET", "HEAD"])
def health_check():
    return {"status": "active", "service": "Anti-Phishing Backend"}

# Load Model
model = PhishingModel()

# --- Pydantic Models ---
class AnalyzeRequest(BaseModel):
    url: str
    features: dict = None

class AnalyzeResponse(BaseModel):
    url: str
    status: str # "safe", "phishing", "suspicious"
    confidence: int # 0-100
    reason: str # Description of detection

class ReportRequest(BaseModel):
    url: str
    reason: str = "user_report"

# --- Endpoints ---



@app.post("/analyze", response_model=AnalyzeResponse)
@limiter.limit("60/minute")
def analyze_url(request: Request, body: AnalyzeRequest, background_tasks: BackgroundTasks):
    logger.info(f"Analyzing URL: {body.url}")
    
    try:
        # Prediction
        result, confidence, reason = model.predict(body.url)
        
        # Log to Firebase using Background Tasks (non-blocking)
        try:
            if result in ["phishing", "suspicious"]:
                background_tasks.add_task(log_attempt, body.url, result, confidence)
        except Exception as e:
            logger.error(f"Failed to schedule Firebase log: {e}")

        return AnalyzeResponse(
            url=body.url,
            status=result,
            confidence=confidence,
            reason=reason
        )
    except Exception as e:
        logger.error(f"Error analyzing URL: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/report")
@limiter.limit("30/minute")
def report_url(request: Request, body: ReportRequest, background_tasks: BackgroundTasks):
    logger.info(f"User Report Received: {body.url}")
    try:
        background_tasks.add_task(log_user_report, body.url, body.reason)
        return {"status": "success", "message": "Report logged"}
    except Exception as e:
        logger.error(f"Error logging report: {e}")
        raise HTTPException(status_code=500, detail="Failed to log report")

@app.api_route("/stats", methods=["GET", "HEAD", "POST", "OPTIONS"])
def get_stats():
    # In a real app, this would fetch from Firestore
    # For now, we return mock/example stats
    return {
        "total_scans": 1245,
        "threats_blocked": 87,
        "system_status": "healthy",
        "model_version": "2.1.0"
    }

if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
