from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
from model import PhishingModel
from firebase_db import log_attempt, log_system_event, log_user_report
import uvicorn
import logging
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

app = FastAPI(title="Anti-Phishing Backend API", lifespan=lifespan)

# Allow CORS (important for Extension to talk to localhost)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # In production, restrict to extension ID
    allow_credentials=True,
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

class ReportRequest(BaseModel):
    url: str
    reason: str = "user_report"

# --- Endpoints ---



@app.post("/analyze", response_model=AnalyzeResponse)
def analyze_url(request: AnalyzeRequest):
    logger.info(f"Analyzing URL: {request.url}")
    
    try:
        # Prediction
        result, confidence = model.predict(request.url)
        
        # Log to Firebase (fire and forget or async ideally, but sync for now)
        try:
            if result in ["phishing", "suspicious"]:
                log_attempt(request.url, result, confidence)
        except Exception as e:
            logger.error(f"Failed to log to Firebase: {e}")

        return AnalyzeResponse(
            url=request.url,
            status=result,
            confidence=confidence
        )
    except Exception as e:
        logger.error(f"Error analyzing URL: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/report")
def report_url(request: ReportRequest):
    logger.info(f"User Report Received: {request.url}")
    try:
        log_user_report(request.url, request.reason)
        return {"status": "success", "message": "Report logged"}
    except Exception as e:
        logger.error(f"Error logging report: {e}")
        raise HTTPException(status_code=500, detail="Failed to log report")

@app.api_route("/stats", methods=["GET", "HEAD"])
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
