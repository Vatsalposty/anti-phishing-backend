from fastapi import FastAPI, HTTPException, Request, BackgroundTasks
from fastapi.responses import JSONResponse
from pydantic import BaseModel, field_validator
from starlette.middleware.base import BaseHTTPMiddleware
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

# Security Headers Middleware
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
        return response

app.add_middleware(SecurityHeadersMiddleware)

@app.api_route("/", methods=["GET", "HEAD"])
def health_check():
    return {"status": "active", "service": "Anti-Phishing Backend"}

# Load Model
model = PhishingModel()

# --- Pydantic Models ---
class AnalyzeRequest(BaseModel):
    url: str
    features: dict = None

    @field_validator('url')
    @classmethod
    def validate_url(cls, v):
        if len(v) > 2048:
            raise ValueError('URL exceeds maximum length of 2048 characters')
        if not v.startswith(('http://', 'https://')):
            raise ValueError('URL must start with http:// or https://')
        return v

class AnalyzeResponse(BaseModel):
    url: str
    status: str # "safe", "phishing", "suspicious"
    confidence: int # 0-100
    reason: str # Description of detection

class ReportRequest(BaseModel):
    url: str
    reason: str = "user_report"

    @field_validator('url')
    @classmethod
    def validate_url(cls, v):
        if len(v) > 2048:
            raise ValueError('URL exceeds maximum length of 2048 characters')
        if not v.startswith(('http://', 'https://')):
            raise ValueError('URL must start with http:// or https://')
        return v

    @field_validator('reason')
    @classmethod
    def validate_reason(cls, v):
        if len(v) > 500:
            raise ValueError('Reason exceeds maximum length of 500 characters')
        return v

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
        raise HTTPException(status_code=500, detail="Internal analysis error")

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

@app.api_route("/stats", methods=["GET", "HEAD"])
@limiter.limit("30/minute")
def get_stats(request: Request):
    return {
        "total_scans": 1245,
        "threats_blocked": 87,
        "system_status": "healthy",
        "model_version": "2.1.0"
    }

# --- Auto-Retrain Endpoint (Protected by Secret Key) ---
def background_retrain():
    try:
        from train_model import train
        logger.info("Retraining model via API in background...")
        success = train()
        if success:
            global model
            model = PhishingModel()
            logger.info("Model retrained and reloaded successfully!")
            log_system_event("retrain", "Model retrained successfully via API")
        else:
            logger.error("Training failed — not enough data")
    except Exception as e:
        logger.error(f"Retraining error: {e}")

@app.post("/retrain")
@limiter.limit("2/hour")
def retrain_model(request: Request, background_tasks: BackgroundTasks):
    """Trigger model retraining. Protected by RETRAIN_SECRET env var."""
    # Verify authorization
    retrain_secret = os.environ.get("RETRAIN_SECRET")
    if not retrain_secret:
        raise HTTPException(status_code=503, detail="Retraining not configured")

    auth_header = request.headers.get("Authorization", "")
    if auth_header != f"Bearer {retrain_secret}":
        raise HTTPException(status_code=403, detail="Unauthorized")

    background_tasks.add_task(background_retrain)
    return {"status": "success", "message": "Model retraining started in the background"}

if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
