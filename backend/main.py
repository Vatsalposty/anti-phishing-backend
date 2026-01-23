from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
from model import PhishingModel
from firebase_db import log_attempt, log_system_event
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

# Load Model
model = PhishingModel()

class AnalyzeRequest(BaseModel):
    url: str
    features: dict = None

class AnalyzeResponse(BaseModel):
    url: str
    status: str # "safe", "phishing", "suspicious"
    confidence: int # 0-100

@app.get("/")
def read_root():
    return {"message": "Anti-Phishing API is running"}

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

if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
