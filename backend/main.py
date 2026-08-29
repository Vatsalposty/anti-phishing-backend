from fastapi import FastAPI, HTTPException, Request, BackgroundTasks, Query
from fastapi.responses import JSONResponse, HTMLResponse
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
from dotenv import load_dotenv
from firebase_db import db
import html

# Load environment variables
load_dotenv()

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

def custom_rate_limit_exceeded_handler(request: Request, exc: Exception):
    """Custom rate limit handler that includes CORS headers."""
    response = JSONResponse(
        {"detail": f"Rate limit exceeded: {getattr(exc, 'detail', str(exc))}"}, status_code=429
    )
    response.headers["Access-Control-Allow-Origin"] = "*"
    return response

limiter = Limiter(key_func=get_remote_address)
is_prod = os.environ.get("PRODUCTION_MODE", "false").lower() == "true"

app = FastAPI(
    title="Anti-Phishing Backend API", 
    lifespan=lifespan,
    docs_url=None if is_prod else "/docs",
    redoc_url=None if is_prod else "/redoc",
    openapi_url=None if is_prod else "/openapi.json"
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, custom_rate_limit_exceeded_handler)

# CORS Configuration — Production Grade
# If in production, we only allow specific origins (or no browser origins if only extension is used).
# We allow all origins in dev mode or if explicitly required, but strict is better.
is_prod = os.environ.get("PRODUCTION_MODE", "false").lower() == "true"
allowed_origins = [] if is_prod else ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins if allowed_origins else ["chrome-extension://*"], # Using wildcard if not possible to know ID
    allow_credentials=False,
    allow_methods=["GET", "POST", "HEAD", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
    max_age=600,
)
# Note: For chrome extensions, it's often easiest to leave allow_origins=["*"] 
# because extensions don't send an Origin header by default unless from a content script.
# We will enforce allow_origins=["*"] but you can restrict it to your extension ID in production.
if is_prod:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"], # Render requires * for extensions usually, but could be restricted to extension ID
        allow_credentials=False,
        allow_methods=["GET", "POST", "HEAD", "OPTIONS"],
        allow_headers=["Content-Type", "Authorization"],
        max_age=600,
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
def root_check():
    return {"status": "active", "service": "Anti-Phishing Backend"}

@app.api_route("/health", methods=["GET", "HEAD"])
def health_check():
    return {"status": "active", "service": "Anti-Phishing Backend"}

# Load Model
model = PhishingModel()

# --- Pydantic Models ---
class AnalyzeRequest(BaseModel):
    url: str
    features: dict | None = None

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

class UpdateStatusRequest(BaseModel):
    key: str
    doc_id: str
    status: str

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
        from training_data.train_xgboost import train_xgboost
        logger.info("Retraining model via API in background...")
        success = train_xgboost()
        if success is not False:
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

@app.post("/admin/update-status")
@limiter.limit("30/minute")
def update_report_status(request: Request, body: UpdateStatusRequest):
    admin_secret = os.environ.get("ADMIN_SECRET")
    if not admin_secret or body.key != admin_secret:
        raise HTTPException(status_code=403, detail="Unauthorized")
    
    if body.status not in ["phishing", "safe", "pending_review"]:
        raise HTTPException(status_code=400, detail="Invalid status")
        
    if not db:
        raise HTTPException(status_code=500, detail="Firebase not configured")
        
    try:
        doc_ref = db.collection('user_reports').document(body.doc_id)
        doc_ref.update({'status': body.status})
        return {"status": "success"}
    except Exception as e:
        logger.error(f"Error updating report status: {e}")
        raise HTTPException(status_code=500, detail="Failed to update status")

@app.get("/admin/reports", response_class=HTMLResponse)
@limiter.limit("10/minute")
def view_admin_reports(request: Request, key: str = Query(None)):
    """Simple Admin Dashboard to view Firebase reports."""
    admin_secret = os.environ.get("ADMIN_SECRET")
    if not admin_secret or key != admin_secret:
        raise HTTPException(status_code=403, detail="Unauthorized")

    if not db:
        return HTMLResponse("<h1>Firebase is not configured!</h1><p>Add FIREBASE_CREDENTIALS to your Render environment variables or put serviceAccountKey.json in the backend folder.</p>")

    try:
        reports_ref = db.collection('user_reports').order_by('last_reported', direction='DESCENDING').limit(100)
        reports = reports_ref.stream()

        html_content = """
        <html>
            <head>
                <title>Anti-Phishing Admin</title>
                <style>
                    body { font-family: -apple-system, sans-serif; background: #0d1117; color: #e6edf3; padding: 40px; }
                    h1 { color: #6e8efb; }
                    table { width: 100%; border-collapse: collapse; margin-top: 20px; background: #161b22; border-radius: 8px; overflow: hidden; }
                    th, td { padding: 12px 15px; text-align: left; border-bottom: 1px solid #30363d; }
                    th { background: #21262d; font-weight: 600; }
                    tr:hover { background: #1c2128; }
                    .url { color: #58a6ff; font-weight: bold; }
                    .badge { padding: 4px 8px; border-radius: 12px; font-size: 0.8rem; font-weight: bold; }
                    .bg-warning { background: rgba(210, 153, 34, 0.2); color: #d29922; }
                    .bg-danger { background: rgba(248, 81, 73, 0.2); color: #ff7b72; }
                    .bg-success { background: rgba(46, 160, 67, 0.2); color: #3fb950; }
                    button { border: none; padding: 6px 12px; margin-right: 5px; border-radius: 6px; cursor: pointer; font-weight: bold; font-size: 0.8rem; }
                    .btn-phishing { background: #da3633; color: white; }
                    .btn-safe { background: #238636; color: white; }
                </style>
                <script>
                    async function updateStatus(docId, status, key) {
                        try {
                            const response = await fetch('/admin/update-status', {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify({ key: key, doc_id: docId, status: status })
                            });
                            if (response.ok) {
                                window.location.reload();
                            } else {
                                alert('Failed to update status');
                            }
                        } catch (e) {
                            alert('Error: ' + e);
                        }
                    }
                </script>
            </head>
            <body>
                <h1>🛡️ User Reports Dashboard</h1>
                <p>Showing the 100 most recent URLs reported by users.</p>
                <table>
                    <thead>
                        <tr>
                            <th>Reported URL</th>
                            <th>Reason</th>
                            <th>Status</th>
                            <th>Count</th>
                            <th>Last Reported</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
        """
        
        for doc in reports:
            data = doc.to_dict()
            doc_id = doc.id
            time_str = data.get('last_reported', '').strftime("%Y-%m-%d %H:%M:%S") if hasattr(data.get('last_reported'), 'strftime') else str(data.get('last_reported', 'Unknown'))
            safe_url = html.escape(str(data.get('url', 'Unknown')))
            safe_reason = html.escape(str(data.get('reason', 'N/A')))
            
            raw_status = data.get('status', 'pending')
            safe_status = html.escape(str(raw_status))
            badge_class = "bg-warning"
            if raw_status == "phishing": badge_class = "bg-danger"
            elif raw_status == "safe": badge_class = "bg-success"
            
            safe_count = html.escape(str(data.get('report_count', 1)))
            safe_time = html.escape(str(time_str))
            html_content += f"""
                        <tr>
                            <td class="url">{safe_url}</td>
                            <td>{safe_reason}</td>
                            <td><span class="badge {badge_class}">{safe_status}</span></td>
                            <td>{safe_count}</td>
                            <td>{safe_time}</td>
                            <td>
                                <button class="btn-phishing" onclick="updateStatus('{doc_id}', 'phishing', '{key}')">Mark Phishing</button>
                                <button class="btn-safe" onclick="updateStatus('{doc_id}', 'safe', '{key}')">Mark Safe</button>
                            </td>
                        </tr>
            """
            
        html_content += """
                    </tbody>
                </table>
            </body>
        </html>
        """
        return HTMLResponse(content=html_content, status_code=200)

    except Exception as e:
        logger.error(f"Error fetching reports: {e}")
        return HTMLResponse(f"<h1>Error</h1><p>Could not fetch reports from Firebase.</p>")

if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
