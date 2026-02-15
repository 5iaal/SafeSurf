from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from typing import Any, Dict

from detectors.url_detector import analyze_url
from detectors.email_detector import analyze_email

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/analyze-url")
async def analyze_url_endpoint(data: Dict[str, Any]):
    """
    payload:
    { "url": "https://..." }
    """
    try:
        url = data.get("url", "")
        riskScore, status, reasons = analyze_url(url)
        return {"riskScore": riskScore, "status": status, "reasons": reasons}
    except Exception as e:
        return {"riskScore": 0.0, "status": "safe", "reasons": [f"Server error: {str(e)}"]}

@app.post("/analyze-email")
async def analyze_email_endpoint(data: Dict[str, Any]):
    """
    payload:
    { "sender": "...", "subject": "...", "body": "..." }
    """
    try:
        sender = data.get("sender", "")
        subject = data.get("subject", "")
        body = data.get("body", "")
        riskScore, status, reasons = analyze_email(sender, subject, body)
        return {"riskScore": riskScore, "status": status, "reasons": reasons}
    except Exception as e:
        return {"riskScore": 0.0, "status": "safe", "reasons": [f"Server error: {str(e)}"]}
