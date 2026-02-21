from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from typing import Any, Dict, List

from detectors.url_detector import analyze_url
from detectors.email_detector import analyze_email
from detectors.url_ml_detector import URLDetector

app = FastAPI()

# Create ML detector once (better performance)
url_ml = URLDetector()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def merge_url_results(
    rule_score: float,
    rule_status: str,
    rule_reasons: List[str],
    ml_pred: str,
    ml_confidence: float,
) -> Dict[str, Any]:
    """
    Merge Rule-based + ML into one final result for the frontend.
    - riskScore: 0..0.99
    - status: safe | low_risk | high_risk
    - reasons: combined explainable list
    """

    # Convert ML confidence (0..100) to 0..0.99 scale
    ml_score = round(min(max(ml_confidence, 0.0) / 100.0, 0.99), 2)

    # Hybrid score (adjust weights as you like)
    # rules more explainable -> 60%, ML -> 40%
    final_score = round(min((rule_score * 0.6) + (ml_score * 0.4), 0.99), 2)

    # Decide status using final_score
    if final_score >= 0.7:
        final_status = "high_risk"
    elif final_score >= 0.4:
        final_status = "low_risk"
    else:
        final_status = "safe"

    # Build reasons (keep it clean, not too long)
    reasons: List[str] = []

    # Add rule reasons first (most explainable)
    if rule_reasons:
        reasons.extend(rule_reasons[:6])

    # Add ML summary
    pred_label = "phishing" if str(ml_pred).lower() in ["phishing", "malicious", "1", "true"] else "legitimate"
    reasons.append(f"ML prediction: {pred_label}")
    reasons.append(f"ML confidence: {round(ml_confidence, 1)}%")

    # Add final explanation
    reasons.append(f"Hybrid score = 60% rules + 40% ML")

    return {
        "riskScore": final_score,
        "status": final_status,
        "reasons": reasons,
        "meta": {  # optional: extra info (frontend can ignore)
            "ruleScore": rule_score,
            "ruleStatus": rule_status,
            "mlScore": ml_score,
            "mlPrediction": pred_label,
            "mlConfidence": ml_confidence,
        },
    }


@app.post("/analyze-url")
async def analyze_url_endpoint(data: Dict[str, Any]):
    """
    payload:
    { "url": "https://..." }
    """
    try:
        url = (data.get("url") or "").strip()

        # 1) Rule-based analysis (your current engine)
        rule_score, rule_status, rule_reasons = analyze_url(url)

        # 2) ML analysis (from url_ml_model.pkl)
        ml_result = url_ml.analyze(url)  # expected keys: prediction, confidence, risk_score (varies)
        ml_pred = ml_result.get("prediction", "legitimate")

        # confidence might be missing -> fallback to 50
        try:
            ml_confidence = float(ml_result.get("confidence", 50.0))
        except Exception:
            ml_confidence = 50.0

        # 3) Merge both results
        merged = merge_url_results(rule_score, rule_status, rule_reasons, ml_pred, ml_confidence)
        return merged

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