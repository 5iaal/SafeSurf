from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import hashlib

app = FastAPI()

# تمكين CORS للـ frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # production: ضع رابط الـ frontend
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# كلمات مفتاحية للخطر
PHISHING_KEYWORDS = ["login", "verify", "update", "password", "suspended", "urgent", "click", "bank", "paypal", "security", "account"]
SUSPICIOUS_KEYWORDS = ["test", "demo", "trial", "example", "sample"]

def calculate_risk_score(text: str) -> float:
    """
    يحسب نسبة الخطر من 0 (safe) لـ 1 (high risk) بناء على الكلمات المفتاحية
    deterministic = نفس النص يعطي نفس النتيجة دائمًا
    """
    text = text.lower()
    
    # عدد كلمات الخطر
    phishing_hits = sum(word in text for word in PHISHING_KEYWORDS)
    suspicious_hits = sum(word in text for word in SUSPICIOUS_KEYWORDS)
    
    # دمج hits مع deterministic hash عشان نفس النص يعطي نفس النتيجة
    h = hashlib.md5(text.encode()).hexdigest()
    base = int(h[:2], 16) / 255  # رقم من 0 إلى 1

    # صيغة لزيادة النسبة مع الكلمات الخطرة
    score = base * 0.3 + phishing_hits * 0.1 + suspicious_hits * 0.05
    score = min(score, 0.99)  # أقصى حد
    return round(score, 2)

def determine_status(risk_score: float) -> str:
    if risk_score > 0.7:
        return "high_risk"
    elif risk_score > 0.3:
        return "low_risk"
    else:
        return "safe"

@app.post("/analyze")
async def analyze(data: dict):
    """
    يتوقع data بالشكل:
    {
        "type": "url" أو "email",
        "value": str (لـ url) أو dict {"sender", "subject", "body"} (لـ email)
    }
    """
    try:
        if data["type"] == "url":
            url = data["value"]
            riskScore = calculate_risk_score(url)
        elif data["type"] == "email":
            email = data["value"]
            combined = email.get("sender", "") + " " + email.get("subject", "") + " " + email.get("body", "")
            riskScore = calculate_risk_score(combined)
        else:
            riskScore = 0.0

        status = determine_status(riskScore)
        return {"status": status, "riskScore": riskScore}
    except Exception as e:
        return {"status": "safe", "riskScore": 0.0}
