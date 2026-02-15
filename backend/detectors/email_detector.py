import hashlib
from typing import List, Tuple

EMAIL_URGENCY_WORDS = ["urgent", "immediately", "asap", "action required", "suspended", "verify now"]
EMAIL_SOCIAL_ENGINEERING = ["confirm your account", "reset your password", "payment failed", "unusual activity"]
EMAIL_LINK_WORDS = ["click", "link", "open", "download", "attachment"]

PHISHING_KEYWORDS = [
    "login", "verify", "update", "password", "suspended", "urgent",
    "click", "bank", "paypal", "security", "account"
]

def _base(text: str) -> float:
    t = (text or "").lower().strip()
    if not t:
        return 0.0
    h = hashlib.md5(t.encode()).hexdigest()
    return int(h[:2], 16) / 255

def analyze_email(sender: str, subject: str, body: str) -> Tuple[float, str, List[str]]:
    reasons: List[str] = []
    s = (sender or "").lower().strip()
    sub = (subject or "").lower().strip()
    b = (body or "").lower().strip()

    combined = f"{s} {sub} {b}".strip()
    if not combined:
        return 0.0, "safe", ["Empty email content"]

    urgency_hits = [w for w in EMAIL_URGENCY_WORDS if w in combined]
    social_hits = [w for w in EMAIL_SOCIAL_ENGINEERING if w in combined]
    link_hits = [w for w in EMAIL_LINK_WORDS if w in combined]
    phishing_hits = [w for w in PHISHING_KEYWORDS if w in combined]

    for w in urgency_hits[:4]:
        reasons.append(f"Urgency language detected: {w}")
    for w in social_hits[:3]:
        reasons.append(f"Social-engineering phrase detected: {w}")
    for w in link_hits[:3]:
        reasons.append(f"Call-to-click/download detected: {w}")
    for w in phishing_hits[:4]:
        reasons.append(f"Suspicious keyword in email: {w}")

    # Sender vs subject simple impersonation check
    if "@" in s:
        domain = s.split("@")[-1]
        if "paypal" in sub and "paypal" not in domain:
            reasons.append("Brand mention doesn't match sender domain (possible impersonation)")

    base = _base(combined)

    # Email scoring (different weights than URL)
    score = (base * 0.2)
    score += len(urgency_hits) * 0.15
    score += len(social_hits) * 0.12
    score += len(link_hits) * 0.08
    score += len(phishing_hits) * 0.06

    score = min(score, 0.99)
    score = round(score, 2)

    if score > 0.7:
        status = "high_risk"
    elif score > 0.3:
        status = "low_risk"
    else:
        status = "safe"

    if not reasons:
        reasons.append("No suspicious email indicators detected")

    return score, status, reasons
