import hashlib
from typing import List, Tuple

PHISHING_KEYWORDS = [
    "login", "verify", "update", "password", "suspended", "urgent",
    "click", "bank", "paypal", "security", "account"
]
SUSPICIOUS_KEYWORDS = ["test", "demo", "trial", "example", "sample"]

def _base(text: str) -> float:
    t = (text or "").lower().strip()
    if not t:
        return 0.0
    h = hashlib.md5(t.encode()).hexdigest()
    return int(h[:2], 16) / 255

def analyze_url(url: str) -> Tuple[float, str, List[str]]:
    reasons: List[str] = []
    u = (url or "").lower().strip()

    if not u:
        return 0.0, "safe", ["Empty URL input"]

    phishing_hits = [w for w in PHISHING_KEYWORDS if w in u]
    suspicious_hits = [w for w in SUSPICIOUS_KEYWORDS if w in u]

    for w in phishing_hits[:5]:
        reasons.append(f"Suspicious keyword in URL: {w}")
    for w in suspicious_hits[:3]:
        reasons.append(f"Possible test/demo keyword in URL: {w}")

    # URL structure heuristics
    if u.startswith("http://"):
        reasons.append("URL is using HTTP (not HTTPS)")
    if u.count(".") >= 4:
        reasons.append("Many subdomains (can be suspicious)")
    if len(u) > 80:
        reasons.append("URL is unusually long")
    if "@" in u:
        reasons.append("URL contains '@' (deception pattern)")
    if "//" in u.replace("https://", "").replace("http://", ""):
        reasons.append("URL contains multiple '//' (suspicious)")

    base = _base(u)

    score = (base * 0.3) + (len(phishing_hits) * 0.12) + (len(suspicious_hits) * 0.06)
    if u.startswith("http://"):
        score += 0.10
    if u.count(".") >= 4:
        score += 0.08
    if len(u) > 80:
        score += 0.06

    score = min(score, 0.99)
    score = round(score, 2)

    # status
    if score > 0.7:
        status = "high_risk"
    elif score > 0.3:
        status = "low_risk"
    else:
        status = "safe"

    if not reasons:
        reasons.append("No suspicious URL indicators detected")

    return score, status, reasons
