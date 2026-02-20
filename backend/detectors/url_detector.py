import re
import math
import ipaddress
from urllib.parse import urlparse
from typing import List, Tuple


# ==============================
# Configuration
# ==============================

TRUSTED_DOMAINS = [
    "google.com",
    "facebook.com",
    "amazon.com",
    "paypal.com",
    "microsoft.com",
    "apple.com",
    "instagram.com"
]

PHISHING_KEYWORDS = [
    "login", "verify", "update", "password",
    "suspended", "urgent", "secure",
    "account", "bank", "confirm",
    "signin", "wp-admin"
]

SUSPICIOUS_KEYWORDS = [
    "test", "demo", "trial", "example"
]


# ==============================
# Utility Functions
# ==============================

def shannon_entropy(string: str) -> float:
    if not string:
        return 0.0
    prob = [float(string.count(c)) / len(string) for c in dict.fromkeys(string)]
    return -sum(p * math.log(p, 2) for p in prob)


def levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        return levenshtein(b, a)
    if len(b) == 0:
        return len(a)

    previous_row = range(len(b) + 1)
    for i, c1 in enumerate(a):
        current_row = [i + 1]
        for j, c2 in enumerate(b):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def is_ip(domain: str) -> bool:
    try:
        ipaddress.ip_address(domain)
        return True
    except ValueError:
        return False


# ==============================
# Main Detection Engine
# ==============================

def analyze_url(url: str) -> Tuple[float, str, List[str]]:

    reasons: List[str] = []
    risk_score = 0.0

    if not url or not url.strip():
        return 0.0, "safe", ["Empty URL input"]

    url = url.strip().lower()

    # Add scheme if missing
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    if domain.startswith("www."):
        domain = domain[4:]

    main_domain = domain.split(":")[0]

    # ==============================
    # 1️⃣ Whitelist Check
    # ==============================
    if any(main_domain.endswith(td) for td in TRUSTED_DOMAINS):
        return 0.0, "safe", ["Trusted domain"]

    # ==============================
    # 2️⃣ IP Address Usage
    # ==============================
    if is_ip(main_domain):
        risk_score += 0.35
        reasons.append("Uses IP address instead of domain")

    # ==============================
    # 3️⃣ HTTP Instead of HTTPS
    # ==============================
    if parsed.scheme == "http":
        risk_score += 0.10
        reasons.append("Uses HTTP instead of HTTPS")

    # ==============================
    # 4️⃣ URL Length
    # ==============================
    if len(url) > 75:
        risk_score += 0.10
        reasons.append("URL is unusually long")

    # ==============================
    # 5️⃣ Excessive Subdomains
    # ==============================
    if main_domain.count(".") > 3:
        risk_score += 0.12
        reasons.append("Too many subdomains")

    # ==============================
    # 6️⃣ '@' Symbol Detection
    # ==============================
    if "@" in url:
        risk_score += 0.25
        reasons.append("Contains '@' (URL deception technique)")

    # ==============================
    # 7️⃣ Hyphen Abuse
    # ==============================
    if "-" in main_domain:
        risk_score += 0.08
        reasons.append("Hyphen in domain name")

    # ==============================
    # 8️⃣ Suspicious Keywords
    # ==============================
    for word in PHISHING_KEYWORDS:
        if word in url:
            risk_score += 0.07
            reasons.append(f"Contains phishing keyword: {word}")
            break

    for word in SUSPICIOUS_KEYWORDS:
        if word in url:
            risk_score += 0.04
            reasons.append(f"Contains suspicious keyword: {word}")
            break

    # ==============================
    # 9️⃣ High Entropy Detection
    # ==============================
    entropy = shannon_entropy(main_domain.replace(".", ""))
    if entropy > 4:
        risk_score += 0.15
        reasons.append("Domain appears random (high entropy)")

    # ==============================
    # 🔟 Brand Impersonation
    # ==============================
    for brand in TRUSTED_DOMAINS:
        brand_name = brand.split(".")[0]
        if brand_name in main_domain and not main_domain.endswith(brand):
            risk_score += 0.25
            reasons.append(f"Possible brand impersonation of '{brand_name}'")
            break

    # ==============================
    # 1️⃣1️⃣ Typosquatting Detection
    # ==============================
    base_domain = main_domain.split(".")[0]
    for trusted in TRUSTED_DOMAINS:
        trusted_base = trusted.split(".")[0]
        distance = levenshtein(base_domain, trusted_base)
        if 0 < distance <= 2:
            risk_score += 0.30
            reasons.append(f"Possible typosquatting of '{trusted_base}'")
            break

    # ==============================
    # Normalize Score
    # ==============================
    risk_score = min(risk_score, 0.99)
    risk_score = round(risk_score, 2)

    # ==============================
    # Final Classification
    # ==============================
    if risk_score >= 0.7:
        status = "high_risk"
    elif risk_score >= 0.4:
        status = "low_risk"
    else:
        status = "safe"

    if not reasons:
        reasons.append("No suspicious indicators detected")

    return risk_score, status, reasons