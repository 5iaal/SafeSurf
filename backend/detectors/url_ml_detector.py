import re
import math
import tldextract
import pickle
import os
import base64
import hashlib
from urllib.parse import urlparse, parse_qs
from difflib import SequenceMatcher

MODEL_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "models", "url_ml_model.pkl"))
SUSPICIOUS_TLDS = {"xyz","top","club","online","site","info","tk"}

SUSPICIOUS_WORDS = {
    "login","verify","secure","update",
    "account","bank","paypal","confirm",
    "password","auth","token","session",
    "redirect","signin","wallet"
}

TOP_BRANDS = {
    "google","paypal","facebook","amazon",
    "apple","microsoft","instagram"
}

CACHE = {}

def load_model():
    if not os.path.exists(MODEL_PATH):
        raise Exception("Model not trained. Run train_url_model.py first.")
    with open(MODEL_PATH,"rb") as f:
        return pickle.load(f)

class URLDetector:

    def __init__(self):
        self.model, self.vectorizer = load_model()

    def analyze(self,url):

        url_hash = hashlib.md5(url.encode()).hexdigest()
        if url_hash in CACHE:
            return CACHE[url_hash]

        parsed = urlparse(url)
        ext = tldextract.extract(url)
        domain = ext.domain.lower()
        full_domain = ext.fqdn.lower()

        risk = 0

        # ===== STRUCTURE =====
        if parsed.scheme != "https":
            risk += 5

        if len(url) > 75:
            risk += 5

        if "@" in url:
            risk += 10

        if ext.suffix in SUSPICIOUS_TLDS:
            risk += 5

        # ===== BRAND =====
        for brand in TOP_BRANDS:
            if brand in full_domain:
                risk += 5
            similarity = SequenceMatcher(None, domain, brand).ratio()
            if 0.8 < similarity < 1:
                risk += 15

        for word in SUSPICIOUS_WORDS:
            if word in url.lower():
                risk += 3

        # ===== QUERY =====
        params = parse_qs(parsed.query)
        for p in params:
            if p.lower() in SUSPICIOUS_WORDS:
                risk += 5
            val = params[p][0]
            if len(val) > 50:
                risk += 3
            try:
                base64.b64decode(val)
                risk += 5
            except:
                pass

        # ===== ML =====
        X = self.vectorizer.transform([url])
        ml_prob = self.model.predict_proba(X)[0][1]
        risk += ml_prob * 20

        confidence = 1 / (1 + math.exp(-risk/15))
        is_phishing = risk > 25

        final_label = "phishing" if is_phishing else "legitimate"

        result = {
            "url": url,
            "prediction": final_label,
            "risk_score": round(risk,2),
            "confidence": round(confidence*100,2)
        }

        CACHE[url_hash] = result
        return result