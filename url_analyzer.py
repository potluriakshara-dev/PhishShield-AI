"""
url_analyzer.py  —  PhishShield AI Backend
Handles all URL feature extraction and risk scoring.

Two scoring modes:
  1. Rule-based (always available) — transparent, fast, zero dependencies.
  2. ML model (Random Forest, if phishing_model.pkl is present) — trained
     on the same features below, gives a calibrated probability + the
     same human-readable flags for explainability.

If no trained model is found, this module falls back to rule-based
scoring automatically — nothing breaks on a fresh clone before you've
run train_model.py.
"""

import re
import os
from urllib.parse import urlparse

# ── Optional ML dependency — degrades gracefully if not installed ───────────
try:
    import joblib
    _ML_AVAILABLE = True
except ImportError:
    _ML_AVAILABLE = False

_MODEL_PATH = os.path.join(os.path.dirname(__file__), "phishing_model.pkl")
_model = None
_model_load_attempted = False


def _get_model():
    """Lazy-load the trained model once. Returns None if unavailable."""
    global _model, _model_load_attempted
    if _model_load_attempted:
        return _model
    _model_load_attempted = True
    if _ML_AVAILABLE and os.path.isfile(_MODEL_PATH):
        try:
            _model = joblib.load(_MODEL_PATH)
        except Exception as e:
            print(f"[url_analyzer] Could not load ML model: {e}")
            _model = None
    return _model

# ── Known shortener domains (common in QR phishing / quishing) ──────────────
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "rb.gy"
}

# ── Keywords commonly found in phishing URLs ─────────────────────────────────
PHISHING_KEYWORDS = [
    "login", "verify", "secure", "update", "bank", "account",
    "confirm", "free", "lucky", "winner", "password", "signin",
    "ebay", "paypal", "amazon", "apple", "microsoft", "netflix",
    "support", "wallet", "reset", "suspend", "unusual", "alert"
]

# ── QR-specific tricks attackers use (quishing patterns) ────────────────────
QR_PHISHING_PATTERNS = [
    r'%[0-9a-fA-F]{2}',            # URL-encoded chars hiding intent
    r'https?://[^/]+//[^/]+',      # Double-slash redirect trick
    r'@',                           # user@domain spoof e.g. paypal.com@evil.com
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # Raw IP instead of domain
]


def extract_features(url: str) -> dict:
    """
    Extract a dictionary of numeric/boolean features from a URL.
    These feed directly into the scoring engine below.
    """
    if not url.startswith("http"):
        url = "https://" + url

    parsed = urlparse(url)
    netloc = parsed.netloc.lower()
    path   = parsed.path.lower()
    full   = url.lower()

    # Strip www. for cleaner domain analysis
    domain = netloc.replace("www.", "")

    features = {
        # ── Structural features ──────────────────────────────────────────────
        "url_length":       len(url),
        "dot_count":        url.count("."),
        "slash_count":      url.count("/"),
        "hyphen_count":     url.count("-"),
        "at_symbol":        1 if "@" in url else 0,
        "double_slash":     1 if "//" in parsed.path else 0,
        "has_port":         1 if parsed.port else 0,

        # ── Security features ────────────────────────────────────────────────
        "has_https":        1 if parsed.scheme == "https" else 0,
        "has_ip_address":   1 if re.search(r'\d{1,3}(\.\d{1,3}){3}', netloc) else 0,
        "has_encoding":     1 if "%" in url else 0,

        # ── Domain features ──────────────────────────────────────────────────
        "subdomain_depth":  max(0, len(domain.split(".")) - 2),
        "is_shortener":     1 if any(s in netloc for s in SHORTENERS) else 0,
        "tld_suspicious":   1 if any(url.endswith(t) for t in [
                                ".xyz", ".top", ".club", ".icu",
                                ".tk", ".ml", ".ga", ".cf"]) else 0,

        # ── Content features ─────────────────────────────────────────────────
        "keyword_count":    sum(1 for k in PHISHING_KEYWORDS if k in full),
        "digit_ratio":      sum(c.isdigit() for c in netloc) / max(len(netloc), 1),

        # ── QR / quishing-specific features ─────────────────────────────────
        "qr_trick_count":   sum(1 for p in QR_PHISHING_PATTERNS
                                if re.search(p, url)),
    }
    return features


def calculate_risk(features: dict) -> dict:
    """
    Convert features into a 0–10 risk score, verdict, and human-readable flags.
    Returns a dict the frontend can directly consume.
    """
    score = 0.0
    flags = []      # Short flag labels shown in the Threat Flags panel
    details = []    # Longer descriptions (can be used in tooltips/reports)

    # ── Rule-based scoring ───────────────────────────────────────────────────

    if not features["has_https"]:
        score += 2.0
        flags.append("⚠ No HTTPS — connection is unencrypted")

    if features["has_ip_address"]:
        score += 2.5
        flags.append("⚠ Raw IP address used instead of domain name")

    if features["at_symbol"]:
        score += 2.0
        flags.append("⚠ @ symbol found — possible domain spoofing")

    if features["url_length"] > 75:
        score += 1.0
        flags.append(f"⚠ URL unusually long ({features['url_length']} chars)")

    if features["dot_count"] > 4:
        score += 1.0
        flags.append(f"⚠ Too many dots ({features['dot_count']}) — deep subdomains")

    if features["hyphen_count"] > 3:
        score += 0.5
        flags.append(f"⚠ Excessive hyphens ({features['hyphen_count']})")

    if features["subdomain_depth"] > 2:
        score += 1.0
        flags.append(f"⚠ Suspicious subdomain depth ({features['subdomain_depth']})")

    if features["is_shortener"]:
        score += 1.5
        flags.append("⚠ URL shortener detected — hides true destination")

    if features["tld_suspicious"]:
        score += 1.5
        flags.append("⚠ Suspicious top-level domain (e.g. .xyz .tk .icu)")

    if features["has_encoding"]:
        score += 1.0
        flags.append("⚠ URL encoding found — may hide malicious intent")

    if features["double_slash"]:
        score += 1.5
        flags.append("⚠ Double-slash redirect trick in path")

    if features["keyword_count"] >= 2:
        score += 1.5
        flags.append(f"⚠ {features['keyword_count']} phishing keywords in URL")
    elif features["keyword_count"] == 1:
        score += 0.5
        flags.append("⚠ Phishing keyword present in URL")

    if features["digit_ratio"] > 0.4:
        score += 1.0
        flags.append("⚠ High ratio of digits in domain (unusual)")

    if features["qr_trick_count"] >= 1:
        score += 2.0 * features["qr_trick_count"]
        flags.append(f"⚠ {features['qr_trick_count']} QR phishing trick(s) detected (quishing)")

    if features["has_port"]:
        score += 1.0
        flags.append("⚠ Non-standard port in URL")

    # ── Safe signals reduce score slightly ───────────────────────────────────
    if features["has_https"] and features["keyword_count"] == 0:
        score -= 0.5
    if not flags:
        flags.append("✅ No suspicious patterns detected")

    # ── Clamp to 0–10 scale ──────────────────────────────────────────────────
    score = round(max(0.0, min(10.0, score)), 1)

    # ── Verdict ──────────────────────────────────────────────────────────────
    if score >= 6:
        verdict = "PHISHING"
    elif score >= 3.5:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"

    return {
        "score":   score,       # float 0.0 – 10.0
        "verdict": verdict,     # "SAFE" | "SUSPICIOUS" | "PHISHING"
        "flags":   flags,       # list of flag strings for the UI panel
    }


def calculate_risk_ml(features: dict) -> dict:
    """
    Score a URL using the trained Random Forest model.
    Falls back to None if no model is loaded — caller should
    fall back to calculate_risk() (rule-based) in that case.

    The model was trained on the exact feature set extract_features()
    produces, so features dicts are passed straight through.
    """
    model = _get_model()
    if model is None:
        return None

    feature_order = [
        "url_length", "dot_count", "slash_count", "hyphen_count", "at_symbol",
        "double_slash", "has_port", "has_https", "has_ip_address", "has_encoding",
        "subdomain_depth", "is_shortener", "tld_suspicious", "keyword_count",
        "digit_ratio", "qr_trick_count",
    ]
    import pandas as pd
    row = pd.DataFrame([[features[k] for k in feature_order]], columns=feature_order)

    proba = model.predict_proba(row)[0][1]   # probability of "phishing" class
    score = round(proba * 10, 1)              # scale to same 0-10 range as rule-based

    if score >= 6:
        verdict = "PHISHING"
    elif score >= 3.5:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"

    return {"score": score, "verdict": verdict, "model": "random_forest"}



def analyze_url(url: str) -> dict:
    """
    Main entry point.
    Call this from the frontend with any URL string.

    Uses the trained Random Forest model for the score when available
    (phishing_model.pkl present), otherwise falls back to the rule-based
    score. The human-readable flags always come from the rule engine,
    so every prediction — ML or rule-based — is explainable.

    Returns:
        {
          "score": float,        # 0.0 - 10.0
          "verdict": str,        # "SAFE" | "SUSPICIOUS" | "PHISHING"
          "flags": list[str],    # explanation, always present
          "model": str           # "random_forest" or "rule_based"
        }
    """
    url = url.strip()
    if not url:
        return {"score": 0.0, "verdict": "SAFE", "flags": ["No URL provided"], "model": "rule_based"}

    features = extract_features(url)
    rule_result = calculate_risk(features)   # always computed — gives the flags
    ml_result = calculate_risk_ml(features)  # None if no trained model present

    if ml_result is not None:
        # Use the ML score/verdict, but keep the rule-based flags as explanation
        return {
            "score": ml_result["score"],
            "verdict": ml_result["verdict"],
            "flags": rule_result["flags"],
            "model": "random_forest",
        }

    # No trained model available — pure rule-based fallback
    rule_result["model"] = "rule_based"
    return rule_result

