"""
url_analyzer.py  —  PhishShield AI Backend
Handles all URL feature extraction and risk scoring.
No changes needed here by the UI member.
"""

import re
from urllib.parse import urlparse

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


def analyze_url(url: str) -> dict:
    """
    Main entry point.
    Call this from the frontend with any URL string.
    Returns {"score": float, "verdict": str, "flags": list[str]}
    """
    url = url.strip()
    if not url:
        return {"score": 0.0, "verdict": "SAFE", "flags": ["No URL provided"]}

    features = extract_features(url)
    result   = calculate_risk(features)
    return result
