"""
generate_dataset.py  —  PhishShield AI
Builds the labeled training dataset used to train the Random Forest model.

This is a SYNTHETIC dataset built from realistic phishing patterns
(typosquatting, IP-based URLs, fake TLDs, URL shorteners, brand
impersonation) combined with real legitimate domains. It is a
prototype-stage dataset — the next milestone is validating against
a live PhishTank feed.

Run:
    python generate_dataset.py

Output:
    phishing_dataset.csv  (601 rows: 288 phishing-pattern, 313 legitimate)
"""

import pandas as pd
import numpy as np
import re
from urllib.parse import urlparse

from url_analyzer import extract_features  # reuse the SAME feature logic as production

np.random.seed(42)

# ── Legitimate domains (real, well-known sites + Indian gov/banking) ────────
LEGIT_DOMAINS = [
    "google.com", "github.com", "wikipedia.org", "amazon.com", "microsoft.com",
    "apple.com", "netflix.com", "linkedin.com", "stackoverflow.com", "reddit.com",
    "nytimes.com", "bbc.com", "spotify.com", "dropbox.com", "adobe.com",
    "salesforce.com", "zoom.us", "slack.com", "notion.so", "figma.com",
    "sbi.co.in", "hdfcbank.com", "icicibank.com", "irctc.co.in", "nic.in",
    "emudhra.com", "digilocker.gov.in", "uidai.gov.in", "incometax.gov.in",
    "flipkart.com", "myntra.com", "swiggy.com", "zomato.com", "paytm.com",
    "phonepe.com", "airtel.in", "jio.com",
]

BRANDS = ["paypal", "sbi", "hdfc", "amazon", "netflix", "icici", "microsoft",
          "apple", "google", "instagram", "flipkart", "paytm"]

# ── Obvious phishing templates (clear red flags) ─────────────────────────────
PHISHING_OBVIOUS = [
    "http://{brand}-login-verify.xyz/account/update",
    "http://{brand}.secure-confirm.tk/signin",
    "http://192.168.{a}.{b}/login/{brand}",
    "https://verify-{brand}-account.club/confirm?user={rand}",
    "http://{brand}secure.bank-update.ga/login",
    "http://{rand}.{rand2}.{brand}.suspend-alert.cf/login",
]

# ── Subtle phishing templates (fewer obvious signals — harder to catch) ─────
PHISHING_SUBTLE = [
    "https://{brand}-support.com/account",
    "https://my-{brand}.net/signin",
    "http://bit.ly/{rand}",
    "https://{brand}online.info/login",
    "https://{brand}.com.{rand}.net/verify",
]

# ── Borderline-legit templates (look slightly suspicious but ARE safe) ──────
LEGIT_TRICKY = [
    "https://accounts.{d}/signin",
    "https://secure.{d}/login",
    "https://{d}/verify-email?token={rand}",
    "https://api.{d}/v2/update-profile",
    "https://{d}/account/confirm-payment",
]

LEGIT_PATHS = ["", "/about", "/docs", "/help", "/products", "/blog/2026/article",
               "/user/settings", "/search?q=python", "/en/index.html"]


def rand_str(n=6):
    return ''.join(np.random.choice(list('abcdefghijklmnopqrstuvwxyz0123456789'), n))


def build_dataset() -> pd.DataFrame:
    rows = []

    # 260 obvious phishing
    for _ in range(260):
        t = np.random.choice(PHISHING_OBVIOUS)
        url = t.format(
            brand=np.random.choice(BRANDS), rand=rand_str(6), rand2=rand_str(4),
            a=np.random.randint(0, 255), b=np.random.randint(0, 255),
        )
        f = extract_features(url)
        f["label"] = 1
        f["url"] = url
        rows.append(f)

    # 190 subtle phishing
    for _ in range(190):
        t = np.random.choice(PHISHING_SUBTLE)
        url = t.format(brand=np.random.choice(BRANDS), rand=rand_str(6))
        f = extract_features(url)
        f["label"] = 1
        f["url"] = url
        rows.append(f)

    # 300 clean legitimate
    for _ in range(300):
        d = np.random.choice(LEGIT_DOMAINS)
        p = np.random.choice(LEGIT_PATHS)
        url = f"https://www.{d}{p}"
        f = extract_features(url)
        f["label"] = 0
        f["url"] = url
        rows.append(f)

    # 100 bare-domain legitimate (no path, no www — most common real-world case)
    for _ in range(100):
        d = np.random.choice(LEGIT_DOMAINS)
        use_www = np.random.choice([True, False])
        url = f"https://{'www.' if use_www else ''}{d}"
        f = extract_features(url)
        f["label"] = 0
        f["url"] = url
        rows.append(f)


    # 150 borderline-legit (harder negative examples)
    for _ in range(150):
        t = np.random.choice(LEGIT_TRICKY)
        d = np.random.choice(LEGIT_DOMAINS)
        url = t.format(d=d, rand=rand_str(8))
        f = extract_features(url)
        f["label"] = 0
        f["url"] = url
        rows.append(f)

    df = pd.DataFrame(rows).sample(frac=1, random_state=42).reset_index(drop=True)
    df = df.drop_duplicates(subset=["url"]).reset_index(drop=True)
    return df


if __name__ == "__main__":
    df = build_dataset()
    df.to_csv("phishing_dataset.csv", index=False)
    print(f"Dataset created: {len(df)} rows "
          f"({df.label.sum()} phishing, {(df.label==0).sum()} legitimate)")
    print("Saved to phishing_dataset.csv")
