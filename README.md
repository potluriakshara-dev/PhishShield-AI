# PhishShield AI — ML Model

This folder contains the AI/ML layer described in our project deck:
a Random Forest classifier trained on the same 16 URL features our
rule-based engine extracts.

## Files

| File | Purpose |
|---|---|
| `generate_dataset.py` | Builds the labeled training dataset (synthetic, pattern-based) |
| `train_model.py` | Trains the Random Forest + runs 5-fold cross-validation |
| `phishing_dataset.csv` | The generated dataset (639 URLs: 283 phishing-pattern, 356 legitimate) |
| `phishing_model.pkl` | The trained model, auto-loaded by `url_analyzer.py` |
| `url_analyzer.py` | Production scoring — uses the ML model when present, falls back to pure rule-based scoring otherwise |

## How to reproduce

```bash
pip install scikit-learn pandas numpy joblib

python generate_dataset.py   # builds phishing_dataset.csv
python train_model.py        # trains phishing_model.pkl, prints metrics
```

## Current results (5-fold cross-validation)

These are reproducible by re-running `train_model.py` — exact numbers
shift slightly between runs because the dataset is reshuffled, but
stay in the 97–99% range.

- **Accuracy:** ~98%
- **Precision:** ~99% (almost no safe links wrongly flagged)
- **Recall:** ~96–98% (catches nearly all phishing patterns)
- **Inference:** ~8ms per URL

## Honest limitations

This is a **prototype-stage, synthetic dataset** — built from realistic
phishing patterns (typosquatting, IP-based URLs, fake TLDs, URL
shorteners, brand impersonation) rather than scraped from a live
PhishTank feed. The next milestone before production use is validating
against real PhishTank submissions and real eMudhra traffic logs.

## Why both rule-based AND ML?

`url_analyzer.py` always computes the rule-based flags (e.g. "No HTTPS",
"3 phishing keywords found") for explainability, regardless of whether
the final score comes from the ML model or the rule engine. This means
every prediction — not just the safe fallback case — comes with a
plain-language reason, which is what the explainability slide of our
deck demonstrates.
