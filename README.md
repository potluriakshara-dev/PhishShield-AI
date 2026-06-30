# 🛡️ PhishShield AI

**Real-time phishing URL detection & QR code (quishing) threat analysis**

PhishShield AI is a web app that checks links — typed, pasted, or hidden inside a QR code — and tells you in plain language whether they're **Safe**, **Suspicious**, or **Phishing**, and *why*.

🔗 Live demo: 
📂 Repo: https://phishshield-w5aa.onrender.com

---

## The problem

Phishing tricks people into giving up passwords through fake, lookalike links (`paypai.com`, `sbi-login-secure.xyz`). Attackers hide the real destination and most users can't tell the danger until it's too late — and a growing share of these links now arrive hidden inside **QR codes** ("quishing"), a threat surface most phishing tools never check at all.

PhishShield AI stops the click before it happens — fast, accurate, and explainable.

## How it works

```
Enter URL / scan QR → extract URL features → ML model scores it → plain-language explanation
```

1. **Rule-based baseline** — instantly checks classic signals: URL length, dot/subdomain count, HTTPS presence, IP-address hosts, `@`/`//` tricks, hyphen count, and suspicious keywords (`login`, `verify`, `secure`, `update`, `bank`...).
2. **ML model (Random Forest)** — trained on the same 16 URL features the rule engine extracts, so it's a direct upgrade on the baseline rather than a separate black box.
3. **Explainability** — every verdict ships with its reasoning (e.g. *"HTTPS missing (top factor), 3 suspicious keywords, IP address used instead of domain"*), not just a label.
4. **QR code scanning** — upload a QR image or scan live via webcam; the decoded URL is run through the same analysis pipeline.

## Model performance

Trained and 5-fold cross-validated on 639 labeled URLs (283 phishing-pattern, 356 legitimate — PhishTank-style attack patterns plus real domains including Indian banking/government sites):

| Metric | Result |
|---|---|
| Accuracy | 98.0% |
| Precision | 98.9% (3 safe links wrongly flagged out of 356) |
| Recall | 96.5% (273 of 283 phishing links caught) |
| Inference time | ~8.4 ms per URL |

Top predictive features: HTTPS presence (24%), keyword count (18%), digit ratio (12%), dot count (11%).

> **Honest limitation:** this is a prototype-stage, synthetic dataset built from realistic phishing patterns rather than a live feed. The next milestone is validating against real PhishTank submissions and live traffic before any production use.

## Two interfaces, one backend

PhishShield AI ships with **both** a web app and a native desktop app — both call the exact same `url_analyzer.py` / `qr_scanner.py` / `logger.py` backend, so results are identical either way.

- 🌐 **Web app** (`web_server.py`, Flask) — the version meant for deployment and the live demo link, accessible from any browser.
- 🖥️ **Desktop app** (`main.py`, Tkinter) — a standalone dark-themed GUI with a circular risk gauge, threat-flags panel, QR upload/webcam scanning, multilingual (Telugu + Hindi) risk warnings, and a scan-history viewer. Good for offline demos at the hackathon table where you want a polished native window instead of a browser tab.

## Features

- 🔗 **URL analyzer** — paste any link for an instant risk score and explanation
- 📷 **QR code scanner** — upload an image or use your webcam to scan and check QR codes before opening them
- 📜 **Scan history** — recent checks are logged to CSV and viewable in both the web dashboard and the desktop app's history window
- 🧠 **Dual-engine scoring** — rule-based engine always runs for explainability; ML model sharpens the verdict when available, with automatic fallback to pure rule-based scoring if the model isn't loaded
- 🌏 **Multilingual warnings** — the desktop app surfaces phishing/suspicious/safe warnings in Telugu and Hindi alongside English
- 🔌 **API-first** — simple REST endpoints (web app) so the detection logic can be dropped into other tools (browser extensions, email scanners, signing workflows)

## Tech stack

- **Backend logic:** Python (`url_analyzer.py`, `qr_scanner.py`, `logger.py`) — shared by both UIs
- **Web UI:** Flask, gunicorn, HTML/CSS/JS templates
- **Desktop UI:** Tkinter + ttk (native Python GUI, no extra install needed)
- **ML:** scikit-learn (Random Forest), pandas, numpy, joblib
- **QR decoding:** OpenCV (`opencv-python-headless`), `pyzbar`
- **Deployment:** Docker (web app only — see deployment note below)

## Project structure

```
.
├── main.py               # Tkinter desktop app — risk gauge, QR scan, multilingual warnings
├── web_server.py         # Flask app — routes for /analyze, /scan_qr_image, /scan_frame, /history
├── url_analyzer.py       # Feature extraction + scoring (rule-based, with ML fallback)
├── qr_scanner.py         # QR decoding from images / webcam
├── logger.py             # Scan history logging (CSV)
├── generate_dataset.py   # Builds the labeled training dataset
├── train_model.py        # Trains the Random Forest model + 5-fold CV
├── phishing_dataset.csv  # Generated training dataset (639 URLs)
├── phishing_model.pkl    # Trained model, auto-loaded by url_analyzer.py
├── templates/             # Web dashboard UI
├── requirements.txt
└── Dockerfile
```

## Running locally

```bash
git clone https://github.com/potluriakshara-dev/PhishShield-AI.git
cd PhishShield-AI

pip install -r requirements.txt
```

**Web app:**
```bash
python web_server.py
```
Open **http://127.0.0.1:5001** in your browser.

**Desktop app (Tkinter):**
```bash
python main.py
```
Opens a native window — no browser needed. Tkinter ships with standard Python on Windows/macOS; on Linux you may need `sudo apt install python3-tk` first.

> **Note on deployment:** Tkinter renders a native OS window and has no way to run inside a browser or behind a public URL, so only the web app (`web_server.py`) gets deployed for judges to access remotely. The desktop app is best demoed live or via a short screen-recording/GIF in your submission, alongside the link to the hosted web app.

To regenerate the dataset and retrain the model yourself:

```bash
pip install scikit-learn pandas numpy joblib
python generate_dataset.py   # builds phishing_dataset.csv
python train_model.py        # trains phishing_model.pkl, prints metrics
```

## API reference

| Endpoint | Method | Description |
|---|---|---|
| `/analyze` | `POST` | Body: `{"url": "..."}` → returns risk score, verdict, and flags |
| `/scan_qr_image` | `POST` | Multipart file upload of a QR image → decodes and analyzes the URL |
| `/scan_frame` | `POST` | Body: `{"image": "<base64>"}` → decodes a webcam frame for a QR code |
| `/history` | `GET` | Returns the most recent 20 scan records |
