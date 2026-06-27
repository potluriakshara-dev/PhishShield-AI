# PhishShield AI — Threat & QR (Quishing) Scanner

PhishShield AI is a cybersecurity utility that protects users against phishing URLs and QR code-based phishing (quishing) threats. It features both a desktop client interface and a responsive, glassmorphic web dashboard.

---

## 🌟 Features

*   **URL Risk Assessment**: Extracts structural, domain, and content features to calculate a risk score (0-10).
*   **QR Code Extraction (Quishing Defense)**: Decodes QR codes from uploaded images.
*   **Live Webcam QR Scanner**: Streams live video, detects QR codes instantly, and evaluates their safety.
*   **Multilingual Alerts**: Displays danger and warning signals in multiple languages (English, Telugu, Hindi).
*   **Recent Scan History Log**: Logs all threat analyses into a local CSV file for security auditing.
*   **Dual Interfaces**:
    *   **Desktop Client**: Tkinter GUI desktop interface.
    *   **Web Dashboard**: Glassmorphic dark-mode web application.

---

## 🛠️ Prerequisites & Installation

To run this application, you must install the Python dependencies and the system C library `zbar` (which is required by the `pyzbar` wrapper to decode QR codes).

### 1. Install System Dependencies (macOS)
Use Homebrew to install the `zbar` library:
```bash
brew install zbar
```

*Note: On Apple Silicon Macs (M1/M2/M3/M4), you may need to symlink the library to your user directory so Python's `find_library` can locate it:*
```bash
mkdir -p ~/lib
ln -sf $(brew --prefix zbar)/lib/libzbar.dylib ~/lib/libzbar.dylib
```

### 2. Install Python Packages
Install the required packages using pip:
```bash
pip install opencv-python pyzbar Pillow scikit-learn numpy requests flask
```

---

## 🚀 Running the Applications

#### 🌐 Live Public URL
 you can access it publicly at:
👉 **[phishshield-ai-production.up.railway.app](https://phishshield-ai-production.up.railway.app)**



### Option B: Run the Desktop Client (Tkinter GUI)
Launch the desktop application:
```bash
python main.py
```

---

## 📁 Project Structure

*   `main.py`: The Tkinter GUI desktop interface.
*   `web_server.py`: The Flask web server for the web demo interface.
*   `templates/index.html`: The HTML/CSS/JS code for the web dashboard.
*   `url_analyzer.py`: Backend scoring and feature extraction engine.
*   `qr_scanner.py`: Camera and image QR code decoder.
*   `logger.py`: Appends scans to local history.
*   `scan_history.csv`: History database (created automatically).
