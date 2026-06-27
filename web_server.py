"""
web_server.py  —  PhishShield AI Web Interface
Exposes the original backend functions via a modern web interface.
No backend logic was modified.

Run:
    python web_server.py
"""

import os
import sys
import base64
import tempfile
import cv2
import numpy as np
from flask import Flask, request, jsonify, render_template

# Ensure the script directory is in Python path to import modules successfully
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.append(current_dir)

# Import original backend modules
from url_analyzer import analyze_url
from qr_scanner import scan_qr_from_image
from logger import log_scan, get_history
from pyzbar.pyzbar import decode

app = Flask(__name__, template_folder=os.path.join(current_dir, 'templates'))

@app.route('/')
def home():
    """Render the dashboard UI."""
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    """Analyze a single URL using url_analyzer and log the result."""
    try:
        data = request.get_json() or {}
        url = data.get('url', '').strip()
        if not url:
            return jsonify({'success': False, 'error': 'No URL provided'}), 400
            
        result = analyze_url(url)
        # Log to the CSV scan history
        log_scan(url, result["score"], result["verdict"], result["flags"])
        return jsonify({'success': True, 'result': result})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/scan_qr_image', methods=['POST'])
def scan_qr_image():
    """Decode QR from an uploaded image, then analyze its URL."""
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No file uploaded'}), 400
        
    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'error': 'Empty filename'}), 400
        
    try:
        # Save image to a temporary file
        temp_dir = tempfile.gettempdir()
        temp_path = os.path.join(temp_dir, file.filename)
        file.save(temp_path)
        
        # Call original qr_scanner logic
        url = scan_qr_from_image(temp_path)
        
        # Clean up temp file
        if os.path.exists(temp_path):
            os.remove(temp_path)
            
        if url:
            # Analyze threat risk score
            result = analyze_url(url)
            # Log result in history CSV
            log_scan(url, result["score"], result["verdict"], result["flags"])
            return jsonify({
                'success': True,
                'url': url,
                'result': result
            })
        else:
            return jsonify({'success': False, 'error': 'No QR code found in the image.'}), 404
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/scan_frame', methods=['POST'])
def scan_frame():
    """Decode a raw base64 frame captured from the client's webcam."""
    try:
        data = request.get_json() or {}
        image_data = data.get('image')
        if not image_data:
            return jsonify({'success': False, 'error': 'No image data provided'}), 400
            
        # Parse base64
        if ',' in image_data:
            image_data = image_data.split(',')[1]
            
        img_bytes = base64.b64decode(image_data)
        nparr = np.frombuffer(img_bytes, np.uint8)
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        
        if img is None:
            return jsonify({'success': False, 'error': 'Failed to decode image frame'}), 400
            
        # Call pyzbar to check for QR code
        decoded_objects = decode(img)
        if decoded_objects:
            url = decoded_objects[0].data.decode('utf-8')
            return jsonify({'success': True, 'url': url})
            
        return jsonify({'success': True, 'url': None})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/history', methods=['GET'])
def history():
    """Return the recent 20 records from the scan history CSV file."""
    try:
        records = get_history(20)
        return jsonify({'success': True, 'records': records})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

if __name__ == '__main__':
    # Listen on port 5001 to avoid Apple's AirPlay Receiver port 5000 conflicts
    print("--------------------------------------------------")
    print("PhishShield AI Web Server starting...")
    print("Open http://127.0.0.1:5001 in your browser.")
    print("--------------------------------------------------")
    app.run(host='127.0.0.1', port=5001, debug=True)
