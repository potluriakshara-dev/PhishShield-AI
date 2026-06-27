"""
qr_scanner.py  —  PhishShield AI Backend
Decodes QR codes from image files or a live webcam feed.
Returns the embedded URL string (or None if nothing found).
"""

import cv2
from pyzbar.pyzbar import decode
from PIL import Image
import numpy as np


def scan_qr_from_image(image_path: str) -> str | None:
    """
    Decode a QR code from a saved image file (.png / .jpg / .jpeg).
    Returns the embedded URL string, or None if no QR found.

    Usage (in main.py):
        url = scan_qr_from_image("path/to/qr.png")
    """
    try:
        # Try pyzbar first (faster)
        img = cv2.imread(image_path)
        if img is None:
            raise FileNotFoundError(f"Cannot open image: {image_path}")

        decoded_objects = decode(img)
        if decoded_objects:
            return decoded_objects[0].data.decode("utf-8")

        # Fallback: convert to grayscale + threshold for low-contrast QR codes
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        _, thresh = cv2.threshold(gray, 128, 255, cv2.THRESH_BINARY)
        decoded_objects = decode(thresh)
        if decoded_objects:
            return decoded_objects[0].data.decode("utf-8")

        return None  # No QR code detected

    except Exception as e:
        print(f"[qr_scanner] Image scan error: {e}")
        return None


def scan_qr_from_webcam(timeout_seconds: int = 20) -> str | None:
    """
    Open the default webcam and scan for a QR code in real time.
    Waits up to `timeout_seconds` before giving up.
    Returns the embedded URL string, or None if nothing found.

    Usage (in main.py):
        url = scan_qr_from_webcam()
    """
    cap = cv2.VideoCapture(0)
    if not cap.isOpened():
        print("[qr_scanner] Webcam not available.")
        return None

    import time
    start = time.time()
    found_url = None

    while True:
        ret, frame = cap.read()
        if not ret:
            break

        decoded_objects = decode(frame)
        if decoded_objects:
            found_url = decoded_objects[0].data.decode("utf-8")

            # Draw green box around detected QR for visual feedback
            for obj in decoded_objects:
                pts = obj.polygon
                if len(pts) == 4:
                    poly = [(p.x, p.y) for p in pts]
                    for i in range(4):
                        cv2.line(frame, poly[i], poly[(i+1) % 4], (0, 255, 0), 2)

            cv2.putText(frame, "QR Detected! Scanning...", (10, 35),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.9, (0, 255, 0), 2)
            cv2.imshow("PhishShield — QR Scanner (press Q to cancel)", frame)
            cv2.waitKey(800)   # Show green box briefly before closing
            break

        # Timeout guard
        if time.time() - start > timeout_seconds:
            print("[qr_scanner] Webcam timeout — no QR code found.")
            break

        cv2.putText(frame, "Point camera at QR code | Q = cancel", (10, 30),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.7, (200, 200, 200), 1)
        cv2.imshow("PhishShield — QR Scanner (press Q to cancel)", frame)

        if cv2.waitKey(1) & 0xFF == ord("q"):
            break

    cap.release()
    cv2.destroyAllWindows()
    return found_url
