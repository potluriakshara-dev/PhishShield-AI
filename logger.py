"""
logger.py  —  PhishShield AI Backend
Saves every scan result to scan_history.csv for review.
"""

import csv
import os
from datetime import datetime

LOG_FILE = "scan_history.csv"
HEADERS  = ["timestamp", "url", "score", "verdict", "flags"]


def log_scan(url: str, score: float, verdict: str, flags: list[str]) -> None:
    """
    Append one scan result to scan_history.csv.
    Creates the file with headers if it doesn't exist yet.

    Usage (in main.py):
        log_scan(url, result["score"], result["verdict"], result["flags"])
    """
    file_exists = os.path.isfile(LOG_FILE)

    with open(LOG_FILE, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(HEADERS)
        writer.writerow([
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            url,
            score,
            verdict,
            " | ".join(flags),
        ])


def get_history(limit: int = 50) -> list[dict]:
    """
    Return the last `limit` scan records as a list of dicts.
    Returns empty list if log file doesn't exist yet.

    Usage (in main.py / UI):
        records = get_history(20)
    """
    if not os.path.isfile(LOG_FILE):
        return []

    with open(LOG_FILE, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    return rows[-limit:]
