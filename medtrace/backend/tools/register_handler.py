"""Register authorized RFID cards: python tools/register_handler.py 04A1B2C3 04D4E5F6 ..."""
import os
import sys

import requests

BASE = os.getenv("BACKEND", "http://127.0.0.1:8000")
TOKEN = os.getenv("ADMIN_TOKEN", "demo-admin")

if len(sys.argv) < 2:
    sys.exit("usage: python tools/register_handler.py UID [UID ...]")
for uid in sys.argv[1:]:
    r = requests.post(f"{BASE}/api/handlers", json={"uid": uid.upper()}, headers={"X-Admin-Token": TOKEN})
    print(uid.upper(), r.status_code, r.text)
