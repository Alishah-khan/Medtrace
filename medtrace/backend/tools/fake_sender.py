"""Demo attack on the API: send a fake reading WITHOUT the device key.
  python tools/fake_sender.py BOX-001
The backend must answer 400 (invalid signature)."""
import hashlib
import os
import sys
import time

import requests

BASE = os.getenv("BACKEND", "http://127.0.0.1:8000")
if len(sys.argv) != 2:
    sys.exit(__doc__)
box = sys.argv[1]
last = requests.get(f"{BASE}/api/records/{box}?limit=1").json()[0]
seq = last["seq"] + 1
payload = f"{box}|{seq}|{int(time.time())}|R|4.00;0;0"
h = hashlib.sha256(f"{last['hash']}|{payload}".encode()).hexdigest()
fake = {"s": seq, "p": payload, "v": last["hash"], "h": h, "g": "3045" + "ab" * 69}
r = requests.post(f"{BASE}/api/sync", json={"box": box, "records": [fake]})
print(r.status_code, r.text)
