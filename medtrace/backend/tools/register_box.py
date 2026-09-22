"""Register a box: python tools/register_box.py BOX-001 pubkey.pem
pubkey.pem = the public key PEM printed on the ESP32 Serial Monitor at boot."""
import os
import sys

import requests

BASE = os.getenv("BACKEND", "http://127.0.0.1:8000")
TOKEN = os.getenv("ADMIN_TOKEN", "demo-admin")

if len(sys.argv) != 3:
    sys.exit("usage: python tools/register_box.py BOX-001 pubkey.pem")
box, pem_file = sys.argv[1], sys.argv[2]
r = requests.post(f"{BASE}/api/boxes", json={"box_id": box, "pubkey_pem": open(pem_file).read()},
                  headers={"X-Admin-Token": TOKEN})
print(r.status_code, r.text)
