"""End-to-end test WITHOUT hardware.
1) build + run the PC simulator:   see firmware/host_test/README (creates sim_pub.pem, sim_log.jsonl)
2) start a fresh local chain and deploy:  npx hardhat node  /  node deploy.js
3) run:  python tools/test_with_sim.py
"""
import json
import os
import sqlite3
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SIM = os.path.join(HERE, "..", "..", "firmware", "host_test")
os.environ["DB_PATH"] = os.path.join(tempfile.mkdtemp(), "test.db")
sys.path.insert(0, os.path.join(HERE, ".."))

from fastapi.testclient import TestClient  # noqa: E402

import app as backend  # noqa: E402

client = TestClient(backend.app)
H = {"X-Admin-Token": os.getenv("ADMIN_TOKEN", "demo-admin")}
BOX = "BOX-SIM"


def check(name, ok, extra=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"  {extra}" if extra else ""))
    if not ok:
        sys.exit(1)


pem = open(os.path.join(SIM, "sim_pub.pem")).read()
lines = [l.strip() for l in open(os.path.join(SIM, "sim_log.jsonl")) if l.strip()]
recs = [json.loads(l) for l in lines]

r = client.post("/api/boxes", json={"box_id": BOX, "pubkey_pem": pem}, headers=H)
check("register box", r.status_code == 200, r.text[:80])
r = client.post("/api/boxes", json={"box_id": BOX, "pubkey_pem": pem}, headers={"X-Admin-Token": "wrong"})
check("register without admin token is refused", r.status_code == 401)
for uid in ("04A1B2C3", "04D4E5F6"):
    check(f"register handler {uid}", client.post("/api/handlers", json={"uid": uid}, headers=H).status_code == 200)

r = client.post("/api/sync", json={"box": BOX, "records": recs[:6]})
check("sync first 6 records", r.status_code == 200 and r.json()["acked_seq"] == 6, r.text[:100])
r = client.post("/api/sync", json={"box": BOX, "records": recs})  # includes 6 duplicates (retry case)
check("sync all 13 (duplicates ignored)", r.status_code == 200 and r.json()["acked_seq"] == 13, r.text[:100])

v = client.get(f"/api/verify/{BOX}").json()
check("verify -> VERIFIED", v["verdict"] == "VERIFIED" and v["batches_checked"] == 2, str(v))

s = client.get(f"/api/status/{BOX}").json()
print("      risk:", s["level"], s["score"], s["reasons"])
print("      custodian:", s["current_custodian"], "| excursions:", s["excursions"])
check("risk is HIGH (unauthorized card)", s["level"] == "HIGH")
check("excursion attributed to receiver of the handover", s["excursions"][0]["custodian"] == "04D4E5F6")

# --- attack 1: fake data without the device key
forged = dict(recs[-1])
forged = {"s": 14, "p": f"{BOX}|14|1790000090|R|4.00;0;0", "v": recs[-1]["h"], "h": "0" * 64, "g": recs[-1]["g"]}
import hashlib  # noqa: E402
forged["h"] = hashlib.sha256(f"{forged['v']}|{forged['p']}".encode()).hexdigest()
r = client.post("/api/sync", json={"box": BOX, "records": [forged]})
check("forged reading is rejected", r.status_code == 400, r.text[:100])

# --- attack 2: edit a stored record in the database
db_path = os.environ["DB_PATH"]
con = sqlite3.connect(db_path)
old = con.execute("SELECT payload FROM records WHERE seq=2").fetchone()[0]
con.execute("UPDATE records SET payload=? WHERE seq=2", (old.replace("4.25", "5.25"),))
con.commit()
v = client.get(f"/api/verify/{BOX}").json()
check("edited record -> TAMPERED", v["verdict"] == "TAMPERED", str(v["issues"][:2]))
con.execute("UPDATE records SET payload=? WHERE seq=2", (old,))
con.commit()
check("restored -> VERIFIED again", client.get(f"/api/verify/{BOX}").json()["verdict"] == "VERIFIED")

# --- attack 3: delete a record
row = con.execute("SELECT * FROM records WHERE seq=5").fetchone()
con.execute("DELETE FROM records WHERE seq=5")
con.commit()
v = client.get(f"/api/verify/{BOX}").json()
check("deleted record -> TAMPERED", v["verdict"] == "TAMPERED", str(v["issues"][:2]))
con.execute("INSERT INTO records VALUES (?,?,?,?,?,?,?,?,?)", tuple(row))
con.commit()

# --- attack 4: recompute hash of an edited record (attacker knows the hashing rule but not the key)
old = con.execute("SELECT payload, prev_hash FROM records WHERE seq=3").fetchone()
new_payload = old[0].replace("4.30", "4.90")
new_hash = hashlib.sha256(f"{old[1]}|{new_payload}".encode()).hexdigest()
con.execute("UPDATE records SET payload=?, hash=? WHERE seq=3", (new_payload, new_hash))
con.commit()
v = client.get(f"/api/verify/{BOX}").json()
check("edit + recomputed hash -> TAMPERED", v["verdict"] == "TAMPERED", str(v["issues"][:2]))

print("\nAll checks passed.")
