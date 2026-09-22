"""MedTrace backend. Run:  uvicorn app:app --host 0.0.0.0 --port 8000"""
import json
import os
import time

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel

import db
import risk
from chain import KIND_TEMP_OUT, KIND_UNAUTH, Chain
from logic import GENESIS, check_record, load_public_key, merkle_root, parse_payload, pubkey_bytes
from verify import verify_box

ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "demo-admin")
FRONTEND = os.path.join(os.path.dirname(__file__), "..", "frontend", "index.html")

app = FastAPI(title="MedTrace")
db.init()
chain = Chain()


class SyncReq(BaseModel):
    box: str
    records: list[dict]


class BoxReq(BaseModel):
    box_id: str
    pubkey_pem: str


class HandlerReq(BaseModel):
    uid: str


def need_admin(token):
    if token != ADMIN_TOKEN:
        raise HTTPException(401, "admin token required")


def rows_of(c, box_id):
    return [dict(r) for r in c.execute(
        "SELECT seq, ts, kind, payload, prev_hash, hash, sig, batch_id FROM records "
        "WHERE box_id=? ORDER BY seq", (box_id,))]


def with_data(rows):
    for r in rows:
        r["data"] = r["payload"].split("|", 4)[4]
    return rows


# ------------------------------------------------------------------ admin
@app.post("/api/boxes")
def register_box(req: BoxReq, x_admin_token: str = Header(None)):
    need_admin(x_admin_token)
    try:
        pub = pubkey_bytes(req.pubkey_pem)
    except Exception:
        raise HTTPException(400, "invalid public key PEM")
    with db.connect() as c:
        if c.execute("SELECT 1 FROM boxes WHERE box_id=?", (req.box_id,)).fetchone():
            raise HTTPException(409, "box already registered")
        try:
            tx = chain.register_box(req.box_id, pub)
        except Exception as e:
            raise HTTPException(503, f"blockchain error: {e}")
        c.execute("INSERT INTO boxes VALUES (?,?,?)", (req.box_id, req.pubkey_pem, int(time.time())))
    return {"ok": True, "tx": tx}


@app.post("/api/handlers")
def register_handler(req: HandlerReq, x_admin_token: str = Header(None)):
    need_admin(x_admin_token)
    try:
        tx = chain.register_handler(req.uid)
    except Exception as e:
        raise HTTPException(503, f"blockchain error: {e}")
    return {"ok": True, "tx": tx}


# ------------------------------------------------------------------ device sync
@app.post("/api/sync")
def sync(req: SyncReq):
    with db.connect() as c:
        box = c.execute("SELECT * FROM boxes WHERE box_id=?", (req.box,)).fetchone()
        if not box:
            raise HTTPException(404, "box not registered")
        pub = load_public_key(box["pubkey_pem"])
        last = c.execute("SELECT seq, hash FROM records WHERE box_id=? ORDER BY seq DESC LIMIT 1",
                         (req.box,)).fetchone()
        last_seq, prev = (last["seq"], last["hash"]) if last else (0, GENESIS)

        new = []
        expect = last_seq + 1
        for rec in sorted(req.records, key=lambda r: r.get("s", 0)):
            s = rec.get("s", 0)
            if s <= last_seq:  # retry of a batch we already have
                old = c.execute("SELECT hash FROM records WHERE box_id=? AND seq=?", (req.box, s)).fetchone()
                if old and old["hash"] == rec.get("h"):
                    continue
                raise HTTPException(409, f"record #{s} conflicts with stored data")
            if s != expect:
                raise HTTPException(400, f"gap: expected record #{expect}, got #{s}")
            err = check_record(pub, req.box, rec, prev)
            if err:
                raise HTTPException(400, f"record #{s} rejected: {err}")
            new.append(rec)
            prev = rec["h"]
            expect += 1

        if not new:
            return {"ok": True, "acked_seq": last_seq, "server_time": int(time.time())}

        # anchor the batch first (critical). If this fails the device simply retries later.
        root = merkle_root([r["h"] for r in new])
        try:
            tx = chain.anchor_batch(req.box, root, new[0]["s"], new[-1]["s"])
        except Exception as e:
            raise HTTPException(503, f"blockchain error: {e}")

        # best-effort extras: handovers and alerts on-chain
        notes = []
        for r in new:
            info = parse_payload(r["p"])
            parts = info["data"].split(";")
            try:
                if info["kind"] == "H" and len(parts) >= 2:
                    chain.record_handover(req.box, parts[0], parts[1], r["h"], info["ts"])
                elif info["kind"] == "E" and parts[0] == "TEMP_OUT":
                    chain.flag_excursion(req.box, info["seq"], KIND_TEMP_OUT)
                elif info["kind"] == "E" and parts[0] == "UNAUTH_CARD":
                    chain.flag_excursion(req.box, info["seq"], KIND_UNAUTH)
            except Exception as e:
                notes.append(f"record #{info['seq']}: on-chain extra failed ({str(e)[:80]})")

        cur = c.execute(
            "INSERT INTO batches (box_id, from_seq, to_seq, merkle_root, tx_hash, notes, created_at) "
            "VALUES (?,?,?,?,?,?,?)",
            (req.box, new[0]["s"], new[-1]["s"], root.hex(), tx, json.dumps(notes), int(time.time())))
        bid = cur.lastrowid
        for r in new:
            info = parse_payload(r["p"])
            c.execute("INSERT INTO records VALUES (?,?,?,?,?,?,?,?,?)",
                      (req.box, info["seq"], info["ts"], info["kind"], r["p"], r["v"], r["h"], r["g"], bid))
        return {"ok": True, "acked_seq": new[-1]["s"], "tx": tx, "server_time": int(time.time())}


# ------------------------------------------------------------------ dashboard / verify
@app.get("/api/records/{box_id}")
def records(box_id: str, limit: int = 40):
    with db.connect() as c:
        rows = with_data(rows_of(c, box_id))
    tail = rows[-limit:][::-1]
    return [{"seq": r["seq"], "ts": r["ts"], "kind": r["kind"], "data": r["data"],
             "hash": r["hash"], "batch": r["batch_id"]} for r in tail]


@app.get("/api/status/{box_id}")
def status(box_id: str):
    with db.connect() as c:
        if not c.execute("SELECT 1 FROM boxes WHERE box_id=?", (box_id,)).fetchone():
            raise HTTPException(404, "box not registered")
        rows = with_data(rows_of(c, box_id))
    out = risk.assess(rows)
    out["box"] = box_id
    out["records"] = len(rows)
    return out


@app.get("/api/verify/{box_id}")
def verify(box_id: str):
    with db.connect() as c:
        box = c.execute("SELECT * FROM boxes WHERE box_id=?", (box_id,)).fetchone()
        if not box:
            raise HTTPException(404, "box not registered")
        rows = rows_of(c, box_id)
    try:
        anchors = chain.anchors(box_id)
    except Exception as e:
        raise HTTPException(503, f"blockchain error: {e}")
    return verify_box(box_id, rows, box["pubkey_pem"], anchors)


@app.get("/")
def index():
    return FileResponse(FRONTEND)
