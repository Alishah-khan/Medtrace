import os
import sqlite3

DB_PATH = os.getenv("DB_PATH", os.path.join(os.path.dirname(__file__), "medtrace.db"))

SCHEMA = """
CREATE TABLE IF NOT EXISTS boxes (
  box_id TEXT PRIMARY KEY,
  pubkey_pem TEXT NOT NULL,
  registered_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS batches (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  box_id TEXT NOT NULL,
  from_seq INTEGER NOT NULL,
  to_seq INTEGER NOT NULL,
  merkle_root TEXT NOT NULL,
  tx_hash TEXT,
  notes TEXT,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS records (
  box_id TEXT NOT NULL,
  seq INTEGER NOT NULL,
  ts INTEGER NOT NULL,
  kind TEXT NOT NULL,
  payload TEXT NOT NULL,
  prev_hash TEXT NOT NULL,
  hash TEXT NOT NULL,
  sig TEXT NOT NULL,
  batch_id INTEGER,
  PRIMARY KEY (box_id, seq)
);
"""


def connect():
    c = sqlite3.connect(DB_PATH, timeout=10)
    c.row_factory = sqlite3.Row
    return c


def init():
    with connect() as c:
        c.executescript(SCHEMA)
