"""Demo attack on the DATABASE (run on the backend machine).
  python tools/tamper_demo.py BOX-001 edit      -> changes one stored temperature
  python tools/tamper_demo.py BOX-001 delete    -> deletes one stored record
  python tools/tamper_demo.py BOX-001 restore   -> puts the original data back
Then open the verify page: it must turn red for edit/delete and green again after restore."""
import json
import os
import sqlite3
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DB = os.getenv("DB_PATH", os.path.join(HERE, "..", "medtrace.db"))
BACKUP = os.path.join(HERE, ".tamper_backup.json")

if len(sys.argv) != 3 or sys.argv[2] not in ("edit", "delete", "restore"):
    sys.exit(__doc__)
box, action = sys.argv[1], sys.argv[2]
con = sqlite3.connect(DB)

if action == "restore":
    with open(BACKUP) as f:
        row = json.load(f)
    con.execute("DELETE FROM records WHERE box_id=? AND seq=?", (box, row[1]))
    con.execute("INSERT INTO records VALUES (?,?,?,?,?,?,?,?,?)", row)
    con.commit()
    print("restored record", row[1])
    sys.exit(0)

row = con.execute("SELECT * FROM records WHERE box_id=? AND kind='R' ORDER BY seq LIMIT 1 OFFSET 2", (box,)).fetchone()
if not row:
    sys.exit("need at least 3 readings first")
with open(BACKUP, "w") as f:
    json.dump(list(row), f)
if action == "edit":
    box_, seq, ts, kind, data = row[4].split("|", 4)
    parts = data.split(";")
    parts[0] = "5.00"
    new_payload = "|".join([box_, seq, ts, kind, ";".join(parts)])
    con.execute("UPDATE records SET payload=? WHERE box_id=? AND seq=?", (new_payload, box, row[1]))
    print(f"edited record {row[1]}: temperature changed to 5.00")
else:
    con.execute("DELETE FROM records WHERE box_id=? AND seq=?", (box, row[1]))
    print(f"deleted record {row[1]}")
con.commit()
