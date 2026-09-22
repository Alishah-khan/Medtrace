"""Full verification of one box: signatures, hash chain, and Merkle roots stored on-chain."""
from logic import GENESIS, check_record, load_public_key, merkle_root


def verify_box(box_id: str, rows: list, pubkey_pem: str, anchors: list) -> dict:
    issues = []
    pub = load_public_key(pubkey_pem)
    by_seq = {r["seq"]: r for r in rows}

    # 1) every stored record: content hash, signature and link to the previous record
    prev = GENESIS
    expected = 1
    for r in rows:
        if r["seq"] != expected:
            issues.append(f"record(s) missing before #{r['seq']}")
        expected = r["seq"] + 1
        rec = {"s": r["seq"], "p": r["payload"], "v": r["prev_hash"], "h": r["hash"], "g": r["sig"]}
        err = check_record(pub, box_id, rec, prev)
        if err:
            issues.append(f"record #{r['seq']}: {err}")
        prev = r["hash"]

    # 2) every on-chain Merkle root must be reproducible from the stored records
    covered = 0
    if anchors and anchors[0]["from"] != 1:
        issues.append("first on-chain batch does not start at record #1")
    for i, a in enumerate(anchors):
        seqs = range(a["from"], a["to"] + 1)
        missing = [s for s in seqs if s not in by_seq]
        if missing:
            issues.append(f"batch {i}: records {missing[0]}..{missing[-1]} are missing")
            continue
        if merkle_root([by_seq[s]["hash"] for s in seqs]) != a["root"]:
            issues.append(f"batch {i} (records {a['from']}-{a['to']}): does not match the on-chain root")
        covered = max(covered, a["to"])

    pending = len([r for r in rows if r["seq"] > covered])
    return {
        "verdict": "TAMPERED" if issues else "VERIFIED",
        "records_checked": len(rows),
        "batches_checked": len(anchors),
        "pending_records": pending,
        "issues": issues[:20],
    }
