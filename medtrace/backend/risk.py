"""Rule-based risk engine + custody / excursion attribution. Simple and explainable."""
import os

TEMP_MIN = float(os.getenv("TEMP_MIN_C", "2.0"))
TEMP_MAX = float(os.getenv("TEMP_MAX_C", "8.0"))
LONG_EXCURSION_S = int(os.getenv("LONG_EXCURSION_S", "120"))   # demo value; use 1800 for real use
TRANSIT_LIMIT_S = int(os.getenv("TRANSIT_LIMIT_S", str(24 * 3600)))


def _f(x):
    try:
        return float(x)
    except (TypeError, ValueError):
        return None


def assess(rows: list) -> dict:
    """rows: list of dicts with keys seq, ts, kind, data (ordered by seq)."""
    out_secs = 0
    prev_ts = None
    prev_out = False
    door_opens = shakes = 0
    unauth = False
    latest = None
    handovers = []
    excursions = []
    custodian = "origin"

    for r in rows:
        kind, data, ts = r["kind"], r["data"], r["ts"]
        parts = data.split(";")
        if kind == "R" and len(parts) >= 3:
            t = _f(parts[0])
            if t is not None:
                out = t < TEMP_MIN or t > TEMP_MAX
                if prev_out and prev_ts is not None:
                    out_secs += max(0, ts - prev_ts)
                prev_out, prev_ts = out, ts
                latest = {"temp": t, "door": parts[1] == "1", "tilt": parts[2] == "1", "ts": ts}
        elif kind == "E":
            name = parts[0]
            if name == "DOOR_OPEN":
                door_opens += 1
            elif name in ("SHAKE", "TILT"):
                shakes += 1
            elif name == "UNAUTH_CARD":
                unauth = True
            elif name == "TEMP_OUT":
                excursions.append({"seq": r["seq"], "ts": ts, "temp": _f(parts[1]) if len(parts) > 1 else None,
                                   "custodian": custodian})
        elif kind == "H" and len(parts) >= 6:
            handovers.append({"seq": r["seq"], "ts": ts, "sender": parts[0], "receiver": parts[1],
                              "min_temp": parts[2], "max_temp": parts[3],
                              "excursions": parts[4], "door_events": parts[5]})
            custodian = parts[1]

    score, reasons = 0, []
    if out_secs >= LONG_EXCURSION_S:
        score += 3
        reasons.append(f"temperature out of range for {out_secs}s (long)")
    elif out_secs > 0:
        score += 1
        reasons.append(f"temperature out of range for {out_secs}s (short)")
    if door_opens:
        score += 2
        reasons.append(f"door opened {door_opens} time(s)")
    if shakes:
        score += 1
        reasons.append(f"{shakes} shake/tilt event(s)")
    if rows and rows[-1]["ts"] - rows[0]["ts"] > TRANSIT_LIMIT_S:
        score += 2
        reasons.append("transit time above limit")

    level = "LOW" if score <= 2 else "MEDIUM" if score <= 4 else "HIGH"
    if unauth:
        level = "HIGH"
        reasons.append("unauthorized card was used on the box")

    return {"level": level, "score": score, "reasons": reasons, "latest": latest,
            "handovers": handovers, "excursions": excursions, "current_custodian": custodian,
            "range": [TEMP_MIN, TEMP_MAX]}
