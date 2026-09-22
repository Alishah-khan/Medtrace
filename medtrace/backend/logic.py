"""Core MedTrace checks: record hashing, signature check, hash chain, Merkle root."""
import hashlib
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

GENESIS = "0" * 64


def record_hash(prev_hex: str, payload: str) -> str:
    """hash = SHA-256( prev_hash_hex + "|" + payload ). Must match the ESP32 code."""
    return hashlib.sha256(f"{prev_hex}|{payload}".encode()).hexdigest()


def parse_payload(payload: str) -> dict:
    """payload = BOX|SEQ|TS|KIND|DATA   (KIND: R reading, E event, H handover)"""
    parts = payload.split("|", 4)
    if len(parts) != 5:
        raise ValueError("bad payload format")
    box, seq, ts, kind, data = parts
    return {"box": box, "seq": int(seq), "ts": int(ts), "kind": kind, "data": data}


def load_public_key(pem: str):
    return serialization.load_pem_public_key(pem.encode())


def pubkey_bytes(pem: str) -> bytes:
    """Uncompressed EC point (65 bytes) stored on-chain for reference."""
    return load_public_key(pem).public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )


def verify_signature(pub, hash_hex: str, sig_hex: str) -> bool:
    """The device signs the 32-byte SHA-256 digest directly (ECDSA P-256, DER)."""
    try:
        pub.verify(
            bytes.fromhex(sig_hex),
            bytes.fromhex(hash_hex),
            ec.ECDSA(utils.Prehashed(hashes.SHA256())),
        )
        return True
    except (InvalidSignature, ValueError):
        return False


def check_record(pub, box_id: str, rec: dict, expected_prev: str) -> Optional[str]:
    """Returns None if the record is valid, otherwise a short error text."""
    for key in ("s", "p", "v", "h", "g"):
        if key not in rec:
            return f"missing field {key}"
    try:
        info = parse_payload(rec["p"])
    except ValueError:
        return "bad payload"
    if info["box"] != box_id:
        return "record belongs to another box"
    if info["seq"] != rec["s"]:
        return "sequence number mismatch"
    if rec["v"] != expected_prev:
        return "hash chain broken (previous hash does not match)"
    if record_hash(rec["v"], rec["p"]) != rec["h"]:
        return "hash does not match content (data edited)"
    if not verify_signature(pub, rec["h"], rec["g"]):
        return "invalid signature (not signed by this box)"
    return None


def merkle_root(hash_hexes: list) -> bytes:
    layer = [bytes.fromhex(h) for h in hash_hexes]
    if not layer:
        raise ValueError("empty batch")
    while len(layer) > 1:
        if len(layer) % 2:
            layer.append(layer[-1])
        layer = [hashlib.sha256(layer[i] + layer[i + 1]).digest() for i in range(0, len(layer), 2)]
    return layer[0]
