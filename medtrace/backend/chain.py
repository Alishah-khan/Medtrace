"""Thin wrapper around web3.py for the MedTrace contract."""
import json
import os

from web3 import Web3

DEPLOYED = os.getenv(
    "DEPLOYED_JSON", os.path.join(os.path.dirname(__file__), "..", "chain", "deployed.json")
)
CARD_SALT = os.getenv("CARD_SALT", "medtrace-demo-salt")
PRIVATE_KEY = os.getenv("PRIVATE_KEY")  # only needed for public testnets

KIND_TEMP_OUT = 1
KIND_UNAUTH = 2
KIND_HUMID_OUT = 3


def box_key(box_id: str) -> bytes:
    return Web3.keccak(text=box_id)


def card_hash(uid: str) -> bytes:
    return Web3.keccak(text=f"{CARD_SALT}:{uid.upper()}")


class Chain:
    def __init__(self):
        if not os.path.exists(DEPLOYED):
            raise SystemExit("chain/deployed.json not found. Run 'node deploy.js' in the chain folder first.")
        with open(DEPLOYED) as f:
            info = json.load(f)
        rpc = os.getenv("RPC_URL", info.get("rpc", "http://127.0.0.1:8545"))
        self.w3 = Web3(Web3.HTTPProvider(rpc))
        if not self.w3.is_connected():
            raise SystemExit(f"Cannot reach the blockchain node at {rpc}. Start it with 'npx hardhat node'.")
        self.contract = self.w3.eth.contract(address=info["address"], abi=info["abi"])
        if PRIVATE_KEY:
            self.acct = self.w3.eth.account.from_key(PRIVATE_KEY)
            self.sender = self.acct.address
        else:
            self.acct = None
            self.sender = self.w3.eth.accounts[0]

    def _send(self, fn) -> str:
        if self.acct:
            tx = fn.build_transaction(
                {"from": self.sender, "nonce": self.w3.eth.get_transaction_count(self.sender)}
            )
            signed = self.acct.sign_transaction(tx)
            h = self.w3.eth.send_raw_transaction(signed.raw_transaction)
        else:
            h = fn.transact({"from": self.sender})
        receipt = self.w3.eth.wait_for_transaction_receipt(h, timeout=120)
        if receipt.status != 1:
            raise RuntimeError("transaction reverted")
        return self.w3.to_hex(h)

    # ---- writes -------------------------------------------------------
    def register_box(self, box_id: str, pub_bytes: bytes) -> str:
        return self._send(self.contract.functions.registerBox(box_key(box_id), pub_bytes))

    def register_handler(self, uid: str) -> str:
        return self._send(self.contract.functions.registerHandler(card_hash(uid)))

    def anchor_batch(self, box_id: str, root: bytes, from_seq: int, to_seq: int) -> str:
        return self._send(self.contract.functions.anchorBatch(box_key(box_id), root, from_seq, to_seq))

    def record_handover(self, box_id, sender_uid, receiver_uid, snapshot_hash_hex, ts) -> str:
        return self._send(
            self.contract.functions.recordHandover(
                box_key(box_id),
                card_hash(sender_uid),
                card_hash(receiver_uid),
                bytes.fromhex(snapshot_hash_hex),
                int(ts),
            )
        )

    def flag_excursion(self, box_id: str, seq: int, kind: int) -> str:
        return self._send(self.contract.functions.flagExcursion(box_key(box_id), seq, kind))

    # ---- reads --------------------------------------------------------
    def box_registered(self, box_id: str) -> bool:
        return self.contract.functions.boxRegistered(box_key(box_id)).call()

    def anchors(self, box_id: str) -> list:
        n = self.contract.functions.anchorCount(box_key(box_id)).call()
        out = []
        for i in range(n):
            root, f, t, at = self.contract.functions.getAnchor(box_key(box_id), i).call()
            out.append({"root": bytes(root), "from": f, "to": t, "at": at})
        return out

    def handover_count(self, box_id: str) -> int:
        return self.contract.functions.handoverCount(box_key(box_id)).call()
