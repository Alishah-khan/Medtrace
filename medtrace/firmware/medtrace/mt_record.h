// mt_record.h - builds signed, hash-chained records.
//   payload = BOX|SEQ|TS|KIND|DATA
//   hash    = SHA-256( previous_hash_hex + "|" + payload )
//   sig     = ECDSA P-256 over the 32-byte hash, DER, hex
// The backend (logic.py) uses exactly the same rules.
#pragma once
#include <string>

#include "mt_crypto.h"

namespace mt {

struct Rec {
  bool ok = false;
  uint32_t seq = 0;
  std::string hash;
  std::string line;  // one JSON object, no newline
};

class Chain {
 public:
  std::string box;
  uint32_t seq = 0;                       // last committed record number
  std::string lastHash = std::string(64, '0');
  Signer* signer = nullptr;

  // Builds the next record WITHOUT changing the chain. Call commit() after it was stored safely.
  Rec build(char kind, const std::string& data, uint32_t ts) {
    Rec r;
    uint32_t next = seq + 1;
    std::string payload =
        box + "|" + std::to_string(next) + "|" + std::to_string(ts) + "|" + std::string(1, kind) + "|" + data;
    unsigned char digest[32];
    std::string h = sha256Hex(lastHash + "|" + payload, digest);
    std::string sig;
    if (!signer || !signer->signDigest(digest, sig)) return r;
    r.line = "{\"s\":" + std::to_string(next) + ",\"p\":\"" + payload + "\",\"v\":\"" + lastHash +
             "\",\"h\":\"" + h + "\",\"g\":\"" + sig + "\"}";
    r.seq = next;
    r.hash = h;
    r.ok = true;
    return r;
  }

  void commit(const Rec& r) {
    seq = r.seq;
    lastHash = r.hash;
  }
};

}  // namespace mt
