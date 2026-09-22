// mt_crypto.h - SHA-256 and ECDSA P-256 signing with mbedTLS 3.x
// (arduino-esp32 core 3.x ships mbedTLS 3.x). No Arduino-specific code, so it also compiles on a PC.
#pragma once
#include <cstdint>
#include <cstring>
#include <string>

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecp.h"
#include "mbedtls/entropy.h"
#include "mbedtls/pk.h"
#include "mbedtls/sha256.h"

namespace mt {

inline std::string toHex(const unsigned char* d, size_t n) {
  static const char* H = "0123456789abcdef";
  std::string s;
  s.reserve(n * 2);
  for (size_t i = 0; i < n; i++) {
    s += H[d[i] >> 4];
    s += H[d[i] & 15];
  }
  return s;
}

// SHA-256 of a string. Writes the raw 32-byte digest to out (if not null), returns lowercase hex.
inline std::string sha256Hex(const std::string& in, unsigned char* out = nullptr) {
  unsigned char d[32];
  mbedtls_sha256(reinterpret_cast<const unsigned char*>(in.data()), in.size(), d, 0);
  if (out) memcpy(out, d, 32);
  return toHex(d, 32);
}

class Signer {
 public:
  Signer() {
    mbedtls_pk_init(&pk_);
    mbedtls_entropy_init(&ent_);
    mbedtls_ctr_drbg_init(&drbg_);
  }
  ~Signer() {
    mbedtls_pk_free(&pk_);
    mbedtls_ctr_drbg_free(&drbg_);
    mbedtls_entropy_free(&ent_);
  }

  // privPem empty  -> generate a new P-256 key. Otherwise load the given PEM private key.
  bool begin(const std::string& privPem) {
    const char* seed = "medtrace";
    if (mbedtls_ctr_drbg_seed(&drbg_, mbedtls_entropy_func, &ent_,
                              reinterpret_cast<const unsigned char*>(seed), strlen(seed)) != 0)
      return false;
    if (privPem.empty()) {
      if (mbedtls_pk_setup(&pk_, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY)) != 0) return false;
      if (mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(pk_), mbedtls_ctr_drbg_random,
                              &drbg_) != 0)
        return false;
    } else {
      // key length must include the terminating NUL for PEM data
      if (mbedtls_pk_parse_key(&pk_, reinterpret_cast<const unsigned char*>(privPem.c_str()),
                               privPem.size() + 1, nullptr, 0, mbedtls_ctr_drbg_random, &drbg_) != 0)
        return false;
    }
    ready_ = true;
    return true;
  }

  std::string privatePem() {
    unsigned char buf[1024];
    memset(buf, 0, sizeof(buf));
    if (mbedtls_pk_write_key_pem(&pk_, buf, sizeof(buf)) != 0) return "";
    return std::string(reinterpret_cast<char*>(buf));
  }

  std::string publicPem() {
    unsigned char buf[512];
    memset(buf, 0, sizeof(buf));
    if (mbedtls_pk_write_pubkey_pem(&pk_, buf, sizeof(buf)) != 0) return "";
    return std::string(reinterpret_cast<char*>(buf));
  }

  // Signs a 32-byte digest, returns the DER signature as lowercase hex.
  bool signDigest(const unsigned char digest[32], std::string& sigHex) {
    if (!ready_) return false;
    unsigned char sig[MBEDTLS_PK_SIGNATURE_MAX_SIZE];
    size_t len = 0;
    if (mbedtls_pk_sign(&pk_, MBEDTLS_MD_SHA256, digest, 32, sig, sizeof(sig), &len,
                        mbedtls_ctr_drbg_random, &drbg_) != 0)
      return false;
    sigHex = toHex(sig, len);
    return true;
  }

 private:
  mbedtls_pk_context pk_;
  mbedtls_entropy_context ent_;
  mbedtls_ctr_drbg_context drbg_;
  bool ready_ = false;
};

}  // namespace mt
