#pragma once
// ============================================================
// OTACrypto.hpp  —  Cryptographic primitives used by OTA
//
// Wraps OpenSSL 3 EVP APIs for:
//   - SHA-256 (integrity verification)
//   - Ed25519 key generation, signing, and verification
//   - CRC-16/CCITT (per-chunk transmission error detection)
//
// These operations correspond directly to the cryptographic
// scheme described in the architecture spec §5 and evaluated
// in thesis Chapter 5.
// ============================================================

#include "OTATypes.hpp"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <chrono>
#include <vector>
#include <stdexcept>

namespace CubeSatOTA {

// ----------------------------------------------------------
// CRC-16/CCITT  (polynomial 0x1021, initial value 0xFFFF)
// Used per-chunk during uplink reception (UplinkReceiver).
// Hardware-equivalent speed on OBC; detects all burst errors
// up to 16 bits. Not a security mechanism — only a channel
// error detector.
// ----------------------------------------------------------
class CRC16 {
public:
    static uint16_t compute(const uint8_t* data, size_t len) {
        uint16_t crc = 0xFFFFu;
        for (size_t i = 0; i < len; ++i) {
            crc ^= static_cast<uint16_t>(data[i]) << 8;
            for (int j = 0; j < 8; ++j)
                crc = (crc & 0x8000u) ? (crc << 1) ^ 0x1021u : crc << 1;
        }
        return crc;
    }
};

// ----------------------------------------------------------
// SHA-256  (integrity verification in IntegrityVerifier)
// Provides 128-bit collision resistance — cryptographically
// strong against intentional tampering, unlike CRC-32.
// ----------------------------------------------------------
class SHA256 {
public:
    // Compute SHA-256 over a contiguous buffer.
    // Returns elapsed milliseconds for Chapter 5 overhead table.
    static uint32_t compute(const uint8_t* data, size_t len,
                            uint8_t out[SHA256_SIZE]) {
        auto t0 = std::chrono::steady_clock::now();

        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx) throw std::runtime_error("EVP_MD_CTX_new failed");

        unsigned int outlen = 0;
        if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1 ||
            EVP_DigestUpdate(ctx, data, len)              != 1 ||
            EVP_DigestFinal_ex(ctx, out, &outlen)         != 1) {
            EVP_MD_CTX_free(ctx);
            throw std::runtime_error("SHA-256 computation failed");
        }
        EVP_MD_CTX_free(ctx);

        auto t1 = std::chrono::steady_clock::now();
        return static_cast<uint32_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(t1-t0).count());
    }

    static bool equal(const uint8_t a[SHA256_SIZE],
                      const uint8_t b[SHA256_SIZE]) {
        return CRYPTO_memcmp(a, b, SHA256_SIZE) == 0;
    }
};

// ----------------------------------------------------------
// Ed25519  (authentication in AuthVerifier)
//
// Selected over RSA-2048 and ECDSA-P256 because:
//   - 32-byte public key (vs 256 bytes for RSA-2048)
//   - 64-byte signature  (vs 256 bytes for RSA-2048)
//   - ~3–8 ms verification on ARM Cortex-M4 @ 120 MHz
//   - Deterministic signing: no random number generator
//     required during signing — critical for ground HSM
//   - Constant-time implementation by design
//
// The OBC stores only the public key. The private key never
// leaves the ground station Hardware Security Module (HSM).
// ----------------------------------------------------------
class Ed25519 {
public:
    struct KeyPair {
        uint8_t pubkey[ED25519_KEY_SIZE]  = {};  // stored on OBC
        uint8_t privkey[ED25519_KEY_SIZE] = {};  // stays on ground HSM
        EVP_PKEY* pkey = nullptr;

        KeyPair() = default;
        // Non-copyable: EVP_PKEY ownership is exclusive
        KeyPair(const KeyPair&) = delete;
        KeyPair& operator=(const KeyPair&) = delete;
        KeyPair(KeyPair&& o) noexcept : pkey(o.pkey) {
            std::memcpy(pubkey,  o.pubkey,  ED25519_KEY_SIZE);
            std::memcpy(privkey, o.privkey, ED25519_KEY_SIZE);
            o.pkey = nullptr;
        }
        KeyPair& operator=(KeyPair&& o) noexcept {
            if (pkey) EVP_PKEY_free(pkey);
            pkey = o.pkey; o.pkey = nullptr;
            std::memcpy(pubkey,  o.pubkey,  ED25519_KEY_SIZE);
            std::memcpy(privkey, o.privkey, ED25519_KEY_SIZE);
            return *this;
        }
        ~KeyPair() { if (pkey) EVP_PKEY_free(pkey); }
    };

    // Generate a new Ed25519 key pair (ground station operation)
    static KeyPair generate() {
        KeyPair kp;

        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
        if (!ctx) throw std::runtime_error("EVP_PKEY_CTX_new_id failed");
        if (EVP_PKEY_keygen_init(ctx) != 1) {
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("EVP_PKEY_keygen_init failed");
        }

        EVP_PKEY* pkey = nullptr;
        if (EVP_PKEY_keygen(ctx, &pkey) != 1) {
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("EVP_PKEY_keygen failed");
        }
        EVP_PKEY_CTX_free(ctx);

        size_t len = ED25519_KEY_SIZE;
        EVP_PKEY_get_raw_public_key(pkey, kp.pubkey, &len);
        len = ED25519_KEY_SIZE;
        EVP_PKEY_get_raw_private_key(pkey, kp.privkey, &len);
        kp.pkey = pkey;
        return kp;
    }

    // Sign message using private key (ground station / HSM operation).
    // Ed25519 signing is deterministic: same key + message → same sig.
    static void sign(const KeyPair& kp,
                     const uint8_t* msg, size_t msglen,
                     uint8_t sig[ED25519_SIG_SIZE]) {
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx) throw std::runtime_error("EVP_MD_CTX_new failed");

        if (EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, kp.pkey) != 1) {
            EVP_MD_CTX_free(ctx);
            throw std::runtime_error("EVP_DigestSignInit failed");
        }

        size_t siglen = ED25519_SIG_SIZE;
        if (EVP_DigestSign(ctx, sig, &siglen, msg, msglen) != 1) {
            EVP_MD_CTX_free(ctx);
            throw std::runtime_error("EVP_DigestSign failed");
        }
        EVP_MD_CTX_free(ctx);
    }

    // Verify signature using public key (OBC operation).
    // Returns {OpResult, elapsed_ms} matching VerifyResultInfo.
    static VerifyResultInfo verify(const uint8_t pubkey[ED25519_KEY_SIZE],
                                   const uint8_t* msg, size_t msglen,
                                   const uint8_t sig[ED25519_SIG_SIZE]) {
        auto t0 = std::chrono::steady_clock::now();

        EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(
            EVP_PKEY_ED25519, nullptr, pubkey, ED25519_KEY_SIZE);
        if (!pkey) {
            return { OpResult::FAIL, 0 };
        }

        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        OpResult result = OpResult::FAIL;
        if (ctx) {
            if (EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, pkey) == 1) {
                int rc = EVP_DigestVerify(ctx, sig, ED25519_SIG_SIZE, msg, msglen);
                result = (rc == 1) ? OpResult::OK : OpResult::FAIL;
            }
            EVP_MD_CTX_free(ctx);
        }
        EVP_PKEY_free(pkey);

        auto t1 = std::chrono::steady_clock::now();
        uint32_t ms = static_cast<uint32_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(t1-t0).count());
        return { result, ms };
    }
};

} // namespace CubeSatOTA
