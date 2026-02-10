// Copyright (c) 2024 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * @file sphincs.h
 * @brief C++ wrapper for SPHINCS+-SHA2-128f-simple post-quantum signatures.
 *
 * SPHINCS+ is a stateless hash-based signature scheme standardized by NIST
 * as FIPS 205 (SLH-DSA). This implementation uses the SHA2-128f-simple
 * parameter set providing NIST Level 1 security (128-bit classical).
 *
 * Parameters:
 *   - Public key:  32 bytes
 *   - Secret key:  64 bytes
 *   - Signature:   17,088 bytes (deterministic upper bound)
 *   - Seed:        48 bytes (SK_SEED || SK_PRF || PUB_SEED)
 *   - Security:    NIST Level 1 (128-bit)
 *   - Hash:        SHA-256
 *   - Variant:     "fast" (f) with simple Merkle tree construction
 *
 * Source: PQClean (https://github.com/PQClean/PQClean)
 * License: MIT (see src/crypto/sphincs/LICENSE)
 */

#ifndef DOGECOIN_CRYPTO_SPHINCS_H
#define DOGECOIN_CRYPTO_SPHINCS_H

#include <cstring>
#include <vector>
#include <stdint.h>
#include <stddef.h>

/* SPHINCS+-SHA2-128f-simple parameter constants */
static const size_t SPHINCS_PUBLICKEY_BYTES = 32;
static const size_t SPHINCS_SECRETKEY_BYTES = 64;
static const size_t SPHINCS_SIG_BYTES       = 17088;
static const size_t SPHINCS_SEED_BYTES      = 48;

/* C API declarations (implemented in sphincs/sign.c) */
extern "C" {

int PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign_seed_keypair(
        uint8_t *pk, uint8_t *sk, const uint8_t *seed);

int PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign_keypair(
        uint8_t *pk, uint8_t *sk);

int PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign_signature(
        uint8_t *sig, size_t *siglen,
        const uint8_t *m, size_t mlen,
        const uint8_t *sk);

int PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign_verify(
        const uint8_t *sig, size_t siglen,
        const uint8_t *m, size_t mlen,
        const uint8_t *pk);

int PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign(
        uint8_t *sm, size_t *smlen,
        const uint8_t *m, size_t mlen,
        const uint8_t *sk);

int PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign_open(
        uint8_t *m, size_t *mlen,
        const uint8_t *sm, size_t smlen,
        const uint8_t *pk);

} // extern "C"

/**
 * SPHINCS+-SHA2-128f-simple key pair.
 *
 * Manages key generation, signing, and provides access to
 * public and secret key material for Dogecoin Core integration.
 */
class CSphincsKeyPair {
private:
    unsigned char pk[SPHINCS_PUBLICKEY_BYTES];
    unsigned char sk[SPHINCS_SECRETKEY_BYTES];
    bool fValid;

public:
    CSphincsKeyPair() : fValid(false) {
        memset(pk, 0, sizeof(pk));
        memset(sk, 0, sizeof(sk));
    }

    ~CSphincsKeyPair() {
        /* Secure erase secret key material */
        memset(sk, 0, sizeof(sk));
        fValid = false;
    }

    /** Generate a new random SPHINCS+ key pair. */
    bool Generate() {
        int ret = PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign_keypair(pk, sk);
        fValid = (ret == 0);
        return fValid;
    }

    /** Generate a SPHINCS+ key pair from a 48-byte seed (deterministic). */
    bool GenerateFromSeed(const unsigned char* seed) {
        int ret = PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign_seed_keypair(pk, sk, seed);
        fValid = (ret == 0);
        return fValid;
    }

    /** Create a detached signature for a message. */
    bool Sign(const unsigned char* msg, size_t msglen,
              std::vector<unsigned char>& sig) const {
        if (!fValid) return false;
        sig.resize(SPHINCS_SIG_BYTES);
        size_t siglen = 0;
        int ret = PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign_signature(
                sig.data(), &siglen, msg, msglen, sk);
        if (ret != 0) {
            sig.clear();
            return false;
        }
        sig.resize(siglen);
        return true;
    }

    /** Create a signed message (signature || message). */
    bool SignMessage(const unsigned char* msg, size_t msglen,
                     std::vector<unsigned char>& sm) const {
        if (!fValid) return false;
        sm.resize(SPHINCS_SIG_BYTES + msglen);
        size_t smlen = 0;
        int ret = PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign(
                sm.data(), &smlen, msg, msglen, sk);
        if (ret != 0) {
            sm.clear();
            return false;
        }
        sm.resize(smlen);
        return true;
    }

    /** Get public key as a vector. */
    std::vector<unsigned char> GetPubKey() const {
        return std::vector<unsigned char>(pk, pk + SPHINCS_PUBLICKEY_BYTES);
    }

    /** Get secret key as a vector. */
    std::vector<unsigned char> GetSecKey() const {
        return std::vector<unsigned char>(sk, sk + SPHINCS_SECRETKEY_BYTES);
    }

    /** Get raw pointer to public key. */
    const unsigned char* GetPubKeyData() const { return pk; }

    /** Get raw pointer to secret key. */
    const unsigned char* GetSecKeyData() const { return sk; }

    /** Import existing key material. */
    void SetKeys(const unsigned char* pubkey, const unsigned char* seckey) {
        memcpy(pk, pubkey, SPHINCS_PUBLICKEY_BYTES);
        memcpy(sk, seckey, SPHINCS_SECRETKEY_BYTES);
        fValid = true;
    }

    /** Check if key pair has been generated or imported. */
    bool IsValid() const { return fValid; }
};

/**
 * Verify a detached SPHINCS+ signature.
 * @param pk      Public key (vector)
 * @param msg     Message bytes
 * @param msglen  Message length
 * @param sig     Signature (vector)
 * @return true if signature is valid
 */
inline bool CSphincsVerify(const std::vector<unsigned char>& pk,
                           const unsigned char* msg, size_t msglen,
                           const std::vector<unsigned char>& sig) {
    if (pk.size() != SPHINCS_PUBLICKEY_BYTES) return false;
    return PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign_verify(
            sig.data(), sig.size(), msg, msglen, pk.data()) == 0;
}

/**
 * Verify a detached SPHINCS+ signature (raw pointer version).
 * @param pk      Public key pointer (32 bytes)
 * @param msg     Message bytes
 * @param msglen  Message length
 * @param sig     Signature pointer
 * @param siglen  Signature length
 * @return true if signature is valid
 */
inline bool CSphincsVerify(const unsigned char* pk,
                           const unsigned char* msg, size_t msglen,
                           const unsigned char* sig, size_t siglen) {
    return PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign_verify(
            sig, siglen, msg, msglen, pk) == 0;
}

/**
 * Open a signed message (verify and extract).
 * @param pk        Public key pointer (32 bytes)
 * @param sm        Signed message (signature || message)
 * @param smlen     Signed message length
 * @param msg_out   Recovered message output
 * @return true if signature is valid and message was recovered
 */
inline bool CSphincsOpen(const unsigned char* pk,
                         const unsigned char* sm, size_t smlen,
                         std::vector<unsigned char>& msg_out) {
    msg_out.resize(smlen);
    size_t mlen = 0;
    int ret = PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign_open(
            msg_out.data(), &mlen, sm, smlen, pk);
    if (ret != 0) {
        msg_out.clear();
        return false;
    }
    msg_out.resize(mlen);
    return true;
}

#endif // DOGECOIN_CRYPTO_SPHINCS_H
