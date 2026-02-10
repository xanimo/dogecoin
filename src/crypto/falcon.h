// Copyright (c) 2024 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef DOGECOIN_CRYPTO_FALCON512_H
#define DOGECOIN_CRYPTO_FALCON512_H

/**
 * @file falcon.h
 * @brief Post-Quantum Digital Signature: Falcon-512 (NIST PQC Round 3 / FN-DSA)
 *
 * Falcon-512 is a lattice-based digital signature scheme selected by NIST
 * for standardization as part of the Post-Quantum Cryptography project.
 * It provides NIST Security Level 1 (equivalent to AES-128).
 *
 * Parameters (Falcon-512):
 *   - Polynomial degree:     n = 512, logn = 9
 *   - Modulus:               q = 12289
 *   - Public key size:       897 bytes
 *   - Secret key size:       1281 bytes
 *   - Signature size:        max 752 bytes (variable, compressed)
 *   - Security level:        NIST Level 1 (~128-bit classical)
 *
 * This implementation is based on the PQClean reference implementation
 * (Thomas Pornin, Falcon Project, MIT License).
 *
 * Usage:
 *   CFalcon512KeyPair kp;
 *   if (!kp.Generate()) { error; }
 *
 *   std::vector<unsigned char> sig;
 *   if (!kp.Sign(msg, msglen, sig)) { error; }
 *
 *   if (!CFalcon512Verify(kp.GetPubKey(), msg, msglen, sig)) { error; }
 */

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

/** Falcon-512 public key size in bytes */
static const size_t FALCON512_PUBLICKEY_BYTES = 897;

/** Falcon-512 secret key size in bytes */
static const size_t FALCON512_SECRETKEY_BYTES = 1281;

/** Falcon-512 maximum signature size in bytes (header + nonce + compressed sig) */
static const size_t FALCON512_SIG_BYTES = 752;

/** Falcon-512 nonce size in bytes */
static const size_t FALCON512_NONCE_BYTES = 40;

/** Falcon-512 algorithm name */
static const char* const FALCON512_ALGNAME = "Falcon-512";

// Forward declarations for the C API
extern "C" {
    int PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair(uint8_t *pk, uint8_t *sk);
    int PQCLEAN_FALCON512_CLEAN_crypto_sign_signature(
        uint8_t *sig, size_t *siglen,
        const uint8_t *m, size_t mlen, const uint8_t *sk);
    int PQCLEAN_FALCON512_CLEAN_crypto_sign_verify(
        const uint8_t *sig, size_t siglen,
        const uint8_t *m, size_t mlen, const uint8_t *pk);
    int PQCLEAN_FALCON512_CLEAN_crypto_sign(
        uint8_t *sm, size_t *smlen,
        const uint8_t *m, size_t mlen, const uint8_t *sk);
    int PQCLEAN_FALCON512_CLEAN_crypto_sign_open(
        uint8_t *m, size_t *mlen,
        const uint8_t *sm, size_t smlen, const uint8_t *pk);
}

/**
 * Falcon-512 key pair container and signing interface.
 *
 * Holds a public key and secret key, provides key generation and signing.
 */
class CFalcon512KeyPair {
private:
    unsigned char pk[FALCON512_PUBLICKEY_BYTES];
    unsigned char sk[FALCON512_SECRETKEY_BYTES];
    bool fValid;

public:
    CFalcon512KeyPair() : fValid(false) {
        memset(pk, 0, sizeof(pk));
        memset(sk, 0, sizeof(sk));
    }

    ~CFalcon512KeyPair() {
        // Securely wipe the secret key
        memset(sk, 0, sizeof(sk));
    }

    /**
     * Generate a new Falcon-512 key pair.
     * @return true on success, false on error
     */
    bool Generate() {
        int ret = PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair(pk, sk);
        fValid = (ret == 0);
        return fValid;
    }

    /**
     * Check if this key pair has been generated and is valid.
     */
    bool IsValid() const { return fValid; }

    /**
     * Get the public key bytes.
     * @return vector containing the 897-byte public key
     */
    std::vector<unsigned char> GetPubKey() const {
        return std::vector<unsigned char>(pk, pk + FALCON512_PUBLICKEY_BYTES);
    }

    /**
     * Get the secret key bytes.
     * @return vector containing the 1281-byte secret key
     */
    std::vector<unsigned char> GetSecKey() const {
        return std::vector<unsigned char>(sk, sk + FALCON512_SECRETKEY_BYTES);
    }

    /**
     * Get a pointer to the raw public key data.
     */
    const unsigned char* GetPubKeyData() const { return pk; }

    /**
     * Get a pointer to the raw secret key data.
     */
    const unsigned char* GetSecKeyData() const { return sk; }

    /**
     * Set the key pair from raw bytes.
     * @param pubkey public key bytes (must be FALCON512_PUBLICKEY_BYTES)
     * @param seckey secret key bytes (must be FALCON512_SECRETKEY_BYTES)
     */
    void SetKeys(const unsigned char* pubkey, const unsigned char* seckey) {
        memcpy(pk, pubkey, FALCON512_PUBLICKEY_BYTES);
        memcpy(sk, seckey, FALCON512_SECRETKEY_BYTES);
        fValid = true;
    }

    /**
     * Sign a message using this key pair.
     * @param msg message to sign
     * @param msglen length of the message
     * @param sig output signature
     * @return true on success, false on error
     */
    bool Sign(const unsigned char* msg, size_t msglen,
              std::vector<unsigned char>& sig) const
    {
        if (!fValid) return false;
        sig.resize(FALCON512_SIG_BYTES);
        size_t siglen = 0;
        int ret = PQCLEAN_FALCON512_CLEAN_crypto_sign_signature(
            sig.data(), &siglen, msg, msglen, sk);
        if (ret != 0) {
            sig.clear();
            return false;
        }
        sig.resize(siglen);
        return true;
    }

    /**
     * Sign a message and prepend the signature (NR-style signed message).
     * @param msg message to sign
     * @param msglen length of the message
     * @param sm output: signature || message
     * @return true on success, false on error
     */
    bool SignMessage(const unsigned char* msg, size_t msglen,
                     std::vector<unsigned char>& sm) const
    {
        if (!fValid) return false;
        sm.resize(FALCON512_SIG_BYTES + msglen);
        size_t smlen = 0;
        int ret = PQCLEAN_FALCON512_CLEAN_crypto_sign(
            sm.data(), &smlen, msg, msglen, sk);
        if (ret != 0) {
            sm.clear();
            return false;
        }
        sm.resize(smlen);
        return true;
    }
};

/**
 * Verify a Falcon-512 signature.
 * @param pubkey public key (FALCON512_PUBLICKEY_BYTES bytes)
 * @param msg message that was signed
 * @param msglen length of the message
 * @param sig signature to verify
 * @param siglen length of the signature
 * @return true if signature is valid, false otherwise
 */
inline bool CFalcon512Verify(const unsigned char* pubkey,
                             const unsigned char* msg, size_t msglen,
                             const unsigned char* sig, size_t siglen)
{
    return PQCLEAN_FALCON512_CLEAN_crypto_sign_verify(
        sig, siglen, msg, msglen, pubkey) == 0;
}

/**
 * Verify a Falcon-512 signature (vector overload).
 */
inline bool CFalcon512Verify(const std::vector<unsigned char>& pubkey,
                             const unsigned char* msg, size_t msglen,
                             const std::vector<unsigned char>& sig)
{
    if (pubkey.size() != FALCON512_PUBLICKEY_BYTES) return false;
    return CFalcon512Verify(pubkey.data(), msg, msglen, sig.data(), sig.size());
}

/**
 * Open a signed message (verify and extract message).
 * @param pubkey public key (FALCON512_PUBLICKEY_BYTES bytes)
 * @param sm signed message (signature || message)
 * @param smlen length of the signed message
 * @param msg output: extracted message
 * @return true if signature is valid, false otherwise
 */
inline bool CFalcon512Open(const unsigned char* pubkey,
                           const unsigned char* sm, size_t smlen,
                           std::vector<unsigned char>& msg)
{
    msg.resize(smlen);
    size_t mlen = 0;
    int ret = PQCLEAN_FALCON512_CLEAN_crypto_sign_open(
        msg.data(), &mlen, sm, smlen, pubkey);
    if (ret != 0) {
        msg.clear();
        return false;
    }
    msg.resize(mlen);
    return true;
}

#endif // DOGECOIN_CRYPTO_FALCON512_H
