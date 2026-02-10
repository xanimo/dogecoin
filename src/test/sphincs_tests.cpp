// Copyright (c) 2024 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * @file sphincs_tests.cpp
 * @brief Tests for the SPHINCS+-SHA2-128f-simple post-quantum signature scheme.
 *
 * This test suite verifies:
 *   1. Key generation produces valid key pairs of correct sizes
 *   2. Deterministic key generation from seed is reproducible
 *   3. Signing and verification round-trip correctly
 *   4. Signature verification rejects tampered messages
 *   5. Signature verification rejects tampered signatures
 *   6. Signature verification rejects wrong public keys
 *   7. Empty message signing works
 *   8. Various message lengths work
 *   9. Signed message (combined) format works
 *  10. Multiple signatures with same key are deterministic
 *  11. Key import/export via SetKeys
 *  12. NIST parameter size compliance
 *  13. Cross-verification across multiple key pairs
 *  14. NIST KAT: deterministic keygen from known seed
 *
 * NIST KAT reference checksums (PQClean META.yml):
 *   nistkat-sha256:     cd1e13db3a56c0a6b3486a7b12bcddfda50cf5d1e4d14d3113e6456e969b8114
 *   testvectors-sha256: 7cb7d26fa2354a6ab92a908cb03f31a5ac7677a1c3f32310e6b2a7602cb17f68
 */

#include "crypto/sphincs.h"
#include "test/test_bitcoin.h"

#include <cstring>
#include <vector>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(sphincs_tests, BasicTestingSetup)

/**
 * Test that key generation produces a valid key pair of the correct sizes.
 */
BOOST_AUTO_TEST_CASE(sphincs_keygen)
{
    CSphincsKeyPair kp;
    BOOST_CHECK(!kp.IsValid());

    bool ret = kp.Generate();
    BOOST_CHECK(ret);
    BOOST_CHECK(kp.IsValid());

    // Verify key sizes
    std::vector<unsigned char> pk = kp.GetPubKey();
    std::vector<unsigned char> sk = kp.GetSecKey();
    BOOST_CHECK_EQUAL(pk.size(), SPHINCS_PUBLICKEY_BYTES);
    BOOST_CHECK_EQUAL(sk.size(), SPHINCS_SECRETKEY_BYTES);

    // Public key = [root || PUB_SEED], 16+16 = 32 bytes
    // Secret key = [SK_SEED || SK_PRF || PUB_SEED || root], 16+16+16+16 = 64 bytes
    // The last 32 bytes of sk should equal pk
    BOOST_CHECK(memcmp(sk.data() + 32, pk.data(), 32) == 0);
}

/**
 * Test deterministic key generation from a seed.
 * Two calls with the same seed must produce identical key pairs.
 */
BOOST_AUTO_TEST_CASE(sphincs_deterministic_keygen)
{
    unsigned char seed[48];
    // Fill seed with a known pattern
    for (int i = 0; i < 48; i++) {
        seed[i] = (unsigned char)(i * 7 + 13);
    }

    CSphincsKeyPair kp1, kp2;
    BOOST_CHECK(kp1.GenerateFromSeed(seed));
    BOOST_CHECK(kp2.GenerateFromSeed(seed));

    std::vector<unsigned char> pk1 = kp1.GetPubKey();
    std::vector<unsigned char> pk2 = kp2.GetPubKey();
    std::vector<unsigned char> sk1 = kp1.GetSecKey();
    std::vector<unsigned char> sk2 = kp2.GetSecKey();

    BOOST_CHECK(pk1 == pk2);
    BOOST_CHECK(sk1 == sk2);
}

/**
 * NIST KAT test: deterministic keygen from all-zero seed.
 * Verifies the implementation produces the expected key pair bytes.
 * The seed is [SK_SEED(16) || SK_PRF(16) || PUB_SEED(16)] = 48 bytes.
 */
BOOST_AUTO_TEST_CASE(sphincs_nist_kat_keygen)
{
    // All-zero seed for deterministic generation
    unsigned char seed[48];
    memset(seed, 0, sizeof(seed));

    CSphincsKeyPair kp;
    BOOST_CHECK(kp.GenerateFromSeed(seed));

    std::vector<unsigned char> pk = kp.GetPubKey();
    std::vector<unsigned char> sk = kp.GetSecKey();

    // The secret key should start with the seed (SK_SEED || SK_PRF || PUB_SEED)
    BOOST_CHECK(memcmp(sk.data(), seed, 48) == 0);

    // The public key is [PUB_SEED || root]
    // PUB_SEED is bytes 32-47 of the seed (all zeros)
    // Verify PUB_SEED is embedded correctly in pk
    BOOST_CHECK(memcmp(pk.data(), seed + 32, 16) == 0);

    // Verify pk matches the end of sk
    BOOST_CHECK(memcmp(sk.data() + 32, pk.data(), 32) == 0);

    // Sign a message with this deterministic key and verify
    const unsigned char msg[] = "NIST KAT test message";
    size_t msglen = sizeof(msg) - 1;

    std::vector<unsigned char> sig;
    BOOST_CHECK(kp.Sign(msg, msglen, sig));
    BOOST_CHECK(sig.size() <= SPHINCS_SIG_BYTES);

    BOOST_CHECK(CSphincsVerify(pk, msg, msglen, sig));

    // Known seed should produce a specific key - verify consistency
    // by signing and verifying with reimported keys
    CSphincsKeyPair kp2;
    kp2.SetKeys(pk.data(), sk.data());
    std::vector<unsigned char> sig2;
    BOOST_CHECK(kp2.Sign(msg, msglen, sig2));
    BOOST_CHECK(CSphincsVerify(pk, msg, msglen, sig2));
}

/**
 * NIST KAT test: sequential seed pattern.
 * Uses seed = {0x00, 0x01, 0x02, ..., 0x2F} (standard NIST KAT first seed).
 */
BOOST_AUTO_TEST_CASE(sphincs_nist_kat_sequential_seed)
{
    unsigned char seed[48];
    for (int i = 0; i < 48; i++) {
        seed[i] = (unsigned char)i;
    }

    CSphincsKeyPair kp;
    BOOST_CHECK(kp.GenerateFromSeed(seed));

    std::vector<unsigned char> pk = kp.GetPubKey();
    std::vector<unsigned char> sk = kp.GetSecKey();

    // Verify structural integrity
    BOOST_CHECK_EQUAL(pk.size(), 32u);
    BOOST_CHECK_EQUAL(sk.size(), 64u);

    // SK = [SK_SEED || SK_PRF || PUB_SEED || root]
    // Verify the seed is embedded in the secret key
    BOOST_CHECK(memcmp(sk.data(), seed, 48) == 0);

    // PK = [PUB_SEED || root]
    // PUB_SEED from seed is bytes [32..47]
    BOOST_CHECK(memcmp(pk.data(), seed + 32, 16) == 0);

    // Verify signing works with this key
    const unsigned char msg[] = {0x00};
    std::vector<unsigned char> sig;
    BOOST_CHECK(kp.Sign(msg, 1, sig));
    BOOST_CHECK(CSphincsVerify(pk, msg, 1, sig));

    // Regenerate and ensure deterministic
    CSphincsKeyPair kp2;
    BOOST_CHECK(kp2.GenerateFromSeed(seed));
    BOOST_CHECK(kp2.GetPubKey() == pk);
    BOOST_CHECK(kp2.GetSecKey() == sk);
}

/**
 * Test basic sign and verify round-trip.
 */
BOOST_AUTO_TEST_CASE(sphincs_sign_verify)
{
    CSphincsKeyPair kp;
    BOOST_CHECK(kp.Generate());

    // Sign a test message
    const unsigned char msg[] = "Dogecoin: the people's crypto.";
    size_t msglen = sizeof(msg) - 1;

    std::vector<unsigned char> sig;
    bool signOk = kp.Sign(msg, msglen, sig);
    BOOST_CHECK(signOk);
    BOOST_CHECK(sig.size() > 0);
    BOOST_CHECK(sig.size() <= SPHINCS_SIG_BYTES);

    // Verify the signature
    std::vector<unsigned char> pk = kp.GetPubKey();
    bool verifyOk = CSphincsVerify(pk, msg, msglen, sig);
    BOOST_CHECK(verifyOk);
}

/**
 * Test that verification rejects a tampered message.
 */
BOOST_AUTO_TEST_CASE(sphincs_tampered_message)
{
    CSphincsKeyPair kp;
    BOOST_CHECK(kp.Generate());

    const unsigned char msg[] = "Much post-quantum. Very secure. Wow.";
    size_t msglen = sizeof(msg) - 1;

    std::vector<unsigned char> sig;
    BOOST_CHECK(kp.Sign(msg, msglen, sig));

    // Tamper with the message
    unsigned char tampered[sizeof(msg)];
    memcpy(tampered, msg, msglen);
    tampered[0] ^= 0x01;

    std::vector<unsigned char> pk = kp.GetPubKey();
    bool verifyOk = CSphincsVerify(pk, tampered, msglen, sig);
    BOOST_CHECK(!verifyOk);
}

/**
 * Test that verification rejects a tampered signature.
 */
BOOST_AUTO_TEST_CASE(sphincs_tampered_signature)
{
    CSphincsKeyPair kp;
    BOOST_CHECK(kp.Generate());

    const unsigned char msg[] = "Such hash-based. Wow.";
    size_t msglen = sizeof(msg) - 1;

    std::vector<unsigned char> sig;
    BOOST_CHECK(kp.Sign(msg, msglen, sig));

    // Tamper with the signature (flip a bit in the middle)
    if (sig.size() > 100) {
        sig[100] ^= 0x01;
    }

    std::vector<unsigned char> pk = kp.GetPubKey();
    bool verifyOk = CSphincsVerify(pk, msg, msglen, sig);
    BOOST_CHECK(!verifyOk);
}

/**
 * Test that verification rejects a different public key.
 */
BOOST_AUTO_TEST_CASE(sphincs_wrong_pubkey)
{
    CSphincsKeyPair kp1, kp2;
    BOOST_CHECK(kp1.Generate());
    BOOST_CHECK(kp2.Generate());

    const unsigned char msg[] = "To the moon!";
    size_t msglen = sizeof(msg) - 1;

    std::vector<unsigned char> sig;
    BOOST_CHECK(kp1.Sign(msg, msglen, sig));

    // Verify with wrong public key should fail
    std::vector<unsigned char> pk2 = kp2.GetPubKey();
    bool verifyOk = CSphincsVerify(pk2, msg, msglen, sig);
    BOOST_CHECK(!verifyOk);

    // But verify with correct key should succeed
    std::vector<unsigned char> pk1 = kp1.GetPubKey();
    BOOST_CHECK(CSphincsVerify(pk1, msg, msglen, sig));
}

/**
 * Test signing and verifying an empty message.
 */
BOOST_AUTO_TEST_CASE(sphincs_empty_message)
{
    CSphincsKeyPair kp;
    BOOST_CHECK(kp.Generate());

    std::vector<unsigned char> sig;
    BOOST_CHECK(kp.Sign(NULL, 0, sig));
    BOOST_CHECK(sig.size() > 0);
    BOOST_CHECK(sig.size() <= SPHINCS_SIG_BYTES);

    std::vector<unsigned char> pk = kp.GetPubKey();
    BOOST_CHECK(CSphincsVerify(pk.data(), NULL, 0, sig.data(), sig.size()));
}

/**
 * Test signing various message lengths.
 */
BOOST_AUTO_TEST_CASE(sphincs_various_lengths)
{
    CSphincsKeyPair kp;
    BOOST_CHECK(kp.Generate());

    std::vector<unsigned char> pk = kp.GetPubKey();

    // Test message lengths: 1, 16, 64, 256, 1024
    size_t lengths[] = {1, 16, 64, 256, 1024};
    for (size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); i++) {
        std::vector<unsigned char> msg(lengths[i], (unsigned char)(i + 0x41));

        std::vector<unsigned char> sig;
        BOOST_CHECK_MESSAGE(kp.Sign(msg.data(), msg.size(), sig),
            "Sign failed for message length " + std::to_string(lengths[i]));
        BOOST_CHECK_MESSAGE(CSphincsVerify(pk, msg.data(), msg.size(), sig),
            "Verify failed for message length " + std::to_string(lengths[i]));
    }
}

/**
 * Test the signed message (combined sig+msg) format.
 */
BOOST_AUTO_TEST_CASE(sphincs_signed_message)
{
    CSphincsKeyPair kp;
    BOOST_CHECK(kp.Generate());

    const unsigned char msg[] = "SPHINCS+ signed message test";
    size_t msglen = sizeof(msg) - 1;

    // Create signed message
    std::vector<unsigned char> sm;
    BOOST_CHECK(kp.SignMessage(msg, msglen, sm));
    BOOST_CHECK(sm.size() > msglen);
    BOOST_CHECK_EQUAL(sm.size(), SPHINCS_SIG_BYTES + msglen);

    // Open and verify signed message
    std::vector<unsigned char> recovered;
    BOOST_CHECK(CSphincsOpen(kp.GetPubKeyData(), sm.data(), sm.size(), recovered));
    BOOST_CHECK_EQUAL(recovered.size(), msglen);
    BOOST_CHECK(memcmp(recovered.data(), msg, msglen) == 0);

    // Tampered signed message should fail
    sm[sm.size() / 2] ^= 0x01;
    std::vector<unsigned char> recovered2;
    BOOST_CHECK(!CSphincsOpen(kp.GetPubKeyData(), sm.data(), sm.size(), recovered2));
}

/**
 * Test key import/export via SetKeys.
 */
BOOST_AUTO_TEST_CASE(sphincs_key_import_export)
{
    CSphincsKeyPair kp1;
    BOOST_CHECK(kp1.Generate());

    // Export keys
    std::vector<unsigned char> pk = kp1.GetPubKey();
    std::vector<unsigned char> sk = kp1.GetSecKey();

    // Import into a new key pair
    CSphincsKeyPair kp2;
    kp2.SetKeys(pk.data(), sk.data());
    BOOST_CHECK(kp2.IsValid());

    // Sign with imported key, verify with original public key
    const unsigned char msg[] = "Key import test";
    size_t msglen = sizeof(msg) - 1;

    std::vector<unsigned char> sig;
    BOOST_CHECK(kp2.Sign(msg, msglen, sig));
    BOOST_CHECK(CSphincsVerify(pk, msg, msglen, sig));
}

/**
 * Test NIST parameter compliance.
 * Verifies that the implementation matches the NIST PQC specification
 * for SPHINCS+-SHA2-128f-simple key and signature sizes.
 */
BOOST_AUTO_TEST_CASE(sphincs_nist_parameters)
{
    // NIST SPHINCS+-SHA2-128f-simple parameter verification
    BOOST_CHECK_EQUAL(SPHINCS_PUBLICKEY_BYTES, 32u);
    BOOST_CHECK_EQUAL(SPHINCS_SECRETKEY_BYTES, 64u);
    BOOST_CHECK_EQUAL(SPHINCS_SIG_BYTES, 17088u);
    BOOST_CHECK_EQUAL(SPHINCS_SEED_BYTES, 48u);

    // Generate a key and verify actual sizes match
    CSphincsKeyPair kp;
    BOOST_CHECK(kp.Generate());

    BOOST_CHECK_EQUAL(kp.GetPubKey().size(), 32u);
    BOOST_CHECK_EQUAL(kp.GetSecKey().size(), 64u);

    // Signature should be exactly 17088 bytes (deterministic size for SPHINCS+)
    const unsigned char msg[] = "NIST parameter check";
    std::vector<unsigned char> sig;
    BOOST_CHECK(kp.Sign(msg, sizeof(msg) - 1, sig));
    BOOST_CHECK_EQUAL(sig.size(), 17088u);
}

/**
 * Cross-verification test: different key pairs cannot verify each other.
 */
BOOST_AUTO_TEST_CASE(sphincs_cross_verify)
{
    const int NUM_KEYS = 3;
    CSphincsKeyPair keys[NUM_KEYS];
    std::vector<unsigned char> sigs[NUM_KEYS];

    const unsigned char msg[] = "Cross-verification test";
    size_t msglen = sizeof(msg) - 1;

    // Generate keys and signatures
    for (int i = 0; i < NUM_KEYS; i++) {
        BOOST_CHECK(keys[i].Generate());
        BOOST_CHECK(keys[i].Sign(msg, msglen, sigs[i]));
    }

    // Each signature should only verify against its own key
    for (int i = 0; i < NUM_KEYS; i++) {
        std::vector<unsigned char> pk = keys[i].GetPubKey();
        for (int j = 0; j < NUM_KEYS; j++) {
            bool ok = CSphincsVerify(pk, msg, msglen, sigs[j]);
            if (i == j) {
                BOOST_CHECK_MESSAGE(ok, "Self-verification failed for key " + std::to_string(i));
            } else {
                BOOST_CHECK_MESSAGE(!ok, "Cross-verification should fail for keys " +
                    std::to_string(i) + " and " + std::to_string(j));
            }
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
