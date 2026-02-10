// Copyright (c) 2024 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * @file falcon_tests.cpp
 * @brief Tests for the Falcon-512 post-quantum digital signature scheme.
 *
 * This test suite verifies:
 *   1. Key generation produces valid key pairs
 *   2. Signing and verification round-trip correctly
 *   3. Signature verification rejects tampered messages
 *   4. Signature verification rejects tampered signatures
 *   5. Signature verification rejects wrong public keys
 *   6. Empty message signing works
 *   7. Various message lengths work
 *   8. Signed message (combined) format works
 *   9. Multiple signatures with same key are independent
 *  10. Key pair size constraints match NIST specification
 *
 * NIST KAT reference checksums (for future deterministic validation):
 *   nistkat-sha256:     da27fe8a462de7307ddf1f9b00072a457d9c5b14e838c148fbe2662094b9a2ca
 *   testvectors-sha256: e6d6d5b0ee34ccdeabfc9d7e5487adafedec13b425f2fe991a1fa6efff3be68a
 */

#include "crypto/falcon.h"
#include "test/test_bitcoin.h"

#include <cstring>
#include <vector>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(falcon_tests, BasicTestingSetup)

/**
 * Test that key generation produces a valid key pair of the correct sizes.
 */
BOOST_AUTO_TEST_CASE(falcon512_keygen)
{
    CFalcon512KeyPair kp;
    BOOST_CHECK(!kp.IsValid());

    bool ret = kp.Generate();
    BOOST_CHECK(ret);
    BOOST_CHECK(kp.IsValid());

    // Verify key sizes
    std::vector<unsigned char> pk = kp.GetPubKey();
    std::vector<unsigned char> sk = kp.GetSecKey();
    BOOST_CHECK_EQUAL(pk.size(), FALCON512_PUBLICKEY_BYTES);
    BOOST_CHECK_EQUAL(sk.size(), FALCON512_SECRETKEY_BYTES);

    // Public key header byte should be 0x00 + logn(9)
    BOOST_CHECK_EQUAL(pk[0], 0x09);
    // Secret key header byte should be 0x50 + logn(9)
    BOOST_CHECK_EQUAL(sk[0], 0x59);
}

/**
 * Test basic sign and verify round-trip.
 */
BOOST_AUTO_TEST_CASE(falcon512_sign_verify)
{
    CFalcon512KeyPair kp;
    BOOST_CHECK(kp.Generate());

    // Sign a test message
    const unsigned char msg[] = "Dogecoin: the people's crypto.";
    size_t msglen = sizeof(msg) - 1;

    std::vector<unsigned char> sig;
    bool signOk = kp.Sign(msg, msglen, sig);
    BOOST_CHECK(signOk);
    BOOST_CHECK(sig.size() > 0);
    BOOST_CHECK(sig.size() <= FALCON512_SIG_BYTES);

    // Verify the signature
    std::vector<unsigned char> pk = kp.GetPubKey();
    bool verifyOk = CFalcon512Verify(pk, msg, msglen, sig);
    BOOST_CHECK(verifyOk);
}

/**
 * Test that verification rejects a tampered message.
 */
BOOST_AUTO_TEST_CASE(falcon512_tampered_message)
{
    CFalcon512KeyPair kp;
    BOOST_CHECK(kp.Generate());

    const unsigned char msg[] = "Much post-quantum. Very secure.";
    size_t msglen = sizeof(msg) - 1;

    std::vector<unsigned char> sig;
    BOOST_CHECK(kp.Sign(msg, msglen, sig));

    // Tamper with the message
    unsigned char tampered[sizeof(msg)];
    memcpy(tampered, msg, msglen);
    tampered[0] ^= 0x01;

    std::vector<unsigned char> pk = kp.GetPubKey();
    bool verifyOk = CFalcon512Verify(pk, tampered, msglen, sig);
    BOOST_CHECK(!verifyOk);
}

/**
 * Test that verification rejects a tampered signature.
 */
BOOST_AUTO_TEST_CASE(falcon512_tampered_signature)
{
    CFalcon512KeyPair kp;
    BOOST_CHECK(kp.Generate());

    const unsigned char msg[] = "Such lattice. Wow.";
    size_t msglen = sizeof(msg) - 1;

    std::vector<unsigned char> sig;
    BOOST_CHECK(kp.Sign(msg, msglen, sig));

    // Tamper with the signature (flip a bit in the compressed part)
    if (sig.size() > 42) { // header(1) + nonce(40) + at least 1 byte
        sig[42] ^= 0x01;
    }

    std::vector<unsigned char> pk = kp.GetPubKey();
    bool verifyOk = CFalcon512Verify(pk, msg, msglen, sig);
    BOOST_CHECK(!verifyOk);
}

/**
 * Test that verification rejects a different public key.
 */
BOOST_AUTO_TEST_CASE(falcon512_wrong_pubkey)
{
    CFalcon512KeyPair kp1, kp2;
    BOOST_CHECK(kp1.Generate());
    BOOST_CHECK(kp2.Generate());

    const unsigned char msg[] = "To the moon!";
    size_t msglen = sizeof(msg) - 1;

    std::vector<unsigned char> sig;
    BOOST_CHECK(kp1.Sign(msg, msglen, sig));

    // Verify with wrong public key should fail
    std::vector<unsigned char> pk2 = kp2.GetPubKey();
    bool verifyOk = CFalcon512Verify(pk2, msg, msglen, sig);
    BOOST_CHECK(!verifyOk);

    // But verify with correct key should succeed
    std::vector<unsigned char> pk1 = kp1.GetPubKey();
    BOOST_CHECK(CFalcon512Verify(pk1, msg, msglen, sig));
}

/**
 * Test signing and verifying an empty message.
 */
BOOST_AUTO_TEST_CASE(falcon512_empty_message)
{
    CFalcon512KeyPair kp;
    BOOST_CHECK(kp.Generate());

    std::vector<unsigned char> sig;
    BOOST_CHECK(kp.Sign(NULL, 0, sig));
    BOOST_CHECK(sig.size() > 0);

    std::vector<unsigned char> pk = kp.GetPubKey();
    BOOST_CHECK(CFalcon512Verify(pk.data(), NULL, 0, sig.data(), sig.size()));
}

/**
 * Test signing various message lengths.
 */
BOOST_AUTO_TEST_CASE(falcon512_various_lengths)
{
    CFalcon512KeyPair kp;
    BOOST_CHECK(kp.Generate());

    std::vector<unsigned char> pk = kp.GetPubKey();

    // Test message lengths: 1, 16, 64, 256, 1024
    size_t lengths[] = {1, 16, 64, 256, 1024};
    for (size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); i++) {
        std::vector<unsigned char> msg(lengths[i], (unsigned char)(i + 0x41));

        std::vector<unsigned char> sig;
        BOOST_CHECK_MESSAGE(kp.Sign(msg.data(), msg.size(), sig),
            "Sign failed for message length " + std::to_string(lengths[i]));
        BOOST_CHECK_MESSAGE(CFalcon512Verify(pk, msg.data(), msg.size(), sig),
            "Verify failed for message length " + std::to_string(lengths[i]));
    }
}

/**
 * Test the signed message (combined sig+msg) format.
 */
BOOST_AUTO_TEST_CASE(falcon512_signed_message)
{
    CFalcon512KeyPair kp;
    BOOST_CHECK(kp.Generate());

    const unsigned char msg[] = "Falcon-512 signed message test";
    size_t msglen = sizeof(msg) - 1;

    // Create signed message
    std::vector<unsigned char> sm;
    BOOST_CHECK(kp.SignMessage(msg, msglen, sm));
    BOOST_CHECK(sm.size() > msglen);

    // Open and verify signed message
    std::vector<unsigned char> recovered;
    BOOST_CHECK(CFalcon512Open(kp.GetPubKeyData(), sm.data(), sm.size(), recovered));
    BOOST_CHECK_EQUAL(recovered.size(), msglen);
    BOOST_CHECK(memcmp(recovered.data(), msg, msglen) == 0);

    // Tampered signed message should fail
    sm[sm.size() / 2] ^= 0x01;
    std::vector<unsigned char> recovered2;
    BOOST_CHECK(!CFalcon512Open(kp.GetPubKeyData(), sm.data(), sm.size(), recovered2));
}

/**
 * Test that multiple signatures from the same key are independent
 * (different nonces produce different signatures).
 */
BOOST_AUTO_TEST_CASE(falcon512_signature_independence)
{
    CFalcon512KeyPair kp;
    BOOST_CHECK(kp.Generate());

    const unsigned char msg[] = "Same message, different nonces";
    size_t msglen = sizeof(msg) - 1;

    std::vector<unsigned char> sig1, sig2;
    BOOST_CHECK(kp.Sign(msg, msglen, sig1));
    BOOST_CHECK(kp.Sign(msg, msglen, sig2));

    // Signatures should be different (different random nonces)
    BOOST_CHECK(sig1 != sig2);

    // But both should verify
    std::vector<unsigned char> pk = kp.GetPubKey();
    BOOST_CHECK(CFalcon512Verify(pk, msg, msglen, sig1));
    BOOST_CHECK(CFalcon512Verify(pk, msg, msglen, sig2));
}

/**
 * Test key import/export via SetKeys.
 */
BOOST_AUTO_TEST_CASE(falcon512_key_import_export)
{
    CFalcon512KeyPair kp1;
    BOOST_CHECK(kp1.Generate());

    // Export keys
    std::vector<unsigned char> pk = kp1.GetPubKey();
    std::vector<unsigned char> sk = kp1.GetSecKey();

    // Import into a new key pair
    CFalcon512KeyPair kp2;
    kp2.SetKeys(pk.data(), sk.data());
    BOOST_CHECK(kp2.IsValid());

    // Sign with imported key, verify with original public key
    const unsigned char msg[] = "Key import test";
    size_t msglen = sizeof(msg) - 1;

    std::vector<unsigned char> sig;
    BOOST_CHECK(kp2.Sign(msg, msglen, sig));
    BOOST_CHECK(CFalcon512Verify(pk, msg, msglen, sig));
}

/**
 * Test NIST parameter compliance.
 * Verifies that the implementation matches the NIST PQC specification
 * for Falcon-512 key and signature sizes.
 */
BOOST_AUTO_TEST_CASE(falcon512_nist_parameters)
{
    // NIST Falcon-512 parameter verification
    BOOST_CHECK_EQUAL(FALCON512_PUBLICKEY_BYTES, 897u);
    BOOST_CHECK_EQUAL(FALCON512_SECRETKEY_BYTES, 1281u);
    BOOST_CHECK_EQUAL(FALCON512_SIG_BYTES, 752u);
    BOOST_CHECK_EQUAL(FALCON512_NONCE_BYTES, 40u);

    // Generate a key and verify actual sizes match
    CFalcon512KeyPair kp;
    BOOST_CHECK(kp.Generate());

    BOOST_CHECK_EQUAL(kp.GetPubKey().size(), 897u);
    BOOST_CHECK_EQUAL(kp.GetSecKey().size(), 1281u);

    // Signature should be at most 752 bytes
    const unsigned char msg[] = "NIST parameter check";
    std::vector<unsigned char> sig;
    BOOST_CHECK(kp.Sign(msg, sizeof(msg) - 1, sig));
    BOOST_CHECK(sig.size() <= 752u);
    BOOST_CHECK(sig.size() > 41u); // At minimum: header(1) + nonce(40) + 1
}

/**
 * Stress test: generate multiple key pairs and cross-verify.
 * Tests that different key pairs cannot cross-verify each other's signatures.
 */
BOOST_AUTO_TEST_CASE(falcon512_cross_verify)
{
    const int NUM_KEYS = 3;
    CFalcon512KeyPair keys[NUM_KEYS];
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
            bool ok = CFalcon512Verify(pk, msg, msglen, sigs[j]);
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
