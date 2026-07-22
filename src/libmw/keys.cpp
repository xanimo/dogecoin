// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mw/crypto/Keys.h>

// prefix.h renames every secp256k1_ identifier to mw_secp256k1_, matching the
// isolated symbol-prefixed zkp library. Must precede the secp256k1 headers.
#include "prefix.h"
#include <secp256k1.h>

// The zkp library predates the secp API rename, so it exports the older
// ec_privkey_tweak_add and the 4-arg ecdh. The default include path resolves
// secp256k1_ecdh.h to the *consensus* secp (modern 6-arg ecdh, seckey_tweak_add),
// so declare the two zkp signatures directly rather than pull in the wrong
// header. prefix.h turns these names into mw_secp256k1_* to match the zkp lib.
// (A libmw-crypto convenience library with zkp-first includes would let us drop
// these forward declarations; see the MWEB notes.)
extern "C" {
    int secp256k1_ec_privkey_tweak_add(
        const secp256k1_context* ctx, unsigned char* seckey, const unsigned char* tweak);
    int secp256k1_ec_privkey_negate(
        const secp256k1_context* ctx, unsigned char* seckey);
    int secp256k1_ecdh(
        const secp256k1_context* ctx, unsigned char* result,
        const secp256k1_pubkey* pubkey, const unsigned char* privkey);
}

#include <stdexcept>
#include <vector>

MW_NAMESPACE
namespace Keys {

namespace {
    secp256k1_context* Ctx()
    {
        static secp256k1_context* ctx =
            secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
        return ctx;
    }

    PublicKey Serialize(const secp256k1_pubkey& pubkey)
    {
        unsigned char out[PublicKey::SIZE];
        size_t len = PublicKey::SIZE;
        secp256k1_ec_pubkey_serialize(Ctx(), out, &len, &pubkey, SECP256K1_EC_COMPRESSED);
        return PublicKey(out);
    }

    secp256k1_pubkey Parse(const PublicKey& pubkey)
    {
        secp256k1_pubkey parsed;
        if (!secp256k1_ec_pubkey_parse(Ctx(), &parsed, pubkey.data(), PublicKey::SIZE)) {
            throw std::runtime_error("Keys: failed to parse public key");
        }
        return parsed;
    }
}

PublicKey PublicKeyFrom(const SecretKey& key)
{
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_create(Ctx(), &pubkey, key.data())) {
        throw std::runtime_error("Keys: invalid secret key");
    }
    return Serialize(pubkey);
}

SecretKey AddSecretKeys(const SecretKey& a, const SecretKey& b)
{
    std::vector<uint8_t> sum(a.data(), a.data() + SecretKey::SIZE);
    if (!secp256k1_ec_privkey_tweak_add(Ctx(), sum.data(), b.data())) {
        throw std::runtime_error("Keys: secret key sum out of range");
    }
    return SecretKey(sum);
}

SecretKey NegateSecretKey(const SecretKey& a)
{
    std::vector<uint8_t> neg(a.data(), a.data() + SecretKey::SIZE);
    if (!secp256k1_ec_privkey_negate(Ctx(), neg.data())) {
        throw std::runtime_error("Keys: secret key negation failed");
    }
    return SecretKey(neg);
}

PublicKey AddPublicKeys(const PublicKey& a, const PublicKey& b)
{
    secp256k1_pubkey pa = Parse(a);
    secp256k1_pubkey pb = Parse(b);
    const secp256k1_pubkey* ptrs[2] = { &pa, &pb };

    secp256k1_pubkey combined;
    if (!secp256k1_ec_pubkey_combine(Ctx(), &combined, ptrs, 2)) {
        throw std::runtime_error("Keys: public key combine failed");
    }
    return Serialize(combined);
}

SecretKey ECDH(const SecretKey& mine, const PublicKey& theirs)
{
    secp256k1_pubkey parsed = Parse(theirs);
    std::vector<uint8_t> shared(SecretKey::SIZE, 0);
    if (!secp256k1_ecdh(Ctx(), shared.data(), &parsed, mine.data())) {
        throw std::runtime_error("Keys: ECDH failed");
    }
    return SecretKey(shared);
}

bool VerifyKeyBalance(const std::vector<PublicKey>& positive,
                      const std::vector<PublicKey>& negative,
                      const BlindingFactor& offset)
{
    // Build the point list: +positives, -negatives, and -offset*G. If they sum
    // to the point at infinity the balance holds. secp256k1_ec_pubkey_combine
    // returns 0 exactly when the result is that point (and 1 for any finite
    // point), which is precisely the balanced/unbalanced distinction -- and the
    // only way to represent "sums to zero" here, since the infinity point has no
    // compressed encoding.
    std::vector<secp256k1_pubkey> points;
    points.reserve(positive.size() + negative.size() + 1);

    for (const PublicKey& p : positive) {
        points.push_back(Parse(p));
    }
    for (const PublicKey& n : negative) {
        secp256k1_pubkey pn = Parse(n);
        if (!secp256k1_ec_pubkey_negate(Ctx(), &pn)) {
            throw std::runtime_error("Keys: public key negation failed");
        }
        points.push_back(pn);
    }
    if (!offset.IsNull()) {
        secp256k1_pubkey off;
        if (!secp256k1_ec_pubkey_create(Ctx(), &off, offset.data())) {
            throw std::runtime_error("Keys: invalid stealth offset");
        }
        if (!secp256k1_ec_pubkey_negate(Ctx(), &off)) {
            throw std::runtime_error("Keys: public key negation failed");
        }
        points.push_back(off);
    }

    if (points.empty()) {
        return true; // nothing to balance
    }

    std::vector<const secp256k1_pubkey*> ptrs;
    ptrs.reserve(points.size());
    for (const secp256k1_pubkey& pt : points) {
        ptrs.push_back(&pt);
    }

    secp256k1_pubkey combined;
    // Balanced <=> the sum is the point at infinity <=> combine returns 0.
    return secp256k1_ec_pubkey_combine(Ctx(), &combined, ptrs.data(), ptrs.size()) == 0;
}

}
END_NAMESPACE
