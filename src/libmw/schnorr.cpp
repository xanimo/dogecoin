// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mw/crypto/Schnorr.h>

// prefix.h renames every secp256k1_ identifier to mw_secp256k1_, matching the
// isolated symbol-prefixed zkp library. Must precede the secp256k1 headers.
#include "prefix.h"
#include <secp256k1.h>
#include <secp256k1_aggsig.h>

#include <random.h>

#include <stdexcept>
#include <vector>

MW_NAMESPACE
namespace Schnorr {

namespace {
    secp256k1_context* Ctx()
    {
        static secp256k1_context* ctx =
            secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
        return ctx;
    }
}

PublicKey BuildPublicKey(const SecretKey& key)
{
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_create(Ctx(), &pubkey, key.data())) {
        throw std::runtime_error("Schnorr: invalid secret key");
    }
    unsigned char out[PublicKey::SIZE];
    size_t len = PublicKey::SIZE;
    secp256k1_ec_pubkey_serialize(Ctx(), out, &len, &pubkey, SECP256K1_EC_COMPRESSED);
    return PublicKey(out);
}

Signature Sign(const SecretKey& key, const uint8_t* message32)
{
    // aggsig requires a 32-byte seed to derive its nonce; use strong entropy.
    unsigned char seed[32];
    GetStrongRandBytes(seed, sizeof(seed));

    unsigned char sig[Signature::SIZE];
    if (!secp256k1_aggsig_sign_single(
            Ctx(), sig, message32, key.data(),
            nullptr, nullptr, nullptr, nullptr, nullptr, seed)) {
        throw std::runtime_error("Schnorr: sign failed");
    }
    return Signature(std::vector<uint8_t>(sig, sig + Signature::SIZE));
}

bool Verify(const Signature& sig, const PublicKey& pubkey, const uint8_t* message32)
{
    secp256k1_pubkey parsed;
    if (!secp256k1_ec_pubkey_parse(Ctx(), &parsed, pubkey.data(), PublicKey::SIZE)) {
        return false;
    }
    return secp256k1_aggsig_verify_single(
        Ctx(), sig.data(), message32,
        nullptr, &parsed, nullptr, nullptr, 0) == 1;
}

}
END_NAMESPACE
