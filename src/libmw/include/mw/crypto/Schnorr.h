// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef MW_CRYPTO_SCHNORR_H
#define MW_CRYPTO_SCHNORR_H

#include <mw/common/Macros.h>
#include <mw/models/crypto/Signature.h>
#include <mw/models/crypto/PublicKey.h>
#include <mw/models/crypto/SecretKey.h>
#include <cstdint>

MW_NAMESPACE

// Schnorr (aggsig single-signer) operations, backed by the isolated
// symbol-prefixed secp256k1-zkp. This is the signature primitive MWEB uses to
// prove ownership of a kernel excess: the signature is over the kernel message
// with the excess blinding factor as the key, verified against the excess
// commitment interpreted as a public key.
namespace Schnorr {

    // Derive the compressed public key (excess*G) for a secret key.
    PublicKey BuildPublicKey(const SecretKey& key);

    // Sign a 32-byte message with `key`. Throws std::runtime_error on failure.
    Signature Sign(const SecretKey& key, const uint8_t* message32);

    // Verify a signature over a 32-byte message against `pubkey`.
    bool Verify(const Signature& sig, const PublicKey& pubkey, const uint8_t* message32);

}

END_NAMESPACE

#endif // MW_CRYPTO_SCHNORR_H
