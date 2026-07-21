// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef MW_CRYPTO_KEYS_H
#define MW_CRYPTO_KEYS_H

#include <mw/common/Macros.h>
#include <mw/models/crypto/PublicKey.h>
#include <mw/models/crypto/SecretKey.h>

MW_NAMESPACE

// Elliptic-curve key operations, backed by the isolated symbol-prefixed
// secp256k1-zkp. These are the building blocks for MWEB stealth addresses and
// one-sided payments: deriving public keys, homomorphically combining keys,
// and computing ECDH shared secrets between a scan/spend key and an ephemeral
// sender key.
namespace Keys {

    // Public key P = k*G for secret key k.
    PublicKey PublicKeyFrom(const SecretKey& key);

    // Scalar sum (a + b) mod n. Used to combine blinding factors / derive keys.
    SecretKey AddSecretKeys(const SecretKey& a, const SecretKey& b);

    // Scalar negation (-a) mod n. With AddSecretKeys this gives subtraction,
    // needed to compute a kernel excess (Sum(out blinds) - Sum(in blinds) - offset).
    SecretKey NegateSecretKey(const SecretKey& a);

    // Point sum A + B. Homomorphic partner of AddSecretKeys:
    // PublicKeyFrom(AddSecretKeys(a,b)) == AddPublicKeys(PublicKeyFrom(a), PublicKeyFrom(b)).
    PublicKey AddPublicKeys(const PublicKey& a, const PublicKey& b);

    // ECDH shared secret (32 bytes) between our secret key and their public key.
    // Symmetric: ECDH(a, P_b) == ECDH(b, P_a). Basis for stealth-address scanning.
    SecretKey ECDH(const SecretKey& mine, const PublicKey& theirs);

}

END_NAMESPACE

#endif // MW_CRYPTO_KEYS_H
