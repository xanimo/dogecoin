// Copyright (c) 2021 The Litecoin Core developers
// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef MW_CONSENSUS_KERNELKEY_H
#define MW_CONSENSUS_KERNELKEY_H

#include <mw/models/tx/Kernel.h>
#include <mw/crypto/Keys.h>
#include <mw/crypto/Pedersen.h>

#include <hash.h>

#include <stdexcept>
#include <vector>

MW_NAMESPACE

/// The hash coefficient H(X||X_s) weighting an excess against a stealth excess.
/// Both keys are in the kernel's signed message, so the coefficient is fixed by
/// the signature and a verifier recomputes it rather than trusting a carried one.
inline SecretKey StealthExcessCoefficient(const PublicKey& excessPubKey,
                                          const PublicKey& stealthExcess)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << excessPubKey << stealthExcess;
    const uint256 h = ss.GetHash();
    return SecretKey(std::vector<uint8_t>(h.begin(), h.end()));
}

/// The public key a kernel signature verifies against.
///
/// With no stealth excess this is the excess commitment read as a point, X.
/// With one it is the hash-weighted aggregate
///
///   X*H(X||X_s) + X_s
///
/// so satisfying it needs the value blind behind X and the secret behind X_s
/// both. The coefficient is what stops a kernel claiming a stealth excess it has
/// no secret for: a plain sum X + X_s is satisfied by knowledge of k alone when
/// the signer picks X_s = K - X, which would let the stealth balance below be
/// closed with a key nobody owns.
inline PublicKey KernelVerificationKey(const Kernel& kernel)
{
    const PublicKey excessPubKey = Pedersen::ToPublicKey(kernel.GetExcess());
    if (!kernel.HasStealthExcess()) {
        return excessPubKey;
    }

    const PublicKey& stealthExcess = kernel.GetStealthExcess();
    if (stealthExcess.IsNull()) {
        throw std::runtime_error("Kernel claims a stealth excess with no key");
    }

    const SecretKey coefficient = StealthExcessCoefficient(excessPubKey, stealthExcess);
    return Keys::AddPublicKeys(Keys::MulPublicKey(excessPubKey, coefficient), stealthExcess);
}

END_NAMESPACE

#endif // MW_CONSENSUS_KERNELKEY_H
