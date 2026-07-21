// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef MW_CRYPTO_BULLETPROOF_H
#define MW_CRYPTO_BULLETPROOF_H

#include <mw/common/Macros.h>
#include <mw/models/crypto/RangeProof.h>
#include <mw/models/crypto/Commitment.h>
#include <mw/models/crypto/BlindingFactor.h>
#include <cstdint>

MW_NAMESPACE

// Bulletproof range proofs, backed by the isolated symbol-prefixed
// secp256k1-zkp. Proves that a Pedersen commitment hides a value in
// [0, 2^64) without revealing it -- the check that stops an MWEB output from
// committing to a negative/overflowing amount (inflation).
//
// Uses the same generator convention as mw::Pedersen (value generator H,
// blinding generator G), so proofs verify against mw::Pedersen::Commit output.
namespace Bulletproof {

    // Prove that `value` (committed under `blind`) lies in a 64-bit range.
    RangeProof Prove(uint64_t value, const BlindingFactor& blind);

    // Verify a range proof against its Pedersen commitment.
    bool Verify(const RangeProof& proof, const Commitment& commit);

}

END_NAMESPACE

#endif // MW_CRYPTO_BULLETPROOF_H
