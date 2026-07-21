// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef MW_CRYPTO_PEDERSEN_H
#define MW_CRYPTO_PEDERSEN_H

#include <mw/common/Macros.h>
#include <mw/models/crypto/Commitment.h>
#include <mw/models/crypto/BlindingFactor.h>
#include <mw/models/crypto/PublicKey.h>
#include <cstdint>
#include <vector>

MW_NAMESPACE

// Pedersen commitment operations, backed by the isolated (symbol-prefixed)
// secp256k1-zkp library. This is the first real MWEB crypto primitive: it
// replaces the byte-blob placeholder behaviour of the Commitment model with
// actual elliptic-curve Pedersen commitments (value*H + blind*G).
namespace Pedersen {

    // Commit to `value` under blinding factor `blind`: C = value*H + blind*G.
    // Throws std::runtime_error on failure.
    Commitment Commit(uint64_t value, const BlindingFactor& blind);

    // Homomorphic sum: (sum of `positive`) - (sum of `negative`).
    Commitment AddCommitments(
        const std::vector<Commitment>& positive,
        const std::vector<Commitment>& negative);

    // Balance check (no inflation): returns true iff
    // (sum of `positive`) - (sum of `negative`) commits to zero.
    // This is the sum-to-zero verification MWEB uses for peg/kernel balance.
    bool VerifyBalance(
        const std::vector<Commitment>& positive,
        const std::vector<Commitment>& negative);

    // Interpret a commitment as a public key. A kernel excess is a commitment
    // to zero (excess*G), so this yields the key its signature verifies against.
    PublicKey ToPublicKey(const Commitment& commit);

}

END_NAMESPACE

#endif // MW_CRYPTO_PEDERSEN_H
