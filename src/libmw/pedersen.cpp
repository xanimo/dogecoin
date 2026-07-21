// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mw/crypto/Pedersen.h>

// prefix.h renames every secp256k1_ identifier to mw_secp256k1_, matching the
// isolated symbol-prefixed zkp library (src/secp256k1-zkp). It MUST be included
// before the secp256k1 headers so the declarations and our calls resolve to the
// mw_ symbols and never collide with the consensus src/secp256k1.
#include "prefix.h"
#include <secp256k1.h>
#include <secp256k1_generator.h>
#include <secp256k1_commitment.h>

#include <stdexcept>

MW_NAMESPACE
namespace Pedersen {

namespace {
    // One shared verification/signing context for the process.
    secp256k1_context* Ctx()
    {
        static secp256k1_context* ctx =
            secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
        return ctx;
    }

    // Parse a 33-byte model Commitment into a secp256k1 commitment.
    secp256k1_pedersen_commitment Parse(const Commitment& commit)
    {
        secp256k1_pedersen_commitment parsed;
        if (!secp256k1_pedersen_commitment_parse(Ctx(), &parsed, commit.data())) {
            throw std::runtime_error("Pedersen: failed to parse commitment");
        }
        return parsed;
    }

    Commitment Serialize(const secp256k1_pedersen_commitment& parsed)
    {
        unsigned char out[Commitment::SIZE];
        secp256k1_pedersen_commitment_serialize(Ctx(), out, &parsed);
        return Commitment(out);
    }
}

Commitment Commit(uint64_t value, const BlindingFactor& blind)
{
    secp256k1_pedersen_commitment commit;
    if (!secp256k1_pedersen_commit(
            Ctx(), &commit, blind.data(), value,
            &secp256k1_generator_const_h, &secp256k1_generator_const_g)) {
        throw std::runtime_error("Pedersen: commit failed");
    }
    return Serialize(commit);
}

Commitment AddCommitments(
    const std::vector<Commitment>& positive,
    const std::vector<Commitment>& negative)
{
    std::vector<secp256k1_pedersen_commitment> pos_owned, neg_owned;
    pos_owned.reserve(positive.size());
    neg_owned.reserve(negative.size());
    for (const Commitment& c : positive) pos_owned.push_back(Parse(c));
    for (const Commitment& c : negative) neg_owned.push_back(Parse(c));

    std::vector<const secp256k1_pedersen_commitment*> pos_ptrs, neg_ptrs;
    for (const auto& c : pos_owned) pos_ptrs.push_back(&c);
    for (const auto& c : neg_owned) neg_ptrs.push_back(&c);

    secp256k1_pedersen_commitment result;
    if (!secp256k1_pedersen_commit_sum(
            Ctx(), &result,
            pos_ptrs.data(), pos_ptrs.size(),
            neg_ptrs.data(), neg_ptrs.size())) {
        throw std::runtime_error("Pedersen: commit_sum failed");
    }
    return Serialize(result);
}

bool VerifyBalance(
    const std::vector<Commitment>& positive,
    const std::vector<Commitment>& negative)
{
    std::vector<secp256k1_pedersen_commitment> pos_owned, neg_owned;
    pos_owned.reserve(positive.size());
    neg_owned.reserve(negative.size());
    for (const Commitment& c : positive) pos_owned.push_back(Parse(c));
    for (const Commitment& c : negative) neg_owned.push_back(Parse(c));

    std::vector<const secp256k1_pedersen_commitment*> pos_ptrs, neg_ptrs;
    for (const auto& c : pos_owned) pos_ptrs.push_back(&c);
    for (const auto& c : neg_owned) neg_ptrs.push_back(&c);

    return secp256k1_pedersen_verify_tally(
        Ctx(),
        pos_ptrs.data(), pos_ptrs.size(),
        neg_ptrs.data(), neg_ptrs.size()) == 1;
}

PublicKey ToPublicKey(const Commitment& commit)
{
    secp256k1_pedersen_commitment parsed = Parse(commit);

    secp256k1_pubkey pubkey;
    if (!secp256k1_pedersen_commitment_to_pubkey(Ctx(), &pubkey, &parsed)) {
        throw std::runtime_error("Pedersen: commitment_to_pubkey failed");
    }

    unsigned char out[PublicKey::SIZE];
    size_t len = PublicKey::SIZE;
    secp256k1_ec_pubkey_serialize(Ctx(), out, &len, &pubkey, SECP256K1_EC_COMPRESSED);
    return PublicKey(out);
}

}
END_NAMESPACE
