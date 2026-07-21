// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mw/crypto/Bulletproof.h>

// prefix.h renames every secp256k1_ identifier to mw_secp256k1_, matching the
// isolated symbol-prefixed zkp library. Must precede the secp256k1 headers.
#include "prefix.h"
#include <secp256k1.h>
#include <secp256k1_generator.h>
#include <secp256k1_commitment.h>
#include <secp256k1_bulletproofs.h>

#include <stdexcept>
#include <vector>

MW_NAMESPACE
namespace Bulletproof {

namespace {
    constexpr size_t NBITS = 64;
    constexpr size_t N_GENERATORS = 256;

    secp256k1_context* Ctx()
    {
        static secp256k1_context* ctx =
            secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
        return ctx;
    }

    // ~1 MiB scratch for the multi-exponentiation, created once.
    secp256k1_scratch_space* Scratch()
    {
        static secp256k1_scratch_space* scratch =
            secp256k1_scratch_space_create(Ctx(), 1024 * 1024);
        return scratch;
    }

    // NUMS generators, blinding generator = G (matches mw::Pedersen's blind_gen),
    // created once.
    secp256k1_bulletproof_generators* Gens()
    {
        static secp256k1_bulletproof_generators* gens =
            secp256k1_bulletproof_generators_create(
                Ctx(), &secp256k1_generator_const_g, N_GENERATORS);
        return gens;
    }
}

RangeProof Prove(uint64_t value, const BlindingFactor& blind)
{
    std::vector<uint8_t> proof(SECP256K1_BULLETPROOF_MAX_PROOF);
    size_t plen = proof.size();

    const uint64_t val = value;
    const unsigned char* blind_ptr = blind.data();
    const unsigned char* const* blinds = &blind_ptr;

    if (!secp256k1_bulletproof_rangeproof_prove(
            Ctx(), Scratch(), Gens(),
            proof.data(), &plen,
            nullptr, nullptr, nullptr,   // tau_x, t_one, t_two (multiparty only)
            &val, nullptr,               // value, min_value (NULL -> 0)
            blinds, nullptr, 1,          // blinds, commits (NULL -> derive), n_commits
            &secp256k1_generator_const_h, NBITS,
            blind.data(),                // nonce
            nullptr, nullptr, 0, nullptr)) {
        throw std::runtime_error("Bulletproof: prove failed");
    }

    proof.resize(plen);
    return RangeProof(std::move(proof));
}

bool Verify(const RangeProof& proof, const Commitment& commit)
{
    secp256k1_pedersen_commitment parsed;
    if (!secp256k1_pedersen_commitment_parse(Ctx(), &parsed, commit.data())) {
        return false;
    }

    const std::vector<uint8_t>& data = proof.GetProofData();
    return secp256k1_bulletproof_rangeproof_verify(
        Ctx(), Scratch(), Gens(),
        data.data(), data.size(),
        nullptr,          // min_value (NULL -> 0)
        &parsed, 1, NBITS,
        &secp256k1_generator_const_h,
        nullptr, 0) == 1;
}

}
END_NAMESPACE
