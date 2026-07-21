// Copyright (c) 2015-2022 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "arith_uint256.h"
#include "chainparams.h"
#include "dogecoin.h"
#include "test/test_bitcoin.h"

#include <mw/crypto/Pedersen.h>
#include <mw/crypto/Schnorr.h>
#include <mw/crypto/Bulletproof.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(dogecoin_tests, TestingSetup)

/**
 * the maximum block reward at a given height for a block without fees
 */
uint64_t expectedMaxSubsidy(int height) {
    if (height < 100000) {
        return 1000000 * COIN;
    } else if (height < 145000) {
        return 500000 * COIN;
    } else if (height < 200000) {
        return 250000 * COIN;
    } else if (height < 300000) {
        return 125000 * COIN;
    } else if (height < 400000) {
        return  62500 * COIN;
    } else if (height < 500000) {
        return  31250 * COIN;
    } else if (height < 600000) {
        return  15625 * COIN;
    } else {
        return  10000 * COIN;
    }
}

/**
 * the minimum possible value for the maximum block reward at a given height
 * for a block without fees
 */
uint64_t expectedMinSubsidy(int height) {
    if (height < 100000) {
        return 0;
    } else if (height < 145000) {
        return 0;
    } else if (height < 200000) {
        return 250000 * COIN;
    } else if (height < 300000) {
        return 125000 * COIN;
    } else if (height < 400000) {
        return  62500 * COIN;
    } else if (height < 500000) {
        return  31250 * COIN;
    } else if (height < 600000) {
        return  15625 * COIN;
    } else {
        return  10000 * COIN;
    }
}

BOOST_AUTO_TEST_CASE(subsidy_first_100k_test)
{
    const CChainParams& mainParams = Params(CBaseChainParams::MAIN);
    CAmount nSum = 0;
    arith_uint256 prevHash = UintToArith256(uint256S("0"));

    for (int nHeight = 0; nHeight <= 100000; nHeight++) {
        const Consensus::Params& params = mainParams.GetConsensus(nHeight);
        CAmount nSubsidy = GetDogecoinBlockSubsidy(nHeight, params, ArithToUint256(prevHash));
        BOOST_CHECK(MoneyRange(nSubsidy));
        BOOST_CHECK(nSubsidy <= 1000000 * COIN);
        nSum += nSubsidy;
        // Use nSubsidy to give us some variation in previous block hash, without requiring full block templates
        prevHash += nSubsidy;
    }

    const CAmount expected = 54894174438 * COIN;
    BOOST_CHECK_EQUAL(expected, nSum);
}

BOOST_AUTO_TEST_CASE(subsidy_100k_145k_test)
{
    const CChainParams& mainParams = Params(CBaseChainParams::MAIN);
    CAmount nSum = 0;
    arith_uint256 prevHash = UintToArith256(uint256S("0"));

    for (int nHeight = 100000; nHeight <= 145000; nHeight++) {
        const Consensus::Params& params = mainParams.GetConsensus(nHeight);
        CAmount nSubsidy = GetDogecoinBlockSubsidy(nHeight, params, ArithToUint256(prevHash));
        BOOST_CHECK(MoneyRange(nSubsidy));
        BOOST_CHECK(nSubsidy <= 500000 * COIN);
        nSum += nSubsidy;
        // Use nSubsidy to give us some variation in previous block hash, without requiring full block templates
        prevHash += nSubsidy;
    }

    const CAmount expected = 12349960000 * COIN;
    BOOST_CHECK_EQUAL(expected, nSum);
}

// Check the simplified rewards after block 145,000
BOOST_AUTO_TEST_CASE(subsidy_post_145k_test)
{
    const CChainParams& mainParams = Params(CBaseChainParams::MAIN);
    const uint256 prevHash = uint256S("0");

    for (int nHeight = 145000; nHeight < 600000; nHeight++) {
        const Consensus::Params& params = mainParams.GetConsensus(nHeight);
        CAmount nSubsidy = GetDogecoinBlockSubsidy(nHeight, params, prevHash);
        CAmount nExpectedSubsidy = (500000 >> (nHeight / 100000)) * COIN;
        BOOST_CHECK(MoneyRange(nSubsidy));
        BOOST_CHECK_EQUAL(nSubsidy, nExpectedSubsidy);
    }

    // Test reward at 600k+ is constant
    CAmount nConstantSubsidy = GetDogecoinBlockSubsidy(600000, mainParams.GetConsensus(600000), prevHash);
    BOOST_CHECK_EQUAL(nConstantSubsidy, 10000 * COIN);

    nConstantSubsidy = GetDogecoinBlockSubsidy(700000, mainParams.GetConsensus(700000), prevHash);
    BOOST_CHECK_EQUAL(nConstantSubsidy, 10000 * COIN);
}

BOOST_AUTO_TEST_CASE(get_next_work_difficulty_limit)
{
    SelectParams(CBaseChainParams::MAIN);
    const Consensus::Params& params = Params().GetConsensus(0);

    CBlockIndex pindexLast;
    int64_t nLastRetargetTime = 1386474927; // Block # 1

    pindexLast.nHeight = 239;
    pindexLast.nTime = 1386475638; // Block #239
    pindexLast.nBits = 0x1e0ffff0;
    BOOST_CHECK_EQUAL(CalculateDogecoinNextWorkRequired(&pindexLast, nLastRetargetTime, params), 0x1e00ffff);
}

BOOST_AUTO_TEST_CASE(get_next_work_pre_digishield)
{
    SelectParams(CBaseChainParams::MAIN);
    const Consensus::Params& params = Params().GetConsensus(0);

    CBlockIndex pindexLast;
    int64_t nLastRetargetTime = 1386942008; // Block 9359

    pindexLast.nHeight = 9599;
    pindexLast.nTime = 1386954113;
    pindexLast.nBits = 0x1c1a1206;
    BOOST_CHECK_EQUAL(CalculateDogecoinNextWorkRequired(&pindexLast, nLastRetargetTime, params), 0x1c15ea59);
}

BOOST_AUTO_TEST_CASE(get_next_work_digishield)
{
    SelectParams(CBaseChainParams::MAIN);
    const Consensus::Params& params = Params().GetConsensus(145000);

    CBlockIndex pindexLast;
    int64_t nLastRetargetTime = 1395094427;

    // First hard-fork at 145,000, which applies to block 145,001 onwards
    pindexLast.nHeight = 145000;
    pindexLast.nTime = 1395094679;
    pindexLast.nBits = 0x1b499dfd;
    BOOST_CHECK_EQUAL(CalculateDogecoinNextWorkRequired(&pindexLast, nLastRetargetTime, params), 0x1b671062);
}

BOOST_AUTO_TEST_CASE(get_next_work_digishield_modulated_upper)
{
    SelectParams(CBaseChainParams::MAIN);
    const Consensus::Params& params = Params().GetConsensus(145000);

    CBlockIndex pindexLast;
    int64_t nLastRetargetTime = 1395100835;

    // Test the upper bound on modulated time using mainnet block #145,107
    pindexLast.nHeight = 145107;
    pindexLast.nTime = 1395101360;
    pindexLast.nBits = 0x1b3439cd;
    BOOST_CHECK_EQUAL(CalculateDogecoinNextWorkRequired(&pindexLast, nLastRetargetTime, params), 0x1b4e56b3);
}

BOOST_AUTO_TEST_CASE(get_next_work_digishield_modulated_lower)
{
    SelectParams(CBaseChainParams::MAIN);
    const Consensus::Params& params = Params().GetConsensus(145000);

    CBlockIndex pindexLast;
    int64_t nLastRetargetTime = 1395380517;

    // Test the lower bound on modulated time using mainnet block #149,423
    pindexLast.nHeight = 149423;
    pindexLast.nTime = 1395380447;
    pindexLast.nBits = 0x1b446f21;
    BOOST_CHECK_EQUAL(CalculateDogecoinNextWorkRequired(&pindexLast, nLastRetargetTime, params), 0x1b335358);
}

BOOST_AUTO_TEST_CASE(get_next_work_digishield_rounding)
{
    SelectParams(CBaseChainParams::MAIN);
    const Consensus::Params& params = Params().GetConsensus(145000);

    CBlockIndex pindexLast;
    int64_t nLastRetargetTime = 1395094679;

    // Test case for correct rounding of modulated time - this depends on
    // handling of integer division, and is not obvious from the code
    pindexLast.nHeight = 145001;
    pindexLast.nTime = 1395094727;
    pindexLast.nBits = 0x1b671062;
    BOOST_CHECK_EQUAL(CalculateDogecoinNextWorkRequired(&pindexLast, nLastRetargetTime, params), 0x1b6558a4);
}

BOOST_AUTO_TEST_CASE(hardfork_parameters)
{
    SelectParams(CBaseChainParams::MAIN);
    const Consensus::Params& initialParams = Params().GetConsensus(0);

    BOOST_CHECK_EQUAL(initialParams.nPowTargetTimespan, 14400);
    BOOST_CHECK_EQUAL(initialParams.fAllowLegacyBlocks, true);
    BOOST_CHECK_EQUAL(initialParams.fDigishieldDifficultyCalculation, false);

    const Consensus::Params& initialParamsEnd = Params().GetConsensus(144999);
    BOOST_CHECK_EQUAL(initialParamsEnd.nPowTargetTimespan, 14400);
    BOOST_CHECK_EQUAL(initialParamsEnd.fAllowLegacyBlocks, true);
    BOOST_CHECK_EQUAL(initialParamsEnd.fDigishieldDifficultyCalculation, false);

    const Consensus::Params& digishieldParams = Params().GetConsensus(145000);
    BOOST_CHECK_EQUAL(digishieldParams.nPowTargetTimespan, 60);
    BOOST_CHECK_EQUAL(digishieldParams.fAllowLegacyBlocks, true);
    BOOST_CHECK_EQUAL(digishieldParams.fDigishieldDifficultyCalculation, true);

    const Consensus::Params& digishieldParamsEnd = Params().GetConsensus(371336);
    BOOST_CHECK_EQUAL(digishieldParamsEnd.nPowTargetTimespan, 60);
    BOOST_CHECK_EQUAL(digishieldParamsEnd.fAllowLegacyBlocks, true);
    BOOST_CHECK_EQUAL(digishieldParamsEnd.fDigishieldDifficultyCalculation, true);

    const Consensus::Params& auxpowParams = Params().GetConsensus(371337);
    BOOST_CHECK_EQUAL(auxpowParams.nHeightEffective, 371337);
    BOOST_CHECK_EQUAL(auxpowParams.nPowTargetTimespan, 60);
    BOOST_CHECK_EQUAL(auxpowParams.fAllowLegacyBlocks, false);
    BOOST_CHECK_EQUAL(auxpowParams.fDigishieldDifficultyCalculation, true);

    const Consensus::Params& auxpowHighParams = Params().GetConsensus(700000); // Arbitrary point after last hard-fork
    BOOST_CHECK_EQUAL(auxpowHighParams.nPowTargetTimespan, 60);
    BOOST_CHECK_EQUAL(auxpowHighParams.fAllowLegacyBlocks, false);
    BOOST_CHECK_EQUAL(auxpowHighParams.fDigishieldDifficultyCalculation, true);
}

// MWEB: real Pedersen commitment crypto, backed by the isolated secp256k1-zkp.
// Guards the balance / no-inflation primitive that peg and kernel checks rely on.
BOOST_AUTO_TEST_CASE(mweb_pedersen_commitment_balance)
{
    const mw::BlindingFactor blindA(std::vector<uint8_t>(32, 0x11));
    const mw::BlindingFactor blindB(std::vector<uint8_t>(32, 0x22));

    // Identical value and blind -> commitments cancel: 100 - 100 == 0.
    const mw::Commitment c100a = mw::Pedersen::Commit(100, blindA);
    const mw::Commitment c100a2 = mw::Pedersen::Commit(100, blindA);
    BOOST_CHECK(mw::Pedersen::VerifyBalance({c100a}, {c100a2}));

    // Inflation must be rejected: 100 - 101 != 0.
    const mw::Commitment c101 = mw::Pedersen::Commit(101, blindA);
    BOOST_CHECK(!mw::Pedersen::VerifyBalance({c100a}, {c101}));

    // Same value but different blinding factor must not spuriously balance.
    const mw::Commitment c100b = mw::Pedersen::Commit(100, blindB);
    BOOST_CHECK(!mw::Pedersen::VerifyBalance({c100a}, {c100b}));

    // Homomorphic sum yields a usable (non-null) commitment.
    const mw::Commitment sum = mw::Pedersen::AddCommitments({c100a}, {});
    BOOST_CHECK(!sum.IsNull());
    BOOST_CHECK(sum == c100a);
}

// MWEB: real Schnorr (aggsig) kernel-signature crypto, backed by secp256k1-zkp.
BOOST_AUTO_TEST_CASE(mweb_schnorr_sign_verify)
{
    const mw::SecretKey key(std::vector<uint8_t>(32, 0x2a));
    const mw::PublicKey pubkey = mw::Schnorr::BuildPublicKey(key);

    std::vector<uint8_t> msg(32, 0x07);
    const mw::Signature sig = mw::Schnorr::Sign(key, msg.data());

    // Valid signature verifies against the matching public key.
    BOOST_CHECK(mw::Schnorr::Verify(sig, pubkey, msg.data()));

    // Tampered message must fail.
    std::vector<uint8_t> badmsg = msg; badmsg[0] ^= 0xff;
    BOOST_CHECK(!mw::Schnorr::Verify(sig, pubkey, badmsg.data()));

    // Wrong public key must fail.
    const mw::SecretKey otherKey(std::vector<uint8_t>(32, 0x3b));
    const mw::PublicKey otherPub = mw::Schnorr::BuildPublicKey(otherKey);
    BOOST_CHECK(!mw::Schnorr::Verify(sig, otherPub, msg.data()));
}

// MWEB: real bulletproof range proofs, backed by secp256k1-zkp. Verifies
// against the matching Pedersen commitment (shared H/G generator convention).
BOOST_AUTO_TEST_CASE(mweb_bulletproof_rangeproof)
{
    const mw::BlindingFactor blind(std::vector<uint8_t>(32, 0x5c));
    const uint64_t value = 1234567;

    const mw::Commitment commit = mw::Pedersen::Commit(value, blind);
    const mw::RangeProof proof = mw::Bulletproof::Prove(value, blind);

    // Proof verifies against its own commitment.
    BOOST_CHECK(mw::Bulletproof::Verify(proof, commit));

    // Proof must NOT verify against a different commitment.
    const mw::Commitment otherCommit = mw::Pedersen::Commit(value + 1, blind);
    BOOST_CHECK(!mw::Bulletproof::Verify(proof, otherCommit));

    // A range proof for value 0 is valid and verifies.
    const mw::Commitment zeroCommit = mw::Pedersen::Commit(0, blind);
    const mw::RangeProof zeroProof = mw::Bulletproof::Prove(0, blind);
    BOOST_CHECK(mw::Bulletproof::Verify(zeroProof, zeroCommit));
}

BOOST_AUTO_TEST_SUITE_END()
