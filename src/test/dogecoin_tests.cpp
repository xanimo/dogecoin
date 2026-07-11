// Copyright (c) 2015-2022 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "arith_uint256.h"
#include "chainparams.h"
#include "dogecoin.h"
#include "test/test_bitcoin.h"

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

// Adversarial timespan clamping (Thread-C). Block timestamps are attacker-
// influenced (bounded only by median-time-past and the 2h future limit), so
// CalculateDogecoinNextWorkRequired must bound how far one retarget can move the
// target regardless of how extreme the reported actual timespan is. These are
// positive controls: they feed timespans FAR outside the modulation window and
// assert the output equals the clamped-ratio target, and that two differently
// extreme manipulations produce the IDENTICAL clamped result (so the adjustment
// is bounded, not proportional to the manipulation).
BOOST_AUTO_TEST_CASE(get_next_work_digishield_clamp_low)
{
    SelectParams(CBaseChainParams::MAIN);
    const Consensus::Params& params = Params().GetConsensus(145000); // digishield: timespan 60
    BOOST_CHECK_EQUAL(params.nPowTargetTimespan, 60);

    CBlockIndex pindexLast;
    pindexLast.nHeight = 145107;
    pindexLast.nTime   = 1395101360;
    pindexLast.nBits   = 0x1b3439cd;

    // nMinTimespan for digishield = timespan - timespan/4 = 45. Any pre-clamp
    // modulated timespan < 45 (i.e. nActual < -60) must clamp to 45.
    arith_uint256 bnExpected;
    bnExpected.SetCompact(pindexLast.nBits);
    bnExpected *= 45;
    bnExpected /= 60;
    const unsigned int expected = bnExpected.GetCompact();

    // Two wildly different "too fast" manipulations -> same clamped result.
    const unsigned int r1 = CalculateDogecoinNextWorkRequired(&pindexLast, pindexLast.nTime + 1000000, params);
    const unsigned int r2 = CalculateDogecoinNextWorkRequired(&pindexLast, pindexLast.nTime + 1000000000, params);
    BOOST_CHECK_EQUAL(r1, expected);
    BOOST_CHECK_EQUAL(r1, r2);          // clamp is bounded, not proportional
    BOOST_CHECK(r1 != 0);               // never produces a zero/degenerate target
}

BOOST_AUTO_TEST_CASE(get_next_work_digishield_clamp_high)
{
    SelectParams(CBaseChainParams::MAIN);
    const Consensus::Params& params = Params().GetConsensus(145000);

    CBlockIndex pindexLast;
    pindexLast.nHeight = 145107;
    pindexLast.nTime   = 1395101360;
    pindexLast.nBits   = 0x1b3439cd;

    // nMaxTimespan for digishield = timespan + timespan/2 = 90. Any pre-clamp
    // modulated timespan > 90 (i.e. nActual > 300) must clamp to 90.
    arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
    arith_uint256 bnExpected;
    bnExpected.SetCompact(pindexLast.nBits);
    bnExpected *= 90;
    bnExpected /= 60;
    if (bnExpected > bnPowLimit) bnExpected = bnPowLimit;
    const unsigned int expected = bnExpected.GetCompact();

    const unsigned int r1 = CalculateDogecoinNextWorkRequired(&pindexLast, pindexLast.nTime - 1000000, params);
    const unsigned int r2 = CalculateDogecoinNextWorkRequired(&pindexLast, pindexLast.nTime - 1000000000, params);
    BOOST_CHECK_EQUAL(r1, expected);
    BOOST_CHECK_EQUAL(r1, r2);
    BOOST_CHECK(r1 != 0);
}

// Overflow safety at the minimum-difficulty boundary: with nBits already at
// powLimit, the *90/60 upscale would exceed powLimit; the result must clamp to
// exactly powLimit's compact (and the 256-bit multiply must not wrap).
BOOST_AUTO_TEST_CASE(get_next_work_clamp_to_powlimit)
{
    SelectParams(CBaseChainParams::MAIN);
    const Consensus::Params& params = Params().GetConsensus(145000);

    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
    CBlockIndex pindexLast;
    pindexLast.nHeight = 200000;
    pindexLast.nTime   = 1395101360;
    pindexLast.nBits   = bnPowLimit.GetCompact(); // already easiest allowed target

    // A "too slow" timespan wants to raise the target above powLimit -> clamp.
    const unsigned int r = CalculateDogecoinNextWorkRequired(&pindexLast, pindexLast.nTime - 1000000, params);
    BOOST_CHECK_EQUAL(r, bnPowLimit.GetCompact());

    // Result decodes back to <= powLimit (no wrap past the limit).
    arith_uint256 bnResult;
    bnResult.SetCompact(r);
    BOOST_CHECK(bnResult <= bnPowLimit);
}

// Pre-digishield clamp branch (nHeight > 10000): min = timespan/4, max =
// timespan*4. Same bounded-adjustment property with the 4h timespan.
BOOST_AUTO_TEST_CASE(get_next_work_pre_digishield_clamp)
{
    SelectParams(CBaseChainParams::MAIN);
    const Consensus::Params& params = Params().GetConsensus(0); // pre-digishield: timespan 14400
    BOOST_CHECK_EQUAL(params.nPowTargetTimespan, 14400);

    CBlockIndex pindexLast;
    pindexLast.nHeight = 20000;      // > 10000 -> min = timespan/4, max = timespan*4
    pindexLast.nTime   = 1386954113;
    pindexLast.nBits   = 0x1c1a1206;

    // too fast -> clamp to nMinTimespan = 14400/4 = 3600
    arith_uint256 bnLow; bnLow.SetCompact(pindexLast.nBits); bnLow *= 3600; bnLow /= 14400;
    const unsigned int rLow1 = CalculateDogecoinNextWorkRequired(&pindexLast, pindexLast.nTime + 1000000, params);
    const unsigned int rLow2 = CalculateDogecoinNextWorkRequired(&pindexLast, pindexLast.nTime + 5000000, params);
    BOOST_CHECK_EQUAL(rLow1, bnLow.GetCompact());
    BOOST_CHECK_EQUAL(rLow1, rLow2);

    // too slow -> clamp to nMaxTimespan = 14400*4 = 57600
    arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
    arith_uint256 bnHigh; bnHigh.SetCompact(pindexLast.nBits); bnHigh *= 57600; bnHigh /= 14400;
    if (bnHigh > bnPowLimit) bnHigh = bnPowLimit;
    const unsigned int rHigh1 = CalculateDogecoinNextWorkRequired(&pindexLast, pindexLast.nTime - 1000000, params);
    const unsigned int rHigh2 = CalculateDogecoinNextWorkRequired(&pindexLast, pindexLast.nTime - 5000000, params);
    BOOST_CHECK_EQUAL(rHigh1, bnHigh.GetCompact());
    BOOST_CHECK_EQUAL(rHigh1, rHigh2);
}

// Subsidy halving-edge exactness at the phase-switch boundaries (Thread-C).
// The existing subsidy_* tests sum ranges; this pins the exact per-height value
// on both sides of the halving/phase edges where an off-by-one would bite.
BOOST_AUTO_TEST_CASE(subsidy_halving_edges)
{
    const CChainParams& mainParams = Params(CBaseChainParams::MAIN);
    const uint256 h = uint256S("0");

    // Simplified-reward phase: value = (500000 >> (height/100000)) * COIN until
    // height >= 6*interval, then constant 10000 * COIN.
    struct { int height; CAmount expect; } cases[] = {
        {145000, (CAmount)(500000 >> 1) * COIN},   // halvings=1
        {199999, (CAmount)(500000 >> 1) * COIN},   // still halvings=1
        {200000, (CAmount)(500000 >> 2) * COIN},   // halvings=2 (edge)
        {599999, (CAmount)(500000 >> 5) * COIN},   // halvings=5 -> 15625
        {600000, (CAmount)10000 * COIN},           // 6*interval -> constant (edge)
        {600001, (CAmount)10000 * COIN},
    };
    for (const auto& c : cases) {
        CAmount s = GetDogecoinBlockSubsidy(c.height, mainParams.GetConsensus(c.height), h);
        BOOST_CHECK_MESSAGE(s == c.expect,
            "height " << c.height << ": got " << s << " expected " << c.expect);
        BOOST_CHECK(MoneyRange(s));
    }
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

BOOST_AUTO_TEST_SUITE_END()
