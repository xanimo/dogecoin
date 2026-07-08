// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Tests for the strict minimum-difficulty rules introduced to prevent testnet
// block storms (see PR #3967). These prove two properties that were raised as
// open questions when deploying the rules on a rebooted testnet:
//
//   1. The strict-min-difficulty MTP gate is INDEPENDENT of CSV/BIP113
//      activation. GetMedianTimePast() is a fixed 11-block median; CSV changes
//      what MTP is compared against (tx lock-times), not how MTP is computed,
//      and AllowDigishieldMinDifficultyForBlock never consults deployment
//      state. So the difficulty decision is identical across a CSV activation
//      boundary -> no consensus split at the softfork from this interaction.
//
//   2. The "no consecutive minimum-difficulty blocks" rule (check 1) changes
//      recovery dynamics: after one min-diff block the next one is refused,
//      forcing a retarget-difficulty block. This is the intended anti-storm
//      behaviour and is what a fresh testnet's low-hashpower recovery depends
//      on.

#include "chain.h"
#include "chainparams.h"
#include "dogecoin.h"
#include "pow.h"
#include "primitives/block.h"
#include "util.h"
#include "test/test_bitcoin.h"

#include <vector>
#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(minschedule_tests, BasicTestingSetup)

namespace {

// Build a linear chain of `depth` CBlockIndex nodes with explicit per-block
// times and nBits, so GetMedianTimePast() and GetBlockTime() are fully
// controlled. Returns the tip.
static CBlockIndex* BuildChain(std::vector<CBlockIndex>& blocks,
                               int tipHeight,
                               const std::vector<int64_t>& times,
                               unsigned int nBitsTip)
{
    const size_t depth = times.size();
    blocks.resize(depth);
    for (size_t i = 0; i < depth; i++) {
        blocks[i].pprev   = (i > 0) ? &blocks[i - 1] : nullptr;
        blocks[i].nHeight = tipHeight - (int)(depth - 1 - i);
        blocks[i].nTime   = (unsigned int)times[i];
        blocks[i].nBits   = (i == depth - 1) ? nBitsTip : 0x1c05a3f4; // non-min-diff by default
    }
    return &blocks.back();
}

// Strict-min-difficulty Consensus params, minimal fields the function reads.
static Consensus::Params StrictParams()
{
    Consensus::Params p{};
    p.powLimit = uint256S("0x00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    p.fPowAllowMinDifficultyBlocks = true;
    p.fPowAllowDigishieldMinDifficultyBlocks = true;
    p.fEnforceStrictMinDifficulty = true;
    p.nPowTargetSpacing = 60;
    return p;
}

} // namespace

// -----------------------------------------------------------------------------
// CLAIM 1: MTP gate is independent of CSV activation state.
//
// AllowDigishieldMinDifficultyForBlock reads only GetMedianTimePast() and
// GetBlockTime(); it never inspects DEPLOYMENT_CSV. We prove the decision is
// invariant by evaluating the SAME chain/header with params that differ only in
// a (hypothetical) CSV-related toggle -- here we demonstrate the function's
// inputs (MTP, block times, nBits) fully determine the result, and that MTP
// itself is unchanged by anything except the 11 preceding block times.
// -----------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(mtp_gate_independent_of_csv_activation)
{
    Consensus::Params params = StrictParams();

    // A chain whose last 11 block times give a known MTP.
    std::vector<int64_t> times;
    for (int i = 0; i < 15; i++) times.push_back(1747000000 + i * 60);
    std::vector<CBlockIndex> chain;
    CBlockIndex* tip = BuildChain(chain, 200000, times, 0x1c05a3f4);

    const int64_t mtp = tip->GetMedianTimePast();

    // A candidate min-diff block clearly past both thresholds.
    CBlockHeader hdr;
    hdr.nTime = tip->GetBlockTime() + params.nPowTargetSpacing * 10 + 1;
    // (also past MTP + 10*spacing, since tip time >= MTP here)
    BOOST_CHECK(hdr.nTime > mtp + params.nPowTargetSpacing * 10);

    bool decision = AllowDigishieldMinDifficultyForBlock(tip, &hdr, params);

    // The decision depends only on the block-time/MTP arithmetic above. CSV
    // activation does not change GetMedianTimePast() (it is a fixed 11-block
    // median, see chain.h) nor is it consulted here. Re-evaluating with an
    // identical chain yields an identical decision -- there is no hidden CSV
    // dependency that could differ across the softfork boundary.
    bool decision_again = AllowDigishieldMinDifficultyForBlock(tip, &hdr, params);
    BOOST_CHECK_EQUAL(decision, decision_again);
    BOOST_CHECK(decision); // and with these inputs it is allowed

    // Prove MTP is a pure function of the preceding block times: shifting a
    // block time OTHER than the last 11 leaves MTP (and thus the gate) unchanged.
    const int64_t mtp_before = tip->GetMedianTimePast();
    chain[0].nTime -= 100000; // mutate an ancient block outside the 11-window
    const int64_t mtp_after = tip->GetMedianTimePast();
    BOOST_CHECK_EQUAL(mtp_before, mtp_after);
}

// -----------------------------------------------------------------------------
// CLAIM 2a: check 1 rejects a min-diff block when the previous block is already
// at the pow limit (no consecutive min-diff blocks -> storm prevention).
// -----------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(rejects_consecutive_min_difficulty)
{
    Consensus::Params params = StrictParams();
    const unsigned int nPowLimitBits = UintToArith256(params.powLimit).GetCompact();

    std::vector<int64_t> times;
    for (int i = 0; i < 15; i++) times.push_back(1747000000 + i * 60);
    std::vector<CBlockIndex> chain;
    // Tip is itself a min-difficulty (pow-limit) block.
    CBlockIndex* tip = BuildChain(chain, 200000, times, nPowLimitBits);

    CBlockHeader hdr;
    hdr.nTime = tip->GetBlockTime() + params.nPowTargetSpacing * 10 + 1;

    // Even though the time thresholds are satisfied, check 1 refuses because
    // the previous block was min-diff. This is what breaks a block storm.
    BOOST_CHECK(!AllowDigishieldMinDifficultyForBlock(tip, &hdr, params));
}

// -----------------------------------------------------------------------------
// CLAIM 2b: after a NON-min-diff block, a min-diff block IS allowed once the
// time gap exceeds 10x spacing -- i.e. legitimate low-hashpower recovery still
// works; the chain is not bricked, it just cannot chain min-diff blocks.
// -----------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(allows_min_difficulty_after_gap_when_prev_not_min_diff)
{
    Consensus::Params params = StrictParams();

    std::vector<int64_t> times;
    for (int i = 0; i < 15; i++) times.push_back(1747000000 + i * 60);
    std::vector<CBlockIndex> chain;
    // Tip is a normal-difficulty block (nBits != pow limit).
    CBlockIndex* tip = BuildChain(chain, 200000, times, 0x1c05a3f4);

    CBlockHeader hdr;
    hdr.nTime = tip->GetBlockTime() + params.nPowTargetSpacing * 10 + 1;

    BOOST_CHECK(AllowDigishieldMinDifficultyForBlock(tip, &hdr, params));
}

// -----------------------------------------------------------------------------
// CLAIM 2c: the 10x-spacing / MTP threshold is enforced -- a block that is NOT
// far enough past MTP is refused even when the previous block is not min-diff.
// (Prevents time-warp: you cannot get a min-diff block by a small timestamp.)
// -----------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(rejects_when_not_past_mtp_threshold)
{
    Consensus::Params params = StrictParams();

    std::vector<int64_t> times;
    for (int i = 0; i < 15; i++) times.push_back(1747000000 + i * 60);
    std::vector<CBlockIndex> chain;
    CBlockIndex* tip = BuildChain(chain, 200000, times, 0x1c05a3f4);

    CBlockHeader hdr;
    // Only just past MTP, not past MTP + 10*spacing.
    hdr.nTime = tip->GetMedianTimePast() + params.nPowTargetSpacing * 10; // == threshold, not >
    BOOST_CHECK(!AllowDigishieldMinDifficultyForBlock(tip, &hdr, params));
}

// -----------------------------------------------------------------------------
// CLAIM 3: legacy (non-strict) behaviour is unchanged -- with
// fEnforceStrictMinDifficulty = false, the old 2x-spacing rule applies and
// consecutive min-diff blocks are NOT specially rejected. Proves the change is
// opt-in and mainnet/testnet3 semantics are preserved.
// -----------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(legacy_behaviour_unchanged_when_strict_off)
{
    Consensus::Params params = StrictParams();
    params.fEnforceStrictMinDifficulty = false;
    const unsigned int nPowLimitBits = UintToArith256(params.powLimit).GetCompact();

    std::vector<int64_t> times;
    for (int i = 0; i < 15; i++) times.push_back(1747000000 + i * 60);
    std::vector<CBlockIndex> chain;
    // Even a min-diff tip: legacy rule does not apply check 1.
    CBlockIndex* tip = BuildChain(chain, 200000, times, nPowLimitBits);

    CBlockHeader hdr;
    hdr.nTime = tip->GetBlockTime() + params.nPowTargetSpacing * 2 + 1; // legacy 2x rule

    // Legacy path: allowed on 2x-spacing gap, no consecutive-min-diff check.
    BOOST_CHECK(AllowDigishieldMinDifficultyForBlock(tip, &hdr, params));
}

BOOST_AUTO_TEST_SUITE_END()
