// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Tests for the strict minimum-difficulty rules added by
// AllowDigishieldMinDifficultyForBlock (see src/dogecoin.cpp).
//
// These rules gate whether a Digishield min-difficulty block is permitted on
// top of a given tip. The decision is a pure function of:
//   - the consensus flags (fPowAllowMinDifficultyBlocks,
//     fPowAllowDigishieldMinDifficultyBlocks, fEnforceStrictMinDifficulty),
//   - the tip's nBits and the chain's powLimit,
//   - the candidate block time, the tip's block time, and the tip's
//     median-time-past (MTP).
//
// Notably it consults NO deployment/versionbits state (CSV/BIP113 etc.). The
// suite below constructs explicit CBlockIndex stub chains with hand-picked
// per-block times so that MTP and block times are fully controlled, and proves
// the CSV-independence property directly: the decision is invariant to blocks
// outside the fixed 11-block MTP window, and is computed without ever building
// a chainstate or versionbits cache.

#include "arith_uint256.h"
#include "chain.h"
#include "consensus/params.h"
#include "dogecoin.h"
#include "primitives/block.h"
#include "uint256.h"
#include "test/test_bitcoin.h"

#include <vector>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(minschedule_tests, BasicTestingSetup)

namespace {

// A powLimit that is easy to reason about; its exact value is irrelevant, we
// only compare a block's nBits against its compact form.
const uint256 POW_LIMIT = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
const int64_t SPACING = 60;             // nPowTargetSpacing
const int64_t STRICT_GAP = SPACING * 10; // 600: strict elapsed threshold
const int64_t LEGACY_GAP = SPACING * 2;  // 120: legacy elapsed threshold

// Base consensus params exercising the min-difficulty path. Only the fields
// read by AllowDigishieldMinDifficultyForBlock are meaningful here.
Consensus::Params MakeParams(bool strict)
{
    Consensus::Params p;
    p.powLimit = POW_LIMIT;
    p.nPowTargetSpacing = SPACING;
    p.fPowAllowMinDifficultyBlocks = true;
    p.fPowAllowDigishieldMinDifficultyBlocks = true;
    p.fEnforceStrictMinDifficulty = strict;
    return p;
}

// Compact nBits meaning "at the pow limit" (i.e. a min-difficulty block).
unsigned int PowLimitBits()
{
    return UintToArith256(POW_LIMIT).GetCompact();
}

// Compact nBits for a strictly harder target (not at the pow limit).
unsigned int HarderBits()
{
    arith_uint256 target = UintToArith256(POW_LIMIT);
    target >>= 8;
    return target.GetCompact();
}

// Owns a chain of CBlockIndex stubs linked via pprev. The vector is sized up
// front and never resized, so element addresses stay stable.
struct StubChain
{
    std::vector<CBlockIndex> blocks;

    // times[i] is the timestamp of block i (i==0 is the oldest). Every block is
    // given nBits, except the tip which is given tipBits.
    StubChain(const std::vector<int64_t>& times, unsigned int nBits, unsigned int tipBits)
        : blocks(times.size())
    {
        for (size_t i = 0; i < times.size(); ++i) {
            blocks[i].nHeight = static_cast<int>(i);
            blocks[i].nTime = static_cast<uint32_t>(times[i]);
            blocks[i].nBits = (i + 1 == times.size()) ? tipBits : nBits;
            blocks[i].pprev = (i == 0) ? nullptr : &blocks[i - 1];
        }
    }

    CBlockIndex* Tip() { return &blocks.back(); }
};

CBlockHeader HeaderAt(int64_t nTime)
{
    CBlockHeader h;
    h.nTime = static_cast<uint32_t>(nTime);
    return h;
}

} // namespace

// Sanity guard for the test helpers themselves: the "harder than min-difficulty"
// nBits used to mark a non-min-diff tip must be genuinely distinct from the
// pow-limit compact used to mark a min-diff tip. If these ever collapsed, the
// strict cases below (which hinge on that distinction for check 1) would pass
// vacuously.
BOOST_AUTO_TEST_CASE(helper_bits_are_distinct)
{
    BOOST_CHECK(HarderBits() != PowLimitBits());
}

// CSV-independence: the decision is deterministic from (nBits, block times,
// MTP) and invariant to blocks that fall outside the fixed 11-block MTP window.
// Two chains that agree on their most recent 11 blocks but differ arbitrarily
// further back must yield identical results. Since MTP is a fixed 11-block
// median and the function reads no deployment state, this is the operational
// proof that CSV/BIP113 activation cannot change the min-difficulty verdict.
BOOST_AUTO_TEST_CASE(csv_independent_and_deterministic)
{
    const Consensus::Params params = MakeParams(/*strict=*/true);

    // Recent window (the last 11 blocks) shared by both chains. Monotonic, with
    // the tip harder than the pow limit so check 1 does not short-circuit.
    std::vector<int64_t> recent;
    for (int i = 0; i < 11; ++i)
        recent.push_back(100000 + i * SPACING);

    // Chain A: 4 extra ancient blocks with ordinary times.
    std::vector<int64_t> timesA;
    for (int i = 0; i < 4; ++i) timesA.push_back(1000 + i);
    timesA.insert(timesA.end(), recent.begin(), recent.end());

    // Chain B: same recent window, but the ancient blocks have wildly different
    // (even out-of-order, far-future) times. These sit outside the 11-block MTP
    // window and must not affect anything.
    std::vector<int64_t> timesB;
    const int64_t junk[4] = {9000000, 5, 8000000, 42};
    for (int i = 0; i < 4; ++i) timesB.push_back(junk[i]);
    timesB.insert(timesB.end(), recent.begin(), recent.end());

    StubChain chainA(timesA, HarderBits(), HarderBits());
    StubChain chainB(timesB, HarderBits(), HarderBits());

    // MTP must be identical despite the different ancient blocks.
    BOOST_CHECK_EQUAL(chainA.Tip()->GetMedianTimePast(),
                      chainB.Tip()->GetMedianTimePast());

    // Sweep candidate block times across the decision boundary; every verdict
    // must match between the two chains, and repeat calls must be stable.
    for (int64_t dt = -2 * STRICT_GAP; dt <= 3 * STRICT_GAP; dt += SPACING) {
        const CBlockHeader block = HeaderAt(chainA.Tip()->GetBlockTime() + dt);
        const bool a = AllowDigishieldMinDifficultyForBlock(chainA.Tip(), &block, params);
        const bool b = AllowDigishieldMinDifficultyForBlock(chainB.Tip(), &block, params);
        BOOST_CHECK_EQUAL(a, b);
        // Determinism: a second identical call yields the same answer.
        BOOST_CHECK_EQUAL(a, AllowDigishieldMinDifficultyForBlock(chainA.Tip(), &block, params));
    }
}

// Check 1: no consecutive min-difficulty blocks. If the tip is already at the
// pow limit, a min-difficulty block is refused regardless of how large the time
// gap is (which would otherwise satisfy checks 2 and 3).
BOOST_AUTO_TEST_CASE(strict_rejects_consecutive_mindiff)
{
    const Consensus::Params params = MakeParams(/*strict=*/true);

    std::vector<int64_t> times;
    for (int i = 0; i < 11; ++i) times.push_back(200000 + i * SPACING);

    // Tip is AT the pow limit (a min-difficulty block).
    StubChain chain(times, HarderBits(), PowLimitBits());

    // A candidate far in the future would pass the time-based checks, yet it
    // must still be rejected because the previous block is min-difficulty.
    const CBlockHeader block = HeaderAt(chain.Tip()->GetBlockTime() + 100 * STRICT_GAP);
    BOOST_CHECK(!AllowDigishieldMinDifficultyForBlock(chain.Tip(), &block, params));
}

// Recovery: a min-difficulty block IS allowed after a sufficient gap when the
// previous block is not itself min-difficulty. The chain is never bricked; a
// low-hashpower chain can still emit a min-difficulty block, it just cannot
// chain them.
BOOST_AUTO_TEST_CASE(strict_allows_mindiff_after_gap)
{
    const Consensus::Params params = MakeParams(/*strict=*/true);

    std::vector<int64_t> times;
    for (int i = 0; i < 11; ++i) times.push_back(300000 + i * SPACING);

    // Tip is NOT at the pow limit (harder than min difficulty).
    StubChain chain(times, HarderBits(), HarderBits());
    const CBlockIndex* tip = chain.Tip();

    // Comfortably beyond both MTP + 10x and tip.time + 10x.
    const int64_t past = std::max(tip->GetMedianTimePast(), tip->GetBlockTime());
    const CBlockHeader ok = HeaderAt(past + STRICT_GAP + 1);
    BOOST_CHECK(AllowDigishieldMinDifficultyForBlock(tip, &ok, params));

    // Just under the tip.time + 10x threshold (check 3) -> refused.
    const CBlockHeader tooSoon = HeaderAt(tip->GetBlockTime() + STRICT_GAP);
    BOOST_CHECK(!AllowDigishieldMinDifficultyForBlock(tip, &tooSoon, params));
}

// Check 2: the MTP + 10x threshold prevents time-warp manipulation. We build a
// non-monotonic tail where the tip's timestamp is dragged BELOW the median, so
// the tip.time + 10x check (check 3) can be satisfied while the MTP + 10x check
// (check 2) is not. The block must be rejected on the MTP check alone.
BOOST_AUTO_TEST_CASE(strict_enforces_mtp_threshold)
{
    const Consensus::Params params = MakeParams(/*strict=*/true);

    // Ten blocks pinned high, then a tip pinned low (a warped timestamp).
    std::vector<int64_t> times(10, 10000);
    times.push_back(5000); // tip.time deliberately below the median

    StubChain chain(times, HarderBits(), HarderBits());
    const CBlockIndex* tip = chain.Tip();

    const int64_t mtp = tip->GetMedianTimePast();
    BOOST_CHECK_EQUAL(mtp, 10000);            // median dominated by the high blocks
    BOOST_CHECK_EQUAL(tip->GetBlockTime(), 5000);
    BOOST_CHECK(mtp > tip->GetBlockTime());   // the warp: MTP above the tip time

    // Candidate passes check 3 (> 5000 + 600 = 5600) but fails check 2
    // (<= 10000 + 600 = 10600): rejected.
    const CBlockHeader warped = HeaderAt(6000);
    BOOST_CHECK(6000 > tip->GetBlockTime() + STRICT_GAP);   // would satisfy check 3
    BOOST_CHECK(6000 <= mtp + STRICT_GAP);                  // but violates check 2
    BOOST_CHECK(!AllowDigishieldMinDifficultyForBlock(tip, &warped, params));

    // Once the candidate clears MTP + 10x it is accepted (tip not at pow limit).
    const CBlockHeader ok = HeaderAt(mtp + STRICT_GAP + 1);
    BOOST_CHECK(AllowDigishieldMinDifficultyForBlock(tip, &ok, params));
}

// Opt-in / mainnet-safe: with fEnforceStrictMinDifficulty off, behavior is the
// legacy 2x-spacing rule. The consecutive-block and MTP checks do NOT apply, so
// a min-difficulty block on top of a min-difficulty tip is accepted, and the
// threshold is 2x (not 10x) spacing. Flipping the flag must be the only thing
// that changes the verdict.
BOOST_AUTO_TEST_CASE(legacy_behavior_unchanged_when_flag_off)
{
    const Consensus::Params legacy = MakeParams(/*strict=*/false);
    const Consensus::Params strict = MakeParams(/*strict=*/true);

    std::vector<int64_t> times;
    for (int i = 0; i < 11; ++i) times.push_back(400000 + i * SPACING);

    // Tip AT the pow limit: strict mode would reject via check 1.
    StubChain chain(times, HarderBits(), PowLimitBits());
    const CBlockIndex* tip = chain.Tip();

    // Gap between 2x and 10x spacing: legacy accepts, strict rejects.
    const CBlockHeader midGap = HeaderAt(tip->GetBlockTime() + LEGACY_GAP + 1);
    BOOST_CHECK(AllowDigishieldMinDifficultyForBlock(tip, &midGap, legacy));
    BOOST_CHECK(!AllowDigishieldMinDifficultyForBlock(tip, &midGap, strict));

    // Legacy 2x threshold is exact: at or below 2x spacing is refused.
    const CBlockHeader atThreshold = HeaderAt(tip->GetBlockTime() + LEGACY_GAP);
    BOOST_CHECK(!AllowDigishieldMinDifficultyForBlock(tip, &atThreshold, legacy));
    const CBlockHeader justOver = HeaderAt(tip->GetBlockTime() + LEGACY_GAP + 1);
    BOOST_CHECK(AllowDigishieldMinDifficultyForBlock(tip, &justOver, legacy));

    // Legacy accepts a min-diff block after a min-diff tip (no check 1),
    // demonstrating the strict rule is genuinely opt-in.
    BOOST_CHECK(AllowDigishieldMinDifficultyForBlock(tip, &justOver, legacy));

    // And with the master flags off entirely, both modes refuse outright.
    Consensus::Params disabled = MakeParams(/*strict=*/true);
    disabled.fPowAllowMinDifficultyBlocks = false;
    const CBlockHeader anything = HeaderAt(tip->GetBlockTime() + 100 * STRICT_GAP);
    BOOST_CHECK(!AllowDigishieldMinDifficultyForBlock(tip, &anything, disabled));
}

BOOST_AUTO_TEST_SUITE_END()
