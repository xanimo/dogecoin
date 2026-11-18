// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bip352.h>
#include <chainparams.h>
#include <consensus/validation.h>
#include <index/tweakindex.h>
#include <key.h>
#include <script/interpreter.h>
#include <script/standard.h>
#include <test/test_bitcoin.h>
#include <utiltime.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

#include <map>
#include <vector>

BOOST_AUTO_TEST_SUITE(tweakindex_tests)

namespace {

void WaitForIndex(CTweakIndex& index)
{
    const int64_t deadline = GetTimeMillis() + 10 * 1000;
    while (!index.BlockUntilSyncedToCurrentChain()) {
        BOOST_REQUIRE(GetTimeMillis() < deadline);
        MilliSleep(100);
    }
}

} // namespace

// The index keys a block's entries by height, and a height is reused across a reorg. What ties
// an answer to a block is the hash stored beside the entries, which ReadBlock compares with the
// block it was asked about. Without that comparison a request naming a block that has since been
// replaced is answered with the replacement's entries under the old block's name, which is the
// answer a client cannot tell from a true one.
BOOST_FIXTURE_TEST_CASE(tweakindex_read_is_bound_to_the_block, TestChain240Setup)
{
    fs::remove_all(GetDataDir() / "indexes" / "tweakindex");
    CTweakIndex index(1 << 20, true, true);

    const CScript coinbase_script = CScript() << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG;

    // The fixture's coinbases pay to a bare key, which is not an eligible input. So one
    // transaction moves a coinbase to a P2PKH output and a second spends that, in the same
    // block. The second is the only one in the block a scanner could use.
    CKey key;
    key.MakeNewKey(true);
    const CScript p2pkh = GetScriptForDestination(CTxDestination(key.GetPubKey().GetID()));

    CMutableTransaction fund;
    fund.nVersion = 1;
    fund.vin.resize(1);
    fund.vin[0].prevout = COutPoint(coinbaseTxns[0].GetHash(), 0);
    fund.vout.resize(1);
    fund.vout[0].nValue = coinbaseTxns[0].vout[0].nValue - COIN;
    fund.vout[0].scriptPubKey = p2pkh;
    {
        std::vector<unsigned char> sig;
        const uint256 hash = SignatureHash(coinbase_script, fund, 0, SIGHASH_ALL, 0, SIGVERSION_BASE);
        BOOST_REQUIRE(coinbaseKey.Sign(hash, sig));
        sig.push_back((unsigned char)SIGHASH_ALL);
        fund.vin[0].scriptSig << sig;
    }

    CMutableTransaction spend;
    spend.nVersion = 1;
    spend.vin.resize(1);
    spend.vin[0].prevout = COutPoint(fund.GetHash(), 0);
    spend.vout.resize(1);
    spend.vout[0].nValue = fund.vout[0].nValue - COIN;
    spend.vout[0].scriptPubKey = coinbase_script;
    {
        std::vector<unsigned char> sig;
        const uint256 hash = SignatureHash(p2pkh, spend, 0, SIGHASH_ALL, 0, SIGVERSION_BASE);
        BOOST_REQUIRE(key.Sign(hash, sig));
        sig.push_back((unsigned char)SIGHASH_ALL);
        spend.vin[0].scriptSig << sig << ToByteVector(key.GetPubKey());
    }

    std::vector<CMutableTransaction> txns;
    txns.push_back(fund);
    txns.push_back(spend);
    const CBlock block_a = CreateAndProcessBlock(txns, coinbase_script);

    CBlockIndex* index_a;
    {
        LOCK(cs_main);
        index_a = chainActive.Tip();
    }
    BOOST_REQUIRE(index_a->GetBlockHash() == block_a.GetHash());
    BOOST_REQUIRE_EQUAL(block_a.vtx.size(), 3U);

    index.Start();
    WaitForIndex(index);

    // What the index holds for the block: one entry, for the transaction with the P2PKH input,
    // and the tweak a scanner would compute from that input itself.
    std::vector<CTweakEntry> entries;
    BOOST_REQUIRE(index.ReadBlock(index_a, entries));
    BOOST_REQUIRE_EQUAL(entries.size(), 1U);
    BOOST_CHECK_EQUAL(entries[0].tx_index, 2U);
    {
        std::map<COutPoint, CScript> spks;
        spks[spend.vin[0].prevout] = p2pkh;
        bip352::CPrevoutsSummary summary;
        BOOST_REQUIRE(bip352::GetPrevoutsSummary(summary, spend.vin, spks) == bip352::PREVOUTS_OK);
        CPubKey expected;
        BOOST_REQUIRE(bip352::ComputeScanTweak(expected, summary));
        BOOST_CHECK(entries[0].tweak == expected);
    }

    // A block index entry at the same height that is not the block the entry was computed from.
    // Nothing is stored for it, so nothing is returned for it, alone or at the end of a range.
    {
        CBlockIndex other(*index_a);
        const uint256 other_hash = uint256S("0c0ffee000000000000000000000000000000000000000000000000000000000");
        other.phashBlock = &other_hash;
        std::vector<CTweakEntry> none;
        BOOST_CHECK(!index.ReadBlock(&other, none));
        BOOST_CHECK(none.empty());
        std::vector<std::vector<CTweakEntry> > range;
        BOOST_CHECK(!index.LookupTweakRange(other.nHeight, &other, range));
        BOOST_CHECK(range.empty());
    }

    // The same thing as it happens: the block is replaced by one with no eligible input, and a
    // request still names the block that was there.
    {
        CValidationState state;
        {
            LOCK(cs_main);
            BOOST_REQUIRE(InvalidateBlock(state, Params(), index_a));
        }
        BOOST_REQUIRE(ActivateBestChain(state, Params()));
    }
    // The two transactions are back in the pool, and the fixture's block keeps the template's
    // coinbase while dropping the template's transactions, so their fees would overpay it.
    mempool.clear();
    const CBlock block_b = CreateAndProcessBlock(std::vector<CMutableTransaction>(), coinbase_script);
    CBlockIndex* index_b;
    {
        LOCK(cs_main);
        index_b = chainActive.Tip();
    }
    BOOST_REQUIRE(index_b->GetBlockHash() == block_b.GetHash());
    BOOST_REQUIRE_EQUAL(index_b->nHeight, index_a->nHeight);
    BOOST_REQUIRE(index_b->GetBlockHash() != index_a->GetBlockHash());
    WaitForIndex(index);

    entries.clear();
    BOOST_REQUIRE(index.ReadBlock(index_b, entries));
    BOOST_CHECK(entries.empty());

    std::vector<CTweakEntry> stale;
    BOOST_CHECK(!index.ReadBlock(index_a, stale));
    BOOST_CHECK(stale.empty());
    std::vector<std::vector<CTweakEntry> > range;
    BOOST_CHECK(!index.LookupTweakRange(index_a->nHeight, index_a, range));
    BOOST_CHECK(index.LookupTweakRange(index_b->nHeight, index_b, range));
    BOOST_REQUIRE_EQUAL(range.size(), 1U);
    BOOST_CHECK(range[0].empty());

    index.Interrupt();
    index.Stop();
}

BOOST_AUTO_TEST_SUITE_END()
