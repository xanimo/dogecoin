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
#include <mw/crypto/Keys.h>
#include <mw/models/tx/Transaction.h>
#include <mw/models/block/Block.h>
#include <mw/models/block/Header.h>
#include <mw/mmr/MMR.h>
#include <mw/mmr/Leafset.h>

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

// MWEB: EC key operations + ECDH, backed by secp256k1-zkp. Underpins stealth
// addresses. Checks the two properties MWEB relies on: key homomorphism and
// ECDH symmetry.
BOOST_AUTO_TEST_CASE(mweb_ec_keys_and_ecdh)
{
    const mw::SecretKey a(std::vector<uint8_t>(32, 0x41));
    const mw::SecretKey b(std::vector<uint8_t>(32, 0x62));

    const mw::PublicKey pubA = mw::Keys::PublicKeyFrom(a);
    const mw::PublicKey pubB = mw::Keys::PublicKeyFrom(b);
    BOOST_CHECK(!pubA.IsNull());
    BOOST_CHECK(pubA != pubB);

    // Homomorphism: pub(a + b) == pub(a) + pub(b).
    const mw::SecretKey sumSec = mw::Keys::AddSecretKeys(a, b);
    const mw::PublicKey sumFromSec = mw::Keys::PublicKeyFrom(sumSec);
    const mw::PublicKey sumOfPubs = mw::Keys::AddPublicKeys(pubA, pubB);
    BOOST_CHECK(sumFromSec == sumOfPubs);

    // ECDH symmetry: ECDH(a, pub(b)) == ECDH(b, pub(a)).
    const mw::SecretKey sharedAB = mw::Keys::ECDH(a, pubB);
    const mw::SecretKey sharedBA = mw::Keys::ECDH(b, pubA);
    BOOST_CHECK(sharedAB == sharedBA);
}

// Builds a fully valid, balanced MWEB transaction, with knobs so each test can
// break exactly one invariant. The transaction is: input of 100 (blind 0),
// one output committing `commitValue` under `outBlind`, a range proof for
// `proofValue`, and a fee-10 kernel whose excess is outBlind*G, signed by
// `signKey`. Kernel offset is 0, so the excess equals the output blind and the
// tx balances when commitValue == 90 (100 == 90 + 10 fee).
static mw::TxBody BuildMWEBBody(uint64_t commitValue, uint64_t proofValue, const mw::SecretKey& signKey)
{
    const mw::BlindingFactor outBlind(std::vector<uint8_t>(32, 0x44));

    mw::Input input(0, mw::Hash(),
        mw::Pedersen::Commit(100, mw::BlindingFactor()),
        mw::PublicKey(), mw::PublicKey(), mw::Signature());

    auto proof = std::make_shared<mw::RangeProof>(mw::Bulletproof::Prove(proofValue, outBlind));
    mw::Output output(mw::Pedersen::Commit(commitValue, outBlind),
        mw::PublicKey(), mw::PublicKey(), mw::OutputMessage(), proof, mw::Signature());

    const uint8_t feat = mw::Kernel::FEE_FEATURE_BIT;
    const mw::Commitment excessCommit = mw::Pedersen::Commit(0, outBlind); // outBlind*G
    const mw::Hash msg = mw::Kernel(feat, 10, 0, 0, excessCommit, mw::Signature()).GetSignatureMessage();
    mw::Kernel kernel(feat, 10, 0, 0, excessCommit, mw::Schnorr::Sign(signKey, msg.data()));

    std::vector<mw::Input> ins;  ins.push_back(input);
    std::vector<mw::Output> outs; outs.push_back(output);
    std::vector<mw::Kernel> kers; kers.push_back(kernel);
    return mw::TxBody(std::move(ins), std::move(outs), std::move(kers));
}

// Kernel offset is 0, matching the excess = output blind convention above.
static mw::Transaction BuildMWEBTx(uint64_t commitValue, uint64_t proofValue, const mw::SecretKey& signKey)
{
    return mw::Transaction(mw::BlindingFactor(), mw::BlindingFactor(),
        BuildMWEBBody(commitValue, proofValue, signKey));
}

// The excess key for a balanced tx is the output blind (outBlind above).
static mw::SecretKey CorrectExcessKey()
{
    return mw::SecretKey(std::vector<uint8_t>(32, 0x44));
}

// MWEB: a fully valid balanced transaction passes all consensus crypto checks.
BOOST_AUTO_TEST_CASE(mweb_transaction_valid)
{
    BOOST_CHECK_NO_THROW(BuildMWEBTx(90, 90, CorrectExcessKey()).Validate());
}

// MWEB: an output whose range proof is for a different value than its
// commitment is rejected (commitment still balances, so only the proof is bad).
BOOST_AUTO_TEST_CASE(mweb_transaction_bad_rangeproof)
{
    BOOST_CHECK_THROW(BuildMWEBTx(90, 91, CorrectExcessKey()).Validate(), std::runtime_error);
}

// MWEB: a kernel signed by the wrong key is rejected.
BOOST_AUTO_TEST_CASE(mweb_transaction_bad_kernel_signature)
{
    const mw::SecretKey wrongKey(std::vector<uint8_t>(32, 0x30));
    BOOST_CHECK_THROW(BuildMWEBTx(90, 90, wrongKey).Validate(), std::runtime_error);
}

// MWEB: the anti-inflation core. Committing to 91 (proof and commitment agree,
// signature valid) still violates 100 == outputs + fee, so it must be rejected.
BOOST_AUTO_TEST_CASE(mweb_transaction_balance)
{
    BOOST_CHECK_THROW(BuildMWEBTx(91, 91, CorrectExcessKey()).Validate(), std::runtime_error);
}

// MWEB: Block::Validate applies the same crypto checks as Transaction::Validate
// (they share ValidateBodyCrypto). A balanced block passes; an inflated one is
// rejected at block scope too.
BOOST_AUTO_TEST_CASE(mweb_block_validation)
{
    auto makeBlock = [](uint64_t commitValue, uint64_t proofValue, const mw::SecretKey& key) {
        auto header = std::make_shared<mw::Header>(
            1, mw::Hash(), mw::Hash(), mw::Hash(),
            mw::BlindingFactor(), mw::BlindingFactor(), 0, 0); // kernel offset 0
        return mw::Block(header, BuildMWEBBody(commitValue, proofValue, key));
    };

    BOOST_CHECK_NO_THROW(makeBlock(90, 90, CorrectExcessKey()).Validate());
    BOOST_CHECK_THROW(makeBlock(91, 91, CorrectExcessKey()).Validate(), std::runtime_error);
}

// MWEB: the Merkle Mountain Range accumulator. Known-answer checks on structure
// (node/peak counts) and roots (folded from the same parent hash), plus
// determinism and sensitivity.
BOOST_AUTO_TEST_CASE(mweb_mmr_root)
{
    auto leaf = [](uint8_t b) { return mw::Hash(std::vector<uint8_t>(32, b)); };
    auto parent = [](const mw::Hash& l, const mw::Hash& r) {
        CHashWriter ss(SER_GETHASH, 0); ss << l << r; return mw::Hash(ss.GetHash());
    };

    // Empty.
    mmr::MMR empty;
    BOOST_CHECK(empty.NumLeaves() == 0);
    BOOST_CHECK(empty.Root().IsNull());

    // 1 leaf -> the leaf is the root; 1 node, 1 peak.
    mmr::MMR m1; m1.Add(leaf(1));
    BOOST_CHECK(m1.NumNodes() == 1 && m1.NumPeaks() == 1);
    BOOST_CHECK(m1.Root() == leaf(1));

    // 2 leaves -> l0,l1,parent = 3 nodes, 1 peak.
    mmr::MMR m2; m2.Add(leaf(1)); m2.Add(leaf(2));
    BOOST_CHECK(m2.NumNodes() == 3 && m2.NumPeaks() == 1);
    BOOST_CHECK(m2.Root() == parent(leaf(1), leaf(2)));

    // 3 leaves -> parent(l0,l1) + l2 = 4 nodes, 2 peaks; root bags them.
    mmr::MMR m3; m3.Add(leaf(1)); m3.Add(leaf(2)); m3.Add(leaf(3));
    BOOST_CHECK(m3.NumNodes() == 4 && m3.NumPeaks() == 2);
    BOOST_CHECK(m3.Root() == parent(parent(leaf(1), leaf(2)), leaf(3)));

    // 4 leaves -> full tree: 7 nodes, 1 peak.
    mmr::MMR m4; for (uint8_t b = 1; b <= 4; b++) m4.Add(leaf(b));
    BOOST_CHECK(m4.NumNodes() == 7 && m4.NumPeaks() == 1);
    BOOST_CHECK(m4.Root() == parent(parent(leaf(1), leaf(2)), parent(leaf(3), leaf(4))));

    // Determinism and sensitivity.
    mmr::MMR a, b;
    for (uint8_t i = 1; i <= 5; i++) { a.Add(leaf(i)); b.Add(leaf(i)); }
    BOOST_CHECK(a.Root() == b.Root());
    mmr::MMR c; for (uint8_t i = 1; i <= 5; i++) c.Add(leaf(i == 3 ? 99 : i));
    BOOST_CHECK(c.Root() != a.Root());
}

// MWEB: MMR inclusion proofs. Every leaf proves against the root; a wrong leaf,
// a wrong root, or a tampered proof must all fail.
BOOST_AUTO_TEST_CASE(mweb_mmr_membership_proof)
{
    auto leaf = [](uint8_t b) { return mw::Hash(std::vector<uint8_t>(32, b)); };

    mmr::MMR m;
    std::vector<mw::Hash> leaves;
    for (uint8_t i = 1; i <= 5; i++) { leaves.push_back(leaf(i)); m.Add(leaf(i)); }
    const mw::Hash root = m.Root();

    for (uint64_t i = 0; i < 5; i++) {
        mmr::MMR::Proof proof = m.ProveLeaf(i);
        BOOST_CHECK(mmr::MMR::Verify(leaves[i], proof, root));          // genuine inclusion
        BOOST_CHECK(!mmr::MMR::Verify(leaf(200), proof, root));         // wrong leaf
        BOOST_CHECK(!mmr::MMR::Verify(leaves[i], proof, leaf(123)));    // wrong root
    }

    // A tampered sibling in the path breaks verification.
    mmr::MMR::Proof tampered = m.ProveLeaf(2);
    BOOST_REQUIRE(!tampered.path.empty());
    tampered.path[0] = leaf(250);
    BOOST_CHECK(!mmr::MMR::Verify(leaves[2], tampered, root));
}

// MWEB: the leafset bitmap (spent-output tracking -> leafsetRoot).
BOOST_AUTO_TEST_CASE(mweb_leafset)
{
    mmr::Leafset ls;
    for (uint64_t i : {0u, 1u, 2u, 3u, 4u, 20u}) ls.Add(i);
    BOOST_CHECK(ls.Size() == 6);
    BOOST_CHECK(ls.Contains(2) && ls.Contains(20));
    BOOST_CHECK(!ls.Contains(5));

    const mw::Hash fullRoot = ls.Root();

    // Spending clears the bit and changes the root.
    ls.Spend(2);
    BOOST_CHECK(!ls.Contains(2));
    BOOST_CHECK(ls.Size() == 5);
    BOOST_CHECK(ls.Root() != fullRoot);

    // Re-adding restores the exact prior set and root.
    ls.Add(2);
    BOOST_CHECK(ls.Root() == fullRoot);

    // Root depends only on the set of unspent leaves, not insertion order or
    // capacity: build the same set differently and via a larger initial index.
    mmr::Leafset other;
    other.Add(20); // forces a larger backing buffer first
    for (uint64_t i : {4u, 3u, 2u, 1u, 0u}) other.Add(i);
    BOOST_CHECK(other.Root() == fullRoot);

    // An empty leafset has a stable, distinct root.
    mmr::Leafset empty;
    BOOST_CHECK(empty.Size() == 0);
    BOOST_CHECK(empty.Root() != fullRoot);
    BOOST_CHECK(empty.Root() == mmr::Leafset().Root());
}

BOOST_AUTO_TEST_SUITE_END()
