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
#include <mw/node/MWEBState.h>
#include <mw/node/BlockBuilder.h>
#include <mw/wallet/TxBuilder.h>
#include <mw/wallet/Stealth.h>

#include "mweb/mweb_node.h"
#include "mweb/mweb_wallet.h"
#include "mweb/mweb_db.h"
#include "script/standard.h"
#include "consensus/validation.h"
#include "primitives/block.h"

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

// MWEB: the accumulated chain state (output MMR + kernel MMR + leafset). Covers
// accumulation, proof against the running output root, and the defining spend
// property: the output MMR is permanent, only the leafset changes.
BOOST_AUTO_TEST_CASE(mweb_state_accumulator)
{
    auto oh = [](uint8_t b) { return mw::Hash(std::vector<uint8_t>(32, b)); };
    auto kh = [](uint8_t b) { return mw::Hash(std::vector<uint8_t>(32, 0x80 | b)); };

    mw::MWEBState state;
    std::vector<uint64_t> leaves;
    for (uint8_t i = 1; i <= 5; i++) leaves.push_back(state.AddOutput(oh(i)).Get());
    state.AddKernel(kh(1));
    state.AddKernel(kh(2));

    BOOST_CHECK(state.NumOutputs() == 5);
    BOOST_CHECK(state.NumKernels() == 2);
    BOOST_CHECK(state.NumUnspent() == 5);
    BOOST_CHECK(!state.OutputRoot().IsNull());
    BOOST_CHECK(!state.KernelRoot().IsNull());
    BOOST_CHECK(state.OutputRoot() != state.KernelRoot());

    // An early output proves against the accumulated output MMR root.
    BOOST_CHECK(mmr::MMR::Verify(oh(2), state.ProveOutput(leaves[1]), state.OutputRoot()));

    // Spend: output root is unchanged (append-only MMR), leafset root changes,
    // and the spent output is still provably in the MMR.
    const mw::Hash beforeOutRoot = state.OutputRoot();
    const mw::Hash beforeLeafRoot = state.LeafsetRoot();
    state.SpendOutput(leaves[2]);
    BOOST_CHECK(!state.IsUnspent(leaves[2]));
    BOOST_CHECK(state.NumUnspent() == 4);
    BOOST_CHECK(state.OutputRoot() == beforeOutRoot);
    BOOST_CHECK(state.LeafsetRoot() != beforeLeafRoot);
    BOOST_CHECK(mmr::MMR::Verify(oh(3), state.ProveOutput(leaves[2]), state.OutputRoot()));
}

// MWEB: driving the state from a real block and matching its header roots -- the
// stateful connect-path logic that verifies a block's outputRoot/kernelRoot/
// leafsetRoot.
BOOST_AUTO_TEST_CASE(mweb_state_apply_block)
{
    auto mkOutput = [](uint8_t v) {
        const mw::BlindingFactor b(std::vector<uint8_t>(32, v));
        auto proof = std::make_shared<mw::RangeProof>(mw::Bulletproof::Prove(v, b));
        return mw::Output(mw::Pedersen::Commit(v, b), mw::PublicKey(), mw::PublicKey(),
                          mw::OutputMessage(), proof, mw::Signature());
    };
    const mw::Output o1 = mkOutput(10);
    const mw::Output o2 = mkOutput(20);

    auto makeBody = [&]() {
        std::vector<mw::Input> ins;
        std::vector<mw::Output> outs; outs.push_back(o1); outs.push_back(o2);
        std::vector<mw::Kernel> kers; kers.emplace_back();
        return mw::TxBody(std::move(ins), std::move(outs), std::move(kers));
    };
    auto dummyHeader = []() {
        return std::make_shared<mw::Header>(1, mw::Hash(), mw::Hash(), mw::Hash(),
            mw::BlindingFactor(), mw::BlindingFactor(), 0, 0);
    };

    // Compute the correct roots by applying the body to a scratch state.
    mw::MWEBState scratch;
    BOOST_CHECK(scratch.ApplyBlock(mw::Block(dummyHeader(), makeBody())));

    // Build the real header committing to those roots, and the block.
    auto header = std::make_shared<mw::Header>(1,
        scratch.OutputRoot(), scratch.KernelRoot(), scratch.LeafsetRoot(),
        mw::BlindingFactor(), mw::BlindingFactor(),
        scratch.NumOutputs(), scratch.NumKernels());
    const mw::Block block(header, makeBody());

    // A fresh state that applies the block matches the header it commits to.
    mw::MWEBState state;
    BOOST_CHECK(state.ApplyBlock(block));
    BOOST_CHECK(state.MatchesHeader(*block.GetHeader()));

    // A header with a wrong output root must not match.
    const mw::Header badHeader(1, mw::Hash(std::vector<uint8_t>(32, 0xEE)),
        scratch.KernelRoot(), scratch.LeafsetRoot(),
        mw::BlindingFactor(), mw::BlindingFactor(),
        scratch.NumOutputs(), scratch.NumKernels());
    BOOST_CHECK(!state.MatchesHeader(badHeader));

    // Spending an output by its ID clears it; an unknown ID is rejected.
    const mw::Hash leafBefore = state.LeafsetRoot();
    BOOST_CHECK(state.SpendByOutputID(o1.GetOutputID()));
    BOOST_CHECK(state.LeafsetRoot() != leafBefore);
    BOOST_CHECK(!state.SpendByOutputID(mw::Hash(std::vector<uint8_t>(32, 0x99))));
}

// MWEB: rewinding the accumulators. An MMR/leafset rewound to N leaves must be
// byte-for-byte the state an independent instance reaches by adding exactly N
// leaves -- this is what makes a block disconnect exact. Covers every shape
// across the binary-counter boundaries (1..8 peaks reshaping).
BOOST_AUTO_TEST_CASE(mweb_mmr_leafset_rewind)
{
    auto leaf = [](uint8_t b) { return mw::Hash(std::vector<uint8_t>(32, b)); };

    // For each target count, a full MMR rewound to it matches one built to it.
    for (uint8_t target = 0; target <= 8; target++) {
        mmr::MMR full;
        for (uint8_t i = 1; i <= 8; i++) full.Add(leaf(i));
        full.Rewind(target);

        mmr::MMR ref;
        for (uint8_t i = 1; i <= target; i++) ref.Add(leaf(i));

        BOOST_CHECK(full.NumLeaves() == ref.NumLeaves());
        BOOST_CHECK(full.NumNodes() == ref.NumNodes());
        BOOST_CHECK(full.NumPeaks() == ref.NumPeaks());
        BOOST_CHECK(full.Root() == ref.Root());
    }

    // A rewound MMR keeps growing correctly (peaks were rebuilt, not just sliced).
    mmr::MMR grow; for (uint8_t i = 1; i <= 6; i++) grow.Add(leaf(i));
    grow.Rewind(3);
    for (uint8_t i = 4; i <= 6; i++) grow.Add(leaf(i));
    mmr::MMR plain; for (uint8_t i = 1; i <= 6; i++) plain.Add(leaf(i));
    BOOST_CHECK(grow.Root() == plain.Root());

    // Leafset rewind drops the high leaves and trims capacity so the root matches
    // an instance that only ever held the low leaves.
    mmr::Leafset ls; for (uint64_t i = 0; i < 12; i++) ls.Add(i);
    ls.Rewind(5);
    mmr::Leafset ref5; for (uint64_t i = 0; i < 5; i++) ref5.Add(i);
    BOOST_CHECK(ls.Size() == 5);
    BOOST_CHECK(!ls.Contains(5) && ls.Contains(4));
    BOOST_CHECK(ls.Root() == ref5.Root());
}

// MWEB: block disconnect via UndoBlock. Connecting a block then undoing it must
// restore the exact prior accumulator state -- including re-marking as unspent
// the earlier-block outputs the undone block had spent.
BOOST_AUTO_TEST_CASE(mweb_state_undo_block)
{
    auto oh = [](uint8_t b) { return mw::Hash(std::vector<uint8_t>(32, b)); };
    auto kh = [](uint8_t b) { return mw::Hash(std::vector<uint8_t>(32, 0x80 | b)); };

    mw::MWEBState state;
    // Block 1: three outputs, one kernel.
    state.AddOutput(oh(1));
    state.AddOutput(oh(2));
    state.AddOutput(oh(3));
    state.AddKernel(kh(1));

    const uint64_t numOutAfter1 = state.NumOutputs();
    const uint64_t numKerAfter1 = state.NumKernels();
    const mw::Hash outRoot1 = state.OutputRoot();
    const mw::Hash kerRoot1 = state.KernelRoot();
    const mw::Hash leafRoot1 = state.LeafsetRoot();

    // Block 2: adds two outputs and a kernel, and spends output oh(2) from block 1.
    state.AddOutput(oh(4));
    state.AddOutput(oh(5));
    state.AddKernel(kh(2));
    BOOST_CHECK(state.SpendByOutputID(oh(2)));

    // Sanity: block 2 really changed every root and the spent bit.
    BOOST_CHECK(state.NumOutputs() == numOutAfter1 + 2);
    BOOST_CHECK(state.OutputRoot() != outRoot1);
    BOOST_CHECK(state.KernelRoot() != kerRoot1);
    BOOST_CHECK(state.LeafsetRoot() != leafRoot1);

    // Undo block 2: rewind to block-1 counts, drop oh(4)/oh(5), re-mark oh(2) unspent.
    const std::vector<mw::Hash> added2 = {oh(4), oh(5)};
    const std::vector<mw::Hash> spent2 = {oh(2)};
    BOOST_CHECK(state.UndoBlock(numOutAfter1, numKerAfter1, added2, spent2));

    // Every root and count is back to exactly the post-block-1 state.
    BOOST_CHECK(state.NumOutputs() == numOutAfter1);
    BOOST_CHECK(state.NumKernels() == numKerAfter1);
    BOOST_CHECK(state.OutputRoot() == outRoot1);
    BOOST_CHECK(state.KernelRoot() == kerRoot1);
    BOOST_CHECK(state.LeafsetRoot() == leafRoot1);
    BOOST_CHECK(state.NumUnspent() == 3);
    BOOST_CHECK(state.IsUnspent(0) && state.IsUnspent(1) && state.IsUnspent(2));
}

// MWEB: the wallet builds transactions that the consensus validator accepts --
// the build -> validate loop. Balanced values pass; unbalanced values are
// caught by Validate.
BOOST_AUTO_TEST_CASE(mweb_txbuilder_build_and_validate)
{
    auto blind = [](uint8_t b) { return mw::BlindingFactor(std::vector<uint8_t>(32, b)); };

    // 1 input 100 -> 1 output 90 + fee 10, with a non-zero offset.
    const std::vector<mw::wallet::Coin> ins  = {{100, blind(0x11)}};
    const std::vector<mw::wallet::Coin> outs = {{90, blind(0x22)}};
    BOOST_CHECK_NO_THROW(mw::wallet::TxBuilder::Build(ins, outs, 10, blind(0x33)).Validate());

    // 2 inputs -> 2 outputs, balanced: 30 + 70 == 40 + 50 + 10 fee.
    const std::vector<mw::wallet::Coin> ins2  = {{30, blind(0x41)}, {70, blind(0x42)}};
    const std::vector<mw::wallet::Coin> outs2 = {{40, blind(0x43)}, {50, blind(0x44)}};
    BOOST_CHECK_NO_THROW(mw::wallet::TxBuilder::Build(ins2, outs2, 10, blind(0x45)).Validate());

    // Unbalanced values (100 != 95 + 10) still produce valid proofs and a valid
    // signature, but must be rejected by the balance check.
    const std::vector<mw::wallet::Coin> badOut = {{95, blind(0x22)}};
    BOOST_CHECK_THROW(mw::wallet::TxBuilder::Build(ins, badOut, 10, blind(0x33)).Validate(),
                      std::runtime_error);
}

// MWEB: peg-in. Value enters MWEB from the canonical chain via the kernel's
// pegin amount and becomes a new MWEB output (no MWEB inputs).
BOOST_AUTO_TEST_CASE(mweb_txbuilder_pegin)
{
    auto blind = [](uint8_t b) { return mw::BlindingFactor(std::vector<uint8_t>(32, b)); };
    const std::vector<mw::wallet::Coin> noInputs;
    const std::vector<mw::wallet::Coin> outs = {{90, blind(0x61)}};

    // pegin 100 == output 90 + fee 10 -> balances.
    BOOST_CHECK_NO_THROW(mw::wallet::TxBuilder::Build(noInputs, outs, 10, 100, blind(0x62)).Validate());

    // A pegin that doesn't cover output + fee (99 != 90 + 10) is rejected.
    BOOST_CHECK_THROW(mw::wallet::TxBuilder::Build(noInputs, outs, 10, 99, blind(0x62)).Validate(),
                      std::runtime_error);
}

// MWEB: peg-out. Value leaves MWEB to the canonical chain via the kernel's
// pegout, spending an MWEB input with no MWEB outputs.
BOOST_AUTO_TEST_CASE(mweb_txbuilder_pegout)
{
    auto blind = [](uint8_t b) { return mw::BlindingFactor(std::vector<uint8_t>(32, b)); };
    const std::vector<mw::wallet::Coin> ins = {{100, blind(0x71)}};
    const std::vector<mw::wallet::Coin> noOutputs;

    CScript script; script << OP_TRUE; // dummy canonical destination

    // input 100 == fee 10 + pegout 90 -> balances.
    std::vector<mw::PegOutCoin> pegouts = { mw::PegOutCoin(90, script) };
    BOOST_CHECK_NO_THROW(
        mw::wallet::TxBuilder::Build(ins, noOutputs, 10, 0, pegouts, blind(0x72)).Validate());

    // A pegout that doesn't match the input minus fee (89 != 100 - 10) is rejected.
    std::vector<mw::PegOutCoin> badPegouts = { mw::PegOutCoin(89, script) };
    BOOST_CHECK_THROW(
        mw::wallet::TxBuilder::Build(ins, noOutputs, 10, 0, badPegouts, blind(0x72)).Validate(),
        std::runtime_error);
}

// MWEB: stealth (one-sided) payments. A sender pays a published address with no
// recipient interaction; the recipient detects the output and recovers the
// blind and one-time spend key, while a stranger cannot.
BOOST_AUTO_TEST_CASE(mweb_stealth_payment)
{
    auto sk = [](uint8_t b) { return mw::SecretKey(std::vector<uint8_t>(32, b)); };

    // Recipient publishes (scanPub, spendPub).
    const mw::SecretKey scanKey = sk(0x11), spendKey = sk(0x22);
    const mw::wallet::StealthAddress addr{
        mw::Keys::PublicKeyFrom(scanKey), mw::Keys::PublicKeyFrom(spendKey) };

    // Sender pays 500 using an ephemeral key, without contacting the recipient.
    const mw::wallet::StealthResult sent = mw::wallet::Stealth::Send(addr, 500, sk(0x33));

    // Recipient detects it; a different recipient does not.
    BOOST_CHECK(mw::wallet::Stealth::IsMine(sent.output, scanKey, mw::Keys::PublicKeyFrom(spendKey)));
    BOOST_CHECK(!mw::wallet::Stealth::IsMine(sent.output, sk(0x44), mw::Keys::PublicKeyFrom(sk(0x55))));

    // Recipient recovers the blind and can rebuild the exact commitment.
    const mw::BlindingFactor recovered = mw::wallet::Stealth::RecoverBlind(sent.output, scanKey);
    BOOST_CHECK(recovered == sent.blind);
    BOOST_CHECK(mw::Pedersen::Commit(500, recovered) == sent.output.GetCommitment());

    // Recipient holds the one-time private key that can spend the output.
    const mw::SecretKey spend = mw::wallet::Stealth::RecoverSpendKey(sent.output, scanKey, spendKey);
    BOOST_CHECK(mw::Keys::PublicKeyFrom(spend) == sent.output.GetReceiverPubKey());
}

// MWEB: the full wallet lifecycle -- a coin received via a stealth payment can
// be recovered and re-spent in a valid transaction.
BOOST_AUTO_TEST_CASE(mweb_stealth_receive_and_spend)
{
    auto sk = [](uint8_t b) { return mw::SecretKey(std::vector<uint8_t>(32, b)); };
    auto blind = [](uint8_t b) { return mw::BlindingFactor(std::vector<uint8_t>(32, b)); };

    // Recipient receives a 500-value stealth payment.
    const mw::SecretKey scanKey = sk(0x11), spendKey = sk(0x22);
    const mw::wallet::StealthAddress addr{
        mw::Keys::PublicKeyFrom(scanKey), mw::Keys::PublicKeyFrom(spendKey) };
    const uint64_t received = 500;
    const mw::wallet::StealthResult sent = mw::wallet::Stealth::Send(addr, received, sk(0x33));

    // It's theirs, and they recover the blind (value known out-of-band here).
    BOOST_REQUIRE(mw::wallet::Stealth::IsMine(sent.output, scanKey, mw::Keys::PublicKeyFrom(spendKey)));
    const mw::BlindingFactor recovered = mw::wallet::Stealth::RecoverBlind(sent.output, scanKey);

    // Spend it: the received coin becomes an input worth `received`.
    const std::vector<mw::wallet::Coin> ins  = {{received, recovered}};
    const std::vector<mw::wallet::Coin> outs = {{received - 10, blind(0x99)}}; // 500 = 490 + 10 fee
    BOOST_CHECK_NO_THROW(mw::wallet::TxBuilder::Build(ins, outs, 10, blind(0xAB)).Validate());
}

// MWEB (2f bridge): a transaction built by the wallet, wrapped into a
// CTransaction, is accepted by the node's actual validation entry point
// (MWEB::Node::CheckTransaction, called from validation.cpp) -- not just by the
// libmw Validate() directly.
BOOST_AUTO_TEST_CASE(mweb_node_accepts_builder_tx)
{
    auto blind = [](uint8_t b) { return mw::BlindingFactor(std::vector<uint8_t>(32, b)); };
    auto wrap = [](const mw::Transaction& t) {
        CMutableTransaction mtx;
        mtx.mweb_tx = MWEB::Tx(std::make_shared<mw::Transaction>(t));
        return CTransaction(mtx);
    };

    // A valid wallet-built transfer passes the node's transaction check.
    const mw::Transaction good =
        mw::wallet::TxBuilder::Build({{100, blind(0x11)}}, {{90, blind(0x22)}}, 10, blind(0x33));
    CValidationState s1;
    BOOST_CHECK(MWEB::Node::CheckTransaction(wrap(good), s1));

    // An unbalanced one is rejected by the node.
    const mw::Transaction bad =
        mw::wallet::TxBuilder::Build({{100, blind(0x11)}}, {{95, blind(0x22)}}, 10, blind(0x33));
    CValidationState s2;
    BOOST_CHECK(!MWEB::Node::CheckTransaction(wrap(bad), s2));
}

// MWEB: the wallet assembles a peg-in as a complete CTransaction -- an MWEB body
// pegging value in, paired with the canonical peg-in output the consensus rules
// require. The node accepts a well-formed one and rejects a canonical output that
// disagrees with (or is missing for) the MWEB peg-in kernel.
BOOST_AUTO_TEST_CASE(mweb_wallet_pegin_transaction)
{
    auto blind = [](uint8_t b) { return mw::BlindingFactor(std::vector<uint8_t>(32, b)); };

    // Wallet builds the MWEB body: peg in 100 -> one output of 90 + fee 10.
    const std::vector<mw::wallet::Coin> noInputs;
    const std::vector<mw::wallet::Coin> outs = {{90, blind(0x61)}};
    const mw::Transaction mwtx =
        mw::wallet::TxBuilder::Build(noInputs, outs, 10, /*pegin=*/100, blind(0x62));
    BOOST_REQUIRE(mwtx.GetPegIns().size() == 1);
    BOOST_CHECK(mwtx.GetPegIns()[0].GetAmount() == 100);

    // Assemble the full peg-in CTransaction (dummy funding input; coin
    // selection/signing is out of scope for this structural check).
    const std::vector<CTxIn> vin(1);
    const CTransaction tx = MWEB::Wallet::CreatePegInTransaction(mwtx, vin);

    // The canonical peg-in output is present, keyed by the kernel, with the amount.
    BOOST_REQUIRE(tx.vout.size() == 1);
    mw::Hash kid;
    BOOST_CHECK(tx.vout[0].scriptPubKey.IsMWEBPegin(&kid));
    BOOST_CHECK(kid == mwtx.GetPegIns()[0].GetKernelID());
    BOOST_CHECK(tx.vout[0].nValue == 100);

    // The node accepts the well-formed peg-in.
    CValidationState s1;
    BOOST_CHECK(MWEB::Node::CheckTransaction(tx, s1));

    // A canonical peg-in output whose amount disagrees with the kernel is rejected.
    CMutableTransaction mtxBad(tx);
    mtxBad.vout[0].nValue = 99;
    CValidationState s2;
    BOOST_CHECK(!MWEB::Node::CheckTransaction(CTransaction(mtxBad), s2));

    // A missing canonical peg-in output (kernel with no match) is rejected.
    CMutableTransaction mtxMissing(tx);
    mtxMissing.vout.clear();
    CValidationState s3;
    BOOST_CHECK(!MWEB::Node::CheckTransaction(CTransaction(mtxMissing), s3));
}

// MWEB: the miner's BlockBuilder and the validator's accumulator agree. A block
// the builder produces must carry exactly the header roots the validator computes
// when it applies that block onto the same starting state -- across two blocks, so
// the second builds correctly on top of the first (seeded from prior state).
BOOST_AUTO_TEST_CASE(mweb_blockbuilder_matches_validator)
{
    auto blind = [](uint8_t b) { return mw::BlindingFactor(std::vector<uint8_t>(32, b)); };

    // The validator's running accumulator; the miner is seeded from a copy of it.
    mw::MWEBState chainState;

    // --- Block 1: peg in 100 -> one output of 90 + fee 10. ---
    const mw::Transaction tx1 =
        mw::wallet::TxBuilder::Build({}, {{90, blind(0x71)}}, 10, /*pegin=*/100, blind(0x72));
    auto builder1 = mw::BlockBuilder::Create(1, /*prevHeader=*/nullptr, chainState);
    BOOST_REQUIRE(builder1->AddTransaction(std::make_shared<mw::Transaction>(tx1), tx1.GetPegIns()));
    mw::Block::Ptr block1 = builder1->Build();
    BOOST_REQUIRE(block1 != nullptr);

    // The validator accumulates the same block and the miner's header matches.
    BOOST_REQUIRE(chainState.ApplyBlock(*block1));
    BOOST_CHECK(chainState.MatchesHeader(*block1->GetHeader()));
    BOOST_CHECK_NO_THROW(block1->Validate());

    // --- Block 2: another peg-in, built ON TOP of the post-block-1 state. ---
    const mw::Transaction tx2 =
        mw::wallet::TxBuilder::Build({}, {{40, blind(0x73)}}, 10, /*pegin=*/50, blind(0x74));
    auto builder2 = mw::BlockBuilder::Create(2, block1->GetHeader(), chainState);
    BOOST_REQUIRE(builder2->AddTransaction(std::make_shared<mw::Transaction>(tx2), tx2.GetPegIns()));
    mw::Block::Ptr block2 = builder2->Build();
    BOOST_REQUIRE(block2 != nullptr);

    // Counts advanced from block 1, and the roots still match the validator.
    BOOST_CHECK(block2->GetHeader()->GetNumTXOs() == block1->GetHeader()->GetNumTXOs() + 1);
    BOOST_REQUIRE(chainState.ApplyBlock(*block2));
    BOOST_CHECK(chainState.MatchesHeader(*block2->GetHeader()));
    BOOST_CHECK_NO_THROW(block2->Validate());
}

// MWEB: the accumulator rebuilds exactly from its persisted append-only log. A
// state loaded from (output IDs, kernel IDs, leafset) reproduces the live state's
// roots -- including which outputs are spent, since the permanent output MMR is
// replayed and the leafset restores the spent bits.
BOOST_AUTO_TEST_CASE(mweb_state_load_reconstructs)
{
    auto oh = [](uint8_t b) { return mw::Hash(std::vector<uint8_t>(32, b)); };
    auto kh = [](uint8_t b) { return mw::Hash(std::vector<uint8_t>(32, 0x80 | b)); };

    mw::MWEBState live;
    std::vector<mw::Hash> outIDs, kerIDs;
    std::vector<uint64_t> leaves;
    for (uint8_t i = 1; i <= 5; i++) { outIDs.push_back(oh(i)); leaves.push_back(live.AddOutput(oh(i)).Get()); }
    for (uint8_t i = 1; i <= 2; i++) { kerIDs.push_back(kh(i)); live.AddKernel(kh(i)); }
    BOOST_REQUIRE(live.SpendByOutputID(oh(2)));
    BOOST_REQUIRE(live.SpendByOutputID(oh(4)));

    // Rebuild purely from the persisted log + leafset bytes.
    mw::MWEBState loaded;
    loaded.Load(outIDs, kerIDs, live.GetLeafsetBytes());

    BOOST_CHECK(loaded.OutputRoot() == live.OutputRoot());
    BOOST_CHECK(loaded.KernelRoot() == live.KernelRoot());
    BOOST_CHECK(loaded.LeafsetRoot() == live.LeafsetRoot());
    BOOST_CHECK(loaded.NumOutputs() == live.NumOutputs());
    BOOST_CHECK(loaded.NumKernels() == live.NumKernels());
    BOOST_CHECK(loaded.NumUnspent() == live.NumUnspent());
    BOOST_CHECK(!loaded.IsUnspent(leaves[1]) && !loaded.IsUnspent(leaves[3])); // oh(2), oh(4) spent
    BOOST_CHECK(loaded.IsUnspent(leaves[0]) && loaded.IsUnspent(leaves[4]));   // others unspent
    // A reloaded output can still be re-spent by ID (the output index rebuilt).
    BOOST_CHECK(loaded.SpendByOutputID(oh(1)));
}

// MWEB: the state DB survives a restart. Connecting blocks through one CMWEBStateDB
// persists the accumulator; a second instance opened on the same directory rebuilds
// an identical accumulator from disk (matching the last block's header roots).
BOOST_AUTO_TEST_CASE(mweb_state_db_persistence)
{
    auto blind = [](uint8_t b) { return mw::BlindingFactor(std::vector<uint8_t>(32, b)); };

    // Two peg-in blocks, built so their headers match the accumulator.
    mw::MWEBState seed;
    const mw::Transaction tx1 =
        mw::wallet::TxBuilder::Build({}, {{90, blind(0x81)}}, 10, /*pegin=*/100, blind(0x82));
    auto b1 = mw::BlockBuilder::Create(1, nullptr, seed);
    BOOST_REQUIRE(b1->AddTransaction(std::make_shared<mw::Transaction>(tx1), tx1.GetPegIns()));
    mw::Block::Ptr block1 = b1->Build();
    BOOST_REQUIRE(block1 && seed.ApplyBlock(*block1));

    const mw::Transaction tx2 =
        mw::wallet::TxBuilder::Build({}, {{40, blind(0x83)}}, 10, /*pegin=*/50, blind(0x84));
    auto b2 = mw::BlockBuilder::Create(2, block1->GetHeader(), seed);
    BOOST_REQUIRE(b2->AddTransaction(std::make_shared<mw::Transaction>(tx2), tx2.GetPegIns()));
    mw::Block::Ptr block2 = b2->Build();
    BOOST_REQUIRE(block2 != nullptr);

    mw::Hash outRoot, kerRoot, leafRoot;
    uint64_t nOut, nKer;
    {
        // Fresh DB: connect both blocks (drives + persists the accumulator).
        CMWEBStateDB db(1 << 20, /*fMemory=*/false, /*fWipe=*/true);
        std::vector<UTXO> spent;
        std::vector<mw::Hash> added;
        BOOST_REQUIRE(db.ConnectBlock(*block1, nullptr, spent, added));
        BOOST_REQUIRE(db.ConnectBlock(*block2, block1->GetHeader(), spent, added));
        BOOST_CHECK(db.State().MatchesHeader(*block2->GetHeader()));
        outRoot = db.State().OutputRoot();
        kerRoot = db.State().KernelRoot();
        leafRoot = db.State().LeafsetRoot();
        nOut = db.State().NumOutputs();
        nKer = db.State().NumKernels();
        BOOST_REQUIRE(db.Flush());
    } // db destroyed -> leveldb lock released

    {
        // Reopen the same directory without wiping: the accumulator must rebuild.
        CMWEBStateDB db2(1 << 20, /*fMemory=*/false, /*fWipe=*/false);
        BOOST_CHECK(db2.State().NumOutputs() == nOut);
        BOOST_CHECK(db2.State().NumKernels() == nKer);
        BOOST_CHECK(db2.State().OutputRoot() == outRoot);
        BOOST_CHECK(db2.State().KernelRoot() == kerRoot);
        BOOST_CHECK(db2.State().LeafsetRoot() == leafRoot);
        BOOST_CHECK(db2.State().MatchesHeader(*block2->GetHeader()));
    }
}

// MWEB: a full block assembled the way the miner assembles one -- coinbase, a
// canonical peg-in transaction, and a HogEx, with the MWEB extension block -- passes
// the node's block-level MWEB validation (peg-in matching + MWEB block crypto). A
// canonical peg-in output that disagrees with the MWEB kernel is rejected.
BOOST_AUTO_TEST_CASE(mweb_node_validates_full_block)
{
    auto blind = [](uint8_t b) { return mw::BlindingFactor(std::vector<uint8_t>(32, b)); };

    // Wallet builds the MWEB body (peg in 100 -> 90 out + 10 fee); miner builds the
    // MWEB extension block from it.
    const mw::Transaction mwtx =
        mw::wallet::TxBuilder::Build({}, {{90, blind(0x91)}}, 10, /*pegin=*/100, blind(0x92));
    auto builder = mw::BlockBuilder::Create(1, nullptr, mw::MWEBState());
    BOOST_REQUIRE(builder->AddTransaction(std::make_shared<mw::Transaction>(mwtx), mwtx.GetPegIns()));
    mw::Block::Ptr mwebBlock = builder->Build();
    BOOST_REQUIRE(mwebBlock != nullptr);

    // Canonical peg-in transaction carrying the peg-in output paired with the kernel.
    const CTransaction peginTx =
        MWEB::Wallet::CreatePegInTransaction(mwtx, std::vector<CTxIn>(1));

    // Assemble the canonical block: coinbase, peg-in tx, HogEx (last), + MWEB block.
    auto makeBlock = [&](const CTransaction& pegin) {
        CBlock block;
        CMutableTransaction coinbase;
        coinbase.vin.resize(1);
        coinbase.vin[0].prevout.SetNull();
        coinbase.vout.resize(1);
        block.vtx.push_back(MakeTransactionRef(coinbase));
        block.vtx.push_back(MakeTransactionRef(pegin));
        CMutableTransaction hogex;
        hogex.m_hogEx = true;
        hogex.vout.resize(1); // vout[0] is the HogAddr; no peg-outs here
        block.vtx.push_back(MakeTransactionRef(std::move(hogex)));
        block.mweb_block.m_block = mwebBlock;
        return block;
    };

    // A well-formed block validates.
    BOOST_CHECK(MWEB::Node::ValidateMWEBBlock(makeBlock(peginTx)));

    // A canonical peg-in output whose amount disagrees with the MWEB kernel fails.
    CMutableTransaction badPegin(peginTx);
    badPegin.vout[0].nValue = 99;
    BOOST_CHECK(!MWEB::Node::ValidateMWEBBlock(makeBlock(CTransaction(badPegin))));
}

// MWEB: the wallet's peg-in builder produces a valid, balanced MWEB transaction
// creating one output worth (amount - fee), with fresh randomness each call.
BOOST_AUTO_TEST_CASE(mweb_wallet_build_pegin)
{
    const CAmount amount = 100 * COIN;
    const CAmount fee = 100000;

    MWEB::Wallet::PegInResult r = MWEB::Wallet::BuildPegIn(amount, fee);
    BOOST_CHECK(r.outputValue == amount - fee);
    BOOST_REQUIRE(r.tx.GetPegIns().size() == 1);
    BOOST_CHECK(r.tx.GetPegIns().front().GetAmount() == amount);
    BOOST_CHECK(r.tx.GetOutputs().size() == 1);
    BOOST_CHECK_NO_THROW(r.tx.Validate()); // balanced values + sound crypto

    // Fresh randomness each call -> a different kernel.
    MWEB::Wallet::PegInResult r2 = MWEB::Wallet::BuildPegIn(amount, fee);
    BOOST_CHECK(r.tx.GetPegIns().front().GetKernelID() != r2.tx.GetPegIns().front().GetKernelID());

    // The peg-in amount must exceed the fee.
    BOOST_CHECK_THROW(MWEB::Wallet::BuildPegIn(fee, fee), std::runtime_error);
}

// MWEB: a tracked output can be spent. Spending references the output by its real
// output ID (a hash of the whole output), so the accumulator finds and spends it;
// an input built with only the commitment hash would not match the added output.
BOOST_AUTO_TEST_CASE(mweb_spend_tracked_output)
{
    auto blind = [](uint8_t b) { return mw::BlindingFactor(std::vector<uint8_t>(32, b)); };

    // Peg in to create an MWEB output the wallet owns (knows value + blind + ID).
    MWEB::Wallet::PegInResult peg = MWEB::Wallet::BuildPegIn(100 * COIN, 100000);
    BOOST_REQUIRE(peg.tx.GetOutputs().size() == 1);
    const mw::Hash outID = peg.tx.GetOutputs()[0].GetOutputID();

    // Accumulate it, as connecting the peg-in block would.
    mw::MWEBState state;
    const uint64_t leaf = state.AddOutput(outID).Get();
    BOOST_CHECK(state.IsUnspent(leaf));

    // Spend it: input is the tracked coin carrying its real output ID; output is a
    // new coin worth value - fee.
    const CAmount fee2 = 100000;
    const mw::wallet::Coin inCoin{ (uint64_t)peg.outputValue, peg.outputBlind, outID };
    const mw::wallet::Coin outCoin{ (uint64_t)(peg.outputValue - fee2), blind(0x55) };
    const mw::Transaction spend =
        mw::wallet::TxBuilder::Build({inCoin}, {outCoin}, fee2, blind(0x56));

    // The input references the real output; the tx balances; the accumulator spends it.
    BOOST_REQUIRE(spend.GetInputs().size() == 1);
    BOOST_CHECK(spend.GetInputs()[0].GetOutputID() == outID);
    BOOST_CHECK_NO_THROW(spend.Validate());
    BOOST_CHECK(state.SpendByOutputID(spend.GetInputs()[0].GetOutputID()));
    BOOST_CHECK(!state.IsUnspent(leaf));

    // An input that does not carry the output ID falls back to the commitment hash
    // and so cannot spend the accumulated output.
    const mw::wallet::Coin noId{ (uint64_t)peg.outputValue, peg.outputBlind };
    const mw::Transaction badSpend =
        mw::wallet::TxBuilder::Build({noId}, {outCoin}, fee2, blind(0x56));
    mw::MWEBState fresh;
    fresh.AddOutput(outID);
    BOOST_CHECK(badSpend.GetInputs()[0].GetOutputID() != outID);
    BOOST_CHECK(!fresh.SpendByOutputID(badSpend.GetInputs()[0].GetOutputID()));
}

BOOST_AUTO_TEST_SUITE_END()
