// Cases that pin what the second review round's fixes establish, in the state database and in
// the kernel signature. Each was written to show a defect and now asserts that it is gone.

#include "test/test_bitcoin.h"

#include <mw/crypto/Pedersen.h>
#include <mw/crypto/Schnorr.h>
#include <mw/crypto/Bulletproof.h>
#include <mw/crypto/Keys.h>
#include <mw/consensus/KernelKey.h>
#include <mw/consensus/Weight.h>
#include <mw/models/tx/Transaction.h>
#include <mw/models/block/Block.h>
#include <mw/models/block/Header.h>
#include <mw/node/MWEBState.h>
#include <mw/node/BlockBuilder.h>
#include <mw/wallet/TxBuilder.h>
#include <mw/wallet/Stealth.h>

#include "mweb/mweb_node.h"
#include "mweb/mweb_wallet.h"
#include "mweb/mweb_db.h"
#include "script/standard.h"
#include "consensus/validation.h"
#include "crypto/sha256.h"
#include "hash.h"
#include "random.h"
#include "streams.h"
#include "utilstrencodings.h"
#include "core_io.h"

#include <boost/test/unit_test.hpp>

#include <cstdio>
#include <cstdlib>

namespace {

mw::SecretKey K(uint8_t b) { return mw::SecretKey(std::vector<uint8_t>(32, b)); }

mw::BlindingFactor RandomOffset()
{
    std::vector<uint8_t> v(32);
    GetStrongRandBytes(v.data(), 32);
    return mw::BlindingFactor(v);
}

mw::SecretKey RandomKey()
{
    std::vector<uint8_t> v(32);
    GetStrongRandBytes(v.data(), 32);
    return mw::SecretKey(v);
}

mw::Transaction Reassemble(const mw::BlindingFactor& kernelOffset, const mw::BlindingFactor& stealthOffset,
                           std::vector<mw::Input> ins, std::vector<mw::Output> outs, std::vector<mw::Kernel> kers)
{
    std::sort(ins.begin(), ins.end(), [](const mw::Input& a, const mw::Input& b) { return a.GetHash() < b.GetHash(); });
    std::sort(outs.begin(), outs.end(), [](const mw::Output& a, const mw::Output& b) { return a.GetHash() < b.GetHash(); });
    std::sort(kers.begin(), kers.end(), [](const mw::Kernel& a, const mw::Kernel& b) { return a.GetHash() < b.GetHash(); });
    return mw::Transaction(kernelOffset, stealthOffset, mw::TxBody(std::move(ins), std::move(outs), std::move(kers)));
}

const char* Name(CMWEBStateDB::ConnectResult r)
{
    switch (r) {
    case CMWEBStateDB::ConnectResult::OK: return "OK";
    case CMWEBStateDB::ConnectResult::INVALID: return "INVALID";
    case CMWEBStateDB::ConnectResult::DB_ERROR: return "DB_ERROR";
    }
    return "?";
}

const CAmount FEE = 100000;

// a peg-in of `pegin` paying one stealth output to `addr`. `sr` is what its sender keeps.
mw::Transaction PegInTo(const mw::wallet::StealthAddress& addr, CAmount pegin, mw::wallet::StealthResult& sr)
{
    const mw::SecretKey e = RandomKey();
    sr = mw::wallet::Stealth::Send(addr, pegin - FEE, e);
    const mw::Transaction plain = mw::wallet::TxBuilder::Build(
        {}, {MWEB::Wallet::StealthOutputCoin(pegin - FEE, sr.blind, e)}, FEE, pegin, RandomOffset());
    return Reassemble(plain.GetKernelOffset(), plain.GetStealthOffset(), {}, {sr.output}, plain.GetKernels());
}

// the same peg-in with the kernel the wallet built before the stealth blind fix: no stealth excess,
// signed with the bare excess. `e` is the output's sender key and `off` the kernel offset.
mw::Transaction BarePegInTo(const mw::wallet::StealthAddress& addr, CAmount pegin, const mw::SecretKey& e,
                            const mw::BlindingFactor& off, mw::wallet::StealthResult& sr)
{
    const CAmount value = pegin - FEE;
    sr = mw::wallet::Stealth::Send(addr, value, e);
    const mw::Transaction built = mw::wallet::TxBuilder::Build(
        {}, {MWEB::Wallet::StealthOutputCoin(value, sr.blind, e)}, FEE, pegin, {}, off);
    const mw::Kernel& bk = built.GetKernels()[0];

    // excess = output blind - offset; one output, no inputs
    const mw::SecretKey x = mw::Keys::AddSecretKeys(mw::SecretKey(sr.blind.vec()),
                                                    mw::Keys::NegateSecretKey(mw::SecretKey(off.vec())));
    BOOST_REQUIRE(mw::Pedersen::Commit(0, mw::BlindingFactor(x.vec())) == bk.GetExcess());

    const uint8_t features = bk.GetFeatures() & ~mw::Kernel::STEALTH_EXCESS_FEATURE_BIT;
    const mw::Hash msg = mw::Kernel(features, bk.GetFee(), bk.GetPegIn(), bk.GetPegOuts(), bk.GetLockHeight(),
                                    mw::PublicKey(), bk.GetExcess(), mw::Signature()).GetSignatureMessage();
    const mw::Kernel bare(features, bk.GetFee(), bk.GetPegIn(), bk.GetPegOuts(), bk.GetLockHeight(),
                          mw::PublicKey(), bk.GetExcess(), mw::Schnorr::Sign(x, msg.data()));
    // with no blind term the stealth offset of a body with no inputs is the sender key
    return Reassemble(off, mw::BlindingFactor(e.vec()), {}, {sr.output}, {bare});
}

// the extension block a miner with accumulator `state` builds from one transaction, at `height`,
// on a parent whose header is `prev` (null when the parent carried no extension block).
mw::Block::Ptr BlockOf(int height, const mw::Header::CPtr& prev, const mw::MWEBState& state, const mw::Transaction& tx)
{
    auto b = mw::BlockBuilder::Create(height, prev, state);
    BOOST_REQUIRE(b->AddTransaction(std::make_shared<mw::Transaction>(tx), tx.GetPegIns()));
    mw::Block::Ptr block = b->Build();
    BOOST_REQUIRE(block != nullptr);
    return block;
}

struct Keys2 {
    mw::SecretKey scan, spend;
    mw::wallet::StealthAddress addr;
    Keys2() : scan(K(0x11)), spend(K(0x22)), addr{mw::Keys::PublicKeyFrom(scan), mw::Keys::PublicKeyFrom(spend)} {}
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(mweb_round2_tests, TestingSetup)

// round one, items 1 and 2, against what the wallet builds now.
BOOST_AUTO_TEST_CASE(wallet_shapes_after_the_stealth_blind_fix)
{
    const Keys2 k;

    const MWEB::Wallet::PegInResult peg = MWEB::Wallet::BuildPegIn(10 * COIN, FEE, k.addr);
    BOOST_REQUIRE_NO_THROW(peg.tx.Validate());
    const mw::Output& out = peg.tx.GetOutputs()[0];
    const bool offsetIsSenderKey =
        (mw::Keys::PublicKeyFrom(mw::SecretKey(peg.tx.GetStealthOffset().vec())) == out.GetSenderPubKey());

    mw::wallet::StealthResult sr;
    const mw::Transaction funding = PegInTo(k.addr, 5 * COIN + FEE, sr);
    const mw::wallet::Coin coin{static_cast<uint64_t>(5 * COIN), mw::wallet::Stealth::RecoverBlind(sr.output, k.scan),
                                sr.output.GetOutputID(), mw::wallet::Stealth::RecoverSpendKey(sr.output, k.scan, k.spend)};
    std::vector<mw::PegOutCoin> pegouts = {mw::PegOutCoin(5 * COIN - FEE, CScript() << OP_1)};
    // the call the pegout rpc makes
    const mw::Transaction pegout = mw::wallet::TxBuilder::Build({coin}, {}, FEE, 0, pegouts, RandomOffset());
    BOOST_REQUIRE_NO_THROW(pegout.Validate());
    const mw::SecretKey neg = mw::Keys::NegateSecretKey(mw::SecretKey(pegout.GetStealthOffset().vec()));
    const bool offsetIsOneTimeKey = (mw::Keys::PublicKeyFrom(neg) == pegout.GetInputs()[0].GetOutputPubKey());

    printf("[wallet] peg-in:  kernel has a stealth excess %d, offset*G == sender key %d\n",
           (int)peg.tx.GetKernels()[0].HasStealthExcess(), offsetIsSenderKey);
    printf("[wallet] peg-out: kernel has a stealth excess %d, -offset is the one-time key %d\n",
           (int)pegout.GetKernels()[0].HasStealthExcess(), offsetIsOneTimeKey);
    BOOST_CHECK(!offsetIsSenderKey);
    BOOST_CHECK(!offsetIsOneTimeKey);
}

// a peg-in with a bare kernel. nothing in consensus or policy asks for a stealth excess, so the
// body is accepted. round one's item 4, moving its excess, is closed by the signed message.
BOOST_AUTO_TEST_CASE(a_bare_kernel_is_accepted_but_its_excess_cannot_be_moved)
{
    const Keys2 k;
    const CAmount pegin = 10 * COIN;
    const mw::BlindingFactor off = RandomOffset();
    mw::wallet::StealthResult sr;
    const mw::Transaction tx = BarePegInTo(k.addr, pegin, RandomKey(), off, sr);
    const mw::Kernel bare = tx.GetKernels()[0];
    const uint8_t features = bare.GetFeatures();
    const mw::Hash msg = bare.GetSignatureMessage();

    bool validates = true;
    try { tx.Validate(); } catch (const std::exception& ex) { validates = false; printf("  rejected: %s\n", ex.what()); }

    CMutableTransaction mtx;
    mtx.vin.emplace_back(COutPoint(uint256S("01"), 0));
    mtx.vout.emplace_back(pegin, GetScriptForMWEBPegin(bare.GetKernelID()));
    mtx.mweb_tx = MWEB::Tx(std::make_shared<mw::Transaction>(tx));
    CValidationState st;
    const bool nodeAccepts = MWEB::Node::CheckTransaction(CTransaction(mtx), st);

    const bool offsetIsSenderKey =
        (mw::Keys::PublicKeyFrom(mw::SecretKey(tx.GetStealthOffset().vec())) == sr.output.GetSenderPubKey());

    // round one's item 4 on this kernel: (R, s + e*d) under X + d*G, the kernel offset absorbing d
    const std::vector<uint8_t> sig = bare.GetSignature().vec();
    uint8_t ch[32];
    CSHA256().Write(sig.data(), 32).Write(msg.data(), 32).Finalize(ch);
    const mw::SecretKey d = K(0x77);
    const mw::Commitment x2 = mw::Pedersen::AddCommitments(
        {bare.GetExcess(), mw::Pedersen::Commit(0, mw::BlindingFactor(d.vec()))}, {});
    const mw::SecretKey s2 = mw::Keys::AddSecretKeys(
        mw::SecretKey(std::vector<uint8_t>(sig.begin() + 32, sig.end())),
        mw::Keys::MulSecretKeys(mw::SecretKey(std::vector<uint8_t>(ch, ch + 32)), d));
    std::vector<uint8_t> sig2(sig.begin(), sig.begin() + 32);
    sig2.insert(sig2.end(), s2.data(), s2.data() + 32);
    const mw::Kernel moved(features, bare.GetFee(), bare.GetPegIn(), bare.GetPegOuts(), bare.GetLockHeight(),
                           mw::PublicKey(), x2, mw::Signature(sig2));
    const mw::SecretKey off2 = mw::Keys::AddSecretKeys(mw::SecretKey(off.vec()), mw::Keys::NegateSecretKey(d));
    const mw::Transaction tx2 = Reassemble(mw::BlindingFactor(off2.vec()), tx.GetStealthOffset(), {}, {sr.output}, {moved});
    bool movedValidates = true;
    try { tx2.Validate(); } catch (const std::exception&) { movedValidates = false; }

    printf("[bare kernel] Transaction::Validate %d, IsStandard %d, MWEB::Node::CheckTransaction %d\n",
           validates, (int)tx.IsStandard(), nodeAccepts);
    printf("[bare kernel] offset*G == sender key %d; excess moved by a third party validates %d, kernel id changed %d\n",
           offsetIsSenderKey, movedValidates, (int)!(moved.GetKernelID() == bare.GetKernelID()));

    // A kernel without a stealth excess is still valid, standard and accepted,
    // as upstream has it. What it is not is malleable: the excess is in the
    // signed message, so (R, s + H(R||msg)*d) over X + d*G no longer verifies.
    BOOST_CHECK(validates);
    BOOST_CHECK(tx.IsStandard());
    BOOST_CHECK(nodeAccepts);
    BOOST_CHECK(!movedValidates);
    BOOST_CHECK(!(moved.GetKernelID() == bare.GetKernelID()));
}

// round one's item 1 on the same body, which the signed message does not reach: with no kernel
// stealth excess the stealth offset is the sender key in the clear, and the sender key is what
// signs the output. this pins what the rules accept from a wallet that leaves the excess out, not
// what is wanted from them. TxBuilder never builds such a body.
BOOST_AUTO_TEST_CASE(a_body_with_no_kernel_stealth_excess_can_be_readdressed)
{
    const Keys2 k;
    const CAmount pegin = 10 * COIN, value = pegin - FEE;
    mw::wallet::StealthResult sr;
    const mw::Transaction tx = BarePegInTo(k.addr, pegin, RandomKey(), RandomOffset(), sr);
    BOOST_REQUIRE_NO_THROW(tx.Validate());
    BOOST_REQUIRE(mw::wallet::Stealth::IsMine(tx.GetOutputs()[0], k.scan, k.addr.spend));

    // from here on only the transaction's bytes are used, and further down the address it pays
    const mw::Output& out = tx.GetOutputs()[0];
    const mw::Kernel& kernel = tx.GetKernels()[0];
    const mw::SecretKey leaked(tx.GetStealthOffset().vec());
    const bool offsetIsSenderKey = (mw::Keys::PublicKeyFrom(leaked) == out.GetSenderPubKey());

    const mw::SecretKey other = K(0x66);
    const mw::Output unsignedOut(out.GetCommitment(), out.GetSenderPubKey(), mw::Keys::PublicKeyFrom(other),
                                 out.GetOutputMessage(), out.GetRangeProof(), mw::Signature());
    const mw::Output moved(out.GetCommitment(), out.GetSenderPubKey(), mw::Keys::PublicKeyFrom(other),
                           out.GetOutputMessage(), out.GetRangeProof(),
                           mw::Schnorr::Sign(leaked, unsignedOut.GetSignatureMessage().data()));
    const mw::Transaction tx2 = Reassemble(tx.GetKernelOffset(), tx.GetStealthOffset(), {}, {moved}, tx.GetKernels());
    bool validates = true;
    try { tx2.Validate(); } catch (const std::exception& ex) { validates = false; printf("  rejected: %s\n", ex.what()); }
    const bool sameKernel = (tx2.GetKernels()[0].GetKernelID() == kernel.GetKernelID());

    // the canonical peg-in output the sender signed names the kernel, which has not changed
    CMutableTransaction mtx;
    mtx.vin.emplace_back(COutPoint(uint256S("01"), 0));
    mtx.vout.emplace_back(pegin, GetScriptForMWEBPegin(kernel.GetKernelID()));
    mtx.mweb_tx = MWEB::Tx(std::make_shared<mw::Transaction>(tx2));
    CValidationState st;
    const bool nodeAccepts = MWEB::Node::CheckTransaction(CTransaction(mtx), st);
    const bool ownerSeesIt = mw::wallet::Stealth::IsMine(moved, k.scan, k.addr.spend);

    // with the address as well, the shared secret and so the blind
    const mw::BlindingFactor blind(mw::Keys::ECDH(leaked, k.addr.scan).vec());
    const bool opened = (mw::Pedersen::Commit(value, blind) == out.GetCommitment());

    mw::MWEBState seed;
    const mw::Block::Ptr block1 = BlockOf(1, nullptr, seed, tx2);
    CMWEBStateDB db(1 << 20, /*fMemory=*/true, /*fWipe=*/true);
    std::vector<UTXO> spent;
    std::vector<mw::Hash> added;
    BOOST_REQUIRE(db.ConnectBlock(*block1, nullptr, spent, added) == CMWEBStateDB::ConnectResult::OK);
    BOOST_REQUIRE(seed.ApplyBlock(*block1));

    mw::wallet::Coin in;
    in.value = static_cast<uint64_t>(value);
    in.blind = blind;
    in.outputID = moved.GetOutputID();
    in.spendKey = other;
    const CScript anyone = CScript() << OP_TRUE;
    const mw::Transaction spend = mw::wallet::TxBuilder::Build(
        {in}, {}, FEE, 0, {mw::PegOutCoin(value - FEE, anyone)}, RandomOffset());
    bool spendValidates = true;
    try { spend.Validate(); } catch (const std::exception& ex) { spendValidates = false; printf("  rejected: %s\n", ex.what()); }
    CMWEBStateDB::ConnectResult spendConnects = CMWEBStateDB::ConnectResult::INVALID;
    if (spendValidates) {
        const mw::Block::Ptr block2 = BlockOf(2, block1->GetHeader(), seed, spend);
        spendConnects = db.ConnectBlock(*block2, block1->GetHeader(), spent, added);
    }

    printf("[bare body] offset*G == sender key %d; output re-addressed and signed with the offset: Transaction::Validate %d, IsStandard %d, same kernel id %d, MWEB::Node::CheckTransaction %d\n",
           offsetIsSenderKey, validates, (int)tx2.IsStandard(), sameKernel, nodeAccepts);
    printf("[bare body] the address it paid sees the output %d; with the address the commitment opens %d and a spend by the new key connects: %s\n",
           ownerSeesIt, opened, Name(spendConnects));

    BOOST_CHECK(offsetIsSenderKey);
    BOOST_CHECK(validates);
    BOOST_CHECK(sameKernel);
    BOOST_CHECK(nodeAccepts);
    BOOST_CHECK(!ownerSeesIt);
    BOOST_CHECK(opened);
    BOOST_CHECK(spendConnects == CMWEBStateDB::ConnectResult::OK);
}

// 75b001555 refuses a block that re-creates an output id. the refusal used to run UndoBlock with
// the block's output ids, which dropped the original from the accumulator's index.
BOOST_AUTO_TEST_CASE(refusing_a_duplicate_output_keeps_the_original)
{
    const Keys2 k;
    const CAmount pegin = 10 * COIN, value = pegin - FEE;

    const mw::SecretKey e = RandomKey();
    const mw::wallet::StealthResult sr = mw::wallet::Stealth::Send(k.addr, value, e);
    auto fund = [&]() {
        const mw::Transaction plain = mw::wallet::TxBuilder::Build(
            {}, {MWEB::Wallet::StealthOutputCoin(value, sr.blind, e)}, FEE, pegin, RandomOffset());
        return Reassemble(plain.GetKernelOffset(), plain.GetStealthOffset(), {}, {sr.output}, plain.GetKernels());
    };
    const mw::Transaction tx1 = fund();
    const mw::Hash id = sr.output.GetOutputID();

    mw::MWEBState seed;
    const mw::Block::Ptr block1 = BlockOf(1, nullptr, seed, tx1);
    BOOST_REQUIRE(seed.ApplyBlock(*block1));

    CMWEBStateDB db(1 << 20, /*fMemory=*/true, /*fWipe=*/true);
    std::vector<UTXO> spent;
    std::vector<mw::Hash> added;
    BOOST_REQUIRE(db.ConnectBlock(*block1, nullptr, spent, added) == CMWEBStateDB::ConnectResult::OK);
    const bool before = db.State().IsUnspentByOutputID(id);

    // the same output bytes under a second kernel, in a block from a miner that does not use the builder
    const mw::Transaction tx2 = fund();
    mw::MWEBState st = seed;
    st.AddOutput(id);
    st.AddKernel(tx2.GetKernels()[0].GetKernelID());
    auto header2 = std::make_shared<mw::Header>(2, st.OutputRoot(), st.KernelRoot(), st.LeafsetRoot(),
                                                tx2.GetKernelOffset(), tx2.GetStealthOffset(),
                                                st.NumOutputs(), st.NumKernels());
    const mw::Block dup(header2, mw::TxBody(std::vector<mw::Input>(), std::vector<mw::Output>{sr.output},
                                            std::vector<mw::Kernel>(tx2.GetKernels())));
    bool dupValidates = true;
    try { dup.Validate(tx2.GetPegIns(), {}); } catch (const std::exception&) { dupValidates = false; }
    const CMWEBStateDB::ConnectResult rdup = db.ConnectBlock(dup, block1->GetHeader(), spent, added);
    const bool rowAfter = db.HasOutput(id);
    const bool after = db.State().IsUnspentByOutputID(id);

    // the owner spends the original, in a block from a miner that never saw the duplicate
    const mw::wallet::Coin coin{static_cast<uint64_t>(value), mw::wallet::Stealth::RecoverBlind(sr.output, k.scan), id,
                                mw::wallet::Stealth::RecoverSpendKey(sr.output, k.scan, k.spend)};
    const mw::Transaction spendTx = MWEB::Wallet::BuildStealthSpend(coin, FEE, k.addr);
    const mw::Block::Ptr block3 = BlockOf(2, block1->GetHeader(), seed, spendTx);
    bool spendValidates = true;
    try { block3->Validate({}, {}); } catch (const std::exception&) { spendValidates = false; }
    const CMWEBStateDB::ConnectResult rhere = db.ConnectBlock(*block3, block1->GetHeader(), spent, added);

    CMWEBStateDB clean(1 << 20, /*fMemory=*/true, /*fWipe=*/true);
    BOOST_REQUIRE(clean.ConnectBlock(*block1, nullptr, spent, added) == CMWEBStateDB::ConnectResult::OK);
    const CMWEBStateDB::ConnectResult rclean = clean.ConnectBlock(*block3, block1->GetHeader(), spent, added);

    printf("[dup] original output known unspent to the accumulator before the duplicate block: %d\n", before);
    printf("[dup] duplicate block: Block::Validate %d, ConnectBlock %s\n", dupValidates, Name(rdup));
    printf("[dup] after the refusal: utxo row still in the db %d, known unspent to the accumulator %d\n", rowAfter, after);
    printf("[dup] block spending the original: Block::Validate %d; ConnectBlock on the node that saw the duplicate %s, on one that did not %s\n",
           spendValidates, Name(rhere), Name(rclean));

    // A refused block must leave the state as it found it: the original stays
    // spendable here and on a node that never saw the duplicate.
    BOOST_CHECK(before);
    BOOST_CHECK(dupValidates);
    BOOST_CHECK(rdup == CMWEBStateDB::ConnectResult::INVALID);
    BOOST_CHECK(rowAfter);
    BOOST_CHECK(after);
    BOOST_CHECK(spendValidates);
    BOOST_CHECK(rhere == CMWEBStateDB::ConnectResult::OK);
    BOOST_CHECK(rclean == CMWEBStateDB::ConnectResult::OK);
}

// 05a3a54ed skips a block whose hash is the one recorded as applied. disconnecting did not
// change the record, so the block that was just disconnected was skipped when it came back.
BOOST_AUTO_TEST_CASE(reconnect_after_disconnect_is_applied)
{
    const Keys2 k;
    mw::wallet::StealthResult sr1, sr2;
    const mw::Transaction tx1 = PegInTo(k.addr, 10 * COIN, sr1);
    const mw::Hash id = sr1.output.GetOutputID();

    mw::MWEBState seed;
    const mw::Block::Ptr block1 = BlockOf(1, nullptr, seed, tx1);

    CMWEBStateDB db(1 << 20, /*fMemory=*/true, /*fWipe=*/true);
    std::vector<UTXO> spent;
    std::vector<mw::Hash> added;
    BOOST_REQUIRE(db.ConnectBlock(*block1, nullptr, spent, added) == CMWEBStateDB::ConnectResult::OK);
    const uint64_t n0 = db.State().NumOutputs();
    BOOST_REQUIRE(db.DisconnectBlock(mw::BlockUndo(nullptr, std::vector<UTXO>(spent), std::vector<mw::Hash>(added))));
    const uint64_t n1 = db.State().NumOutputs();
    const CMWEBStateDB::ConnectResult again = db.ConnectBlock(*block1, nullptr, spent, added);
    const uint64_t n2 = db.State().NumOutputs();

    // the next block, from a miner whose state does hold block1
    BOOST_REQUIRE(seed.ApplyBlock(*block1));
    const mw::Transaction tx2 = PegInTo(k.addr, 7 * COIN, sr2);
    const mw::Block::Ptr block2 = BlockOf(2, block1->GetHeader(), seed, tx2);
    const CMWEBStateDB::ConnectResult next = db.ConnectBlock(*block2, block1->GetHeader(), spent, added);

    printf("[reconnect] outputs in the accumulator: connected %llu, disconnected %llu, connected again (%s) %llu\n",
           (unsigned long long)n0, (unsigned long long)n1, Name(again), (unsigned long long)n2);
    printf("[reconnect] block1's output: utxo row %d, known unspent %d; the next block from the network connects: %s\n",
           (int)db.HasOutput(id), (int)db.State().IsUnspentByOutputID(id), Name(next));

    // Connecting a block again after disconnecting it must re-apply it, not be
    // skipped by hash, or the node is a block short and refuses the next one.
    BOOST_CHECK_EQUAL(n0, 1u);
    BOOST_CHECK_EQUAL(n1, 0u);
    BOOST_CHECK(again == CMWEBStateDB::ConnectResult::OK);
    BOOST_CHECK_EQUAL(n2, 1u);
    BOOST_CHECK(db.HasOutput(id));
    BOOST_CHECK(db.State().IsUnspentByOutputID(id));
    BOOST_CHECK(next == CMWEBStateDB::ConnectResult::OK);
}

// f1528b690 lets a block carry no extension block. validation.cpp hands ConnectBlock the parent's
// mweb_header as prevHeader, and a parent with no extension block has none. the reject path
// rewound the accumulator to prevHeader's counts, so one block that failed after a gap rewound
// it to nothing.
BOOST_AUTO_TEST_CASE(a_refused_block_after_a_gap_leaves_the_accumulator)
{
    const Keys2 k;
    mw::wallet::StealthResult sr1, sr2, sr3;
    const mw::Transaction tx1 = PegInTo(k.addr, 10 * COIN, sr1);
    const mw::Hash id1 = sr1.output.GetOutputID();

    mw::MWEBState seed;
    const mw::Block::Ptr block1 = BlockOf(1, nullptr, seed, tx1);   // height 1: extension block
    BOOST_REQUIRE(seed.ApplyBlock(*block1));
    //                                                                  height 2: no extension block

    CMWEBStateDB db(1 << 20, /*fMemory=*/true, /*fWipe=*/true);
    std::vector<UTXO> spent;
    std::vector<mw::Hash> added;
    BOOST_REQUIRE(db.ConnectBlock(*block1, nullptr, spent, added) == CMWEBStateDB::ConnectResult::OK);
    const uint64_t o0 = db.State().NumOutputs();

    // height 3 from a miner whose header does not describe this chain: here, one whose
    // accumulator never held height 1. any header that does not match will do.
    const mw::Block::Ptr wrong = BlockOf(3, nullptr, mw::MWEBState(), PegInTo(k.addr, 7 * COIN, sr2));
    bool wrongValidates = true;
    try { wrong->Validate(wrong->GetPegIns(), {}); } catch (const std::exception&) { wrongValidates = false; }
    const CMWEBStateDB::ConnectResult rw = db.ConnectBlock(*wrong, /*prevHeader=*/nullptr, spent, added);
    const uint64_t o1 = db.State().NumOutputs();

    // height 3 as the rest of the network mines it
    const mw::Block::Ptr right = BlockOf(3, nullptr, seed, PegInTo(k.addr, 3 * COIN, sr3));
    const CMWEBStateDB::ConnectResult rr = db.ConnectBlock(*right, nullptr, spent, added);

    CMWEBStateDB clean(1 << 20, /*fMemory=*/true, /*fWipe=*/true);
    BOOST_REQUIRE(clean.ConnectBlock(*block1, nullptr, spent, added) == CMWEBStateDB::ConnectResult::OK);
    const CMWEBStateDB::ConnectResult rc = clean.ConnectBlock(*right, nullptr, spent, added);

    printf("[gap] accumulator before: %llu outputs. block with a header that does not match, on a parent with no extension block: Block::Validate %d, ConnectBlock %s\n",
           (unsigned long long)o0, wrongValidates, Name(rw));
    printf("[gap] accumulator after the refusal: %llu outputs; height 1's output: utxo row %d, known unspent %d\n",
           (unsigned long long)o1, (int)db.HasOutput(id1), (int)db.State().IsUnspentByOutputID(id1));
    printf("[gap] the block the network mines at that height: ConnectBlock here %s, on a node that never saw the refused one %s\n",
           Name(rr), Name(rc));

    // Refusing a block whose header does not match must not rewind the
    // accumulator to a null previous header's zero counts.
    BOOST_CHECK_EQUAL(o0, 1u);
    BOOST_CHECK(wrongValidates);
    BOOST_CHECK(rw == CMWEBStateDB::ConnectResult::INVALID);
    BOOST_CHECK_EQUAL(o1, 1u);
    BOOST_CHECK(db.HasOutput(id1));
    BOOST_CHECK(db.State().IsUnspentByOutputID(id1));
    BOOST_CHECK(rr == CMWEBStateDB::ConnectResult::OK);
    BOOST_CHECK(rc == CMWEBStateDB::ConnectResult::OK);
}

// the replay 05a3a54ed is for, with the coins database two extension blocks behind and not one.
BOOST_AUTO_TEST_CASE(replay_of_two_blocks_after_unclean_shutdown)
{
    const Keys2 k;
    mw::wallet::StealthResult sr1, sr2;
    const mw::Transaction tx1 = PegInTo(k.addr, 10 * COIN, sr1);
    const mw::Transaction tx2 = PegInTo(k.addr, 7 * COIN, sr2);

    mw::MWEBState seed;
    const mw::Block::Ptr block1 = BlockOf(1, nullptr, seed, tx1);
    BOOST_REQUIRE(seed.ApplyBlock(*block1));
    const mw::Block::Ptr block2 = BlockOf(2, block1->GetHeader(), seed, tx2);

    CMWEBStateDB db(1 << 20, /*fMemory=*/true, /*fWipe=*/true);
    std::vector<UTXO> spent;
    std::vector<mw::Hash> added;
    BOOST_REQUIRE(db.ConnectBlock(*block1, nullptr, spent, added) == CMWEBStateDB::ConnectResult::OK);
    BOOST_REQUIRE(db.ConnectBlock(*block2, block1->GetHeader(), spent, added) == CMWEBStateDB::ConnectResult::OK);
    const uint64_t o0 = db.State().NumOutputs();

    const CMWEBStateDB::ConnectResult r1 = db.ConnectBlock(*block1, nullptr, spent, added);
    const uint64_t o1 = db.State().NumOutputs();
    const CMWEBStateDB::ConnectResult r2 = db.ConnectBlock(*block2, block1->GetHeader(), spent, added);
    const uint64_t o2 = db.State().NumOutputs();

    printf("[replay] state holds blocks 1 and 2: %llu outputs\n", (unsigned long long)o0);
    printf("[replay] block 1 again: %s, accumulator now %llu outputs; block 2 again: %s, accumulator %llu outputs\n",
           Name(r1), (unsigned long long)o1, Name(r2), (unsigned long long)o2);

    // Re-applying a block the state already holds is refused, and refusing it
    // leaves the state untouched, however many blocks the replay covers.
    BOOST_CHECK_EQUAL(o0, 2u);
    BOOST_CHECK(r1 == CMWEBStateDB::ConnectResult::INVALID);
    BOOST_CHECK_EQUAL(o1, 2u);
    BOOST_CHECK(r2 == CMWEBStateDB::ConnectResult::INVALID);
    BOOST_CHECK_EQUAL(o2, 2u);
}

BOOST_AUTO_TEST_SUITE_END()
