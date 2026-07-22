// Copyright (c) 2021 The Litecoin Core developers
// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef DOGECOIN_MWEB_WALLET_H
#define DOGECOIN_MWEB_WALLET_H

#include <primitives/transaction.h>
#include <amount.h>
#include <random.h>
#include <script/standard.h>
#include <mw/models/tx/Transaction.h>
#include <mw/models/tx/TxBody.h>
#include <mw/models/crypto/BlindingFactor.h>
#include <mw/models/crypto/SecretKey.h>
#include <mw/wallet/TxBuilder.h>
#include <mw/wallet/Stealth.h>

#include <memory>
#include <stdexcept>
#include <vector>

namespace MWEB {

/// Wallet-side assembly of MWEB transactions into canonical CTransactions.
///
/// The cryptographic MWEB body (commitments, range proofs, kernels) is built
/// by the libmw wallet TxBuilder; this layer bridges that body to the canonical
/// chain by attaching the CTransaction structure the consensus rules require.
///
/// These helpers are header-only (inline): they are used only by the wallet and
/// the tests, and inlining keeps them out of the server library so no wallet ->
/// server archive dependency is introduced at link time.
namespace Wallet {

/// Assemble a peg-in CTransaction from an already-built MWEB transaction.
///
/// A peg-in moves value from the canonical chain into the MWEB. On the MWEB
/// side each peg-in is a kernel carrying an amount (mwtx.GetPegIns()); on the
/// canonical side that value must appear as an output paying a peg-in witness
/// program keyed by the kernel ID (see GetScriptForMWEBPegin). This helper adds
/// one such output per peg-in coin so MWEB::Node::CheckTransaction's peg-in
/// match succeeds.
///
/// `canonicalInputs` are the canonical coins that fund the peg-in (supplied by
/// the wallet's coin selection); this helper does not select or sign them.
inline CTransaction CreatePegInTransaction(
    const mw::Transaction& mwtx,
    const std::vector<CTxIn>& canonicalInputs)
{
    CMutableTransaction mtx;
    mtx.vin = canonicalInputs;
    mtx.mweb_tx = MWEB::Tx(std::make_shared<mw::Transaction>(mwtx));

    // Pair each MWEB peg-in kernel with a canonical peg-in output carrying the
    // same amount and keyed by the kernel ID. This is exactly what the node's
    // peg-in match verifies in MWEB::Node::CheckTransaction.
    for (const mw::PegInCoin& pegin : mwtx.GetPegIns()) {
        mtx.vout.emplace_back(pegin.GetAmount(), GetScriptForMWEBPegin(pegin.GetKernelID()));
    }

    return CTransaction(mtx);
}

/// The MWEB side of a peg-in the wallet has built: the MWEB transaction plus the
/// secret (blinding factor) and value of the single output it creates, which the
/// wallet needs in order to spend that output later.
struct PegInResult {
    mw::Transaction tx;
    mw::BlindingFactor outputBlind;
    CAmount outputValue{0};
};

/// Build the MWEB side of a peg-in: peg `pegInAmount` in from the canonical chain
/// and create one MWEB output worth `pegInAmount - mwebFee` under a fresh random
/// blinding factor, with a fresh random kernel offset. The returned transaction
/// passes Transaction::Validate. The caller (the wallet) funds and signs the
/// canonical peg-in output separately. Requires pegInAmount > mwebFee.
inline PegInResult BuildPegIn(CAmount pegInAmount, CAmount mwebFee)
{
    if (pegInAmount <= mwebFee) {
        throw std::runtime_error("peg-in amount must exceed the MWEB fee");
    }

    // Fresh random secrets: the output's blinding factor and the kernel offset.
    std::vector<uint8_t> blindBytes(mw::BlindingFactor::SIZE);
    std::vector<uint8_t> offsetBytes(mw::BlindingFactor::SIZE);
    GetStrongRandBytes(blindBytes.data(), static_cast<int>(blindBytes.size()));
    GetStrongRandBytes(offsetBytes.data(), static_cast<int>(offsetBytes.size()));

    PegInResult result;
    result.outputBlind = mw::BlindingFactor(blindBytes);
    result.outputValue = pegInAmount - mwebFee;

    const std::vector<mw::wallet::Coin> inputs;
    const std::vector<mw::wallet::Coin> outputs = {
        { static_cast<uint64_t>(result.outputValue), result.outputBlind }
    };
    result.tx = mw::wallet::TxBuilder::Build(
        inputs, outputs,
        static_cast<uint64_t>(mwebFee),
        static_cast<uint64_t>(pegInAmount),
        mw::BlindingFactor(offsetBytes));

    return result;
}

/// Rebuild `tx` with its single output replaced by `stealthOutput`. Only the
/// output's key-exchange fields change; its commitment (and so the kernel excess
/// and the value balance) are unchanged because the stealth output was built with
/// the same value and blinding factor. This lets us reuse TxBuilder to construct
/// and sign the kernel, then swap in an output the recipient can recognise and
/// open by scanning -- without teaching TxBuilder about stealth addresses.
///
/// The stealth output introduces a sender key (`ephemeral`*G) into the stealth
/// (owner-key) balance, so fold `ephemeral` into the transaction's stealth offset
/// to keep Sum(sender keys) - Sum(owner keys) == stealthOffset*G.
inline mw::Transaction WithStealthOutput(const mw::Transaction& tx, const mw::Output& stealthOutput,
                                         const mw::SecretKey& ephemeral)
{
    std::vector<mw::Input> inputs = tx.GetInputs();
    std::vector<mw::Output> outputs = { stealthOutput };
    std::vector<mw::Kernel> kernels = tx.GetKernels();

    const mw::BlindingFactor& prev = tx.GetStealthOffset();
    const mw::BlindingFactor stealthOffset = prev.IsNull()
        ? mw::BlindingFactor(ephemeral.vec())
        : mw::BlindingFactor(mw::Keys::AddSecretKeys(mw::SecretKey(prev.vec()), ephemeral).vec());

    return mw::Transaction(tx.GetKernelOffset(), stealthOffset,
                           mw::TxBody(std::move(inputs), std::move(outputs), std::move(kernels)));
}

/// Build the MWEB side of a peg-in whose output is a stealth output to `address`,
/// so the wallet (or any recipient) can recover it by scanning the MWEB UTXO set
/// -- no out-of-band secret needed. Equivalent to BuildPegIn but the created
/// output carries the stealth key-exchange data. Requires pegInAmount > mwebFee.
inline PegInResult BuildPegIn(CAmount pegInAmount, CAmount mwebFee,
                              const mw::wallet::StealthAddress& address)
{
    if (pegInAmount <= mwebFee) {
        throw std::runtime_error("peg-in amount must exceed the MWEB fee");
    }
    const CAmount outValue = pegInAmount - mwebFee;

    std::vector<uint8_t> ephBytes(mw::SecretKey::SIZE);
    std::vector<uint8_t> offsetBytes(mw::BlindingFactor::SIZE);
    GetStrongRandBytes(ephBytes.data(), static_cast<int>(ephBytes.size()));
    GetStrongRandBytes(offsetBytes.data(), static_cast<int>(offsetBytes.size()));

    // The stealth output's blind is derived from the ECDH secret, so the recipient
    // recovers it from the output alone.
    const mw::SecretKey ephemeral(ephBytes);
    const mw::wallet::StealthResult sr =
        mw::wallet::Stealth::Send(address, static_cast<uint64_t>(outValue), ephemeral);

    const mw::Transaction plain = mw::wallet::TxBuilder::Build(
        {}, { { static_cast<uint64_t>(outValue), sr.blind } },
        static_cast<uint64_t>(mwebFee), static_cast<uint64_t>(pegInAmount),
        mw::BlindingFactor(offsetBytes));

    PegInResult result;
    result.tx = WithStealthOutput(plain, sr.output, ephemeral);
    result.outputBlind = sr.blind;
    result.outputValue = outValue;
    return result;
}

/// Build an MWEB-only spend of `input`, creating one stealth output worth
/// (input value - mwebFee) to `address`, recoverable by scanning. The change (or
/// payment) coin is thus a full spendable coin for the recipient without any
/// out-of-band secret. Requires input.amount > mwebFee.
inline mw::Transaction BuildStealthSpend(
    const mw::wallet::Coin& input, CAmount mwebFee,
    const mw::wallet::StealthAddress& address)
{
    if (input.value <= static_cast<uint64_t>(mwebFee)) {
        throw std::runtime_error("MWEB input must exceed the MWEB fee");
    }
    const CAmount outValue = static_cast<CAmount>(input.value) - mwebFee;

    std::vector<uint8_t> ephBytes(mw::SecretKey::SIZE);
    std::vector<uint8_t> offsetBytes(mw::BlindingFactor::SIZE);
    GetStrongRandBytes(ephBytes.data(), static_cast<int>(ephBytes.size()));
    GetStrongRandBytes(offsetBytes.data(), static_cast<int>(offsetBytes.size()));

    const mw::SecretKey ephemeral(ephBytes);
    const mw::wallet::StealthResult sr =
        mw::wallet::Stealth::Send(address, static_cast<uint64_t>(outValue), ephemeral);

    const mw::Transaction plain = mw::wallet::TxBuilder::Build(
        { input }, { { static_cast<uint64_t>(outValue), sr.blind } },
        static_cast<uint64_t>(mwebFee), mw::BlindingFactor(offsetBytes));

    return WithStealthOutput(plain, sr.output, ephemeral);
}

} // namespace Wallet

} // namespace MWEB

#endif // DOGECOIN_MWEB_WALLET_H
