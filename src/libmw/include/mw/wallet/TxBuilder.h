// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef MW_WALLET_TXBUILDER_H
#define MW_WALLET_TXBUILDER_H

#include <mw/common/Macros.h>
#include <mw/models/tx/Transaction.h>
#include <mw/crypto/Pedersen.h>
#include <mw/crypto/Bulletproof.h>
#include <mw/crypto/Schnorr.h>
#include <mw/crypto/Keys.h>

#include <algorithm>
#include <vector>

MW_NAMESPACE
namespace wallet {

// A value committed under a blinding factor: an input being spent or an output
// being created. When spending a specific existing output, `outputID` carries
// that output's ID (Output::GetOutputID(), a hash of the whole output) so the
// input references it and the accumulator can find and spend it. `spendKey` is
// the output's one-time private key (the recipient recovers it via
// Stealth::RecoverSpendKey); when set, the input is signed with it to prove
// ownership. Both are left null for outputs, and for inputs in tests that only
// exercise the value balance. All members zero-initialise, keeping Coin an
// aggregate.
struct Coin {
    uint64_t value;
    BlindingFactor blind;
    mw::Hash outputID;
    SecretKey spendKey;
};

// Constructs valid MWEB transactions -- the inverse of Transaction::Validate.
// The wallet knows the values and blinding factors; the builder turns them into
// commitments, range proofs, and a correctly-signed, balanced kernel.
class TxBuilder {
public:
    // Build a transaction spending `inputs`, creating `outputs`, paying `fee`.
    // Convenience overload with no peg-in (a pure in-MWEB transfer).
    static Transaction Build(
        const std::vector<Coin>& inputs,
        const std::vector<Coin>& outputs,
        uint64_t fee,
        const BlindingFactor& offset)
    {
        return Build(inputs, outputs, fee, /*pegin=*/0, offset);
    }

    // Build with a peg-in but no peg-out.
    static Transaction Build(
        const std::vector<Coin>& inputs,
        const std::vector<Coin>& outputs,
        uint64_t fee,
        uint64_t pegin,
        const BlindingFactor& offset)
    {
        return Build(inputs, outputs, fee, pegin, std::vector<PegOutCoin>{}, offset);
    }

    // Build a transaction that spends `inputs`, creates `outputs`, pays `fee`,
    // pegs in `pegin` and pegs out `pegouts`, using kernel offset `offset`.
    // Balanced values required:
    //   Sum(input values) + pegin == Sum(output values) + fee + Sum(pegout amounts).
    // The result passes Transaction::Validate. Needs at least one output or input
    // (a pure peg-out may have no MWEB outputs).
    static Transaction Build(
        const std::vector<Coin>& inputs,
        const std::vector<Coin>& outputs,
        uint64_t fee,
        uint64_t pegin,
        std::vector<PegOutCoin> pegouts,
        const BlindingFactor& offset)
    {
        // Inputs: commit to each spent coin. When the caller supplies the output
        // ID of the coin being spent, reference it so the accumulator can find and
        // spend the real output; otherwise fall back to the commitment hash (used
        // by value-balance-only tests that do not reference on-chain outputs).
        std::vector<Input> ins;
        for (const Coin& c : inputs) {
            const Commitment commit = Pedersen::Commit(c.value, c.blind);
            const mw::Hash outID = c.outputID.IsNull() ? Hashed(commit) : c.outputID;
            if (c.spendKey.IsNull()) {
                // Value-balance-only input (tests): no owner key or signature.
                ins.emplace_back(0, outID, commit,
                                 PublicKey(), PublicKey(), Signature());
            } else {
                // Owner-signed input: the output's one-time public key is the
                // verifying key, and we sign the input with its private key to
                // prove the right to spend the referenced output.
                const PublicKey ownerPubKey = Keys::PublicKeyFrom(c.spendKey);
                const Input unsigned_in(0, outID, commit, PublicKey(), ownerPubKey, Signature());
                const mw::Hash msg = unsigned_in.GetSignatureMessage();
                ins.emplace_back(0, outID, commit, PublicKey(), ownerPubKey,
                                 Schnorr::Sign(c.spendKey, msg.data()));
            }
        }

        // Outputs: commit and range-prove each new coin.
        std::vector<Output> outs;
        for (const Coin& c : outputs) {
            const Commitment commit = Pedersen::Commit(c.value, c.blind);
            auto proof = std::make_shared<RangeProof>(Bulletproof::Prove(c.value, c.blind));
            outs.emplace_back(commit, PublicKey(), PublicKey(), OutputMessage(),
                              proof, Signature());
        }

        // Kernel excess = Sum(output blinds) - Sum(input blinds) - offset.
        // With balanced values this is the blinding that makes the commitments
        // sum to zero; the excess*G commitment is signed to prove ownership.
        const SecretKey excess = ComputeExcess(inputs, outputs, offset);
        const Commitment excessCommit = Pedersen::Commit(0, ToBlind(excess));

        uint8_t features = Kernel::FEE_FEATURE_BIT;
        if (pegin > 0) features |= Kernel::PEGIN_FEATURE_BIT;
        if (!pegouts.empty()) features |= Kernel::PEGOUT_FEATURE_BIT;
        const CAmount feeAmt = static_cast<CAmount>(fee);
        const CAmount peginAmt = static_cast<CAmount>(pegin);
        const mw::Hash message =
            Kernel(features, feeAmt, peginAmt, pegouts, 0, excessCommit, Signature())
                .GetSignatureMessage();
        Kernel kernel(features, feeAmt, peginAmt, std::move(pegouts), 0, excessCommit,
                      Schnorr::Sign(excess, message.data()));

        // Bodies must be sorted by hash for Validate to accept them.
        std::sort(ins.begin(), ins.end(),
                  [](const Input& a, const Input& b) { return a.GetHash() < b.GetHash(); });
        std::sort(outs.begin(), outs.end(),
                  [](const Output& a, const Output& b) { return a.GetHash() < b.GetHash(); });

        // Stealth (owner-key) offset: negate the sum of the signed inputs' spend
        // keys. Since these inputs carry those keys' public keys as their owner
        // keys, this makes the stealth balance
        //   Sum(output sender keys) - Sum(input owner keys) == stealthOffset*G
        // hold for a body whose outputs have no sender key (plain outputs, and
        // pure peg-outs with no MWEB output). A stealth output added afterwards
        // via WithStealthOutput folds its ephemeral sender key into this offset.
        const BlindingFactor stealthOffset = ComputeStealthOffset(inputs);

        std::vector<Kernel> kers; kers.push_back(kernel);
        return Transaction(offset, stealthOffset,
            TxBody(std::move(ins), std::move(outs), std::move(kers)));
    }

private:
    static SecretKey ToSecret(const BlindingFactor& b)
    {
        return SecretKey(std::vector<uint8_t>(b.data(), b.data() + BlindingFactor::SIZE));
    }
    static BlindingFactor ToBlind(const SecretKey& s)
    {
        return BlindingFactor(std::vector<uint8_t>(s.data(), s.data() + SecretKey::SIZE));
    }

    // -Sum(spend keys of the signed inputs). Inputs without a spend key (value-
    // balance-only) contribute nothing; with none, the offset is null (identity).
    static BlindingFactor ComputeStealthOffset(const std::vector<Coin>& inputs)
    {
        bool have = false;
        SecretKey acc;
        for (const Coin& c : inputs) {
            if (c.spendKey.IsNull()) continue;
            acc = have ? Keys::AddSecretKeys(acc, c.spendKey) : c.spendKey;
            have = true;
        }
        if (!have) return BlindingFactor();
        return ToBlind(Keys::NegateSecretKey(acc));
    }

    // excess = Sum(output blinds) - Sum(input blinds) - offset. Folds robustly so
    // it works with no outputs (a pure peg-out) as long as there is some term.
    static SecretKey ComputeExcess(
        const std::vector<Coin>& inputs,
        const std::vector<Coin>& outputs,
        const BlindingFactor& offset)
    {
        bool have = false;
        SecretKey acc;
        auto addPositive = [&](const SecretKey& s) {
            acc = have ? Keys::AddSecretKeys(acc, s) : s;
            have = true;
        };
        auto addNegative = [&](const SecretKey& s) {
            const SecretKey neg = Keys::NegateSecretKey(s);
            acc = have ? Keys::AddSecretKeys(acc, neg) : neg;
            have = true;
        };

        for (const Coin& c : outputs) addPositive(ToSecret(c.blind));
        for (const Coin& c : inputs)  addNegative(ToSecret(c.blind));
        if (!offset.IsNull()) addNegative(ToSecret(offset));
        return acc;
    }
};

}
END_NAMESPACE

#endif // MW_WALLET_TXBUILDER_H
