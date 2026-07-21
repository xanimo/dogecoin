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
// being created.
struct Coin {
    uint64_t value;
    BlindingFactor blind;
};

// Constructs valid MWEB transactions -- the inverse of Transaction::Validate.
// The wallet knows the values and blinding factors; the builder turns them into
// commitments, range proofs, and a correctly-signed, balanced kernel.
class TxBuilder {
public:
    // Build a transaction that spends `inputs`, creates `outputs`, pays `fee`,
    // and uses kernel offset `offset`. The caller must provide balanced values:
    //   Sum(input values) == Sum(output values) + fee.
    // The result passes Transaction::Validate. Requires at least one output.
    static Transaction Build(
        const std::vector<Coin>& inputs,
        const std::vector<Coin>& outputs,
        uint64_t fee,
        const BlindingFactor& offset)
    {
        // Inputs: commit to each spent coin.
        std::vector<Input> ins;
        for (const Coin& c : inputs) {
            const Commitment commit = Pedersen::Commit(c.value, c.blind);
            ins.emplace_back(0, Hashed(commit), commit,
                             PublicKey(), PublicKey(), Signature());
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

        const uint8_t features = Kernel::FEE_FEATURE_BIT;
        const mw::Hash message =
            Kernel(features, static_cast<CAmount>(fee), 0, 0, excessCommit, Signature())
                .GetSignatureMessage();
        Kernel kernel(features, static_cast<CAmount>(fee), 0, 0, excessCommit,
                      Schnorr::Sign(excess, message.data()));

        // Bodies must be sorted by hash for Validate to accept them.
        std::sort(ins.begin(), ins.end(),
                  [](const Input& a, const Input& b) { return a.GetHash() < b.GetHash(); });
        std::sort(outs.begin(), outs.end(),
                  [](const Output& a, const Output& b) { return a.GetHash() < b.GetHash(); });

        std::vector<Kernel> kers; kers.push_back(kernel);
        return Transaction(offset, BlindingFactor(),
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

    static SecretKey ComputeExcess(
        const std::vector<Coin>& inputs,
        const std::vector<Coin>& outputs,
        const BlindingFactor& offset)
    {
        SecretKey excess = ToSecret(outputs[0].blind);
        for (size_t i = 1; i < outputs.size(); ++i) {
            excess = Keys::AddSecretKeys(excess, ToSecret(outputs[i].blind));
        }
        for (const Coin& c : inputs) {
            excess = Keys::AddSecretKeys(excess, Keys::NegateSecretKey(ToSecret(c.blind)));
        }
        if (!offset.IsNull()) {
            excess = Keys::AddSecretKeys(excess, Keys::NegateSecretKey(ToSecret(offset)));
        }
        return excess;
    }
};

}
END_NAMESPACE

#endif // MW_WALLET_TXBUILDER_H
