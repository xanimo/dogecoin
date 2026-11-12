// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef MW_WALLET_TXBUILDER_H
#define MW_WALLET_TXBUILDER_H

#include <mw/common/Macros.h>
#include <mw/consensus/InputKey.h>
#include <mw/consensus/KernelKey.h>
#include <mw/models/tx/Transaction.h>
#include <mw/crypto/Pedersen.h>
#include <mw/crypto/Bulletproof.h>
#include <mw/crypto/Schnorr.h>
#include <mw/crypto/Keys.h>

#include <random.h>

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
    SecretKey spendKey;     // one-time key of the output being spent (inputs)
    SecretKey senderKey;    // ephemeral key signing a new output (outputs)
    PublicKey receiverPubKey; // one-time key the new output pays to (outputs)
    SecretKey inputKey;     // per-spend stealth key aggregated into the input
                            // signature (inputs); derived from the spend key and
                            // output ID when left null
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
    // Every kernel carries a stealth excess E' = stealthBlind*G. A caller may
    // supply the blind; otherwise one is drawn here. It must never be null: the
    // offset is Sum(sender keys) - Sum(spend keys) - stealthBlind, so a body
    // with no inputs publishes a sender key and a body with no outputs
    // publishes a spend key, and both of those are secret. Litecoin draws one
    // per kernel for the same reason.
    static Transaction Build(
        const std::vector<Coin>& inputs,
        const std::vector<Coin>& outputs,
        uint64_t fee,
        uint64_t pegin,
        std::vector<PegOutCoin> pegouts,
        const BlindingFactor& offset,
        const SecretKey& suppliedStealthBlind = SecretKey())
    {
        // Drawn before use, so every path below has a non-null blind.
        const SecretKey stealthBlind = suppliedStealthBlind.IsNull()
            ? RandomStealthBlind() : suppliedStealthBlind;

        // Inputs: commit to each spent coin. When the caller supplies the output
        // ID of the coin being spent, reference it so the accumulator can find and
        // spend the real output; otherwise fall back to the commitment hash (used
        // by value-balance-only tests that do not reference on-chain outputs).
        std::vector<Input> ins;
        for (const Coin& c : inputs) {
            const Commitment commit = Pedersen::Commit(c.value, c.blind);
            const mw::Hash outID = SpentOutputID(c);
            // Owner-signed input, with the per-spend stealth key litecoin's
            // wallet always sets. The verifying key is the aggregate
            // K_i + H(K_i||K_o)*K_o, so the signature needs both the output's
            // one-time key and the fresh input key. A coin with no spend key
            // cannot be spent; building one would produce a body the validator
            // rejects.
            if (c.spendKey.IsNull()) {
                throw std::runtime_error("Cannot spend a coin with no spend key");
            }
            const PublicKey ownerPubKey = Keys::PublicKeyFrom(c.spendKey);
            const SecretKey inputKey = InputStealthKey(c, outID);
            const PublicKey inputPubKey = Keys::PublicKeyFrom(inputKey);

            // k_agg = k_i + H(K_i||K_o)*k_o, the scalar counterpart of the key
            // InputVerificationKey rebuilds.
            const SecretKey coefficient = StealthKeyCoefficient(inputPubKey, ownerPubKey);
            const SecretKey sigKey = Keys::AddSecretKeys(
                Keys::MulSecretKeys(c.spendKey, coefficient), inputKey);

            const uint8_t inFeatures = Input::STEALTH_KEY_FEATURE_BIT;
            const Input unsigned_in(inFeatures, outID, commit, inputPubKey, ownerPubKey,
                                    Signature());
            const mw::Hash msg = unsigned_in.GetSignatureMessage();
            ins.emplace_back(inFeatures, outID, commit, inputPubKey, ownerPubKey,
                             Schnorr::Sign(sigKey, msg.data()));
        }

        // Outputs: commit and range-prove each new coin, then sign it with the
        // sender key so the receiver key and message cannot be swapped in flight.
        // A coin with no sender key gets a deterministic one derived from its
        // blind, so every output carries one.
        std::vector<Output> outs;
        for (const Coin& c : outputs) {
            const Commitment commit = Pedersen::Commit(c.value, c.blind);
            auto proof = std::make_shared<RangeProof>(Bulletproof::Prove(c.value, c.blind));
            const SecretKey senderKey = OutputSenderKey(c);
            const PublicKey senderPubKey = Keys::PublicKeyFrom(senderKey);
            const PublicKey receiverPubKey =
                c.receiverPubKey.IsNull() ? senderPubKey : c.receiverPubKey;
            const Output unsigned_out(commit, senderPubKey, receiverPubKey,
                                      OutputMessage(), proof, Signature());
            outs.emplace_back(commit, senderPubKey, receiverPubKey, OutputMessage(), proof,
                              Schnorr::Sign(senderKey, unsigned_out.GetSignatureMessage().data()));
        }

        // Kernel excess = Sum(output blinds) - Sum(input blinds) - offset.
        // With balanced values this is the blinding that makes the commitments
        // sum to zero; the excess*G commitment is signed to prove ownership.
        const SecretKey excess = ComputeExcess(inputs, outputs, offset);
        const Commitment excessCommit = Pedersen::Commit(0, ToBlind(excess));

        uint8_t features = Kernel::FEE_FEATURE_BIT;
        if (pegin > 0) features |= Kernel::PEGIN_FEATURE_BIT;
        if (!pegouts.empty()) features |= Kernel::PEGOUT_FEATURE_BIT;
        features |= Kernel::STEALTH_EXCESS_FEATURE_BIT;
        const CAmount feeAmt = static_cast<CAmount>(fee);
        const CAmount peginAmt = static_cast<CAmount>(pegin);

        // With a stealth excess the signing key is weighted to match the key the
        // verifier rebuilds: k = excess*H(X||X_s) + stealthBlind. Both keys are in
        // the signed message, so the coefficient is fixed before the signature.
        const PublicKey stealthExcess = Keys::PublicKeyFrom(stealthBlind);
        const SecretKey coefficient =
            StealthExcessCoefficient(Pedersen::ToPublicKey(excessCommit), stealthExcess);
        const SecretKey sigKey =
            Keys::AddSecretKeys(Keys::MulSecretKeys(excess, coefficient), stealthBlind);

        const mw::Hash message =
            Kernel(features, feeAmt, peginAmt, pegouts, 0, stealthExcess, excessCommit,
                   Signature())
                .GetSignatureMessage();
        Kernel kernel(features, feeAmt, peginAmt, std::move(pegouts), 0, stealthExcess,
                      excessCommit, Schnorr::Sign(sigKey, message.data()));

        // Bodies must be sorted by hash for Validate to accept them.
        std::sort(ins.begin(), ins.end(),
                  [](const Input& a, const Input& b) { return a.GetHash() < b.GetHash(); });
        std::sort(outs.begin(), outs.end(),
                  [](const Output& a, const Output& b) { return a.GetHash() < b.GetHash(); });

        // Stealth (owner-key) offset: the sum of the outputs' sender keys less
        // the sum of the signed inputs' spend keys, which is what the stealth
        // balance checks:
        //   Sum(output sender keys) - Sum(input owner keys) == stealthOffset*G
        // Every output gets a sender key, derived from its blind when the coin
        // supplies none, so every output contributes a term. A caller that
        // substitutes a stealth output afterwards must therefore build its coin
        // with the same sender key that output carries, or the term computed
        // here is not the one the body ends up with.
        const BlindingFactor stealthOffset =
            ComputeStealthOffset(inputs, outputs, stealthBlind);

        std::vector<Kernel> kers; kers.push_back(kernel);
        return Transaction(offset, stealthOffset,
            TxBody(std::move(ins), std::move(outs), std::move(kers)));
    }

    // Exposed so a caller (and the tests) can recompute the per-spend key the
    // builder derives, without duplicating the derivation.
    static SecretKey InputStealthKeyFor(const Coin& c) { return InputStealthKey(c, SpentOutputID(c)); }

private:
    // A fresh stealth blind. Secret, so it comes from the strong pool rather
    // than from anything derived off the coin.
    static SecretKey RandomStealthBlind()
    {
        std::vector<uint8_t> b(SecretKey::SIZE);
        GetStrongRandBytes(b.data(), (int)b.size());
        return SecretKey(b);
    }

    static SecretKey ToSecret(const BlindingFactor& b)
    {
        return SecretKey(std::vector<uint8_t>(b.data(), b.data() + BlindingFactor::SIZE));
    }
    static BlindingFactor ToBlind(const SecretKey& s)
    {
        return BlindingFactor(std::vector<uint8_t>(s.data(), s.data() + SecretKey::SIZE));
    }

    // The sender key of an output with none supplied: deterministic in its blind,
    // so the same coin always yields the same key and the offset below matches.
    static SecretKey OutputSenderKey(const Coin& c)
    {
        if (!c.senderKey.IsNull()) return c.senderKey;
        CHashWriter ss(SER_GETHASH, 0);
        ss << std::vector<uint8_t>(c.blind.data(), c.blind.data() + BlindingFactor::SIZE);
        const uint256 h = ss.GetHash();
        return SecretKey(std::vector<uint8_t>(h.begin(), h.end()));
    }

    // The ID of the output a coin spends: the coin's own when it references a
    // real output, else the commitment hash (value-balance-only tests). Shared by
    // the input loop and the offset so both derive the same stealth key.
    static mw::Hash SpentOutputID(const Coin& c)
    {
        if (!c.outputID.IsNull()) return c.outputID;
        return Hashed(Pedersen::Commit(c.value, c.blind));
    }

    // The per-spend stealth key of an input with none supplied: deterministic in
    // the spend key and the output being spent, so only the owner can compute it
    // and the same spend always yields the same key. Tagged so it cannot collide
    // with the sender-key derivation above.
    static SecretKey InputStealthKey(const Coin& c, const mw::Hash& outputID)
    {
        if (!c.inputKey.IsNull()) return c.inputKey;
        CHashWriter ss(SER_GETHASH, 0);
        ss << std::string("mweb/input-stealth-key");
        ss << std::vector<uint8_t>(c.spendKey.data(), c.spendKey.data() + SecretKey::SIZE);
        ss << outputID;
        const uint256 h = ss.GetHash();
        return SecretKey(std::vector<uint8_t>(h.begin(), h.end()));
    }

    // Sum(output sender keys) + Sum(input stealth keys) - Sum(input spend keys)
    // - the kernel's stealth blind, which is what the stealth balance checks
    // against stealthOffset*G. Every input is signed and every output carries a
    // sender key, so every term contributes; an empty body gives the null offset
    // (identity). The spend keys and the stealth blind are subtracted because
    // their public counterparts sit on the far side of the validator's equation.
    static BlindingFactor ComputeStealthOffset(const std::vector<Coin>& inputs,
                                               const std::vector<Coin>& outputs,
                                               const SecretKey& stealthBlind)
    {
        bool have = false;
        SecretKey acc;
        auto fold = [&](const SecretKey& k) {
            acc = have ? Keys::AddSecretKeys(acc, k) : k;
            have = true;
        };

        for (const Coin& c : outputs) {
            fold(OutputSenderKey(c));
        }
        for (const Coin& c : inputs) {
            if (c.spendKey.IsNull()) continue;
            // Same key the input loop signed with, so the two cannot disagree.
            fold(InputStealthKey(c, SpentOutputID(c)));
            fold(Keys::NegateSecretKey(c.spendKey));
        }
        if (!stealthBlind.IsNull()) {
            fold(Keys::NegateSecretKey(stealthBlind));
        }
        if (!have) return BlindingFactor();
        return ToBlind(acc);
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
