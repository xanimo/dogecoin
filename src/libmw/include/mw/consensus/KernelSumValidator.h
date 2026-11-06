// Copyright (c) 2021 The Litecoin Core developers
// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef MW_CONSENSUS_KERNELSUMVALIDATOR_H
#define MW_CONSENSUS_KERNELSUMVALIDATOR_H

#include <mw/models/tx/TxBody.h>
#include <mw/models/crypto/BlindingFactor.h>
#include <mw/crypto/Pedersen.h>

#include <stdexcept>
#include <vector>

MW_NAMESPACE

/// The anti-inflation check: a body's commitments must sum to zero once the
/// kernel offset and the value entering or leaving the MWEB are accounted for.
///
///   Sum(outputs) + (fees + pegouts)*H
///     == Sum(inputs) + Sum(kernel excesses) + pegins*H + offset*G
///
/// Checked as sum-to-zero. Fees and pegs are non-negative, so the H value is
/// split across both sides rather than committing a negative amount; zero terms
/// are skipped, since their commitment is the point at infinity.
class KernelSumValidator
{
public:
    /// Validate a complete body against its kernel offset. Throws on failure.
    static void Validate(const TxBody& body, const BlindingFactor& kernelOffset)
    {
        std::vector<Commitment> positive;
        std::vector<Commitment> negative;

        for (const Output& output : body.GetOutputs()) {
            positive.push_back(output.GetCommitment());
        }
        for (const Input& input : body.GetInputs()) {
            negative.push_back(input.GetCommitment());
        }

        uint64_t hPositive = 0; // fees + pegouts: value leaving the MWEB balance
        uint64_t hNegative = 0; // pegins: value entering the MWEB balance
        for (const Kernel& kernel : body.GetKernels()) {
            negative.push_back(kernel.GetExcess());
            hPositive += static_cast<uint64_t>(kernel.GetFee());
            for (const PegOutCoin& pegout : kernel.GetPegOuts()) {
                hPositive += static_cast<uint64_t>(pegout.GetAmount());
            }
            hNegative += static_cast<uint64_t>(kernel.GetPegIn());
        }

        const BlindingFactor zeroBlind;
        if (hPositive > 0) positive.push_back(Pedersen::Commit(hPositive, zeroBlind));
        if (hNegative > 0) negative.push_back(Pedersen::Commit(hNegative, zeroBlind));
        if (!kernelOffset.IsNull()) {
            negative.push_back(Pedersen::Commit(0, kernelOffset));
        }

        if (!Pedersen::VerifyBalance(positive, negative)) {
            throw std::runtime_error("Body does not balance (inflation)");
        }
    }
};

END_NAMESPACE

#endif // MW_CONSENSUS_KERNELSUMVALIDATOR_H
