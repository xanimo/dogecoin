// Copyright (c) 2021 The Litecoin Core developers
// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef MW_CONSENSUS_STEALTHSUMVALIDATOR_H
#define MW_CONSENSUS_STEALTHSUMVALIDATOR_H

#include <mw/models/tx/TxBody.h>
#include <mw/models/crypto/BlindingFactor.h>
#include <mw/crypto/Keys.h>

#include <stdexcept>
#include <vector>

MW_NAMESPACE

/// The one-sided-payment keys must tie to the stealth offset the way the value
/// blinds tie to the kernel offset:
///
///   Sum(output sender keys) - Sum(input owner keys)
///       - Sum(kernel stealth excesses) == stealthOffset*G
///
/// Each output's sender key is the ephemeral key the sender chose; each spent
/// input's owner key is the one-time key of the output it consumes; each kernel
/// stealth excess is a key the kernel signer owns, proven by the weighted
/// verification key (see KernelKey.h). This makes owner keys non-malleable under
/// the aggregation of transactions into a block, since the block offset is the
/// sum of the transaction offsets.
///
/// Litecoin's equation is `Sum(K_s) + Sum(K_i) == Sum(E') + x'*G + Sum(K_o)`.
/// This is that identity with the input stealth keys `K_i` dropped, the one key
/// class the port does not use.
class StealthSumValidator
{
public:
    /// Validate a complete body against its stealth offset. Throws on failure.
    /// Callers must have already rejected outputs with no sender key and inputs
    /// with no owner key; this only checks that the keys present balance.
    static void Validate(const TxBody& body, const BlindingFactor& stealthOffset)
    {
        std::vector<PublicKey> senderKeys;
        std::vector<PublicKey> ownerKeys;

        for (const Output& output : body.GetOutputs()) {
            senderKeys.push_back(output.GetSenderPubKey());
        }
        for (const Input& input : body.GetInputs()) {
            ownerKeys.push_back(input.GetOutputPubKey());
        }
        for (const Kernel& kernel : body.GetKernels()) {
            if (kernel.HasStealthExcess()) {
                ownerKeys.push_back(kernel.GetStealthExcess());
            }
        }

        if (!Keys::VerifyKeyBalance(senderKeys, ownerKeys, stealthOffset)) {
            throw std::runtime_error("Stealth offset does not balance");
        }
    }
};

END_NAMESPACE

#endif // MW_CONSENSUS_STEALTHSUMVALIDATOR_H
