// Copyright (c) 2021 The Litecoin Core developers
// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef MW_CONSENSUS_INPUTKEY_H
#define MW_CONSENSUS_INPUTKEY_H

#include <mw/models/tx/Input.h>
#include <mw/crypto/Keys.h>

#include <hash.h>

#include <stdexcept>
#include <vector>

MW_NAMESPACE

/// The hash coefficient H(K_i||K_o) weighting an output's one-time key against
/// the spender's per-spend input key. Both keys are in the input's signed
/// message, so a verifier recomputes it rather than trusting a carried one.
inline SecretKey StealthKeyCoefficient(const PublicKey& inputPubKey,
                                       const PublicKey& outputPubKey)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << inputPubKey << outputPubKey;
    const uint256 h = ss.GetHash();
    return SecretKey(std::vector<uint8_t>(h.begin(), h.end()));
}

/// The public key an input signature verifies against.
///
/// Without a stealth key this is the spent output's one-time key K_o alone.
/// With one it is litecoin's aggregate
///
///   K_agg = K_i + H(K_i||K_o)*K_o
///
/// so satisfying it needs the secret behind K_o and the one behind K_i both.
/// The coefficient defends against the rogue-key choice K_i = K - K_o, which
/// would otherwise let a signer knowing only k satisfy a plain K_i + K_o and
/// spend an output it does not own.
///
/// Note this port signs a wider message than litecoin does (the commitment and
/// both keys are in it, see Input::SerializeSigMessage), so the aggregate is
/// additional binding here rather than the only binding.
inline PublicKey InputVerificationKey(const Input& input)
{
    const PublicKey& outputPubKey = input.GetOutputPubKey();
    if (!input.HasStealthKey()) {
        return outputPubKey;
    }

    const PublicKey& inputPubKey = input.GetInputPubKey();
    if (inputPubKey.IsNull()) {
        throw std::runtime_error("Input claims a stealth key with no key");
    }

    const SecretKey coefficient = StealthKeyCoefficient(inputPubKey, outputPubKey);
    return Keys::AddPublicKeys(Keys::MulPublicKey(outputPubKey, coefficient), inputPubKey);
}

END_NAMESPACE

#endif // MW_CONSENSUS_INPUTKEY_H
