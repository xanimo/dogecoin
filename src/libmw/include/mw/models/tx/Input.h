// Copyright (c) 2021 The Litecoin Core developers
// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef MW_MODELS_TX_INPUT_H
#define MW_MODELS_TX_INPUT_H

#include <mw/common/Traits.h>
#include <mw/models/crypto/Commitment.h>
#include <mw/models/crypto/PublicKey.h>
#include <mw/models/crypto/Signature.h>
#include <hash.h>
#include <serialize.h>
#include <uint256.h>
#include <vector>
#include <memory>

MW_NAMESPACE

/// A MimbleWimble transaction input. Spends a previously created output
/// by referencing its output ID (hash) and proving ownership via signature.
class Input : public Traits::IHashable {
public:
    enum FeatureBit : uint8_t {
        STEALTH_KEY_FEATURE_BIT = 0x01,
        EXTRA_DATA_FEATURE_BIT  = 0x02,
    };

    using CPtr = std::shared_ptr<const Input>;
    using Ptr = std::shared_ptr<Input>;

    Input() : m_features(0) {}

    Input(
        uint8_t features,
        mw::Hash outputID,
        Commitment commitment,
        PublicKey inputPubKey,
        PublicKey outputPubKey,
        Signature signature)
        : m_features(features),
          m_outputID(std::move(outputID)),
          m_commitment(std::move(commitment)),
          m_inputPubKey(std::move(inputPubKey)),
          m_outputPubKey(std::move(outputPubKey)),
          m_signature(std::move(signature)) {}

    // Getters
    uint8_t GetFeatures() const { return m_features; }
    const mw::Hash& GetOutputID() const { return m_outputID; }
    const Commitment& GetCommitment() const { return m_commitment; }
    const PublicKey& GetInputPubKey() const { return m_inputPubKey; }
    const PublicKey& GetOutputPubKey() const { return m_outputPubKey; }
    const Signature& GetSignature() const { return m_signature; }

    bool HasStealthKey() const { return m_features & STEALTH_KEY_FEATURE_BIT; }
    const std::vector<uint8_t>& GetExtraData() const { return m_extraData; }

    const mw::Hash& GetHash() const override {
        if (m_hash.IsNull()) {
            m_hash = Hashed(*this);
        }
        return m_hash;
    }

    // The bytes the owner signature commits to: the whole input except the
    // signature itself. Mirrors Kernel::SerializeSigMessage; Serialize reuses it
    // so the signed message and the wire encoding can never drift apart.
    template<typename Stream>
    void SerializeSigMessage(Stream& s) const {
        s << m_features;
        s << m_outputID;
        s << m_commitment;
        if (m_features & STEALTH_KEY_FEATURE_BIT) s << m_inputPubKey;
        s << m_outputPubKey;
        if (m_features & EXTRA_DATA_FEATURE_BIT) {
            WriteCompactSize(s, m_extraData.size());
            s.write((const char*)m_extraData.data(), m_extraData.size());
        }
    }

    // Message the input's owner signature must verify against (its output pubkey
    // being the verifying key). Do NOT use GetHash(): that includes the signature.
    mw::Hash GetSignatureMessage() const {
        CHashWriter ss(SER_GETHASH, 0);
        SerializeSigMessage(ss);
        return mw::Hash(ss.GetHash());
    }

    template<typename Stream>
    void Serialize(Stream& s) const {
        SerializeSigMessage(s);
        s << m_signature;
    }

    template<typename Stream>
    void Unserialize(Stream& s) {
        s >> m_features;
        s >> m_outputID;
        s >> m_commitment;
        if (m_features & STEALTH_KEY_FEATURE_BIT) s >> m_inputPubKey;
        else m_inputPubKey = PublicKey();
        s >> m_outputPubKey;
        if (m_features & EXTRA_DATA_FEATURE_BIT) {
            size_t len = ReadCompactSize(s);
            m_extraData.resize(len);
            s.read((char*)m_extraData.data(), len);
        } else {
            m_extraData.clear();
        }
        s >> m_signature;
        m_hash = mw::Hash(); // reset cached hash
    }

private:
    uint8_t m_features;
    mw::Hash m_outputID;
    Commitment m_commitment;
    PublicKey m_inputPubKey;
    PublicKey m_outputPubKey;
    std::vector<uint8_t> m_extraData;
    Signature m_signature;
    mutable mw::Hash m_hash;
};

END_NAMESPACE

#endif // MW_MODELS_TX_INPUT_H
