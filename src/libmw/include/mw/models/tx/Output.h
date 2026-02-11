// Copyright (c) 2021 The Litecoin Core developers
// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef MW_MODELS_TX_OUTPUT_H
#define MW_MODELS_TX_OUTPUT_H

#include <mw/common/Traits.h>
#include <mw/models/crypto/Commitment.h>
#include <mw/models/crypto/PublicKey.h>
#include <mw/models/crypto/Signature.h>
#include <mw/models/crypto/RangeProof.h>
#include <serialize.h>
#include <vector>
#include <memory>
#include <cstdint>

MW_NAMESPACE

/// The message portion of an output, containing the key exchange data
/// and masked values needed for the receiver to reconstruct the output.
class OutputMessage {
public:
    enum FeatureBit : uint8_t {
        STANDARD_FIELDS_FEATURE_BIT = 0x01,
        EXTRA_DATA_FEATURE_BIT      = 0x02,
    };

    OutputMessage() : m_features(0), m_viewTag(0), m_maskedValue(0), m_maskedNonce(0) {}

    uint8_t GetFeatures() const { return m_features; }
    const PublicKey& GetKeyExchangePubKey() const { return m_keyExchangePubKey; }
    uint8_t GetViewTag() const { return m_viewTag; }
    uint64_t GetMaskedValue() const { return m_maskedValue; }
    uint64_t GetMaskedNonce() const { return m_maskedNonce; }
    const std::vector<uint8_t>& GetExtraData() const { return m_extraData; }
    bool HasStandardFields() const { return m_features & STANDARD_FIELDS_FEATURE_BIT; }

    template<typename Stream>
    void Serialize(Stream& s) const {
        s << m_features;
        if (m_features & STANDARD_FIELDS_FEATURE_BIT) {
            s << m_keyExchangePubKey;
            s << m_viewTag;
            ser_writedata64(s, m_maskedValue);
            ser_writedata64(s, m_maskedNonce);
        }
        if (m_features & EXTRA_DATA_FEATURE_BIT) {
            WriteCompactSize(s, m_extraData.size());
            s.write((const char*)m_extraData.data(), m_extraData.size());
        }
    }

    template<typename Stream>
    void Unserialize(Stream& s) {
        s >> m_features;
        if (m_features & STANDARD_FIELDS_FEATURE_BIT) {
            s >> m_keyExchangePubKey;
            s >> m_viewTag;
            m_maskedValue = ser_readdata64(s);
            m_maskedNonce = ser_readdata64(s);
        }
        if (m_features & EXTRA_DATA_FEATURE_BIT) {
            size_t len = ReadCompactSize(s);
            m_extraData.resize(len);
            s.read((char*)m_extraData.data(), len);
        } else {
            m_extraData.clear();
        }
    }

private:
    uint8_t m_features;
    PublicKey m_keyExchangePubKey;
    uint8_t m_viewTag;
    uint64_t m_maskedValue;
    uint64_t m_maskedNonce;
    std::vector<uint8_t> m_extraData;
};


/// A MimbleWimble transaction output. Contains a Pedersen commitment
/// hiding the value, public keys for the sender and receiver, an
/// OutputMessage with view tag and masked data, and a Bulletproof
/// range proof proving the committed value is non-negative.
class Output : public Traits::IHashable {
public:
    using CPtr = std::shared_ptr<const Output>;
    using Ptr = std::shared_ptr<Output>;

    Output() = default;

    // Getters
    const Commitment& GetCommitment() const { return m_commitment; }
    const PublicKey& GetSenderPubKey() const { return m_senderPubKey; }
    const PublicKey& GetReceiverPubKey() const { return m_receiverPubKey; }
    const OutputMessage& GetMessage() const { return m_message; }
    const RangeProof::CPtr& GetRangeProof() const { return m_pRangeProof; }
    const Signature& GetSignature() const { return m_signature; }

    bool HasStandardFields() const { return m_message.HasStandardFields(); }
    const std::vector<uint8_t>& GetExtraData() const { return m_message.GetExtraData(); }

    /// The output ID is a hash of the output (excluding the full range proof data,
    /// using only the proof hash for efficiency)
    const mw::Hash& GetOutputID() const { return GetHash(); }

    const mw::Hash& GetHash() const override {
        if (m_hash.IsNull()) {
            m_hash = Hashed(*this);
        }
        return m_hash;
    }

    template<typename Stream>
    void Serialize(Stream& s) const {
        s << m_commitment;
        s << m_senderPubKey;
        s << m_receiverPubKey;
        s << m_message;
        if (m_pRangeProof) {
            s << *m_pRangeProof;
        } else {
            RangeProof empty;
            s << empty;
        }
        s << m_signature;
    }

    template<typename Stream>
    void Unserialize(Stream& s) {
        s >> m_commitment;
        s >> m_senderPubKey;
        s >> m_receiverPubKey;
        s >> m_message;
        auto proof = std::make_shared<RangeProof>();
        s >> *proof;
        m_pRangeProof = std::move(proof);
        s >> m_signature;
        m_hash = mw::Hash(); // reset cached hash
    }

private:
    Commitment m_commitment;
    PublicKey m_senderPubKey;
    PublicKey m_receiverPubKey;
    OutputMessage m_message;
    RangeProof::CPtr m_pRangeProof;
    Signature m_signature;
    mutable mw::Hash m_hash;
};

END_NAMESPACE

#endif // MW_MODELS_TX_OUTPUT_H
