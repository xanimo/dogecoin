// Copyright (c) 2021 The Litecoin Core developers
// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef MW_MODELS_TX_UTXO_H
#define MW_MODELS_TX_UTXO_H

#include <mw/common/Macros.h>
#include <mw/common/Traits.h>
#include <mw/models/tx/Output.h>
#include <mw/mmr/LeafIndex.h>
#include <serialize.h>

/// A UTXO entry in the MWEB UTXO set, tracking the block height at which
/// the output was included, its position in the output MMR (leaf index),
/// and the full Output data.
class UTXO : public mw::Traits::ISerializable
{
public:
    using CPtr = std::shared_ptr<const UTXO>;

    UTXO() : m_blockHeight(0), m_leafIdx(), m_output() {}
    UTXO(const int32_t blockHeight, mmr::LeafIndex leafIdx, mw::Output output)
        : m_blockHeight(blockHeight), m_leafIdx(std::move(leafIdx)), m_output(std::move(output)) {}

    int32_t GetBlockHeight() const noexcept { return m_blockHeight; }
    const mmr::LeafIndex& GetLeafIndex() const noexcept { return m_leafIdx; }
    const mw::Output& GetOutput() const noexcept { return m_output; }

    const mw::Hash& GetOutputID() const noexcept { return m_output.GetOutputID(); }
    const mw::Commitment& GetCommitment() const noexcept { return m_output.GetCommitment(); }
    const mw::PublicKey& GetSenderPubKey() const noexcept { return m_output.GetSenderPubKey(); }
    const mw::PublicKey& GetReceiverPubKey() const noexcept { return m_output.GetReceiverPubKey(); }
    const mw::OutputMessage& GetOutputMessage() const noexcept { return m_output.GetOutputMessage(); }
    const mw::RangeProof::CPtr& GetRangeProof() const noexcept { return m_output.GetRangeProof(); }
    const mw::Signature& GetSignature() const noexcept { return m_output.GetSignature(); }

    //
    // ISerializable
    //
    std::vector<uint8_t> Serialized() const override {
        CDataStream ss(SER_DISK, PROTOCOL_VERSION);
        ss << *this;
        return std::vector<uint8_t>(ss.begin(), ss.end());
    }

    template<typename Stream>
    void Serialize(Stream& s) const {
        ser_writedata32(s, m_blockHeight);
        s << m_leafIdx;
        s << m_output;
    }

    template<typename Stream>
    void Unserialize(Stream& s) {
        m_blockHeight = ser_readdata32(s);
        s >> m_leafIdx;
        s >> m_output;
    }

private:
    int32_t m_blockHeight;
    mmr::LeafIndex m_leafIdx;
    mw::Output m_output;
};

/// MWEB UTXO wrapper that supports serialization into multiple formats
/// for use in network messages (full output, hash-only, or compact).
class NetUTXO
{
public:
    static const uint8_t FULL_UTXO = 0x00;
    static const uint8_t HASH_ONLY = 0x01;
    static const uint8_t COMPACT_UTXO = 0x02;

    NetUTXO() : m_format(FULL_UTXO) {}
    NetUTXO(const uint8_t format, const UTXO::CPtr& utxo)
        : m_format(format), m_utxo(utxo) {}

    template<typename Stream>
    void Serialize(Stream& s) const {
        WriteCompactSize(s, m_utxo->GetLeafIndex().Get());

        if (m_format == FULL_UTXO) {
            s << m_utxo->GetOutput();
        } else if (m_format == HASH_ONLY) {
            s << m_utxo->GetOutputID();
        } else if (m_format == COMPACT_UTXO) {
            s << m_utxo->GetCommitment();
            s << m_utxo->GetSenderPubKey();
            s << m_utxo->GetReceiverPubKey();
            s << m_utxo->GetOutputMessage();
            s << m_utxo->GetRangeProof()->GetHash();
            s << m_utxo->GetSignature();
        } else {
            throw std::ios_base::failure("Unsupported MWEB UTXO serialization format");
        }
    }

private:
    uint8_t m_format;
    UTXO::CPtr m_utxo;
};

#endif // MW_MODELS_TX_UTXO_H
