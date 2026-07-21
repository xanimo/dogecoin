// Copyright (c) 2021 The Litecoin Core developers
// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef MW_MODELS_BLOCK_BLOCKUNDO_H
#define MW_MODELS_BLOCK_BLOCKUNDO_H

#include <mw/common/Macros.h>
#include <mw/common/Traits.h>
#include <mw/models/block/Header.h>
#include <mw/models/tx/UTXO.h>
#include <serialize.h>
#include <vector>

MW_NAMESPACE

/// Contains the data necessary to undo an MWEB block from the chain state.
///
/// When performing a reorg, the undo data is used to:
/// 1. Add back the UTXOs that were spent in the block
/// 2. Remove the UTXOs that were created in the block
/// 3. Restore the previous MWEB header as the chain tip
class BlockUndo : public Traits::ISerializable
{
public:
    BlockUndo() = default;
    BlockUndo(
        const mw::Header::CPtr& pPrevHeader,
        std::vector<UTXO>&& coinsSpent,
        std::vector<mw::Hash>&& coinsAdded)
        : m_pPrevHeader(pPrevHeader),
          m_coinsSpent(std::move(coinsSpent)),
          m_coinsAdded(std::move(coinsAdded)) {}

    //
    // Getters
    //
    const mw::Header::CPtr& GetPreviousHeader() const noexcept { return m_pPrevHeader; }
    const std::vector<UTXO>& GetCoinsSpent() const noexcept { return m_coinsSpent; }
    const std::vector<mw::Hash>& GetCoinsAdded() const noexcept { return m_coinsAdded; }

    bool IsNull() const noexcept { return m_pPrevHeader == nullptr; }

    //
    // ISerializable
    //
    std::vector<uint8_t> Serialized() const override {
        // CVectorWriter (not CDataStream) to keep the secure allocator's
        // memory_cleanse out of this vtable; see mw::Transaction::Serialized.
        std::vector<uint8_t> vch;
        CVectorWriter(SER_DISK, PROTOCOL_VERSION, vch, 0) << *this;
        return vch;
    }

    //
    // Serialization
    //
    template<typename Stream>
    void Serialize(Stream& s) const {
        bool hasHeader = (m_pPrevHeader != nullptr);
        s << hasHeader;
        if (hasHeader) {
            s << *m_pPrevHeader;
        }

        WriteCompactSize(s, m_coinsSpent.size());
        for (const auto& utxo : m_coinsSpent) {
            s << utxo;
        }

        WriteCompactSize(s, m_coinsAdded.size());
        for (const auto& hash : m_coinsAdded) {
            s << hash;
        }
    }

    template<typename Stream>
    void Unserialize(Stream& s) {
        bool hasHeader;
        s >> hasHeader;
        if (hasHeader) {
            auto pHeader = std::make_shared<mw::Header>();
            s >> *pHeader;
            m_pPrevHeader = std::move(pHeader);
        } else {
            m_pPrevHeader = nullptr;
        }

        size_t numSpent = ReadCompactSize(s);
        m_coinsSpent.resize(numSpent);
        for (auto& utxo : m_coinsSpent) {
            s >> utxo;
        }

        size_t numAdded = ReadCompactSize(s);
        m_coinsAdded.resize(numAdded);
        for (auto& hash : m_coinsAdded) {
            s >> hash;
        }
    }

private:
    mw::Header::CPtr m_pPrevHeader;
    std::vector<UTXO> m_coinsSpent;
    std::vector<mw::Hash> m_coinsAdded;
};

END_NAMESPACE

#endif // MW_MODELS_BLOCK_BLOCKUNDO_H
