// Copyright (c) 2021 The Litecoin Core developers
// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef DOGECOIN_MWEB_MODELS_H
#define DOGECOIN_MWEB_MODELS_H

#include <amount.h>
#include <mw/models/block/Block.h>
#include <mw/models/tx/Transaction.h>
#include <serialize.h>
#include <tinyformat.h>

#include <algorithm>
#include <memory>
#include <set>
#include <vector>

namespace MWEB {

/// A convenience wrapper around a possibly-null extension block.
/// Used by CBlock to hold the optional MWEB extension data.
struct Block {
    mw::Block::CPtr m_block;

    Block() = default;
    Block(const mw::Block::CPtr& block)
        : m_block(block) {}

    CAmount GetTotalFee() const noexcept
    {
        return IsNull() ? 0 : m_block->GetTotalFee();
    }

    CAmount GetSupplyChange() const noexcept
    {
        return IsNull() ? 0 : m_block->GetSupplyChange();
    }

    mw::Hash GetHash() const noexcept
    {
        return IsNull() ? mw::Hash{} : m_block->GetHash();
    }

    mw::Header::CPtr GetMWEBHeader() const noexcept
    {
        return IsNull() ? mw::Header::CPtr{nullptr} : m_block->GetHeader();
    }

    int32_t GetHeight() const noexcept
    {
        return IsNull() ? -1 : m_block->GetHeight();
    }

    std::vector<mw::Hash> GetSpentIDs() const
    {
        if (IsNull()) return {};
        return m_block->GetBody().GetSpentIDs();
    }

    std::vector<mw::Hash> GetOutputIDs() const
    {
        if (IsNull()) return {};
        return m_block->GetBody().GetOutputIDs();
    }

    std::set<mw::Hash> GetKernelIDs() const
    {
        if (IsNull()) return {};
        auto ids = m_block->GetBody().GetKernelIDs();
        return std::set<mw::Hash>(ids.begin(), ids.end());
    }

    template<typename Stream>
    void Serialize(Stream& s) const
    {
        if (!IsNull()) {
            s << *m_block;
        }
    }

    template<typename Stream>
    void Unserialize(Stream& s)
    {
        auto pBlock = std::make_shared<mw::Block>();
        s >> *pBlock;
        m_block = std::move(pBlock);
    }

    bool IsNull() const noexcept { return m_block == nullptr; }
    void SetNull() noexcept { m_block.reset(); }
};

/// A convenience wrapper around a possibly-null MWEB transaction.
/// Used by CTransaction to hold the optional MWEB transaction data.
struct Tx {
    mw::Transaction::CPtr m_transaction;

    Tx() = default;
    Tx(const mw::Transaction::CPtr& tx)
        : m_transaction(tx) {}

    std::set<mw::Hash> GetSpentIDs() const noexcept
    {
        if (IsNull()) return {};
        std::vector<mw::Hash> ids;
        for (const auto& input : m_transaction->GetInputs()) {
            ids.push_back(input.GetOutputID());
        }
        return std::set<mw::Hash>(ids.begin(), ids.end());
    }

    std::set<mw::Hash> GetKernelIDs() const noexcept
    {
        if (IsNull()) return {};
        std::vector<mw::Hash> ids;
        for (const auto& kernel : m_transaction->GetKernels()) {
            ids.push_back(kernel.GetKernelID());
        }
        return std::set<mw::Hash>(ids.begin(), ids.end());
    }

    std::set<mw::Hash> GetOutputIDs() const noexcept
    {
        if (IsNull()) return {};
        std::vector<mw::Hash> ids;
        for (const auto& output : m_transaction->GetOutputs()) {
            ids.push_back(output.GetOutputID());
        }
        return std::set<mw::Hash>(ids.begin(), ids.end());
    }

    std::vector<mw::PegInCoin> GetPegIns() const noexcept
    {
        if (IsNull()) return {};
        return m_transaction->GetPegIns();
    }

    bool HasPegOut() const noexcept
    {
        if (IsNull()) return false;
        const auto& kernels = m_transaction->GetKernels();
        return std::any_of(
            kernels.cbegin(), kernels.cend(),
            [](const mw::Kernel& kernel) { return kernel.HasPegOut(); }
        );
    }

    std::vector<mw::PegOutCoin> GetPegOuts() const noexcept
    {
        if (IsNull()) return {};
        return m_transaction->GetPegOuts();
    }

    uint64_t GetMWEBWeight() const noexcept
    {
        return IsNull() ? 0 : m_transaction->GetBody().GetTotalFee(); // placeholder; full weight calc needs Weight::Calculate
    }

    CAmount GetFee() const noexcept
    {
        return IsNull() ? 0 : m_transaction->GetTotalFee();
    }

    int32_t GetLockHeight() const noexcept
    {
        return IsNull() ? 0 : m_transaction->GetBody().GetLockHeight();
    }

    bool GetOutput(const mw::Hash& output_id, mw::Output& output) const noexcept
    {
        if (IsNull()) return false;
        for (const auto& out : m_transaction->GetOutputs()) {
            if (out.GetOutputID() == output_id) {
                output = out;
                return true;
            }
        }
        return false;
    }

    template<typename Stream>
    void Serialize(Stream& s) const
    {
        if (!IsNull()) {
            uint8_t indicator = 1;
            s << indicator;
            s << *m_transaction;
        } else {
            uint8_t indicator = 0;
            s << indicator;
        }
    }

    template<typename Stream>
    void Unserialize(Stream& s)
    {
        uint8_t indicator;
        s >> indicator;
        if (indicator == 1) {
            auto pTx = std::make_shared<mw::Transaction>();
            s >> *pTx;
            m_transaction = std::move(pTx);
        } else {
            m_transaction.reset();
        }
    }

    bool IsNull() const noexcept { return m_transaction == nullptr; }
    void SetNull() noexcept { m_transaction.reset(); }

    std::string ToString() const
    {
        return IsNull() ? "" : m_transaction->Print();
    }
};

} // namespace MWEB

#endif // DOGECOIN_MWEB_MODELS_H
