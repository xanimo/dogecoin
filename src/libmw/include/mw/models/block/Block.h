// Copyright (c) 2021 The Litecoin Core developers
// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef MW_MODELS_BLOCK_BLOCK_H
#define MW_MODELS_BLOCK_BLOCK_H

#include <mw/common/Macros.h>
#include <mw/common/Traits.h>
#include <mw/models/block/Header.h>
#include <mw/models/tx/TxBody.h>
#include <mw/models/tx/Input.h>
#include <mw/models/tx/Output.h>
#include <mw/models/tx/Kernel.h>
#include <mw/models/tx/PegInCoin.h>
#include <mw/models/tx/PegOutCoin.h>
#include <mw/models/crypto/BlindingFactor.h>
#include <amount.h>
#include <serialize.h>
#include <memory>

MW_NAMESPACE

/// Full MWEB extension block consisting of a header and a transaction body.
/// The header commits to the Merkle roots and aggregate offsets.
/// The body contains all inputs, outputs, and kernels.
class Block : public Traits::IHashable
{
public:
    using CPtr = std::shared_ptr<const Block>;
    using Ptr = std::shared_ptr<Block>;

    Block() = default;
    Block(const mw::Header::CPtr& pHeader, TxBody body)
        : m_pHeader(pHeader), m_body(std::move(body)) {}

    //
    // Getters
    //
    const mw::Header::CPtr& GetHeader() const noexcept { return m_pHeader; }
    const TxBody& GetBody() const noexcept { return m_body; }

    int32_t GetHeight() const noexcept {
        return m_pHeader ? m_pHeader->GetHeight() : -1;
    }

    const std::vector<Input>& GetInputs() const noexcept { return m_body.GetInputs(); }
    const std::vector<Output>& GetOutputs() const noexcept { return m_body.GetOutputs(); }
    const std::vector<Kernel>& GetKernels() const noexcept { return m_body.GetKernels(); }

    const BlindingFactor& GetKernelOffset() const noexcept {
        return m_pHeader->GetKernelOffset();
    }
    const BlindingFactor& GetStealthOffset() const noexcept {
        return m_pHeader->GetStealthOffset();
    }

    CAmount GetTotalFee() const noexcept { return m_body.GetTotalFee(); }
    CAmount GetSupplyChange() const noexcept { return m_body.GetSupplyChange(); }

    std::vector<PegInCoin> GetPegIns() const { return m_body.GetPegIns(); }
    std::vector<PegOutCoin> GetPegOuts() const { return m_body.GetPegOuts(); }

    //
    // IHashable - The block hash is the header hash
    //
    const mw::Hash& GetHash() const noexcept override {
        return m_pHeader->GetHash();
    }

    //
    // Serialization
    //
    template<typename Stream>
    void Serialize(Stream& s) const {
        if (m_pHeader) {
            s << *m_pHeader;
        } else {
            mw::Header empty;
            s << empty;
        }
        s << m_body;
    }

    template<typename Stream>
    void Unserialize(Stream& s) {
        auto pHeader = std::make_shared<mw::Header>();
        s >> *pHeader;
        m_pHeader = std::move(pHeader);
        s >> m_body;
    }

    //
    // Context-free validation of the block.
    // Validates pegin and pegout amounts balance with the MWEB transaction body.
    //
    void Validate(const std::vector<PegInCoin>& pegins, const std::vector<PegOutCoin>& pegouts) const;
    void Validate() const;

private:
    mw::Header::CPtr m_pHeader;
    TxBody m_body;
};

END_NAMESPACE

#endif // MW_MODELS_BLOCK_BLOCK_H
