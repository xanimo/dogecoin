// Copyright (c) 2021 The Litecoin Core developers
// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef MW_MODELS_TX_TRANSACTION_H
#define MW_MODELS_TX_TRANSACTION_H

#include <mw/common/Macros.h>
#include <mw/common/Traits.h>
#include <mw/models/crypto/BlindingFactor.h>
#include <mw/models/tx/TxBody.h>

#include <memory>
#include <vector>

MW_NAMESPACE

////////////////////////////////////////
// TRANSACTION - Represents a MW transaction or merged transactions
// before they've been included in a block.
////////////////////////////////////////
class Transaction :
    public Traits::IHashable,
    public Traits::ISerializable
{
public:
    using CPtr = std::shared_ptr<const Transaction>;
    using Ptr = std::shared_ptr<Transaction>;

    //
    // Constructors
    //
    Transaction() = default;
    Transaction(BlindingFactor kernel_offset, BlindingFactor stealth_offset, TxBody body)
        : m_kernelOffset(std::move(kernel_offset)),
          m_stealthOffset(std::move(stealth_offset)),
          m_body(std::move(body))
    {
        m_hash = Hashed(*this);
    }
    Transaction(const Transaction& tx) = default;
    Transaction(Transaction&& tx) noexcept = default;

    //
    // Factory
    //
    static Transaction::CPtr Create(
        BlindingFactor kernel_offset,
        BlindingFactor stealth_offset,
        std::vector<Input> inputs,
        std::vector<Output> outputs,
        std::vector<Kernel> kernels)
    {
        std::sort(inputs.begin(), inputs.end(), [](const Input& a, const Input& b) {
            return a.GetHash() < b.GetHash();
        });
        std::sort(outputs.begin(), outputs.end(), [](const Output& a, const Output& b) {
            return a.GetHash() < b.GetHash();
        });
        std::sort(kernels.begin(), kernels.end(), [](const Kernel& a, const Kernel& b) {
            return a.GetHash() < b.GetHash();
        });

        return std::make_shared<Transaction>(
            std::move(kernel_offset),
            std::move(stealth_offset),
            TxBody{
                std::move(inputs),
                std::move(outputs),
                std::move(kernels)
            }
        );
    }

    //
    // Destructor
    //
    virtual ~Transaction() = default;

    //
    // Operators
    //
    Transaction& operator=(const Transaction& tx) = default;
    Transaction& operator=(Transaction&& tx) noexcept = default;
    bool operator<(const Transaction& tx) const noexcept { return GetHash() < tx.GetHash(); }
    bool operator==(const Transaction& tx) const noexcept { return GetHash() == tx.GetHash(); }
    bool operator!=(const Transaction& tx) const noexcept { return GetHash() != tx.GetHash(); }

    //
    // Getters
    //
    const BlindingFactor& GetKernelOffset() const noexcept { return m_kernelOffset; }
    const BlindingFactor& GetStealthOffset() const noexcept { return m_stealthOffset; }
    const TxBody& GetBody() const noexcept { return m_body; }
    const std::vector<Input>& GetInputs() const noexcept { return m_body.GetInputs(); }
    const std::vector<Output>& GetOutputs() const noexcept { return m_body.GetOutputs(); }
    const std::vector<Kernel>& GetKernels() const noexcept { return m_body.GetKernels(); }

    CAmount GetTotalFee() const noexcept { return m_body.GetTotalFee(); }
    CAmount GetPegInAmount() const noexcept {
        CAmount total = 0;
        for (const auto& kernel : m_body.GetKernels()) {
            total += kernel.GetPegIn();
        }
        return total;
    }
    std::vector<PegOutCoin> GetPegOuts() const noexcept { return m_body.GetPegOuts(); }
    CAmount GetSupplyChange() const noexcept { return m_body.GetSupplyChange(); }

    std::vector<PegInCoin> GetPegIns() const { return m_body.GetPegIns(); }

    bool IsStandard() const noexcept {
        for (const auto& kernel : m_body.GetKernels()) {
            if (!kernel.IsStandard()) return false;
        }
        return true;
    }

    std::string Print() const {
        return "Tx(" + GetHash().GetHex() + ")";
    }

    //
    // IHashable
    //
    const mw::Hash& GetHash() const noexcept override { return m_hash; }

    //
    // Validation
    //
    void Validate() const;

    //
    // ISerializable
    //
    std::vector<uint8_t> Serialized() const override {
        CDataStream ss(SER_DISK, PROTOCOL_VERSION);
        ss << *this;
        return std::vector<uint8_t>(ss.begin(), ss.end());
    }

    //
    // Serialization
    //
    template<typename Stream>
    void Serialize(Stream& s) const {
        s << m_kernelOffset;
        s << m_stealthOffset;
        s << m_body;
    }

    template<typename Stream>
    void Unserialize(Stream& s) {
        s >> m_kernelOffset;
        s >> m_stealthOffset;
        s >> m_body;
        m_hash = Hashed(*this);

        if (m_body.GetKernels().empty()) {
            throw std::ios_base::failure("Transaction requires at least one kernel");
        }
    }

private:
    BlindingFactor m_kernelOffset;
    BlindingFactor m_stealthOffset;
    TxBody m_body;
    mw::Hash m_hash;
};

END_NAMESPACE

#endif // MW_MODELS_TX_TRANSACTION_H
