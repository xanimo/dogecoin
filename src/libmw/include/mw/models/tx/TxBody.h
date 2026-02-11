// Copyright (c) 2021 The Litecoin Core developers
// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef MW_MODELS_TX_TXBODY_H
#define MW_MODELS_TX_TXBODY_H

#include <mw/models/tx/Input.h>
#include <mw/models/tx/Output.h>
#include <mw/models/tx/Kernel.h>
#include <mw/models/tx/PegInCoin.h>
#include <mw/models/tx/PegOutCoin.h>
#include <amount.h>
#include <serialize.h>
#include <vector>
#include <numeric>

MW_NAMESPACE

/// Container holding the inputs, outputs, and kernels for a MW transaction or block body
class TxBody {
public:
    TxBody() = default;
    TxBody(std::vector<Input>&& inputs, std::vector<Output>&& outputs, std::vector<Kernel>&& kernels)
        : m_inputs(std::move(inputs)), m_outputs(std::move(outputs)), m_kernels(std::move(kernels)) {}

    const std::vector<Input>& GetInputs() const { return m_inputs; }
    const std::vector<Output>& GetOutputs() const { return m_outputs; }
    const std::vector<Kernel>& GetKernels() const { return m_kernels; }

    std::vector<Input>& GetInputs() { return m_inputs; }
    std::vector<Output>& GetOutputs() { return m_outputs; }
    std::vector<Kernel>& GetKernels() { return m_kernels; }

    /// Get all peg-in coins from kernel data
    std::vector<PegInCoin> GetPegIns() const {
        std::vector<PegInCoin> pegins;
        for (const auto& kernel : m_kernels) {
            if (kernel.HasPegIn()) {
                pegins.emplace_back(kernel.GetPegIn(), kernel.GetKernelID());
            }
        }
        return pegins;
    }

    /// Get all peg-out coins from kernel data
    std::vector<PegOutCoin> GetPegOuts() const {
        std::vector<PegOutCoin> pegouts;
        for (const auto& kernel : m_kernels) {
            if (kernel.HasPegOut()) {
                for (const auto& pegout : kernel.GetPegOuts()) {
                    pegouts.push_back(pegout);
                }
            }
        }
        return pegouts;
    }

    /// Total fee across all kernels
    CAmount GetTotalFee() const {
        CAmount total = 0;
        for (const auto& kernel : m_kernels) {
            total += kernel.GetFee();
        }
        return total;
    }

    /// Net supply change: peg-ins minus peg-outs minus fees
    CAmount GetSupplyChange() const {
        CAmount change = 0;
        for (const auto& kernel : m_kernels) {
            change += kernel.GetSupplyChange();
        }
        return change - GetTotalFee();
    }

    /// Get all spent output IDs from inputs
    std::vector<mw::Hash> GetSpentIDs() const {
        std::vector<mw::Hash> ids;
        for (const auto& input : m_inputs) {
            ids.push_back(input.GetOutputID());
        }
        return ids;
    }

    /// Get all output IDs from outputs
    std::vector<mw::Hash> GetOutputIDs() const {
        std::vector<mw::Hash> ids;
        for (const auto& output : m_outputs) {
            ids.push_back(output.GetOutputID());
        }
        return ids;
    }

    /// Get all kernel IDs
    std::vector<mw::Hash> GetKernelIDs() const {
        std::vector<mw::Hash> ids;
        for (const auto& kernel : m_kernels) {
            ids.push_back(kernel.GetKernelID());
        }
        return ids;
    }

    /// Get total peg-in amount
    CAmount GetPegInAmount() const {
        CAmount total = 0;
        for (const auto& kernel : m_kernels) {
            total += kernel.GetPegIn();
        }
        return total;
    }

    /// Maximum lock height across all kernels
    int32_t GetLockHeight() const {
        int32_t maxHeight = 0;
        for (const auto& kernel : m_kernels) {
            if (kernel.GetLockHeight() > maxHeight)
                maxHeight = kernel.GetLockHeight();
        }
        return maxHeight;
    }

    template<typename Stream>
    void Serialize(Stream& s) const {
        WriteCompactSize(s, m_inputs.size());
        for (const auto& input : m_inputs) s << input;
        WriteCompactSize(s, m_outputs.size());
        for (const auto& output : m_outputs) s << output;
        WriteCompactSize(s, m_kernels.size());
        for (const auto& kernel : m_kernels) s << kernel;
    }

    template<typename Stream>
    void Unserialize(Stream& s) {
        size_t numInputs = ReadCompactSize(s);
        m_inputs.resize(numInputs);
        for (auto& input : m_inputs) s >> input;
        size_t numOutputs = ReadCompactSize(s);
        m_outputs.resize(numOutputs);
        for (auto& output : m_outputs) s >> output;
        size_t numKernels = ReadCompactSize(s);
        m_kernels.resize(numKernels);
        for (auto& kernel : m_kernels) s >> kernel;
    }

private:
    std::vector<Input> m_inputs;
    std::vector<Output> m_outputs;
    std::vector<Kernel> m_kernels;
};

END_NAMESPACE

#endif // MW_MODELS_TX_TXBODY_H
