// Copyright (c) 2021 The Litecoin Core developers
// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mw/models/block/Block.h>
#include <mw/models/tx/Transaction.h>
#include <mw/consensus/Weight.h>

MW_NAMESPACE

void Block::Validate(const std::vector<PegInCoin>& pegins, const std::vector<PegOutCoin>& pegouts) const
{
    if (!m_pHeader) {
        throw std::runtime_error("Block has no header");
    }

    // Validate that the block doesn't exceed the maximum weight
    if (Weight::ExceedsMaximum(m_body)) {
        throw std::runtime_error("Block exceeds maximum weight");
    }

    // Verify that pegin amounts match between canonical chain and MWEB kernels
    std::vector<PegInCoin> kernel_pegins = m_body.GetPegIns();
    if (pegins.size() != kernel_pegins.size()) {
        throw std::runtime_error("Pegin count mismatch");
    }

    for (size_t i = 0; i < pegins.size(); i++) {
        if (!(pegins[i] == kernel_pegins[i])) {
            throw std::runtime_error("Pegin mismatch at index " + std::to_string(i));
        }
    }

    // Verify that pegout amounts match between MWEB kernels and HogEx outputs
    std::vector<PegOutCoin> kernel_pegouts = m_body.GetPegOuts();
    if (pegouts.size() != kernel_pegouts.size()) {
        throw std::runtime_error("Pegout count mismatch");
    }

    for (size_t i = 0; i < pegouts.size(); i++) {
        if (!(pegouts[i] == kernel_pegouts[i])) {
            throw std::runtime_error("Pegout mismatch at index " + std::to_string(i));
        }
    }

    // Basic structural validation
    Validate();
}

void Block::Validate() const
{
    if (!m_pHeader) {
        throw std::runtime_error("Block has no header");
    }

    // Validate that the block doesn't exceed the maximum weight
    if (Weight::ExceedsMaximum(m_body)) {
        throw std::runtime_error("Block exceeds maximum weight");
    }

    // Verify inputs are sorted
    for (size_t i = 1; i < m_body.GetInputs().size(); i++) {
        if (!(m_body.GetInputs()[i - 1].GetHash() < m_body.GetInputs()[i].GetHash())) {
            throw std::runtime_error("Block inputs not sorted");
        }
    }

    // Verify outputs are sorted
    for (size_t i = 1; i < m_body.GetOutputs().size(); i++) {
        if (!(m_body.GetOutputs()[i - 1].GetHash() < m_body.GetOutputs()[i].GetHash())) {
            throw std::runtime_error("Block outputs not sorted");
        }
    }

    // Verify kernels are sorted
    for (size_t i = 1; i < m_body.GetKernels().size(); i++) {
        if (!(m_body.GetKernels()[i - 1].GetHash() < m_body.GetKernels()[i].GetHash())) {
            throw std::runtime_error("Block kernels not sorted");
        }
    }

    // Verify no duplicate inputs
    {
        std::set<mw::Hash> input_ids;
        for (const auto& input : m_body.GetInputs()) {
            if (!input_ids.insert(input.GetOutputID()).second) {
                throw std::runtime_error("Duplicate input");
            }
        }
    }

    // Verify no duplicate outputs
    {
        std::set<mw::Hash> output_ids;
        for (const auto& output : m_body.GetOutputs()) {
            if (!output_ids.insert(output.GetOutputID()).second) {
                throw std::runtime_error("Duplicate output");
            }
        }
    }

    // Verify no duplicate kernels
    {
        std::set<mw::Hash> kernel_ids;
        for (const auto& kernel : m_body.GetKernels()) {
            if (!kernel_ids.insert(kernel.GetKernelID()).second) {
                throw std::runtime_error("Duplicate kernel");
            }
        }
    }

    // TODO: When full libmw crypto backend is available, verify:
    // - All kernel signatures are valid
    // - All range proofs are valid
    // - Kernel sum balances (no inflation)
    // - Owner sum balances (stealth offsets)
    // - Commitment sums: (sum_outputs + sum_fees*H - sum_inputs) == (sum_kernel_excesses + kernel_offset*G)
}

END_NAMESPACE

// Transaction validation
void mw::Transaction::Validate() const
{
    if (m_body.GetKernels().empty()) {
        throw std::runtime_error("Transaction must have at least one kernel");
    }

    // Verify inputs are sorted
    for (size_t i = 1; i < m_body.GetInputs().size(); i++) {
        if (!(m_body.GetInputs()[i - 1].GetHash() < m_body.GetInputs()[i].GetHash())) {
            throw std::runtime_error("Transaction inputs not sorted");
        }
    }

    // Verify outputs are sorted
    for (size_t i = 1; i < m_body.GetOutputs().size(); i++) {
        if (!(m_body.GetOutputs()[i - 1].GetHash() < m_body.GetOutputs()[i].GetHash())) {
            throw std::runtime_error("Transaction outputs not sorted");
        }
    }

    // Verify kernels are sorted
    for (size_t i = 1; i < m_body.GetKernels().size(); i++) {
        if (!(m_body.GetKernels()[i - 1].GetHash() < m_body.GetKernels()[i].GetHash())) {
            throw std::runtime_error("Transaction kernels not sorted");
        }
    }

    // TODO: When full libmw crypto backend is available, verify:
    // - All kernel signatures are valid
    // - All range proofs are valid
    // - Commitment sums balance (no inflation)
}
