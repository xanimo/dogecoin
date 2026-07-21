// Copyright (c) 2021 The Litecoin Core developers
// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mw/models/block/Block.h>
#include <mw/models/tx/Transaction.h>
#include <mw/consensus/Weight.h>
#include <mw/node/BlockBuilder.h>
#include <mw/crypto/Bulletproof.h>

#include <algorithm>
#include <set>

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

    // Verify each output's range proof: proves the committed amount is in
    // [0, 2^64) so an output cannot hide a negative/overflowing value.
    for (const Output& output : m_body.GetOutputs()) {
        if (!output.GetRangeProof()) {
            throw std::runtime_error("Output missing range proof");
        }
        if (!Bulletproof::Verify(*output.GetRangeProof(), output.GetCommitment())) {
            throw std::runtime_error("Invalid range proof");
        }
    }

    // TODO (next wiring increments): verify kernel signatures, and that
    // commitment sums balance (no inflation).
}

//
// BlockBuilder implementation
//

mw::BlockBuilder::BlockBuilder(int32_t height, const mw::Header::CPtr& prevHeader)
    : m_height(height), m_prevHeader(prevHeader) {}

mw::BlockBuilder::Ptr mw::BlockBuilder::Create(int32_t height, const mw::Header::CPtr& prevHeader)
{
    return mw::BlockBuilder::Ptr(new mw::BlockBuilder(height, prevHeader));
}

bool mw::BlockBuilder::AddTransaction(const mw::Transaction::CPtr& pTransaction,
                                       const std::vector<mw::PegInCoin>& pegins)
{
    if (!pTransaction) return false;
    if (pTransaction->GetKernels().empty()) return false;

    m_transactions.push_back(pTransaction);
    return true;
}

mw::BlindingFactor mw::BlockBuilder::CombineOffsets(const mw::BlindingFactor& a, const mw::BlindingFactor& b)
{
    // Placeholder: XOR blinding factors as a stand-in for proper ECC addition.
    // In a real implementation, this would use secp256k1 scalar addition.
    std::vector<uint8_t> result(mw::BlindingFactor::SIZE);
    for (size_t i = 0; i < mw::BlindingFactor::SIZE; i++) {
        result[i] = a.data()[i] ^ b.data()[i];
    }
    return mw::BlindingFactor(result);
}

mw::Hash mw::BlockBuilder::AggregateHash(std::vector<mw::Hash> hashes)
{
    if (hashes.empty()) return mw::Hash();

    std::sort(hashes.begin(), hashes.end());

    CHashWriter hasher(SER_GETHASH, 0);
    for (const auto& h : hashes) {
        hasher << h;
    }
    return mw::Hash(hasher.GetHash());
}

mw::Block::Ptr mw::BlockBuilder::Build()
{
    if (m_transactions.empty()) return nullptr;

    // Merge all transaction bodies
    std::vector<mw::Input> allInputs;
    std::vector<mw::Output> allOutputs;
    std::vector<mw::Kernel> allKernels;
    mw::BlindingFactor aggregateKernelOffset;
    mw::BlindingFactor aggregateStealthOffset;

    for (const auto& tx : m_transactions) {
        // Merge inputs, outputs, kernels
        for (const auto& input : tx->GetInputs())
            allInputs.push_back(input);
        for (const auto& output : tx->GetOutputs())
            allOutputs.push_back(output);
        for (const auto& kernel : tx->GetKernels())
            allKernels.push_back(kernel);

        // Combine offsets
        aggregateKernelOffset = CombineOffsets(aggregateKernelOffset, tx->GetKernelOffset());
        aggregateStealthOffset = CombineOffsets(aggregateStealthOffset, tx->GetStealthOffset());
    }

    // Sort all elements by hash (required by consensus)
    std::sort(allInputs.begin(), allInputs.end(),
              [](const mw::Input& a, const mw::Input& b) { return a.GetHash() < b.GetHash(); });
    std::sort(allOutputs.begin(), allOutputs.end(),
              [](const mw::Output& a, const mw::Output& b) { return a.GetHash() < b.GetHash(); });
    std::sort(allKernels.begin(), allKernels.end(),
              [](const mw::Kernel& a, const mw::Kernel& b) { return a.GetHash() < b.GetHash(); });

    // Compute Merkle roots as aggregate hashes of the sorted element hashes
    // (placeholder for real MMR/PMMR roots)
    std::vector<mw::Hash> outputHashes, kernelHashes;
    for (const auto& output : allOutputs)
        outputHashes.push_back(output.GetHash());
    for (const auto& kernel : allKernels)
        kernelHashes.push_back(kernel.GetHash());

    mw::Hash outputRoot = AggregateHash(outputHashes);
    mw::Hash kernelRoot = AggregateHash(kernelHashes);

    // Leafset root: hash of the output hashes (simplified)
    mw::Hash leafsetRoot = outputRoot; // placeholder

    // Compute TXO and kernel counts
    uint64_t prevNumTXOs = m_prevHeader ? m_prevHeader->GetNumTXOs() : 0;
    uint64_t prevNumKernels = m_prevHeader ? m_prevHeader->GetNumKernels() : 0;
    uint64_t numTXOs = prevNumTXOs + allOutputs.size();
    uint64_t numKernels = prevNumKernels + allKernels.size();

    // Build the header
    auto pHeader = std::make_shared<mw::Header>(
        m_height,
        std::move(outputRoot),
        std::move(kernelRoot),
        std::move(leafsetRoot),
        aggregateKernelOffset,
        aggregateStealthOffset,
        numTXOs,
        numKernels
    );

    // Build the body
    mw::TxBody body(std::move(allInputs), std::move(allOutputs), std::move(allKernels));

    // Build the block
    return std::make_shared<mw::Block>(pHeader, std::move(body));
}
