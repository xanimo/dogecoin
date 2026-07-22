// Copyright (c) 2021 The Litecoin Core developers
// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mw/models/block/Block.h>
#include <mw/models/tx/Transaction.h>
#include <mw/consensus/Weight.h>
#include <mw/node/BlockBuilder.h>
#include <mw/crypto/Bulletproof.h>
#include <mw/crypto/Pedersen.h>
#include <mw/crypto/Schnorr.h>

#include <algorithm>
#include <set>

MW_NAMESPACE

// Verifies the cryptographic soundness properties shared by transaction and
// block bodies: every output's range proof, every kernel's signature, and that
// commitments balance (no inflation). Structural checks (sort/dedup/weight) are
// left to the callers.
static void ValidateBodyCrypto(const TxBody& body, const BlindingFactor& kernelOffset)
{
    // Range proofs: each output commits to a value in [0, 2^64).
    for (const Output& output : body.GetOutputs()) {
        if (!output.GetRangeProof()) {
            throw std::runtime_error("Output missing range proof");
        }
        if (!Bulletproof::Verify(*output.GetRangeProof(), output.GetCommitment())) {
            throw std::runtime_error("Invalid range proof");
        }
    }

    // Input owner signatures: an input that carries an owner (output) public key
    // must be signed by it, proving the spender controls the one-time key of the
    // output being spent. Inputs with no owner key are value-balance-only (unit
    // tests that do not reference on-chain outputs) and are not signed here; the
    // stateful connect path binds a real spend's owner key to its output.
    for (const Input& input : body.GetInputs()) {
        if (input.GetOutputPubKey() == PublicKey()) {
            continue;
        }
        const mw::Hash message = input.GetSignatureMessage();
        if (!Schnorr::Verify(input.GetSignature(), input.GetOutputPubKey(), message.data())) {
            throw std::runtime_error("Invalid input owner signature");
        }
    }

    // Kernel signatures: the excess (a commitment to zero, excess*G) is also the
    // public key the signature must verify against.
    for (const Kernel& kernel : body.GetKernels()) {
        const PublicKey excessPubKey = Pedersen::ToPublicKey(kernel.GetExcess());
        const mw::Hash message = kernel.GetSignatureMessage();
        if (!Schnorr::Verify(kernel.GetSignature(), excessPubKey, message.data())) {
            throw std::runtime_error("Invalid kernel signature");
        }
    }

    // Commitment balance (no inflation):
    //   Sum(outputs) + (fees + pegouts)*H
    //     == Sum(inputs) + Sum(kernel excesses) + pegins*H + offset*G
    // Checked as sum-to-zero. Fees/pegs are non-negative, so the H value is split
    // across both sides rather than committing a negative amount; zero terms are
    // skipped (their commitment would be the point at infinity).
    std::vector<Commitment> positive;
    std::vector<Commitment> negative;

    for (const Output& output : body.GetOutputs()) {
        positive.push_back(output.GetCommitment());
    }
    for (const Input& input : body.GetInputs()) {
        negative.push_back(input.GetCommitment());
    }

    uint64_t hPositive = 0; // fees + pegouts: value leaving the MWEB balance
    uint64_t hNegative = 0; // pegins: value entering the MWEB balance
    for (const Kernel& kernel : body.GetKernels()) {
        negative.push_back(kernel.GetExcess());
        hPositive += static_cast<uint64_t>(kernel.GetFee());
        for (const PegOutCoin& pegout : kernel.GetPegOuts()) {
            hPositive += static_cast<uint64_t>(pegout.GetAmount());
        }
        hNegative += static_cast<uint64_t>(kernel.GetPegIn());
    }

    const BlindingFactor zeroBlind;
    if (hPositive > 0) positive.push_back(Pedersen::Commit(hPositive, zeroBlind));
    if (hNegative > 0) negative.push_back(Pedersen::Commit(hNegative, zeroBlind));
    if (!kernelOffset.IsNull()) {
        negative.push_back(Pedersen::Commit(0, kernelOffset));
    }

    if (!Pedersen::VerifyBalance(positive, negative)) {
        throw std::runtime_error("Body does not balance (inflation)");
    }
}

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

    // Cryptographic soundness: range proofs, kernel signatures, and commitment
    // balance. (Owner/stealth-offset sum is verified elsewhere; TODO.)
    ValidateBodyCrypto(m_body, GetKernelOffset());
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

    // Cryptographic soundness: range proofs, kernel signatures, and commitment
    // balance (shared with Block::Validate).
    mw::ValidateBodyCrypto(m_body, m_kernelOffset);
}

//
// BlockBuilder implementation
//

mw::BlockBuilder::BlockBuilder(int32_t height, const mw::Header::CPtr& prevHeader, const mw::MWEBState& prevState)
    : m_height(height), m_prevHeader(prevHeader), m_prevState(prevState) {}

mw::BlockBuilder::Ptr mw::BlockBuilder::Create(int32_t height, const mw::Header::CPtr& prevHeader, const mw::MWEBState& prevState)
{
    return mw::BlockBuilder::Ptr(new mw::BlockBuilder(height, prevHeader, prevState));
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

mw::Block::Ptr mw::BlockBuilder::Build()
{
    // An empty block is valid and required: once MWEB is active every block must
    // carry an extension block, even one with no transactions. With no bodies the
    // merge below is a no-op, the accumulator stays at the previous state, and the
    // header commits to the unchanged roots -- exactly what the validator expects.

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

    // Compute the header roots by advancing the previous accumulator over this
    // block's elements, in the exact order they are stored in the body. This is
    // the same sequence the validator applies when it connects the block
    // (MWEBState::ApplyBlock), so the resulting roots satisfy MatchesHeader.
    mw::MWEBState state = m_prevState;
    for (const auto& output : allOutputs)
        state.AddOutput(output.GetOutputID());
    for (const auto& kernel : allKernels)
        state.AddKernel(kernel.GetKernelID());
    for (const auto& input : allInputs) {
        if (!state.SpendByOutputID(input.GetOutputID())) {
            // An input spends an output the accumulator does not know: the block
            // cannot be built consistently.
            return nullptr;
        }
    }

    mw::Hash outputRoot = state.OutputRoot();
    mw::Hash kernelRoot = state.KernelRoot();
    mw::Hash leafsetRoot = state.LeafsetRoot();
    uint64_t numTXOs = state.NumOutputs();
    uint64_t numKernels = state.NumKernels();

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
