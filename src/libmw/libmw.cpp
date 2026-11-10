// Copyright (c) 2021 The Litecoin Core developers
// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mw/models/block/Block.h>
#include <mw/models/tx/Transaction.h>
#include <mw/consensus/KernelSumValidator.h>
#include <mw/consensus/StealthSumValidator.h>
#include <mw/consensus/Weight.h>
#include <mw/node/BlockBuilder.h>
#include <mw/crypto/Bulletproof.h>
#include <mw/crypto/Keys.h>
#include <mw/crypto/Pedersen.h>
#include <mw/crypto/Schnorr.h>

#include <algorithm>
#include <map>
#include <set>

MW_NAMESPACE

// Verifies the cryptographic soundness properties shared by transaction and
// block bodies: every output's range proof, every kernel's signature, and that
// commitments balance (no inflation). Structural checks (sort/dedup/weight) are
// left to the callers.
static void ValidateBodyCrypto(const TxBody& body, const BlindingFactor& kernelOffset,
                               const BlindingFactor& stealthOffset)
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

    // Output sender signatures: every output must carry a sender key and be
    // signed by it. The signed message covers the receiver key and the output
    // message, so a relayed output cannot be re-addressed or have its value hint
    // rewritten without invalidating the signature.
    for (const Output& output : body.GetOutputs()) {
        if (output.GetSenderPubKey() == PublicKey()) {
            throw std::runtime_error("Output has no sender key");
        }
        const mw::Hash message = output.GetSignatureMessage();
        if (!Schnorr::Verify(output.GetSignature(), output.GetSenderPubKey(), message.data())) {
            throw std::runtime_error("Invalid output sender signature");
        }
    }

    // Input owner signatures: every input must carry the one-time (owner) public
    // key of the output it spends and be signed by it, proving the spender
    // controls that key. An input with no owner key is rejected rather than
    // skipped: a null key would otherwise bind nothing here and compare equal to
    // a null receiver key when the block connects.
    for (const Input& input : body.GetInputs()) {
        if (input.GetOutputPubKey() == PublicKey()) {
            throw std::runtime_error("Input has no owner key");
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

    // The two sum rules, in mw/consensus so a caller holding a partial set can
    // run them against it rather than only against a merged body. The sender and
    // owner keys they read were checked non-null above.
    KernelSumValidator::Validate(body, kernelOffset);
    StealthSumValidator::Validate(body, stealthOffset);
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

    // Verify that pegin amounts match between canonical chain and MWEB kernels.
    // Match by kernel ID, not by position: the canonical pegins are supplied in
    // block order (the order the pegin transactions sit in block.vtx) while the
    // kernel pegins are in the body's hash-sorted order, so the two lists need not
    // line up when a block carries more than one peg-in.
    std::vector<PegInCoin> kernel_pegins = m_body.GetPegIns();
    if (pegins.size() != kernel_pegins.size()) {
        throw std::runtime_error("Pegin count mismatch");
    }
    std::map<mw::Hash, CAmount> kernel_pegin_amounts;
    for (const PegInCoin& k : kernel_pegins) {
        kernel_pegin_amounts[k.GetKernelID()] = k.GetAmount();
    }
    for (const PegInCoin& p : pegins) {
        auto it = kernel_pegin_amounts.find(p.GetKernelID());
        if (it == kernel_pegin_amounts.end() || it->second != p.GetAmount()) {
            throw std::runtime_error("Pegin mismatch: no kernel for canonical peg-in output");
        }
        kernel_pegin_amounts.erase(it);
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

    // Cryptographic soundness: range proofs, kernel + input owner signatures,
    // and the value (kernel offset) and stealth (owner-key offset) balances.
    ValidateBodyCrypto(m_body, GetKernelOffset(), GetStealthOffset());
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

    // Cryptographic soundness: range proofs, kernel + input owner signatures, and
    // the value + stealth balances (shared with Block::Validate).
    mw::ValidateBodyCrypto(m_body, m_kernelOffset, m_stealthOffset);
}

//
// BlockBuilder implementation
//

mw::BlockBuilder::BlockBuilder(int32_t height, const mw::Header::CPtr& prevHeader, const mw::MWEBState& prevState)
    : m_height(height), m_prevHeader(prevHeader), m_prevState(prevState),
      m_numInputs(0), m_weight(0) {}

mw::BlockBuilder::Ptr mw::BlockBuilder::Create(int32_t height, const mw::Header::CPtr& prevHeader, const mw::MWEBState& prevState)
{
    return mw::BlockBuilder::Ptr(new mw::BlockBuilder(height, prevHeader, prevState));
}

bool mw::BlockBuilder::AddTransaction(const mw::Transaction::CPtr& pTransaction,
                                       const std::vector<mw::PegInCoin>& pegins)
{
    if (!pTransaction) return false;
    if (pTransaction->GetKernels().empty()) return false;

    // Resource caps, counted against what is already staged rather than against
    // the candidate alone. Block::Validate enforces the same two limits, but only
    // once the block exists; refusing here keeps the template inside them.
    const size_t nNewInputs = pTransaction->GetInputs().size();
    if (m_numInputs + nNewInputs > mw::MAX_NUM_INPUTS) return false;

    const size_t nNewWeight = Weight::Calculate(pTransaction->GetBody());
    if (m_weight + nNewWeight > mw::MAX_BLOCK_WEIGHT) return false;

    // The peg-in list the caller names must be exactly the one the transaction
    // carries. The canonical peg-in outputs are paid in block.vtx while the
    // kernels live in the extension block, so a mismatch here becomes a block
    // whose two halves disagree about how much entered the MWEB.
    {
        const std::vector<mw::PegInCoin> carried = pTransaction->GetPegIns();
        if (carried.size() != pegins.size()) return false;

        std::set<mw::Hash> namedKernels;
        CAmount namedTotal = 0;
        for (const mw::PegInCoin& pegin : pegins) {
            if (!namedKernels.insert(pegin.GetKernelID()).second) return false; // duplicate
            namedTotal += pegin.GetAmount();
        }
        if (namedTotal != pTransaction->GetPegInAmount()) return false;

        for (const mw::PegInCoin& pegin : carried) {
            auto it = namedKernels.find(pegin.GetKernelID());
            if (it == namedKernels.end()) return false;
        }
    }

    // Revalidate rather than trust the caller. The miner has already checked this
    // at mempool acceptance, but the builder is reachable from elsewhere and a
    // template is cheaper to refuse than a block is to discard.
    try {
        pTransaction->Validate();
    } catch (const std::exception&) {
        return false;
    }

    // Identity rules across the staged set. Duplicate kernels or outputs make a
    // body Block::Validate rejects, and an input must spend something that either
    // exists unspent on chain or was created by a transaction already staged.
    for (const mw::Kernel& kernel : pTransaction->GetKernels()) {
        if (m_stagedKernels.count(kernel.GetKernelID()) > 0) return false;
    }
    for (const mw::Output& output : pTransaction->GetOutputs()) {
        const mw::Hash id = output.GetOutputID();
        if (m_stagedOutputs.count(id) > 0) return false;
        if (m_prevState.HasOutput(id)) return false;
    }
    for (const mw::Input& input : pTransaction->GetInputs()) {
        const mw::Hash id = input.GetOutputID();
        if (!m_prevState.IsUnspentByOutputID(id) && m_stagedOutputs.count(id) == 0) return false;
    }

    const size_t nInputs = m_body.GetInputs().size();
    const size_t nOutputs = m_body.GetOutputs().size();
    const size_t nKernels = m_body.GetKernels().size();
    const mw::BlindingFactor kernelOffset = m_kernelOffset;
    const mw::BlindingFactor stealthOffset = m_stealthOffset;

    for (const auto& input : pTransaction->GetInputs())
        m_body.GetInputs().push_back(input);
    for (const auto& output : pTransaction->GetOutputs())
        m_body.GetOutputs().push_back(output);
    for (const auto& kernel : pTransaction->GetKernels())
        m_body.GetKernels().push_back(kernel);

    m_kernelOffset = CombineOffsets(m_kernelOffset, pTransaction->GetKernelOffset());
    m_stealthOffset = CombineOffsets(m_stealthOffset, pTransaction->GetStealthOffset());

    // Both rules run against the whole staged set, not against the new
    // transaction alone. Balanced transactions do sum to a balanced set, but only
    // while the block offset is the scalar sum of theirs, so checking the set
    // checks the identity the block will be validated against rather than
    // assuming CombineOffsets produces it. The offsets were XOR-combined once,
    // which balanced only a one-transaction block.
    try {
        KernelSumValidator::Validate(m_body, m_kernelOffset);
        StealthSumValidator::Validate(m_body, m_stealthOffset);
    } catch (const std::exception&) {
        m_body.GetInputs().resize(nInputs);
        m_body.GetOutputs().resize(nOutputs);
        m_body.GetKernels().resize(nKernels);
        m_kernelOffset = kernelOffset;
        m_stealthOffset = stealthOffset;
        return false;
    }

    m_numInputs += nNewInputs;
    m_weight += nNewWeight;
    for (const mw::Output& output : pTransaction->GetOutputs())
        m_stagedOutputs.insert(output.GetOutputID());
    for (const mw::Kernel& kernel : pTransaction->GetKernels())
        m_stagedKernels.insert(kernel.GetKernelID());

    return true;
}

mw::BlindingFactor mw::BlockBuilder::CombineOffsets(const mw::BlindingFactor& a, const mw::BlindingFactor& b)
{
    // A block's kernel/stealth offset is the elliptic-curve scalar SUM of its
    // transactions' offsets. Summing each transaction's balance identity
    //   Sum(outputs) + (fees+pegouts)*H == Sum(inputs) + Sum(excess) + pegins*H + offset*G
    // over all transactions in the block yields the same identity for the merged
    // body with offset = the sum of the per-transaction offsets -- so the block
    // balances against a single offset exactly when that offset is this sum.
    // (The earlier XOR happened to be identity-correct only for one transaction:
    // XOR against the zero seed returns the transaction's own offset.)
    //
    // A null (all-zero) offset contributes nothing and is returned as-is: zero is
    // not a valid secp256k1 scalar, so it must not be fed to scalar addition.
    if (a.IsNull()) return b;
    if (b.IsNull()) return a;

    const SecretKey sa(std::vector<uint8_t>(a.data(), a.data() + mw::BlindingFactor::SIZE));
    const SecretKey sb(std::vector<uint8_t>(b.data(), b.data() + mw::BlindingFactor::SIZE));
    const SecretKey sum = Keys::AddSecretKeys(sa, sb);
    return mw::BlindingFactor(std::vector<uint8_t>(sum.data(), sum.data() + SecretKey::SIZE));
}

mw::Block::Ptr mw::BlockBuilder::Build()
{
    // An empty block is valid and required: once MWEB is active every block must
    // carry an extension block, even one with no transactions. With nothing staged
    // the sort below is a no-op, the accumulator stays at the previous state, and
    // the header commits to the unchanged roots -- exactly what the validator
    // expects.
    //
    // The merge and the offset sums happened as each transaction was staged, and
    // the staged set was checked against both sum rules at that point, so there is
    // nothing left to balance here.
    // Copied rather than moved: Build() leaves the builder usable, as it was when
    // it merged from a transaction list held separately.
    std::vector<mw::Input> allInputs = m_body.GetInputs();
    std::vector<mw::Output> allOutputs = m_body.GetOutputs();
    std::vector<mw::Kernel> allKernels = m_body.GetKernels();
    const mw::BlindingFactor& aggregateKernelOffset = m_kernelOffset;
    const mw::BlindingFactor& aggregateStealthOffset = m_stealthOffset;

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
