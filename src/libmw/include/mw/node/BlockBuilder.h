// Copyright (c) 2021 The Litecoin Core developers
// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef MW_NODE_BLOCKBUILDER_H
#define MW_NODE_BLOCKBUILDER_H

#include <mw/common/Macros.h>
#include <mw/models/block/Block.h>
#include <mw/models/block/Header.h>
#include <mw/models/tx/Transaction.h>
#include <mw/models/tx/PegInCoin.h>
#include <mw/models/crypto/BlindingFactor.h>

#include <memory>
#include <vector>

MW_NAMESPACE

/// Accumulates MWEB transactions and builds an MWEB extension block.
///
/// The builder collects individual transactions, merges their bodies,
/// and produces a Block with a Header summarizing the aggregate state.
///
/// NOTE: Without a full crypto backend, the header Merkle roots are
/// computed as simple serial hashes of the sorted element hashes,
/// and the aggregate offsets use XOR as a placeholder for proper
/// elliptic curve addition.
class BlockBuilder {
public:
    using Ptr = std::shared_ptr<BlockBuilder>;

    /// Create a new BlockBuilder for the given height.
    /// @param height       The height of the block being built.
    /// @param prevHeader   The previous block's MWEB header (may be null for genesis).
    static BlockBuilder::Ptr Create(int32_t height, const mw::Header::CPtr& prevHeader = nullptr);

    /// Add a transaction to the block being assembled.
    /// @return true if the transaction was accepted.
    bool AddTransaction(const mw::Transaction::CPtr& pTransaction,
                        const std::vector<mw::PegInCoin>& pegins);

    /// Finalize and build the MWEB block.
    /// Merges all accumulated transactions, computes the header, and
    /// returns the complete Block.
    mw::Block::Ptr Build();

    /// Returns true if any transactions have been added.
    bool HasTransactions() const { return !m_transactions.empty(); }

private:
    BlockBuilder(int32_t height, const mw::Header::CPtr& prevHeader);

    /// Combine blinding factors using XOR (placeholder for real ECC addition).
    static BlindingFactor CombineOffsets(const BlindingFactor& a, const BlindingFactor& b);

    /// Compute a simple aggregate hash over a sorted list of hashes.
    static mw::Hash AggregateHash(std::vector<mw::Hash> hashes);

    int32_t m_height;
    mw::Header::CPtr m_prevHeader;
    std::vector<mw::Transaction::CPtr> m_transactions;
};

END_NAMESPACE

#endif // MW_NODE_BLOCKBUILDER_H
