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
#include <mw/node/MWEBState.h>

#include <memory>
#include <vector>

MW_NAMESPACE

/// Accumulates MWEB transactions and builds an MWEB extension block.
///
/// The builder collects individual transactions, merges their bodies,
/// and produces a Block whose Header commits to the accumulated chain
/// state after this block. The header roots are computed by applying the
/// block's elements to a copy of the previous accumulator (the output and
/// kernel MMRs plus the leafset), exactly as the validator does when it
/// connects the block -- so a block this builder produces satisfies
/// MWEBState::MatchesHeader.
///
/// The aggregate kernel/stealth offset is the elliptic-curve scalar sum of the
/// transactions' offsets (see CombineOffsets), so a block carrying multiple MWEB
/// transactions balances against its single header offset.
class BlockBuilder {
public:
    using Ptr = std::shared_ptr<BlockBuilder>;

    /// Create a new BlockBuilder for the given height.
    /// @param height       The height of the block being built.
    /// @param prevHeader   The previous block's MWEB header (may be null for genesis).
    /// @param prevState    The accumulated chain state as of the previous block, from
    ///                     which this block's header roots are derived. Defaults to an
    ///                     empty accumulator (the genesis case).
    static BlockBuilder::Ptr Create(int32_t height,
                                    const mw::Header::CPtr& prevHeader = nullptr,
                                    const mw::MWEBState& prevState = mw::MWEBState());

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
    BlockBuilder(int32_t height, const mw::Header::CPtr& prevHeader, const mw::MWEBState& prevState);

    /// Elliptic-curve scalar sum of two offsets (a null offset acts as identity).
    static BlindingFactor CombineOffsets(const BlindingFactor& a, const BlindingFactor& b);

    int32_t m_height;
    mw::Header::CPtr m_prevHeader;
    mw::MWEBState m_prevState;
    std::vector<mw::Transaction::CPtr> m_transactions;
};

END_NAMESPACE

#endif // MW_NODE_BLOCKBUILDER_H
