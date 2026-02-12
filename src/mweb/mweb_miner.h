// Copyright (c) 2021 The Litecoin Core developers
// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef DOGECOIN_MWEB_MINER_H
#define DOGECOIN_MWEB_MINER_H

#include "mweb/mweb_models.h"
#include "primitives/transaction.h"
#include "txmempool.h"
#include <mw/node/BlockBuilder.h>

// Forward Declarations
class CBlock;
class CBlockIndex;
struct CBlockTemplate;

namespace MWEB {

class Miner
{
public:
    /// Called when starting to build a new block.
    void NewBlock(const uint64_t nHeight, const mw::Header::CPtr& prevHeader);

    /// Attempts to add an MWEB transaction from the mempool to the
    /// in-progress MWEB block being built.
    /// Returns true if the transaction was successfully added.
    bool AddMWEBTransaction(CTxMemPool::txiter iter);

    /// Finalizes the MWEB block and creates the HogEx (integrating)
    /// transaction that bridges the MWEB and canonical chain.
    void AddHogExTransaction(const CBlockIndex* pIndexPrev, CBlock* pblock,
                             CBlockTemplate* pblocktemplate, CAmount& nFees);

private:
    /// Validates that the pegin outputs in a transaction match the MWEB
    /// pegin kernels.
    bool ValidatePegIns(const CTransactionRef& pTx,
                        const std::vector<mw::PegInCoin>& pegins) const;

    // MWEB block builder
    mw::BlockBuilder::Ptr mweb_builder;
    CAmount mweb_amount_change{0};
    CAmount hogex_fees{0};
    int64_t hogex_sigops{0};
    std::vector<CTxIn> hogex_inputs;
    std::vector<CTxOut> hogex_outputs;
};

} // namespace MWEB

#endif // DOGECOIN_MWEB_MINER_H
