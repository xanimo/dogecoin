// Copyright (c) 2021 The Litecoin Core developers
// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef DOGECOIN_MWEB_NODE_H
#define DOGECOIN_MWEB_NODE_H

#include <mweb/mweb_models.h>
#include <consensus/params.h>
#include <consensus/validation.h>

class CBlock;
class CBlockIndex;
class CTransaction;

namespace MWEB {

/// Provides MWEB-related validation functions for blocks and transactions.
class Node
{
public:
    /// Context-independent validation of the CBlock's MWEB rules.
    /// If MWEB is included in the block, this verifies:
    /// * Only the final transaction in the block is marked as the HogEx
    /// * MWEB header hash matches hash committed to by HogEx transaction
    /// * Peg-In kernels match canonical peg-in outputs
    /// * Peg-Out kernels match HogEx peg-out outputs
    /// * MWEB block does not exceed max weight
    /// * Inputs, outputs, and kernels are properly sorted
    /// * No invalid duplicate inputs, outputs, or kernels
    /// * All signatures and rangeproofs are valid
    /// * Kernel sums balance (no inflation)
    /// * Owner sums balance
    static bool CheckBlock(const CBlock& block, CValidationState& state);

    /// MWEB validation checks that require knowledge of the block's context.
    /// * MWEB is included when the feature is active, or not included when inactive
    /// * MWEB header block height matches the expected height
    /// * The first HogEx input points to the HogAddr output of the previous HogEx
    /// * The remaining HogEx inputs exactly match the pegin outputs
    /// * HogEx fee matches the total MWEB fee
    /// * HogAddr amount is correct (previous + pegins - pegouts - fees)
    static bool ContextualCheckBlock(
        const CBlock& block,
        const Consensus::Params& consensus_params,
        const CBlockIndex* pindexPrev,
        CValidationState& state
    );

    /// Validates an MWEB transaction.
    static bool CheckTransaction(const CTransaction& tx, CValidationState& state);

    /// Validates the MWEB extension block itself against the canonical block:
    /// the peg-in outputs in the block's transactions and the peg-out outputs in
    /// the HogEx must match the MWEB kernels, and the MWEB block's crypto (range
    /// proofs, kernel signatures, commitment balance) must be sound. Context-
    /// independent; ContextualCheckBlock calls this after its structural checks.
    static bool ValidateMWEBBlock(const CBlock& block);
};

} // namespace MWEB

#endif // DOGECOIN_MWEB_NODE_H
