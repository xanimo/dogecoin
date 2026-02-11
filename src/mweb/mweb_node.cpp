// Copyright (c) 2021 The Litecoin Core developers
// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "mweb/mweb_node.h"

#include "chain.h"
#include "consensus/validation.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "validation.h"

using namespace MWEB;

bool Node::CheckBlock(const CBlock& block, CValidationState& state)
{
    // HasMWEBTx() is true only when mweb txs being shared outside of a block (for use by mempools).
    // Blocks themselves do not store mweb txs like normal txs.
    // They are instead stored and processed separately in the mweb block.
    // So at this point, no txs should contain MWEB data.
    for (const CTransactionRef& pTx : block.vtx) {
        if (pTx->HasMWEBTx()) {
            return state.DoS(100, false, REJECT_INVALID, "unexpected-mweb-data",
                false, "Block contains transactions with MWEB data attached");
        }
    }

    return true;
}

bool Node::ContextualCheckBlock(
    const CBlock& block,
    const Consensus::Params& consensus_params,
    const CBlockIndex* pindexPrev,
    CValidationState& state)
{
    // If MWEB is enabled, we must have an mweb_block. If it's not enabled, we must not have an MWEB block.
    if (!IsMWEBEnabled(pindexPrev, consensus_params)) {
        // No MWEB data is allowed in blocks that don't commit to MWEB data
        if (!block.mweb_block.IsNull()) {
            return state.DoS(100, false, REJECT_INVALID, "unexpected-mweb-data",
                false, "MWEB not activated, but extension block found");
        }
        return true;
    } else if (block.mweb_block.IsNull()) {
        return state.DoS(100, false, REJECT_INVALID, "mweb-missing",
            false, "MWEB activated but extension block not found");
    }

    // Validate each transaction in the block.
    for (const auto& tx : block.vtx) {
        // Verify that there are no pegin outputs in the coinbase or HogEx transactions.
        if (tx->IsCoinBase() || tx->IsHogEx()) {
            for (const CTxOut& out : tx->vout) {
                if (out.scriptPubKey.IsMWEBPegin()) {
                    return state.DoS(100, false, REJECT_INVALID, "bad-tx-unexpected-pegin",
                        false, "Pegin found in coinbase or HogEx");
                }
            }
        }
    }

    // Last transaction must be marked as HogEx.
    const CTransactionRef& pHogEx = block.vtx.back();
    if (!pHogEx->IsHogEx()) {
        return state.DoS(100, false, REJECT_INVALID, "bad-hogex-missing",
            false, "Last transaction is not marked as HogEx");
    }

    // Verify that the first output of the HogEx is a valid HogAddr.
    mw::Hash mweb_hash;
    if (pHogEx->vout.empty() || !pHogEx->vout.front().scriptPubKey.IsMWEBHogAddr(&mweb_hash)) {
        return state.DoS(100, false, REJECT_INVALID, "bad-hogex",
            false, "HogEx missing or invalid HogAddr");
    }

    // Verify that the MWEB header hash matches.
    if (mweb_hash != block.mweb_block.m_block->GetHash()) {
        return state.DoS(100, false, REJECT_INVALID, "mweb-hash-mismatch",
            false, "MWEB header hash doesn't match hogex hash");
    }

    // Verify that the MWEB block's height is correct.
    if (block.mweb_block.GetHeight() != (pindexPrev->nHeight + 1)) {
        return state.DoS(100, false, REJECT_INVALID, "mweb-height-mismatch",
            false, "Invalid MWEB block height");
    }

    // For the very first HogEx transaction, all inputs are pegins, so start at index of 0.
    // For all other HogEx transactions, the first input is not a pegin, so start looking at index 1.
    const bool is_first_hogex = !IsMWEBEnabled(pindexPrev->pprev, consensus_params);
    size_t next_pegin_idx = is_first_hogex ? 0 : 1;

    // Loop through the block's txs looking for all outputs with pegin scriptPubKeys.
    // While looping, we:
    // 1. Calculate the total value of the HogEx inputs (hogex_input_amount).
    // 2. Verify the HogEx inputs exactly match the pegin outputs.
    CAmount hogex_input_amount = pindexPrev->mweb_amount;
    for (size_t nTx = 1; nTx < block.vtx.size() - 1; nTx++) {
        const CTransactionRef& pTx = block.vtx[nTx];
        for (size_t nOut = 0; nOut < pTx->vout.size(); nOut++) {
            const CTxOut& output = pTx->vout[nOut];
            if (output.scriptPubKey.IsMWEBPegin()) {
                if (pHogEx->vin.size() <= next_pegin_idx) {
                    return state.DoS(100, false, REJECT_INVALID, "missing-hogex-input",
                        false, "HogEx is missing expected pegin input");
                }

                // Verify the HogEx input matches this pegin output
                const COutPoint& hogex_input = pHogEx->vin[next_pegin_idx].prevout;
                if (hogex_input.hash != pTx->GetHash() || hogex_input.n != (uint32_t)nOut) {
                    return state.DoS(100, false, REJECT_INVALID, "pegin-mismatch",
                        false, "HogEx input does not match pegin output");
                }

                hogex_input_amount += output.nValue;
                if (!MoneyRange(hogex_input_amount)) {
                    return state.DoS(100, false, REJECT_INVALID, "accumulated-pegin-outofrange",
                        false, "Accumulated pegin amount is out of range");
                }

                next_pegin_idx++;
            }
        }
    }

    // Verify there are no extra HogEx inputs beyond what is expected.
    if (next_pegin_idx != pHogEx->vin.size()) {
        return state.DoS(100, false, REJECT_INVALID, "extra-hogex-input",
            false, "HogEx contains unexpected input(s)");
    }

    // Verify that the mw::Block is valid, and the pegins and pegouts all match.
    if (!MWEB::Node::ValidateMWEBBlock(block)) {
        return state.DoS(100, false, REJECT_INVALID, "bad-blk-mweb",
            false, "MWEB block validation failed");
    }

    return true;
}

bool Node::ValidateMWEBBlock(const CBlock& block)
{
    const CTransactionRef& pHogEx = block.vtx.back();

    // Find all pegin scriptPubKeys in the block.
    // We don't support pegins in the coinbase tx or the HogEx tx, so skip those.
    std::vector<mw::PegInCoin> block_pegins;
    for (size_t i = 1; i < block.vtx.size() - 1; i++) {
        for (const CTxOut& out : block.vtx[i]->vout) {
            mw::Hash kernel_id;
            if (out.scriptPubKey.IsMWEBPegin(&kernel_id)) {
                block_pegins.push_back(mw::PegInCoin{out.nValue, std::move(kernel_id)});
            }
        }
    }

    // Find all pegout outputs in the HogEx transaction.
    // The first output is not a pegout. It contains the MWEB balance and header hash.
    // The remaining outputs are all pegouts.
    std::vector<mw::PegOutCoin> block_pegouts;
    for (size_t i = 1; i < pHogEx->vout.size(); i++) {
        block_pegouts.push_back(mw::PegOutCoin{pHogEx->vout[i].nValue, pHogEx->vout[i].scriptPubKey});
    }

    try {
        block.mweb_block.m_block->Validate(block_pegins, block_pegouts);
    } catch (const std::exception&) {
        return false;
    }

    return true;
}

bool Node::CheckTransaction(const CTransaction& tx, CValidationState& state)
{
    // Verify pegin amounts match
    if (tx.HasMWEBTx()) {
        std::vector<mw::PegInCoin> pegins = tx.mweb_tx.GetPegIns();

        // Build a map of kernel_id -> pegin_amount from canonical outputs
        std::map<mw::Hash, CAmount> tx_pegins;
        for (const CTxOut& out : tx.vout) {
            mw::Hash kernel_id;
            if (out.scriptPubKey.IsMWEBPegin(&kernel_id)) {
                tx_pegins[kernel_id] = out.nValue;
            }
        }

        // Verify each MWEB pegin matches a canonical pegin output
        for (const mw::PegInCoin& pegin : pegins) {
            auto iter = tx_pegins.find(pegin.GetKernelID());
            if (iter == tx_pegins.end() || pegin.GetAmount() != iter->second) {
                return state.DoS(100, false, REJECT_INVALID, "pegin-mismatch");
            }
        }

        // If the transaction has MWEB data, call the libmw transaction validation logic.
        try {
            tx.mweb_tx.m_transaction->Validate();
        } catch (const std::exception&) {
            return state.DoS(100, false, REJECT_INVALID, "bad-mweb-txn");
        }
    }

    return true;
}
