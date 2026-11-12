// Copyright (c) 2021 The Litecoin Core developers
// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "mweb/mweb_node.h"

#include "mweb/mweb_db.h"

#include "chain.h"
#include "consensus/validation.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "util.h"
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
                true, "MWEB not activated, but extension block found");
        }

        // The HogEx marker is not committed by the canonical merkle root, so before
        // activation it is mutated data, just like an extension block.
        for (const CTransactionRef& pTx : block.vtx) {
            if (pTx->IsHogEx()) {
                return state.DoS(100, false, REJECT_INVALID, "unexpected-mweb-data",
                    true, "MWEB not activated, but HogEx marker found");
            }
        }

        return true;
    } else if (block.mweb_block.IsNull()) {
        // After activation an extension block is permitted, not required. A miner
        // with nothing to put in one makes an ordinary block, which is what makes
        // the feature miner opt-in and is the model litecoin ships.
        //
        // Requiring one deadlocked the chain once the HogEx needed an input: the
        // first extension block has no previous HogAddr to spend, so without a
        // peg-in in the mempool there was no valid block to mine at all, and
        // CreateNewBlock failed on bad-txns-vin-empty. It also meant any miner
        // that had not upgraded produced blocks the rest rejected, so the latch
        // at 1500 of 2000 left up to a quarter of hashrate forked off.
        for (const CTransactionRef& pTx : block.vtx) {
            if (pTx->IsHogEx()) {
                return state.DoS(100, false, REJECT_INVALID, "bad-hogex-no-mweb",
                    true, "HogEx marker without an extension block");
            }
        }
        return true;
    }

    // Last transaction must be marked as HogEx. The marker is not committed by the
    // canonical merkle root, so a missing one is mutated data rather than a reason
    // to fail the hash: a valid body shares it.
    const CTransactionRef& pHogEx = block.vtx.back();
    if (!pHogEx->IsHogEx()) {
        return state.DoS(100, false, REJECT_INVALID, "bad-hogex-missing",
            true, "Last transaction is not marked as HogEx");
    }

    // Only the last transaction in the block should be marked as the HogEx.
    for (size_t i = 0; i < block.vtx.size() - 1; i++) {
        if (block.vtx[i]->IsHogEx()) {
            return state.DoS(100, false, REJECT_INVALID, "bad-hogex-position",
                true, "HogEx marker in wrong position");
        }
    }

    // Validate each transaction in the block. HogEx placement must be checked first
    // because the marker is not committed by the canonical merkle root: otherwise a
    // marker moved onto a pegin-bearing transaction rejects here, as consensus-
    // invalid, and poisons a hash the honest block also has.
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

    // Verify that the first output of the HogEx is a valid HogAddr.
    mw::Hash mweb_hash;
    if (pHogEx->vout.empty() || !pHogEx->vout.front().scriptPubKey.IsMWEBHogAddr(&mweb_hash)) {
        return state.DoS(100, false, REJECT_INVALID, "bad-hogex",
            false, "HogEx missing or invalid HogAddr");
    }

    // Verify that the MWEB header hash matches. The extension block is not committed
    // by the canonical merkle root either, so this is mutation and not invalidity.
    if (mweb_hash != block.mweb_block.m_block->GetHash()) {
        return state.DoS(100, false, REJECT_INVALID, "mweb-hash-mismatch",
            true, "MWEB header hash doesn't match hogex hash");
    }

    // Verify that the MWEB block's height is correct.
    if (block.mweb_block.GetHeight() != (pindexPrev->nHeight + 1)) {
        return state.DoS(100, false, REJECT_INVALID, "mweb-height-mismatch",
            false, "Invalid MWEB block height");
    }

    // Kernel feature bits must be canonical: a bit set over an empty field lets
    // the same kernel be expressed two ways. Unconditional rather than gated on
    // an activation height as upstream needs, because MWEB has never activated
    // here and there are no kernels predating the rule to grandfather.
    //
    // Mutation rather than invalidity. Nothing has authenticated the body
    // against the HogEx-committed header yet (ValidateMWEBBlock does that, and
    // runs below), so a body swapped in under an honest header reaches here
    // carrying the honest block's canonical hash. Failing it as consensus would
    // mark that hash permanently invalid and the real block could never be
    // accepted.
    for (const mw::Kernel& kernel : block.mweb_block.m_block->GetKernels()) {
        if (!kernel.HasCanonicalPegOutFeature()) {
            return state.DoS(100, false, REJECT_INVALID, "bad-mweb-empty-pegout",
                true, "Pegout feature set without pegouts");
        }
        if (!kernel.HasCanonicalExtraDataFeature()) {
            return state.DoS(100, false, REJECT_INVALID, "bad-mweb-empty-extradata",
                true, "Extra data feature set without extra data");
        }
        if (!kernel.HasCanonicalStealthExcessFeature()) {
            return state.DoS(100, false, REJECT_INVALID, "bad-mweb-empty-stealthexcess",
                true, "Stealth excess feature set without a key");
        }
    }

    for (const mw::Input& input : block.mweb_block.m_block->GetInputs()) {
        if (!input.HasCanonicalStealthKeyFeature()) {
            return state.DoS(100, false, REJECT_INVALID, "bad-mweb-empty-stealthkey",
                true, "Stealth key feature set without a key");
        }
    }

    // The HogEx accounting is NOT checked here. It reads the previous block's
    // hogex_hash and mweb_amount, which ConnectBlock only populates when that
    // block connects, and this function runs from AcceptBlock. During a reindex
    // every block in a file is accepted before any is activated, so the previous
    // block's values are still zero and the accounting would reject a valid
    // chain. ConnectBlock calls CheckHogEx instead, where the values are present.

    // Verify that the mw::Block is valid, and the pegins and pegouts all match.
    // The HogAddr commits to the MWEB header, not to the body, so a body that
    // disagrees with an otherwise matching header is mutation: the honest body
    // has this same canonical block hash.
    if (!MWEB::Node::ValidateMWEBBlock(block)) {
        return state.DoS(100, false, REJECT_INVALID, "bad-blk-mweb",
            true, "MWEB block validation failed");
    }

    return true;
}

bool Node::CheckHogEx(
    const CBlock& block,
    const uint256& prev_hogex_hash,
    CAmount prev_mweb_amount,
    bool is_first_hogex,
    CValidationState& state)
{
    const CTransactionRef& pHogEx = block.vtx.back();

    // The first input rolls the previous pool forward. Without this the HogEx can
    // fund its HogAddr from anywhere, leaving the previous HogAddr unspent while
    // the accounting still assumes it was consumed.
    size_t next_pegin_idx = is_first_hogex ? 0 : 1;
    if (!is_first_hogex) {
        if (pHogEx->vin.empty() ||
            pHogEx->vin[0].prevout != COutPoint(prev_hogex_hash, 0)) {
            return state.DoS(100, false, REJECT_INVALID, "bad-hogex-prevout",
                false, "HogEx does not spend the previous HogAddr");
        }
    }

    // Loop through the block's txs looking for all outputs with pegin scriptPubKeys.
    // While looping, we:
    // 1. Calculate the total value of the HogEx inputs (hogex_input_amount).
    // 2. Verify the HogEx inputs exactly match the pegin outputs.
    CAmount hogex_input_amount = prev_mweb_amount;
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

    // The HogAddr carries what is left in the pool: everything pegged in, less
    // what pegs out and less the MWEB fees. ConnectBlock's input rules only cap
    // the HogEx's outputs at its inputs, so without this an under-funded HogAddr
    // hands the difference to the miner as fee -- pegged-in value leaving the
    // pool with every consensus rule still satisfied.
    CAmount pegout_amount = 0;
    for (size_t i = 1; i < pHogEx->vout.size(); i++) {
        pegout_amount += pHogEx->vout[i].nValue;
        if (!MoneyRange(pegout_amount)) {
            return state.DoS(100, false, REJECT_INVALID, "pegout-outofrange",
                false, "Accumulated pegout amount is out of range");
        }
    }

    const CAmount mweb_fee = block.mweb_block.m_block->GetTotalFee();
    const CAmount expected_amount = hogex_input_amount - pegout_amount - mweb_fee;
    if (!MoneyRange(expected_amount) || pHogEx->vout.front().nValue != expected_amount) {
        return state.DoS(100, false, REJECT_INVALID, "bad-hogex-amount",
            false, "HogAddr amount does not match the MWEB balance");
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
    } catch (const std::exception& e) {
        LogPrintf("MWEB::Node::ValidateMWEBBlock: mweb block invalid: %s (pegins=%d pegouts=%d)\n",
                  e.what(), block_pegins.size(), block_pegouts.size());
        return false;
    }

    return true;
}

bool Node::CheckTransaction(const CTransaction& tx, CValidationState& state)
{
    // Every MWEB input must spend an output that exists and is still unspent.
    // Nothing else on the mempool path consults MWEB state, so without this a
    // body spending an output nobody created is accepted and ranked by whatever
    // fee it declares, which is what relay and eviction sort on. The builder
    // refuses to mine it, so it never leaves and never expires.
    if (tx.HasMWEBTx() && g_mweb_state) {
        for (const mw::Input& input : tx.mweb_tx.m_transaction->GetInputs()) {
            if (!g_mweb_state->State().IsUnspentByOutputID(input.GetOutputID())) {
                return state.DoS(10, false, REJECT_INVALID, "bad-mweb-missing-input",
                    false, "MWEB input spends an output that is not unspent");
            }
        }
    }

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
