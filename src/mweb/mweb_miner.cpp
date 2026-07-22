// Copyright (c) 2021 The Litecoin Core developers
// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "mweb/mweb_miner.h"

#include "mweb/mweb_db.h"
#include "chain.h"
#include "consensus/consensus.h"
#include "consensus/validation.h"
#include "miner.h"
#include "primitives/block.h"
#include "script/script.h"
#include "util.h"
#include "validation.h"

using namespace MWEB;

void Miner::NewBlock(const uint64_t nHeight, const mw::Header::CPtr& prevHeader)
{
    // Reset state for the new block
    mweb_amount_change = 0;
    hogex_fees = 0;
    hogex_sigops = 0;
    hogex_inputs.clear();

    // Create the block builder, seeded with the current accumulated MWEB state so
    // the header roots it computes match what the validator will accumulate when it
    // connects the block. Falls back to an empty accumulator if state is unavailable.
    const mw::MWEBState prevState = g_mweb_state ? g_mweb_state->State() : mw::MWEBState();
    mweb_builder = mw::BlockBuilder::Create(static_cast<int32_t>(nHeight), prevHeader, prevState);
}

bool Miner::ValidatePegIns(const CTransactionRef& pTx,
                            const std::vector<mw::PegInCoin>& pegins) const
{
    // Verify pegin amounts match between canonical outputs and MWEB kernels
    std::map<mw::Hash, CAmount> kernel_pegins;
    for (const mw::PegInCoin& pegin : pegins) {
        kernel_pegins[pegin.GetKernelID()] = pegin.GetAmount();
    }

    for (size_t i = 0; i < pTx->vout.size(); i++) {
        mw::Hash kernel_id;
        if (pTx->vout[i].scriptPubKey.IsMWEBPegin(&kernel_id)) {
            auto it = kernel_pegins.find(kernel_id);
            if (it == kernel_pegins.end() || it->second != pTx->vout[i].nValue) {
                return false;
            }
            kernel_pegins.erase(it);
        }
    }

    // All kernel pegins should have been matched
    return kernel_pegins.empty();
}

bool Miner::AddMWEBTransaction(CTxMemPool::txiter iter)
{
    const CTransactionRef& pTx = iter->GetSharedTx();

    if (!pTx->HasMWEBTx()) {
        return false;
    }

    std::vector<mw::PegInCoin> pegins = pTx->mweb_tx.GetPegIns();

    // Validate pegins
    if (!pegins.empty() && !ValidatePegIns(pTx, pegins)) {
        LogPrintf("Invalid MWEB pegin amounts\n");
        return false;
    }

    // Calculate pegin/pegout amounts
    CAmount pegin_amount = 0;
    for (const mw::PegInCoin& pegin : pegins) {
        pegin_amount += pegin.GetAmount();
    }

    CAmount pegout_amount = 0;
    std::vector<mw::PegOutCoin> pegouts = pTx->mweb_tx.GetPegOuts();
    for (const mw::PegOutCoin& pegout : pegouts) {
        pegout_amount += pegout.GetAmount();
    }

    CAmount tx_fee = pTx->mweb_tx.GetFee();
    if (tx_fee < 0) {
        LogPrintf("Invalid MWEB fee amount\n");
        return false;
    }

    // Add to MWEB block builder
    if (!mweb_builder->AddTransaction(pTx->mweb_tx.m_transaction, pegins)) {
        LogPrintf("Failed to add MWEB transaction to block builder\n");
        return false;
    }

    // The HogEx integrates the peg-in by spending each canonical peg-in output
    // of this transaction (moving that value into the MWEB). Reference the peg-in
    // outputs by outpoint -- not the transaction's funding inputs, and not its
    // outputs. ContextualCheckBlock verifies the HogEx inputs are exactly these
    // peg-in outputs, and the peg-out outputs come from the MWEB kernels, not from
    // the canonical transaction. Order matches ContextualCheckBlock's scan
    // (transactions in block order, outputs in index order).
    const uint256 txid = pTx->GetHash();
    for (size_t nOut = 0; nOut < pTx->vout.size(); nOut++) {
        if (pTx->vout[nOut].scriptPubKey.IsMWEBPegin()) {
            hogex_inputs.push_back(CTxIn(COutPoint(txid, static_cast<uint32_t>(nOut))));
        }
    }

    mweb_amount_change += (CAmount(pegin_amount) - CAmount(pegout_amount + tx_fee));

    if (pTx->IsMWEBOnly()) {
        hogex_fees += tx_fee;
        hogex_sigops += iter->GetSigOpCost();
    }

    return true;
}

void Miner::AddHogExTransaction(const CBlockIndex* pIndexPrev, CBlock* pblock,
                                 CBlockTemplate* pblocktemplate, CAmount& nFees)
{
    // Once MWEB is active the miner must attach an extension block to every block,
    // even when no MWEB transactions were selected -- ContextualCheckBlock rejects
    // an active-MWEB block with no extension data. So finalize whenever the builder
    // exists (it is created in NewBlock only when MWEB is active); an empty builder
    // yields an empty extension block plus a HogEx that just rolls the HogAddr
    // forward.
    if (!mweb_builder) {
        return;
    }

    // 1. Finalize the MWEB block (may be empty)
    mw::Block::Ptr mweb_block = mweb_builder->Build();
    if (!mweb_block) {
        LogPrintf("MWEB::Miner: Failed to build MWEB block\n");
        return;
    }

    // 2. Create the HogEx transaction
    CMutableTransaction hogex;
    hogex.m_hogEx = true;

    // Input: Previous HogAddr UTXO (if previous block had MWEB state)
    CAmount prev_hogex_amount = 0;
    if (pIndexPrev->mweb_header != nullptr) {
        COutPoint prev_hogaddr(pIndexPrev->hogex_hash, 0);
        hogex.vin.push_back(CTxIn(prev_hogaddr));
        prev_hogex_amount = pIndexPrev->mweb_amount;
    }

    // Additional inputs: pegin inputs collected from MWEB transactions
    for (const auto& vin : hogex_inputs) {
        hogex.vin.push_back(vin);
    }

    // Output 0: HogAddr — witness v8 program committing to the MWEB header hash.
    // This output holds the accumulated MWEB value (previous amount + net change).
    const mw::Hash& header_hash = mweb_block->GetHeader()->GetHash();
    CScript hogAddrScript;
    hogAddrScript << OP_8;
    hogAddrScript << std::vector<uint8_t>(header_hash.begin(), header_hash.end());
    CAmount new_hogex_amount = prev_hogex_amount + mweb_amount_change;
    hogex.vout.push_back(CTxOut(new_hogex_amount, hogAddrScript));

    // Remaining outputs: peg-out outputs from the MWEB kernels. These are the
    // only non-HogAddr outputs the HogEx carries -- canonical outputs of the
    // block's transactions (peg-in outputs, change) stay in those transactions.
    std::vector<mw::PegOutCoin> pegouts = mweb_block->GetPegOuts();
    for (const auto& pegout : pegouts) {
        hogex.vout.push_back(CTxOut(pegout.GetAmount(), pegout.GetScriptPubKey()));
    }

    // 3. Set the MWEB block on the CBlock
    pblock->mweb_block.m_block = mweb_block;

    // 4. Append HogEx as the last transaction in the block
    CTransactionRef hogex_ref = MakeTransactionRef(std::move(hogex));
    pblock->vtx.push_back(hogex_ref);
    pblocktemplate->vTxFees.push_back(hogex_fees);
    pblocktemplate->vTxSigOpsCost.push_back(hogex_sigops);

    // 5. Add collected MWEB fees to the block's total fees
    nFees += hogex_fees;

    LogPrintf("MWEB::Miner: Added HogEx transaction with %d inputs, %d outputs, fees=%d\n",
              hogex_ref->vin.size(), hogex_ref->vout.size(), hogex_fees);
}
