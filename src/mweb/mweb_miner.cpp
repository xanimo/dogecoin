// Copyright (c) 2021 The Litecoin Core developers
// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "mweb/mweb_miner.h"

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
    hogex_outputs.clear();

    // Create the block builder
    mweb_builder = mw::BlockBuilder::Create(static_cast<int32_t>(nHeight), prevHeader);
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

    // Collect HogEx inputs and outputs from this transaction
    for (const CTxIn& vin : pTx->vin) {
        hogex_inputs.push_back(vin);
    }
    for (const CTxOut& vout : pTx->vout) {
        hogex_outputs.push_back(vout);
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
    // If no MWEB transactions were added, nothing to do
    if (!mweb_builder || !mweb_builder->HasTransactions()) {
        return;
    }

    // 1. Finalize the MWEB block
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

    // Remaining outputs: pegout outputs from MWEB kernels
    std::vector<mw::PegOutCoin> pegouts = mweb_block->GetPegOuts();
    for (const auto& pegout : pegouts) {
        hogex.vout.push_back(CTxOut(pegout.GetAmount(), pegout.GetScriptPubKey()));
    }

    // Also append any non-MWEB outputs collected from mixed transactions
    for (const auto& vout : hogex_outputs) {
        hogex.vout.push_back(vout);
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
