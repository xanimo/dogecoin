// Copyright (c) 2021 The Litecoin Core developers
// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "mweb/mweb_miner.h"

#include "chain.h"
#include "consensus/consensus.h"
#include "consensus/validation.h"
#include "primitives/block.h"
#include "script/script.h"
#include "util.h"
#include "validation.h"

using namespace MWEB;

void Miner::NewBlock(const uint64_t nHeight)
{
    // Reset state for the new block
    mweb_amount_change = 0;
    hogex_fees = 0;
    hogex_sigops = 0;
    hogex_inputs.clear();
    hogex_outputs.clear();

    // TODO: Initialize mweb_builder when libmw BlockBuilder is available
    // mweb_builder = mw::BlockBuilder::Create(nHeight);
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

    // TODO: Add transaction to MWEB block builder when available
    // if (!mweb_builder->AddTransaction(pTx->mweb_tx.m_transaction, pegins)) {
    //     LogPrintf("Failed to add MWEB transaction\n");
    //     return false;
    // }

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
    // TODO: Implement full HogEx transaction creation when libmw BlockBuilder is available
    // This will:
    // 1. Finalize the MWEB block via mweb_builder->Build()
    // 2. Create the HogEx transaction with:
    //    a. First output = HogAddr (OP_8 + mweb_header_hash)
    //    b. Remaining outputs = pegout outputs from MWEB kernels
    //    c. Inputs = previous HogAddr + pegin inputs
    // 3. Set pblock->mweb_block
    // 4. Append HogEx as the last transaction in the block
}
