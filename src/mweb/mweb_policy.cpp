// Copyright (c) 2021 The Litecoin Core developers
// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "mweb/mweb_policy.h"

#include "primitives/transaction.h"
#include "script/script.h"

#include <mw/consensus/Params.h>
#include <mw/consensus/Weight.h>

#include <set>

using namespace MWEB;

// Relay/mempool limits for MWEB transactions, which are policy and not consensus.
//
// The consensus limits (mw::MAX_BLOCK_WEIGHT, mw::MAX_NUM_INPUTS) let a single
// transaction carry an entire block's worth of inputs, outputs and kernels.
// Signature and rangeproof verification runs during mempool acceptance, before
// any fee is required, so relaying such a transaction would let a peer buy a
// full block of crypto verification for nothing. Relayed transactions are
// therefore bounded to ~2% of the consensus limits. Inputs carry no MWEB weight,
// so they are bounded by count rather than by weight.
static constexpr size_t MAX_STANDARD_MWEB_TX_WEIGHT = mw::MAX_BLOCK_WEIGHT / 50; // 4,000
static constexpr size_t MAX_STANDARD_MWEB_TX_INPUTS = mw::MAX_NUM_INPUTS / 50;   // 1,000

bool Policy::IsStandardTx(const CTransaction& tx, std::string& reason)
{
    // Transaction aggregation is not allowed for transactions that also carry
    // canonical data: every canonical peg-in output must name a kernel the MWEB
    // data carries, and every such kernel must have its canonical output.
    if (!tx.IsMWEBOnly()) {
        std::set<mw::Hash> pegin_kernels;
        for (const CTxOut& txout : tx.vout) {
            mw::Hash kernel_id;
            if (txout.scriptPubKey.IsMWEBPegin(&kernel_id)) {
                pegin_kernels.insert(std::move(kernel_id));
            }
        }

        if (pegin_kernels != tx.mweb_tx.GetKernelIDs()) {
            reason = "kernel-mismatch";
            return false;
        }
    }

    if (tx.HasMWEBTx() && !tx.mweb_tx.m_transaction->IsStandard()) {
        reason = "non-standard-mweb-tx";
        return false;
    }

    return true;
}

bool Policy::CheckWeight(const CTransaction& tx, std::string& reason)
{
    if (!tx.HasMWEBTx()) {
        return true;
    }

    // HasMWEBTx() guarantees m_transaction is non-null.
    const mw::TxBody& body = tx.mweb_tx.m_transaction->GetBody();

    if (body.GetInputs().size() > MAX_STANDARD_MWEB_TX_INPUTS) {
        reason = "mweb-txn-too-many-inputs";
        return false;
    }

    if (Weight::Calculate(body) > MAX_STANDARD_MWEB_TX_WEIGHT) {
        reason = "mweb-txn-oversize";
        return false;
    }

    return true;
}
