// Copyright (c) 2021 The Litecoin Core developers
// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "mweb/mweb_wallet.h"

#include "script/standard.h"

#include <memory>

namespace MWEB {
namespace Wallet {

CTransaction CreatePegInTransaction(
    const mw::Transaction& mwtx,
    const std::vector<CTxIn>& canonicalInputs)
{
    CMutableTransaction mtx;
    mtx.vin = canonicalInputs;
    mtx.mweb_tx = MWEB::Tx(std::make_shared<mw::Transaction>(mwtx));

    // Pair each MWEB peg-in kernel with a canonical peg-in output carrying the
    // same amount and keyed by the kernel ID. This is exactly what the node's
    // peg-in match verifies in MWEB::Node::CheckTransaction.
    for (const mw::PegInCoin& pegin : mwtx.GetPegIns()) {
        mtx.vout.emplace_back(pegin.GetAmount(), GetScriptForMWEBPegin(pegin.GetKernelID()));
    }

    return CTransaction(mtx);
}

} // namespace Wallet
} // namespace MWEB
