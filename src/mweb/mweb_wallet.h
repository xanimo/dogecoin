// Copyright (c) 2021 The Litecoin Core developers
// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef DOGECOIN_MWEB_WALLET_H
#define DOGECOIN_MWEB_WALLET_H

#include <primitives/transaction.h>
#include <mw/models/tx/Transaction.h>

#include <vector>

namespace MWEB {

/// Wallet-side assembly of MWEB transactions into canonical CTransactions.
///
/// The cryptographic MWEB body (commitments, range proofs, kernels) is built
/// by the libmw wallet TxBuilder; this layer bridges that body to the canonical
/// chain by attaching the CTransaction structure the consensus rules require.
namespace Wallet {

/// Assemble a peg-in CTransaction from an already-built MWEB transaction.
///
/// A peg-in moves value from the canonical chain into the MWEB. On the MWEB
/// side each peg-in is a kernel carrying an amount (mwtx.GetPegIns()); on the
/// canonical side that value must appear as an output paying a peg-in witness
/// program keyed by the kernel ID (see GetScriptForMWEBPegin). This helper adds
/// one such output per peg-in coin so MWEB::Node::CheckTransaction's peg-in
/// match succeeds.
///
/// `canonicalInputs` are the canonical coins that fund the peg-in (supplied by
/// the wallet's coin selection); this helper does not select or sign them.
CTransaction CreatePegInTransaction(
    const mw::Transaction& mwtx,
    const std::vector<CTxIn>& canonicalInputs);

} // namespace Wallet

} // namespace MWEB

#endif // DOGECOIN_MWEB_WALLET_H
