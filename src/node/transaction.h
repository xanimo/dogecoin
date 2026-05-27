// Copyright (c) 2017-2018 The Bitcoin Core developers
// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_TRANSACTION_H
#define BITCOIN_NODE_TRANSACTION_H

#include <amount.h>
#include <primitives/transaction.h>
#include <uint256.h>

/**
 * Broadcast a transaction.
 *
 * Submits the transaction to the local mempool and, on success, relays it to
 * all peers. On failure throws a JSONRPCError describing the problem.
 *
 * @param[in]  tx              The transaction to broadcast.
 * @param[in]  fLimitFree      Whether to enforce free-transaction relay limits.
 * @param[in]  nMaxRawTxFee    Reject the transaction if its absolute fee
 *                             exceeds this value (0 to allow any fee).
 * @return the transaction hash.
 */
uint256 BroadcastTransaction(CTransactionRef tx, bool fLimitFree, CAmount nMaxRawTxFee);

#endif // BITCOIN_NODE_TRANSACTION_H
