// Copyright (c) 2021 The Litecoin Core developers
// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_MWEB_MWEB_POLICY_H
#define BITCOIN_MWEB_MWEB_POLICY_H

#include <string>

class CTransaction;

namespace MWEB {

class Policy
{
public:
    /// Checks a transaction against the MWEB-specific standardness rules: its
    /// canonical peg-in outputs must name exactly the kernels its MWEB data
    /// carries, and its kernels must use only standard features.
    static bool IsStandardTx(const CTransaction& tx, std::string& reason);

    /// Cheaply bounds a relayed MWEB transaction's input count and weight, well
    /// below the consensus limits. Runs before the signature and rangeproof
    /// verification in MWEB::Node::CheckTransaction, which is otherwise free for
    /// a peer to trigger at full block scale.
    static bool CheckWeight(const CTransaction& tx, std::string& reason);
};

}

#endif // BITCOIN_MWEB_MWEB_POLICY_H
