// Copyright (c) 2021 The Litecoin Core developers
// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_MWEB_MWEB_POLICY_H
#define BITCOIN_MWEB_MWEB_POLICY_H

#include <string>

class CFeeRate;
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

    /// Requires the kernel fees of a relayed MWEB transaction to cover its MWEB
    /// weight: the relay rate on mw::BYTES_PER_WEIGHT bytes for every unit, which
    /// is the rate libmw itself converts extra bytes to weight at. The mempool
    /// charges by the canonical serialization, and that is 10 bytes for a
    /// transaction that lives only in the extension block, whatever it carries.
    /// Reads the transaction alone, so it runs before the cryptography as well.
    static bool CheckFee(const CTransaction& tx, const CFeeRate& relayRate, std::string& reason);
};

}

#endif // BITCOIN_MWEB_MWEB_POLICY_H
