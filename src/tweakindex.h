// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TWEAKINDEX_H
#define BITCOIN_TWEAKINDEX_H

#include "dbwrapper.h"
#include "pubkey.h"

#include <stdint.h>
#include <utility>
#include <vector>

class CCoinsViewCache;
class CTransaction;

/** One scannable transaction in a block: its index in vtx, and input_hash * A compressed. */
struct CTweakEntry
{
    uint32_t tx_index;
    CPubKey tweak;

    CTweakEntry() : tx_index(0) {}
    CTweakEntry(uint32_t n, const CPubKey& t) : tx_index(n), tweak(t) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(tx_index);
        READWRITE(tweak);
    }
};

/**
 * Per-block BIP352 scanning tweaks.
 *
 * Keyed by height rather than by txid, because every consumer wants a block's worth at a time: a
 * local scanner walks a range, and a light client asks for one block. A txid key would serve
 * neither without a second index.
 *
 * Only transactions with at least one eligible input appear, so a block's vector is usually
 * shorter than its vtx, and an empty vector is written rather than omitted so that "scanned, and
 * nothing here" is distinguishable from "never indexed".
 */
class CTweakIndex : public CDBWrapper
{
public:
    CTweakIndex(size_t nCacheSize, bool fMemory = false, bool fWipe = false);

    bool WriteBlock(int height, const std::vector<CTweakEntry>& entries);
    bool ReadBlock(int height, std::vector<CTweakEntry>& entries) const;
    bool EraseBlock(int height);

    //! Highest height written, so a restart knows where to resume.
    bool WriteBestHeight(int height);
    bool ReadBestHeight(int& height) const;

private:
    CTweakIndex(const CTweakIndex&);
    void operator=(const CTweakIndex&);
};

/**
 * Compute one transaction's tweak from the coins it is about to spend.
 *
 * Must be called while `view` still holds those coins, which in ConnectBlock means immediately
 * before UpdateCoins for this same transaction, and not earlier: a transaction may spend an
 * output created by an earlier transaction in the same block, and that output does not exist in
 * the view until UpdateCoins has run for the one that created it.
 *
 * Returns false when the transaction has no eligible input, which is not an error.
 */
bool ComputeTxTweak(CPubKey& out, const CTransaction& tx, const CCoinsViewCache& view);

/** The active tweak index, or nullptr when -tweakindex is off. */
extern CTweakIndex* ptweakindex;

static const bool DEFAULT_TWEAKINDEX = false;

#endif // BITCOIN_TWEAKINDEX_H
