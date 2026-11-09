// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_INDEX_TWEAKINDEX_H
#define BITCOIN_INDEX_TWEAKINDEX_H

#include <chain.h>
#include <index/base.h>
#include <pubkey.h>

#include <stdint.h>
#include <vector>

class CBlockUndo;
class CTransaction;
class CTxUndo;

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
class CTweakIndex final : public BaseIndex
{
private:
    const std::unique_ptr<BaseIndex::DB> m_db;

protected:
    bool WriteBlock(const CBlock& block, const CBlockIndex* pindex) override;

    bool Rewind(const CBlockIndex* current_tip, const CBlockIndex* new_tip) override;

    BaseIndex::DB& GetDB() const override { return *m_db; }

    const char* GetName() const override { return "tweakindex"; }

public:
    explicit CTweakIndex(size_t n_cache_size, bool f_memory = false, bool f_wipe = false);

    /** Look up one block's tweaks. False means the height was never indexed. */
    bool ReadBlock(int height, std::vector<CTweakEntry>& entries) const;
};

/**
 * Compute one transaction's tweak from the coins it spent.
 *
 * Takes the spent coins from undo data rather than the UTXO set, so it does not care whether an
 * input was created in this same block: undo data records what the input actually spent either
 * way. Deriving from a live view instead forced the tweak to be computed between a transaction's
 * script checks and its UpdateCoins, and getting that order wrong aborted the node on mainnet at
 * height 1181, where one transaction spends an output of an earlier one in the same block.
 *
 * `tx_undo.vprevout[j]` is the coin spent by `tx.vin[j]`.
 *
 * Returns false when the transaction has no eligible input, which is not an error.
 */
bool ComputeTxTweak(CPubKey& out, const CTransaction& tx, const CTxUndo& tx_undo);

/** The active tweak index, or null when -tweakindex is off. */
extern std::unique_ptr<CTweakIndex> g_tweakindex;

static const bool DEFAULT_TWEAKINDEX = false;

#endif // BITCOIN_INDEX_TWEAKINDEX_H
