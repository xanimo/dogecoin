// Copyright (c) 2021 The Litecoin Core developers
// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef DOGECOIN_MWEB_DB_H
#define DOGECOIN_MWEB_DB_H

#include "dbwrapper.h"
#include <mw/models/block/Block.h>
#include <mw/models/block/BlockUndo.h>
#include <mw/models/tx/Output.h>
#include <mw/models/tx/UTXO.h>

#include <memory>
#include <set>
#include <vector>

/// Database key prefixes for MWEB state storage
namespace MWEBDBKeys {
    static const char UTXO       = 'u';   // UTXO by output_id
    static const char LEAFSET    = 'l';   // leafset bitmap
    static const char BEST_HASH  = 'B';   // best block hash
}

/// Persistent MWEB state database backed by LevelDB.
///
/// Stores the MWEB UTXO set and leafset bitmap in a dedicated database
/// directory (mwebstate/). This is analogous to the chainstate/ database
/// for canonical UTXOs, but tracks MW extension block outputs.
///
/// The database is updated atomically via ConnectBlock/DisconnectBlock
/// to keep it in sync with the main chain.
class CMWEBStateDB
{
public:
    CMWEBStateDB(size_t nCacheSize, bool fMemory = false, bool fWipe = false);

    /// Add an MWEB output to the UTXO set.
    bool AddOutput(const mw::Output& output);

    /// Remove an MWEB output from the UTXO set (when spent).
    bool SpendOutput(const mw::Hash& output_id);

    /// Retrieve an MWEB output by its output ID.
    /// Returns true if found.
    bool GetOutput(const mw::Hash& output_id, mw::Output& output) const;

    /// Check if an MWEB output exists in the UTXO set.
    bool HasOutput(const mw::Hash& output_id) const;

    /// Retrieve a range of UTXOs starting at a given leaf index.
    /// Returns up to max_count UTXOs ordered by their output IDs.
    std::vector<mw::Output> GetUTXOs(uint64_t start_index, uint64_t max_count);

    /// Apply an MWEB block's changes to the state database.
    /// Adds new outputs, removes spent inputs, and updates the best block hash.
    /// Returns the undo data needed to reverse this block during a reorg.
    bool ConnectBlock(const mw::Block& block,
                      const mw::Header::CPtr& prevHeader,
                      std::vector<UTXO>& spentUTXOs,
                      std::vector<mw::Hash>& addedOutputIDs);

    /// Reverse an MWEB block's changes using the undo data.
    /// Restores spent UTXOs and removes added outputs.
    bool DisconnectBlock(const mw::BlockUndo& undo);

    /// Get the hash of the block that this state was last updated for.
    bool GetBestBlockHash(uint256& hash) const;

    /// Set the best block hash.
    bool SetBestBlockHash(const uint256& hash);

    /// Flush the database.
    bool Flush() { return db.Flush(); }

private:
    CDBWrapper db;
};

/// Global MWEB state database instance (initialized in init.cpp)
extern std::unique_ptr<CMWEBStateDB> g_mweb_state;

#endif // DOGECOIN_MWEB_DB_H
