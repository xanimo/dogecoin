// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "tweakindex.h"

#include "bip352.h"
#include "coins.h"
#include "primitives/block.h"
#include "util.h"

CTweakIndex* ptweakindex = NULL;

static const char DB_TWEAKS = 't';
static const char DB_BEST_HEIGHT = 'B';

CTweakIndex::CTweakIndex(size_t nCacheSize, bool fMemory, bool fWipe)
    : CDBWrapper(GetDataDir() / "indexes" / "tweakindex", nCacheSize, fMemory, fWipe)
{
}

bool CTweakIndex::WriteBlock(int height, const std::vector<CTweakEntry>& entries)
{
    return Write(std::make_pair(DB_TWEAKS, height), entries);
}

bool CTweakIndex::ReadBlock(int height, std::vector<CTweakEntry>& entries) const
{
    return Read(std::make_pair(DB_TWEAKS, height), entries);
}

bool CTweakIndex::EraseBlock(int height)
{
    return Erase(std::make_pair(DB_TWEAKS, height));
}

bool CTweakIndex::WriteBestHeight(int height)
{
    return Write(DB_BEST_HEIGHT, height);
}

bool CTweakIndex::ReadBestHeight(int& height) const
{
    return Read(DB_BEST_HEIGHT, height);
}

bool ComputeTxTweak(CPubKey& out, const CTransaction& tx, const CCoinsViewCache& view)
{
    if (tx.IsCoinBase()) return false;

    std::map<COutPoint, CScript> prevout_spks;
    for (size_t j = 0; j < tx.vin.size(); j++) {
        const COutPoint& prevout = tx.vin[j].prevout;
        const CCoins* coins = view.AccessCoins(prevout.hash);
        if (!coins || !coins->IsAvailable(prevout.n)) return false;
        prevout_spks[prevout] = coins->vout[prevout.n].scriptPubKey;
    }

    bip352::CPrevoutsSummary summary;
    if (bip352::GetPrevoutsSummary(summary, tx.vin, prevout_spks) != bip352::PREVOUTS_OK) {
        return false;                              // no eligible input, nothing to scan
    }
    return bip352::ComputeScanTweak(out, summary);
}
