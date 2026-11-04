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

bool ComputeBlockTweaks(std::vector<CTweakEntry>& out, const CBlock& block, const CCoinsViewCache& view)
{
    out.clear();
    for (size_t i = 1; i < block.vtx.size(); i++) {   // the coinbase spends nothing
        const CTransaction& tx = *(block.vtx[i]);

        std::map<COutPoint, CScript> prevout_spks;
        bool have_all = true;
        for (size_t j = 0; j < tx.vin.size(); j++) {
            const COutPoint& prevout = tx.vin[j].prevout;
            const CCoins* coins = view.AccessCoins(prevout.hash);
            if (!coins || !coins->IsAvailable(prevout.n)) {
                have_all = false;
                break;
            }
            prevout_spks[prevout] = coins->vout[prevout.n].scriptPubKey;
        }
        // Inputs are checked before this runs, so a miss means the caller handed us the wrong
        // view rather than a bad block. Refuse the whole block instead of indexing part of it.
        if (!have_all) return false;

        bip352::CPrevoutsSummary summary;
        if (bip352::GetPrevoutsSummary(summary, tx.vin, prevout_spks) != bip352::PREVOUTS_OK) {
            continue;                                  // no eligible input, nothing to scan
        }

        CPubKey tweak;
        if (!bip352::ComputeScanTweak(tweak, summary)) continue;
        out.push_back(CTweakEntry((uint32_t)i, tweak));
    }
    return true;
}
