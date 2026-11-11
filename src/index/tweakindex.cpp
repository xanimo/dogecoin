// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <index/tweakindex.h>

#include <bip352.h>
#include <coins.h>
#include <primitives/block.h>
#include <undo.h>
#include <util.h>
#include <validation.h>

std::unique_ptr<CTweakIndex> g_tweakindex;

static const char DB_TWEAKS = 't';

CTweakIndex::CTweakIndex(size_t n_cache_size, bool f_memory, bool f_wipe)
    : m_db(new BaseIndex::DB(GetDataDir() / "indexes" / "tweakindex", n_cache_size, f_memory, f_wipe))
{
}

bool CTweakIndex::ReadBlock(int height, std::vector<CTweakEntry>& entries) const
{
    return m_db->Read(std::make_pair(DB_TWEAKS, height), entries);
}

bool CTweakIndex::LookupTweakRange(int start_height, const CBlockIndex* stop_index,
                                   std::vector<std::vector<CTweakEntry> >& tweaks_out) const
{
    if (start_height < 0 || stop_index == NULL || stop_index->nHeight < start_height) return false;

    tweaks_out.clear();
    tweaks_out.resize(stop_index->nHeight - start_height + 1);

    for (const CBlockIndex* p = stop_index; p != NULL && p->nHeight >= start_height; p = p->pprev) {
        if (!ReadBlock(p->nHeight, tweaks_out[p->nHeight - start_height])) {
            tweaks_out.clear();
            return false;
        }
    }
    return true;
}

bool CTweakIndex::WriteBlock(const CBlock& block, const CBlockIndex* pindex)
{
    std::vector<CTweakEntry> entries;

    /* The genesis block has no undo data, and a coinbase is never scannable anyway. */
    if (pindex->nHeight > 0) {
        CBlockUndo block_undo;
        if (!UndoReadFromDisk(block_undo, pindex->GetUndoPos(), pindex->pprev->GetBlockHash())) {
            return error("%s: UndoReadFromDisk failed for block=%s height=%d",
                         __func__, pindex->GetBlockHash().ToString(), pindex->nHeight);
        }

        /* vtxundo covers all but the coinbase, so vtxundo[i - 1] belongs to vtx[i]. */
        if (block_undo.vtxundo.size() + 1 != block.vtx.size()) {
            return error("%s: undo data has %u entries for %u transactions in block=%s height=%d",
                         __func__, (unsigned)block_undo.vtxundo.size(),
                         (unsigned)block.vtx.size(), pindex->GetBlockHash().ToString(),
                         pindex->nHeight);
        }

        for (size_t i = 1; i < block.vtx.size(); i++) {
            CPubKey tweak;
            if (ComputeTxTweak(tweak, *block.vtx[i], block_undo.vtxundo[i - 1])) {
                entries.push_back(CTweakEntry((uint32_t)i, tweak));
            }
        }
    }

    /* Written even when empty: "scanned, nothing here" must not read as "never indexed". */
    return m_db->Write(std::make_pair(DB_TWEAKS, pindex->nHeight), entries);
}

bool CTweakIndex::Rewind(const CBlockIndex* current_tip, const CBlockIndex* new_tip)
{
    /* Drop the disconnected heights, so a reorg cannot leave a scanner reading tweaks for a
       block that is no longer on the chain. */
    CDBBatch batch(*m_db);
    for (const CBlockIndex* iter = current_tip; iter != new_tip; iter = iter->pprev) {
        batch.Erase(std::make_pair(DB_TWEAKS, iter->nHeight));
    }
    if (!m_db->WriteBatch(batch)) return false;

    return BaseIndex::Rewind(current_tip, new_tip);
}

bool ComputeTxTweak(CPubKey& out, const CTransaction& tx, const CTxUndo& tx_undo)
{
    if (tx.IsCoinBase()) return false;
    if (tx_undo.vprevout.size() != tx.vin.size()) return false;

    std::map<COutPoint, CScript> prevout_spks;
    for (size_t j = 0; j < tx.vin.size(); j++) {
        prevout_spks[tx.vin[j].prevout] = tx_undo.vprevout[j].out.scriptPubKey;
    }

    bip352::CPrevoutsSummary summary;
    if (bip352::GetPrevoutsSummary(summary, tx.vin, prevout_spks) != bip352::PREVOUTS_OK) {
        return false;                              // no eligible input, nothing to scan
    }
    return bip352::ComputeScanTweak(out, summary);
}
