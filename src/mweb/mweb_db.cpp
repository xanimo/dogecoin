// Copyright (c) 2021 The Litecoin Core developers
// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "mweb/mweb_db.h"
#include "util.h"

std::unique_ptr<CMWEBStateDB> g_mweb_state;

CMWEBStateDB::CMWEBStateDB(size_t nCacheSize, bool fMemory, bool fWipe)
    : db(GetDataDir() / "mwebstate", nCacheSize, fMemory, fWipe, true)
{
}

bool CMWEBStateDB::AddOutput(const mw::Output& output)
{
    return db.Write(std::make_pair(MWEBDBKeys::UTXO, output.GetOutputID()), output);
}

bool CMWEBStateDB::SpendOutput(const mw::Hash& output_id)
{
    return db.Erase(std::make_pair(MWEBDBKeys::UTXO, output_id));
}

bool CMWEBStateDB::GetOutput(const mw::Hash& output_id, mw::Output& output) const
{
    return db.Read(std::make_pair(MWEBDBKeys::UTXO, output_id), output);
}

bool CMWEBStateDB::HasOutput(const mw::Hash& output_id) const
{
    return db.Exists(std::make_pair(MWEBDBKeys::UTXO, output_id));
}

std::vector<mw::Output> CMWEBStateDB::GetUTXOs(uint64_t start_index, uint64_t max_count)
{
    std::vector<mw::Output> results;

    std::unique_ptr<CDBIterator> pcursor(db.NewIterator());
    // Seek to the beginning of UTXO entries
    std::pair<char, mw::Hash> seekKey(MWEBDBKeys::UTXO, mw::Hash());
    pcursor->Seek(seekKey);

    uint64_t index = 0;
    while (pcursor->Valid() && results.size() < max_count) {
        std::pair<char, mw::Hash> key;
        if (!pcursor->GetKey(key) || key.first != MWEBDBKeys::UTXO)
            break;

        if (index >= start_index) {
            mw::Output output;
            if (pcursor->GetValue(output)) {
                results.push_back(output);
            }
        }

        ++index;
        pcursor->Next();
    }

    return results;
}

bool CMWEBStateDB::ConnectBlock(const mw::Block& block,
                                 const mw::Header::CPtr& prevHeader,
                                 std::vector<UTXO>& spentUTXOs,
                                 std::vector<mw::Hash>& addedOutputIDs)
{
    spentUTXOs.clear();
    addedOutputIDs.clear();

    const uint64_t prevNumOutputs = prevHeader ? prevHeader->GetNumTXOs() : 0;
    const uint64_t prevNumKernels = prevHeader ? prevHeader->GetNumKernels() : 0;

    // Output/input IDs this block touches, gathered once so a reject can roll the
    // accumulator back to its pre-block state.
    std::vector<mw::Hash> blockAddedIDs;
    std::vector<mw::Hash> blockSpentIDs;
    for (const auto& output : block.GetOutputs()) {
        blockAddedIDs.push_back(output.GetOutputID());
    }
    for (const auto& input : block.GetInputs()) {
        blockSpentIDs.push_back(input.GetOutputID());
    }

    // Drive the in-memory accumulator forward, then confirm the resulting roots are
    // exactly what this block's header commits to. This is the consensus check that
    // the MWEB body actually produces the advertised output/kernel/leafset roots and
    // that every input spends a known unspent output.
    if (!m_state.ApplyBlock(block)) {
        m_state.UndoBlock(prevNumOutputs, prevNumKernels, blockAddedIDs, blockSpentIDs);
        return false;
    }
    if (block.GetHeader() && !m_state.MatchesHeader(*block.GetHeader())) {
        m_state.UndoBlock(prevNumOutputs, prevNumKernels, blockAddedIDs, blockSpentIDs);
        return false;
    }

    // Accumulator agrees with the header — commit the persistent UTXO set changes.
    CDBBatch batch(db);

    // Remove spent inputs and build undo data
    for (const auto& input : block.GetInputs()) {
        const mw::Hash& output_id = input.GetOutputID();

        // Retrieve the full output for undo data
        mw::Output spentOutput;
        if (GetOutput(output_id, spentOutput)) {
            // Create a UTXO entry for undo data (with block height 0 and leaf index 0, as placeholders)
            spentUTXOs.emplace_back(0, mmr::LeafIndex(0), spentOutput);
        }

        batch.Erase(std::make_pair(MWEBDBKeys::UTXO, output_id));
    }

    // Add new outputs
    for (const auto& output : block.GetOutputs()) {
        batch.Write(std::make_pair(MWEBDBKeys::UTXO, output.GetOutputID()), output);
        addedOutputIDs.push_back(output.GetOutputID());
    }

    return db.WriteBatch(batch, true);
}

bool CMWEBStateDB::DisconnectBlock(const mw::BlockUndo& undo)
{
    // Roll the in-memory accumulator back to the pre-block state first, using the
    // pre-block leaf counts from the stored previous header plus the added/spent
    // output IDs the undo data carries.
    const mw::Header::CPtr& prevHeader = undo.GetPreviousHeader();
    const uint64_t prevNumOutputs = prevHeader ? prevHeader->GetNumTXOs() : 0;
    const uint64_t prevNumKernels = prevHeader ? prevHeader->GetNumKernels() : 0;

    std::vector<mw::Hash> spentIDs;
    for (const auto& utxo : undo.GetCoinsSpent()) {
        spentIDs.push_back(utxo.GetOutputID());
    }
    m_state.UndoBlock(prevNumOutputs, prevNumKernels, undo.GetCoinsAdded(), spentIDs);

    CDBBatch batch(db);

    // Remove outputs that were added by this block
    for (const auto& output_id : undo.GetCoinsAdded()) {
        batch.Erase(std::make_pair(MWEBDBKeys::UTXO, output_id));
    }

    // Restore spent UTXOs
    for (const auto& utxo : undo.GetCoinsSpent()) {
        batch.Write(std::make_pair(MWEBDBKeys::UTXO, utxo.GetOutputID()), utxo.GetOutput());
    }

    return db.WriteBatch(batch, true);
}

bool CMWEBStateDB::GetBestBlockHash(uint256& hash) const
{
    return db.Read(MWEBDBKeys::BEST_HASH, hash);
}

bool CMWEBStateDB::SetBestBlockHash(const uint256& hash)
{
    return db.Write(MWEBDBKeys::BEST_HASH, hash, true);
}
