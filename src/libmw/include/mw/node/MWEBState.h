// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef MW_NODE_MWEBSTATE_H
#define MW_NODE_MWEBSTATE_H

#include <mw/common/Macros.h>
#include <mw/models/crypto/Hash.h>
#include <mw/models/block/Block.h>
#include <mw/models/block/Header.h>
#include <mw/mmr/MMR.h>
#include <mw/mmr/Leafset.h>

#include <map>
#include <vector>

MW_NAMESPACE

// The accumulated MWEB chain state: the append-only output and kernel MMRs plus
// the leafset of unspent outputs. Block connection drives this forward, one
// block at a time, and the three roots it exposes are exactly what a block
// header commits to (outputRoot / kernelRoot / leafsetRoot). Verifying a block's
// header roots means applying its body here and comparing.
//
// Key MWEB property: outputs are never removed from the output MMR (it is a
// permanent accumulator). Spending an output only clears its bit in the
// leafset, so a spend changes the leafset root but not the output root.
class MWEBState
{
public:
    // Add a new output (by its hash). Returns the leaf index it was assigned in
    // the output MMR, which also indexes it in the leafset.
    mmr::LeafIndex AddOutput(const mw::Hash& outputID)
    {
        const mmr::LeafIndex index = m_outputMMR.Add(outputID);
        m_leafset.Add(index.Get());
        m_outputIndex[outputID] = index.Get();
        return index;
    }

    // Add a kernel (by its hash) to the kernel MMR.
    void AddKernel(const mw::Hash& kernelHash)
    {
        m_kernelMMR.Add(kernelHash);
    }

    // Mark a previously-added output spent. Leaves the output MMR untouched.
    void SpendOutput(uint64_t leafIndex)
    {
        m_leafset.Spend(leafIndex);
    }

    // Spend an output by its ID (how an MWEB input references what it spends).
    // Returns false if the output is unknown.
    bool SpendByOutputID(const mw::Hash& outputID)
    {
        auto it = m_outputIndex.find(outputID);
        if (it == m_outputIndex.end()) return false;
        m_leafset.Spend(it->second);
        return true;
    }

    // Apply a connected block: append its outputs and kernels, then spend the
    // outputs its inputs reference. Returns false if any input spends an unknown
    // output (a would-be double/invalid spend).
    bool ApplyBlock(const mw::Block& block)
    {
        for (const Output& output : block.GetOutputs()) {
            AddOutput(output.GetOutputID());
        }
        for (const Kernel& kernel : block.GetKernels()) {
            AddKernel(kernel.GetKernelID());
        }
        for (const Input& input : block.GetInputs()) {
            if (!SpendByOutputID(input.GetOutputID())) {
                return false;
            }
        }
        return true;
    }

    // Undo a previously-applied block, rolling the accumulated state back to what
    // it was before that block connected. The MMRs rewind to the pre-block leaf
    // counts (dropping the outputs/kernels the block appended); the block's own
    // outputs are dropped from the index; and the outputs the block spent — which
    // were added by earlier blocks and so survive the rewind — are re-marked
    // unspent from the undo data. Returns false if a spent output is unknown (undo
    // data inconsistent with state).
    bool UndoBlock(uint64_t prevNumOutputs,
                   uint64_t prevNumKernels,
                   const std::vector<mw::Hash>& addedOutputIDs,
                   const std::vector<mw::Hash>& spentOutputIDs)
    {
        m_outputMMR.Rewind(prevNumOutputs);
        m_kernelMMR.Rewind(prevNumKernels);
        m_leafset.Rewind(prevNumOutputs);

        for (const mw::Hash& id : addedOutputIDs) {
            m_outputIndex.erase(id);
        }
        // Restore every spent output we can (continue past any unknown ID rather
        // than aborting mid-rollback, so a reject-path undo still leaves the state
        // consistent); report false if any ID was unknown.
        bool ok = true;
        for (const mw::Hash& id : spentOutputIDs) {
            auto it = m_outputIndex.find(id);
            if (it == m_outputIndex.end()) { ok = false; continue; }
            m_leafset.Add(it->second);
        }
        return ok;
    }

    // Does the accumulated state match what a block header commits to?
    bool MatchesHeader(const mw::Header& header) const
    {
        return OutputRoot() == header.GetOutputRoot()
            && KernelRoot() == header.GetKernelRoot()
            && LeafsetRoot() == header.GetLeafsetRoot()
            && NumOutputs() == header.GetNumTXOs()
            && NumKernels() == header.GetNumKernels();
    }

    // Rebuild the whole accumulator from a persisted append-only log: the output
    // and kernel IDs in leaf order, plus the leafset bitmap. Replaying the adds
    // reconstructs the permanent MMRs and the output index (every leaf initially
    // unspent); the persisted leafset then restores which outputs are spent. This
    // is how a node reconstructs MWEB state on startup, since the output MMR is a
    // permanent accumulator that needs the full history, not just the unspent set.
    void Load(const std::vector<mw::Hash>& outputIDs,
              const std::vector<mw::Hash>& kernelIDs,
              const std::vector<uint8_t>& leafsetBytes)
    {
        m_outputMMR = mmr::MMR();
        m_kernelMMR = mmr::MMR();
        m_leafset = mmr::Leafset();
        m_outputIndex.clear();

        for (const mw::Hash& id : outputIDs) AddOutput(id);
        for (const mw::Hash& id : kernelIDs) AddKernel(id);
        m_leafset.LoadBytes(leafsetBytes);
    }

    // The leafset bitmap, for persistence.
    const std::vector<uint8_t>& GetLeafsetBytes() const { return m_leafset.ToBytes(); }

    bool IsUnspent(uint64_t leafIndex) const { return m_leafset.Contains(leafIndex); }
    uint64_t NumUnspent() const { return m_leafset.Size(); }
    uint64_t NumOutputs() const { return m_outputMMR.NumLeaves(); }
    uint64_t NumKernels() const { return m_kernelMMR.NumLeaves(); }

    mw::Hash OutputRoot() const { return m_outputMMR.Root(); }
    mw::Hash KernelRoot() const { return m_kernelMMR.Root(); }
    mw::Hash LeafsetRoot() const { return m_leafset.Root(); }

    // Inclusion proof that an output leaf is in the current output MMR.
    mmr::MMR::Proof ProveOutput(uint64_t leafIndex) const
    {
        return m_outputMMR.ProveLeaf(leafIndex);
    }

    const mmr::MMR& OutputMMR() const { return m_outputMMR; }
    const mmr::MMR& KernelMMR() const { return m_kernelMMR; }

private:
    mmr::MMR m_outputMMR;
    mmr::MMR m_kernelMMR;
    mmr::Leafset m_leafset;
    std::map<mw::Hash, uint64_t> m_outputIndex; // output ID -> leaf index
};

END_NAMESPACE

#endif // MW_NODE_MWEBSTATE_H
