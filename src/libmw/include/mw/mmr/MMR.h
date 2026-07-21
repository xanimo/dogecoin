// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef MW_MMR_MMR_H
#define MW_MMR_MMR_H

#include <mw/common/Macros.h>
#include <mw/models/crypto/Hash.h>
#include <mw/mmr/LeafIndex.h>

#include <hash.h>

#include <cstdint>
#include <vector>

namespace mmr {

// An append-only Merkle Mountain Range: the accumulator MWEB uses for its
// output and kernel sets. Leaves are added in order; the structure is a series
// of perfect binary trees ("peaks") of strictly decreasing height, merged as
// equal-height peaks appear (like incrementing a binary counter). The root is
// obtained by "bagging" the peaks from smallest to largest.
//
// This first cut computes roots (what the block header commits to). Membership
// proofs and the spent-output leafset are layered on top later.
class MMR
{
public:
    // Inclusion proof for a single leaf: the sibling hashes from the leaf up to
    // its peak (with the side each sibling sits on), plus every peak hash so the
    // reconstructed peak can be bagged back into the root.
    struct Proof {
        uint64_t leafIndex = 0;
        std::vector<mw::Hash> path;    // sibling hashes, leaf -> peak
        std::vector<bool> siblingLeft; // true if that sibling is the LEFT node
        std::vector<mw::Hash> peaks;   // all peak hashes, in MMR order
        size_t peakIndex = 0;          // which peak this leaf reconstructs to
    };

    // Append an already-hashed leaf. Returns its leaf index.
    LeafIndex Add(const mw::Hash& leafHash)
    {
        const LeafIndex index = LeafIndex::At(m_numLeaves);

        m_nodes.push_back(leafHash);
        m_peaks.push_back(m_nodes.size() - 1);
        m_peakHeights.push_back(0);
        ++m_numLeaves;

        // Merge while the two rightmost peaks are the same height.
        while (m_peaks.size() >= 2 &&
               m_peakHeights.back() == m_peakHeights[m_peakHeights.size() - 2]) {
            const mw::Hash& right = m_nodes[m_peaks.back()];
            const mw::Hash& left = m_nodes[m_peaks[m_peaks.size() - 2]];
            const mw::Hash parent = HashParent(left, right);

            const uint8_t mergedHeight = static_cast<uint8_t>(m_peakHeights.back() + 1);
            m_peaks.pop_back();
            m_peaks.pop_back();
            m_peakHeights.pop_back();
            m_peakHeights.pop_back();

            m_nodes.push_back(parent);
            m_peaks.push_back(m_nodes.size() - 1);
            m_peakHeights.push_back(mergedHeight);
        }

        return index;
    }

    // Roll the MMR back to `targetLeaves` leaves. Because Add() only ever appends
    // nodes and never mutates earlier ones, the node array for N leaves is a strict
    // prefix of the array for any larger count, so a rewind is just a truncation to
    // the node count for `targetLeaves` followed by recomputing the peaks. This is
    // how a block disconnect (reorg) undoes the outputs/kernels the block appended.
    void Rewind(uint64_t targetLeaves)
    {
        if (targetLeaves >= m_numLeaves) return;

        // Node count for N leaves in this construction is 2N - popcount(N):
        // every leaf contributes one node and every merge (an internal node) one
        // more, and the number of merges to reach N leaves is N - popcount(N).
        const uint64_t nodeCount = 2 * targetLeaves - PopCount(targetLeaves);
        m_nodes.resize(static_cast<size_t>(nodeCount));
        m_numLeaves = targetLeaves;
        RecomputePeaks();
    }

    uint64_t NumLeaves() const noexcept { return m_numLeaves; }
    uint64_t NumNodes() const noexcept { return m_nodes.size(); }
    size_t NumPeaks() const noexcept { return m_peaks.size(); }

    // The MMR root: bag the peaks from smallest (rightmost) to largest (leftmost),
    // folding as root = H(peak_0, H(peak_1, H(..., peak_n))). Null hash if empty.
    mw::Hash Root() const
    {
        if (m_peaks.empty()) {
            return mw::Hash();
        }

        mw::Hash acc = m_nodes[m_peaks.back()];
        for (size_t i = m_peaks.size() - 1; i-- > 0;) {
            acc = HashParent(m_nodes[m_peaks[i]], acc);
        }
        return acc;
    }

    // Build an inclusion proof for the leaf at `leafIndex`.
    Proof ProveLeaf(uint64_t leafIndex) const
    {
        Proof proof;
        proof.leafIndex = leafIndex;

        uint64_t pos = LeafPos(leafIndex);
        uint8_t height = 0;
        while (!IsPeak(pos)) {
            const uint64_t span = (uint64_t(1) << (height + 1)) - 1;
            uint64_t siblingPos;
            if (Height(pos + 1) > height) {
                // `pos` is a right child: its sibling is to the left, parent is pos+1.
                siblingPos = pos - span;
                proof.siblingLeft.push_back(true);
                pos = pos + 1;
            } else {
                // `pos` is a left child: sibling to the right, parent is pos + 2^(h+1).
                siblingPos = pos + span;
                proof.siblingLeft.push_back(false);
                pos = pos + span + 1;
            }
            proof.path.push_back(m_nodes[siblingPos]);
            ++height;
        }

        for (size_t i = 0; i < m_peaks.size(); ++i) {
            proof.peaks.push_back(m_nodes[m_peaks[i]]);
            if (m_peaks[i] == pos) proof.peakIndex = i;
        }
        return proof;
    }

    // Verify that `leafHash` is included in an MMR with the given `root`.
    static bool Verify(const mw::Hash& leafHash, const Proof& proof, const mw::Hash& root)
    {
        if (proof.path.size() != proof.siblingLeft.size()) return false;
        if (proof.peaks.empty() || proof.peakIndex >= proof.peaks.size()) return false;

        mw::Hash computed = leafHash;
        for (size_t i = 0; i < proof.path.size(); ++i) {
            computed = proof.siblingLeft[i] ? HashParent(proof.path[i], computed)
                                            : HashParent(computed, proof.path[i]);
        }

        std::vector<mw::Hash> peaks = proof.peaks;
        peaks[proof.peakIndex] = computed;

        mw::Hash acc = peaks.back();
        for (size_t i = peaks.size() - 1; i-- > 0;) {
            acc = HashParent(peaks[i], acc);
        }
        return acc == root;
    }

private:
    static mw::Hash HashParent(const mw::Hash& left, const mw::Hash& right)
    {
        CHashWriter ss(SER_GETHASH, 0);
        ss << left << right;
        return mw::Hash(ss.GetHash());
    }

    static uint64_t PopCount(uint64_t x)
    {
        uint64_t bits = 0;
        for (; x; x &= (x - 1)) ++bits;
        return bits;
    }

    // Rebuild m_peaks/m_peakHeights for the current m_numLeaves from scratch. The
    // peaks correspond to the set bits of m_numLeaves: one perfect tree of 2^h
    // leaves per set bit, largest (leftmost) first. A perfect tree of 2^h leaves
    // occupies 2^(h+1)-1 consecutive nodes, so walking those spans left to right
    // lands each peak on the last node of its subtree.
    void RecomputePeaks()
    {
        m_peaks.clear();
        m_peakHeights.clear();
        uint64_t offset = 0;
        for (int h = 63; h >= 0; --h) {
            if (m_numLeaves & (uint64_t(1) << h)) {
                const uint64_t subtreeNodes = (uint64_t(2) << h) - 1; // 2^(h+1)-1
                offset += subtreeNodes;
                m_peaks.push_back(offset - 1);
                m_peakHeights.push_back(static_cast<uint8_t>(h));
            }
        }
    }

    // Position (0-based, post-order) of the i-th leaf: 2*i - popcount(i).
    static uint64_t LeafPos(uint64_t leafIndex)
    {
        uint64_t bits = 0;
        for (uint64_t x = leafIndex; x; x &= (x - 1)) ++bits;
        return 2 * leafIndex - bits;
    }

    // Height of the node at 0-based post-order position `pos`.
    static uint8_t Height(uint64_t pos)
    {
        uint64_t p = pos + 1; // 1-based
        while ((p & (p + 1)) != 0) { // while p is not all-ones (2^k - 1)
            uint64_t msb = 1;
            while ((msb << 1) <= p) msb <<= 1;
            p -= (msb - 1);
        }
        uint8_t h = 0;
        for (uint64_t t = p + 1; t > 1; t >>= 1) ++h;
        return static_cast<uint8_t>(h - 1);
    }

    bool IsPeak(uint64_t pos) const
    {
        for (uint64_t pk : m_peaks) {
            if (pk == pos) return true;
        }
        return false;
    }

    std::vector<mw::Hash> m_nodes;      // every node, in creation order
    std::vector<uint64_t> m_peaks;      // node index of each current peak
    std::vector<uint8_t> m_peakHeights; // height of each current peak
    uint64_t m_numLeaves = 0;
};

} // namespace mmr

#endif // MW_MMR_MMR_H
