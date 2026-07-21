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

private:
    static mw::Hash HashParent(const mw::Hash& left, const mw::Hash& right)
    {
        CHashWriter ss(SER_GETHASH, 0);
        ss << left << right;
        return mw::Hash(ss.GetHash());
    }

    std::vector<mw::Hash> m_nodes;      // every node, in creation order
    std::vector<uint64_t> m_peaks;      // node index of each current peak
    std::vector<uint8_t> m_peakHeights; // height of each current peak
    uint64_t m_numLeaves = 0;
};

} // namespace mmr

#endif // MW_MMR_MMR_H
