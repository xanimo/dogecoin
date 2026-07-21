// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef MW_MMR_LEAFSET_H
#define MW_MMR_LEAFSET_H

#include <mw/common/Macros.h>
#include <mw/models/crypto/Hash.h>

#include <hash.h>

#include <cstdint>
#include <vector>

namespace mmr {

// The leafset: a bitmap over MMR leaf indices where bit i is set iff leaf i is
// unspent. This is the MWEB UTXO set expressed as a compact bitmap over the
// output MMR; spending an output clears its bit. Its hash is the leafsetRoot the
// block header commits to, so nodes agree on exactly which outputs are still
// spendable without storing the outputs themselves.
class Leafset
{
public:
    // Mark leaf `leafIndex` unspent (a new output enters the UTXO set).
    void Add(uint64_t leafIndex)
    {
        EnsureSize(leafIndex);
        m_bits[leafIndex / 8] |= static_cast<uint8_t>(1u << (leafIndex % 8));
    }

    // Mark leaf `leafIndex` spent (leaves the UTXO set).
    void Spend(uint64_t leafIndex)
    {
        if (leafIndex / 8 >= m_bits.size()) return;
        m_bits[leafIndex / 8] &= static_cast<uint8_t>(~(1u << (leafIndex % 8)));
    }

    // Is leaf `leafIndex` currently unspent?
    bool Contains(uint64_t leafIndex) const
    {
        if (leafIndex / 8 >= m_bits.size()) return false;
        return (m_bits[leafIndex / 8] >> (leafIndex % 8)) & 1u;
    }

    // Number of unspent leaves.
    uint64_t Size() const
    {
        uint64_t count = 0;
        for (uint8_t byte : m_bits) {
            for (uint8_t b = byte; b; b &= (b - 1)) ++count;
        }
        return count;
    }

    // Hash of the bitmap. Trailing zero bytes are trimmed so that two leafsets
    // with the same unspent leaves hash identically regardless of capacity.
    mw::Hash Root() const
    {
        size_t len = m_bits.size();
        while (len > 0 && m_bits[len - 1] == 0) --len;

        CHashWriter ss(SER_GETHASH, 0);
        if (len > 0) {
            ss.write(reinterpret_cast<const char*>(m_bits.data()), len);
        }
        return mw::Hash(ss.GetHash());
    }

private:
    void EnsureSize(uint64_t leafIndex)
    {
        const size_t needed = static_cast<size_t>(leafIndex / 8) + 1;
        if (m_bits.size() < needed) {
            m_bits.resize(needed, 0);
        }
    }

    std::vector<uint8_t> m_bits; // packed bitmap; bit i at byte i/8, offset i%8
};

} // namespace mmr

#endif // MW_MMR_LEAFSET_H
