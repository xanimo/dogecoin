// Copyright (c) 2021 The Litecoin Core developers
// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef MW_MMR_LEAFINDEX_H
#define MW_MMR_LEAFINDEX_H

#include <mw/common/Macros.h>
#include <serialize.h>
#include <cstdint>
#include <cassert>

namespace mmr {

/// Represents the position (index) of a leaf in a Merkle Mountain Range.
/// Leaf indices are 0-based and contiguous.
class LeafIndex
{
public:
    LeafIndex() : m_leafIndex(0) {}
    explicit LeafIndex(const uint64_t index) : m_leafIndex(index) {}

    static LeafIndex At(const uint64_t index) { return LeafIndex(index); }

    uint64_t Get() const noexcept { return m_leafIndex; }

    bool operator==(const LeafIndex& rhs) const { return m_leafIndex == rhs.m_leafIndex; }
    bool operator!=(const LeafIndex& rhs) const { return m_leafIndex != rhs.m_leafIndex; }
    bool operator<(const LeafIndex& rhs) const { return m_leafIndex < rhs.m_leafIndex; }
    bool operator<=(const LeafIndex& rhs) const { return m_leafIndex <= rhs.m_leafIndex; }

    LeafIndex Next() const { return LeafIndex(m_leafIndex + 1); }

    template<typename Stream>
    void Serialize(Stream& s) const {
        ser_writedata64(s, m_leafIndex);
    }

    template<typename Stream>
    void Unserialize(Stream& s) {
        m_leafIndex = ser_readdata64(s);
    }

private:
    uint64_t m_leafIndex;
};

} // namespace mmr

#endif // MW_MMR_LEAFINDEX_H
