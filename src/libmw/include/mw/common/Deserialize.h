// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef MW_COMMON_DESERIALIZE_H
#define MW_COMMON_DESERIALIZE_H

#include <mw/common/Macros.h>

#include <serialize.h>

#include <vector>

MW_NAMESPACE

/// Reading a count off the wire and sizing a container to it hands an attacker
/// the allocator: ReadCompactSize permits 33554432, so one short message asks
/// for gigabytes before the stream can run out and throw. The tree's own vector
/// deserializer grows in bounded steps for this reason; these mirror it, so the
/// peak allocation is what the sender actually supplied rather than what it
/// claimed.
///
/// The step is the same 5MB the tree uses, expressed in elements.
namespace deser {

    static constexpr size_t ALLOC_STEP_BYTES = 5000000;

    /// Read `count` elements into `v`, growing in bounded steps.
    template <typename Stream, typename T>
    void ReadVector(Stream& s, std::vector<T>& v)
    {
        const size_t count = ReadCompactSize(s);
        const size_t step = std::max<size_t>(1, ALLOC_STEP_BYTES / sizeof(T));
        v.clear();
        size_t have = 0;
        while (have < count) {
            size_t next = have + step;
            if (next > count) next = count;
            v.resize(next);
            for (; have < next; ++have) {
                s >> v[have];
            }
        }
    }

    /// Read `len` raw bytes into `v`, growing in bounded steps.
    template <typename Stream>
    void ReadBytes(Stream& s, std::vector<uint8_t>& v)
    {
        const size_t len = ReadCompactSize(s);
        v.clear();
        size_t have = 0;
        while (have < len) {
            size_t next = have + ALLOC_STEP_BYTES;
            if (next > len) next = len;
            v.resize(next);
            s.read((char*)v.data() + have, next - have);
            have = next;
        }
    }

}

END_NAMESPACE

#endif // MW_COMMON_DESERIALIZE_H
