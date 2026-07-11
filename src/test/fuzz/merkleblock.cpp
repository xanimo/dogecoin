// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// libFuzzer harness: attacker-controlled bytes -> CPartialMerkleTree deserialize
// -> ExtractMatches().
//
// CPartialMerkleTree is the partial-merkle proof carried in a BIP37 "merkleblock"
// message; a peer supplies nTransactions, the hash list and the bit list, all
// attacker-controlled. ExtractMatches() walks the tree via the recursive
// TraverseAndExtract(), consuming bits and hashes and combining hashes — a
// classic parser/DoS surface (unbounded tree width, bit/hash over-read,
// recursion depth). This target drives both the deserializer and ExtractMatches
// from raw input.
//
// Build: see src/test/fuzz/build-merkleblock-fuzz.sh (clang -fsanitize=fuzzer,address,undefined).

#include "merkleblock.h"
#include "streams.h"
#include "uint256.h"
#include "version.h"

#include <cstdint>
#include <stddef.h>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    CDataStream ds(reinterpret_cast<const char*>(data),
                   reinterpret_cast<const char*>(data) + size,
                   SER_NETWORK, PROTOCOL_VERSION);

    CPartialMerkleTree pmt;
    try {
        ds >> pmt;
    } catch (const std::exception&) {
        return 0; // malformed serialization is expected and uninteresting
    }

    std::vector<uint256> vMatch;
    std::vector<unsigned int> vnIndex;
    try {
        (void)pmt.ExtractMatches(vMatch, vnIndex);
    } catch (const std::exception&) {
        // ExtractMatches should never throw; never let one escape the harness.
    }

    return 0;
}
