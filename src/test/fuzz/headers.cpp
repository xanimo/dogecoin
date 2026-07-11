// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// libFuzzer harness: attacker-controlled bytes -> std::vector<CBlockHeader>
// deserialize (the "headers" P2P message).
//
// The headers handler reads a COMPACTSIZE count followed by that many block
// headers, each of which may carry an auxpow (version-gated optional field).
// This drives the vector allocation loop + repeated auxpow-bearing header parse
// from raw bytes. (net_processing caps the count at MAX_HEADERS_RESULTS before
// use; the deserialize itself, exercised here, uses the incremental vector
// reader.)
//
// Build: see src/test/fuzz/build-headers-fuzz.sh.

#include "primitives/block.h"
#include "streams.h"
#include "version.h"

#include <cstdint>
#include <stddef.h>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    CDataStream ds(reinterpret_cast<const char*>(data),
                   reinterpret_cast<const char*>(data) + size,
                   SER_NETWORK, PROTOCOL_VERSION);

    std::vector<CBlockHeader> headers;
    try {
        ds >> headers;
    } catch (const std::exception&) {
        return 0;
    }

    return 0;
}
