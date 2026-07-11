// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// libFuzzer harness: attacker-controlled bytes -> std::vector<CAddress>
// deserialize (the "addr" P2P message).
//
// A peer sends a COMPACTSIZE count + that many CAddress entries (nServices,
// nTime, and an embedded CService = CNetAddr + port). net_processing caps the
// count at 1000 before use; the deserialize itself (exercised here) uses the
// incremental vector reader. Drives the address parse from raw bytes.
//
// Build: see src/test/fuzz/build-addr-fuzz.sh.

#include "protocol.h"
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

    std::vector<CAddress> addrs;
    try {
        ds >> addrs;
    } catch (const std::exception&) {
        return 0;
    }

    return 0;
}
