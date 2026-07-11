// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// libFuzzer harness: attacker-controlled bytes -> CBloomFilter deserialize ->
// (faithful net_processing sequence) -> insert/contains/IsRelevantAndUpdate.
//
// CBloomFilter is loaded from a BIP37 "filterload" P2P message: vData, nHashFuncs,
// nTweak, nFlags are all attacker-supplied. This target mirrors the real handler
// (net_processing FILTERLOAD): deserialize, reject if !IsWithinSizeConstraints,
// then UpdateEmptyFull(); afterwards it exercises the hash/index path (Hash() =
// MurmurHash3 % (vData.size()*8), and vData[nIndex>>3]) via insert()/contains()
// and the tx-matching path IsRelevantAndUpdate() with a transaction parsed from
// the remaining bytes.

#include "bloom.h"
#include "primitives/transaction.h"
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

    CBloomFilter filter;
    try {
        ds >> filter;
    } catch (const std::exception&) {
        return 0;
    }

    // net_processing rejects a too-large filter before use.
    if (!filter.IsWithinSizeConstraints())
        return 0;

    filter.UpdateEmptyFull(); // recompute isFull/isEmpty exactly as the handler does

    // Exercise the hash/index path (filteradd-style insert + relay-style contains)
    // with a probe key derived from the raw input.
    std::vector<unsigned char> key(data, data + (size < 64 ? size : 64));
    filter.insert(key);
    (void)filter.contains(key);

    // Exercise IsRelevantAndUpdate with a transaction parsed from the remaining
    // stream (the relay-time matching path, which also mutates the filter).
    try {
        CTransaction tx(deserialize, ds);
        (void)filter.IsRelevantAndUpdate(tx);
    } catch (const std::exception&) {
        // No/short trailing tx bytes — fine, the filter path above still ran.
    }

    return 0;
}
