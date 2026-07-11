// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// libFuzzer harness: attacker-controlled bytes -> CBlockHeaderAndShortTxIDs
// deserialize (the BIP152 "cmpctblock" P2P message).
//
// A peer supplies the whole compact block: the header (with optional auxpow),
// the nonce, a COMPACTSIZE count + packed 6-byte short transaction IDs, and a
// vector of prefilled transactions (differential-index-encoded, each a full
// CTransaction). This target drives the deserializer directly — the custom
// incremental shorttxids resize loop, the uint16 index-overflow guard on
// prefilledtxn, and full CTransaction parsing — all from raw bytes.
//
// FillShortTxIDSelector()/GetShortID() (SipHash key derivation, not a parse
// surface, and pulling the mempool-heavy blockencodings.cpp) are stubbed in
// compactblock_shims.cpp so the closure stays light; the attacker-controlled
// parse path is exercised in full.
//
// Build: see src/test/fuzz/build-compactblock-fuzz.sh.

#include "blockencodings.h"
#include "streams.h"
#include "version.h"

#include <cstdint>
#include <stddef.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    CDataStream ds(reinterpret_cast<const char*>(data),
                   reinterpret_cast<const char*>(data) + size,
                   SER_NETWORK, PROTOCOL_VERSION);

    CBlockHeaderAndShortTxIDs cmpctblock;
    try {
        ds >> cmpctblock;
    } catch (const std::exception&) {
        return 0; // malformed serialization is expected and uninteresting
    }

    return 0;
}
