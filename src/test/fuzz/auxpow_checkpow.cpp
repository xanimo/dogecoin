// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// libFuzzer harness: attacker-controlled bytes -> CBlockHeader deserialize ->
// CheckAuxPowProofOfWork(header, params).
//
// This is the FULL network entry point for merge-mining verification (the
// existing auxpow.cpp target drives only CAuxPow::check()). Over check() it adds:
//   * the version-gated OPTIONAL auxpow deserialization in CBlockHeader
//     (CPureBlockHeader version bits decide whether an auxpow follows) — the real
//     shape a P2P block header arrives in;
//   * the chain-ID / legacy-version gate (IsLegacy / GetChainId / fStrictChainId);
//   * CheckProofOfWork(nBits) — the SetCompact() compact-target decode is driven
//     by fuzzer-controlled nBits.
//
// scrypt is stubbed to a no-op in fuzz_shims.cpp, so GetPoWHash() returns a
// zeroed uint256; CheckProofOfWork(0, nBits) then passes its hash<=target test
// whenever nBits decodes to a valid in-range target, letting execution flow past
// the (uninteresting, un-fuzzable) PoW hash into the gate + auxpow->check() while
// still exercising SetCompact() on raw nBits. powLimit is set wide so the target
// range-check rarely short-circuits.
//
// Build: see src/test/fuzz/build-auxpow-checkpow-fuzz.sh.

#include "primitives/block.h"
#include "consensus/params.h"
#include "dogecoin.h"
#include "streams.h"
#include "uint256.h"
#include "version.h"

#include <cstdint>
#include <stddef.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < 1)
        return 0;

    // Control byte: toggle strict-chain-id so the fuzzer can explore both the
    // strict gate and the legacy/non-strict branch independently of the header
    // version bits it is also mutating.
    const uint8_t ctl = data[0];
    ++data;
    --size;

    CDataStream ds(reinterpret_cast<const char*>(data),
                   reinterpret_cast<const char*>(data) + size,
                   SER_NETWORK, PROTOCOL_VERSION);

    CBlockHeader header;
    try {
        ds >> header; // version-gated: may or may not pull an auxpow
    } catch (const std::exception&) {
        return 0; // malformed serialization is expected and uninteresting
    }

    Consensus::Params params;
    params.fStrictChainId = (ctl & 0x01) != 0;
    params.nAuxpowChainId = 0x0062; // Dogecoin's auxpow chain ID
    // Wide powLimit so CheckProofOfWork's range check (bnTarget > powLimit) rarely
    // rejects; the hash side is 0 (scrypt stubbed), so we reach the gate + check().
    params.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

    try {
        (void)CheckAuxPowProofOfWork(header, params);
    } catch (const std::exception&) {
        // CheckAuxPowProofOfWork should never throw; never let one escape the
        // harness (that would be reported as a crash regardless of cause).
    }

    return 0;
}
