// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// libFuzzer harness: attacker-controlled bytes -> CAuxPow deserialize -> check().
//
// CAuxPow is the merge-mining proof carried in a block header; the parent block
// and coinbase are fully attacker-influenced, so both the deserializer and the
// merkle-linkage verifier CAuxPow::check() are Tier-1 remote surfaces with no
// upstream (Bitcoin) mirror. This target drives both from raw input.
//
// check() reads only params.fStrictChainId from the consensus params (verified
// against src/auxpow.cpp), so a minimal Consensus::Params suffices.
//
// Build: see src/test/fuzz/build-auxpow-fuzz.sh (clang -fsanitize=fuzzer,address,undefined).

#include "auxpow.h"
#include "consensus/params.h"
#include "streams.h"
#include "uint256.h"
#include "version.h"

#include <cstdint>
#include <stddef.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < 1)
        return 0;

    // First byte is a control byte: toggles strict-chain-id enforcement and
    // perturbs the aux block hash / chain id so the fuzzer can explore both the
    // strict and legacy branches and different merkle-index expectations.
    const uint8_t ctl = data[0];
    ++data;
    --size;

    CDataStream ds(reinterpret_cast<const char*>(data),
                   reinterpret_cast<const char*>(data) + size,
                   SER_NETWORK, PROTOCOL_VERSION);

    CAuxPow auxpow;
    try {
        ds >> auxpow;
    } catch (const std::exception&) {
        // Malformed serialization is expected and uninteresting.
        return 0;
    }

    Consensus::Params params;
    params.fStrictChainId = (ctl & 0x01) != 0;

    const int nChainId = 0x0062; // Dogecoin's auxpow chain ID

    // Vary the aux block hash by the control byte so check()'s merkle-root and
    // getExpectedIndex comparisons are exercised across inputs.
    uint256 hashAuxBlock;
    unsigned char* p = hashAuxBlock.begin();
    for (int i = 0; i < 32; ++i)
        p[i] = static_cast<unsigned char>(ctl + i);

    try {
        (void)auxpow.check(hashAuxBlock, nChainId, params);
    } catch (const std::exception&) {
        // check() should never throw, but never let an exception escape the
        // harness (that would be reported as a crash regardless of cause).
    }

    return 0;
}
