// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Minimal stubs for the CBloomFilter fuzz target.
//
// bloom.cpp's CRollingBloomFilter path calls GetRand() (random.cpp); it is never
// reached from the CBloomFilter fuzz path, but ASan/coverage roots every
// instrumented function so --gc-sections cannot drop it — stub it rather than
// link random.cpp (which drags OpenSSL RNG / util). LogPrintStr funnels error()/
// LogPrintf from transaction/script; silence it.

#include <cstdint>
#include <string>

uint64_t GetRand(uint64_t /*nMax*/) { return 0; }

int LogPrintStr(const std::string& /*str*/) { return 0; }
