// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Stubs for the CheckPartialMerkleTree fuzz target. merkleblock.cpp also defines
// the CMerkleBlock(const CBlock&, ...) constructors, which reference the bloom
// filter and block/transaction machinery. None are on the CPartialMerkleTree
// deserialize + ExtractMatches fuzz path, but ASan/coverage roots every
// instrumented function so --gc-sections cannot drop them; satisfy the linker
// with never-executed stubs.

#include "bloom.h"

class CTransaction;

bool CBloomFilter::IsRelevantAndUpdate(const CTransaction& /*tx*/) { return false; }
