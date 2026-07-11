// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Extra stubs for the CheckAuxPowProofOfWork fuzz target only (kept out of the
// shared fuzz_shims.cpp so the check()-only target is unaffected).
//
// dogecoin.cpp and pow.cpp carry the difficulty-retarget functions
// (GetNextWorkRequired / CalculateDogecoinNextWorkRequired /
// AllowDigishieldMinDifficultyForBlock). None are on the CheckAuxPowProofOfWork
// path, but ASan/coverage instrumentation roots every function so --gc-sections
// cannot drop them; the linker therefore needs their out-of-line callees. The
// only such symbol is CBlockIndex::GetAncestor (all other CBlockIndex uses are
// data members / inline). Never executed on the fuzz path.

#include "chain.h"

CBlockIndex* CBlockIndex::GetAncestor(int) { return nullptr; }
const CBlockIndex* CBlockIndex::GetAncestor(int) const { return nullptr; }
