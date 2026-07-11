// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Stubs for the compact-block (BIP152) deserialize fuzz target.
//
// CBlockHeaderAndShortTxIDs::SerializationOp calls FillShortTxIDSelector() after
// reading. That method — and GetShortID() referenced by the never-called
// CBlockHeaderAndShortTxIDs(const CBlock&, bool) constructor — live in
// blockencodings.cpp, whose translation unit also compiles the mempool-heavy
// InitData()/FillBlock(). To keep the fuzz closure light (no txmempool/validation
// linkage) we do NOT compile blockencodings.cpp and instead provide these two
// members here. They only derive the SipHash short-id key from the header, which
// is not an attacker-controlled allocation/parse surface; the deserializer itself
// (shorttxids resize loop + prefilledtxn + CTransaction parse) runs in full.

#include "blockencodings.h"
#include "uint256.h"

void CBlockHeaderAndShortTxIDs::FillShortTxIDSelector() const
{
    shorttxidk0 = 0;
    shorttxidk1 = 0;
}

uint64_t CBlockHeaderAndShortTxIDs::GetShortID(const uint256& /*txhash*/) const
{
    return 0;
}
