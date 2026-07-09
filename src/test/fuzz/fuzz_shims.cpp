// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Minimal shims so the focused auxpow fuzz target links without pulling in the
// full daemon (validation/net/txmempool). auxpow.cpp defines CMerkleTx helper
// methods (GetDepthInMainChain, GetBlocksToMaturity, AcceptToMemoryPool) and
// CAuxPow::initAuxPow that reference daemon globals; none are reachable from the
// deserialize + check() fuzz path, but ASan/coverage metadata roots every
// instrumented function so --gc-sections cannot drop them. We therefore satisfy
// the linker with never-executed stubs.

#include <cstddef>
#include <list>
#include <memory>
#include <string>

#include "chainparams.h"     // CChainParams (for GetConsensus)
#include "consensus/params.h"
#include "primitives/block.h" // CBlockHeader::SetAuxpow

// --- logging: error()/LogPrintf funnel through LogPrintStr(); silence it. ---
int LogPrintStr(const std::string& /*str*/) { return 0; }

// --- scrypt PoW hash: only via CPureBlockHeader::GetPoWHash(), never on the
//     deserialize+check() path. ---
void scrypt_1024_1_1_256(const char* /*input*/, char* /*output*/) {}

// --- daemon globals referenced only by never-called CMerkleTx methods.
//     Provide raw storage of ample size; the objects are never constructed or
//     accessed on the fuzz path (the linker matches by symbol name only). ---
alignas(64) char chainActive[1024];
alignas(64) char mapBlockIndex[1024];
alignas(64) char mempool[16384];

// --- free/member functions referenced by the same never-called methods. ---
class CTxMemPool;
class CValidationState;
class CTransaction;

bool AcceptToMemoryPool(CTxMemPool&, CValidationState&,
                        const std::shared_ptr<const CTransaction>&, bool, bool*,
                        std::list<std::shared_ptr<const CTransaction> >*, bool,
                        long)
{
    return false;
}

const CChainParams& Params()
{
    static char storage[16384];
    return *reinterpret_cast<const CChainParams*>(storage);
}

// CChainParams::GetConsensus() is inline in chainparams.h and forwards to this
// method on the consensus-params tree; stub it to return the node itself.
const Consensus::Params* Consensus::Params::GetConsensus(uint32_t) const
{
    return this;
}

void CBlockHeader::SetAuxpow(CAuxPow* /*apow*/) {}
