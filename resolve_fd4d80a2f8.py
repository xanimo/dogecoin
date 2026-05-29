#!/usr/bin/env python3
"""
Resolve all conflicts in the fd4d80a2f8 cherry-pick of validation.cpp and validation.h.
Each conflict is identified by line number and resolved according to the strategy below.
"""

import re
import sys

def read_file(path):
    with open(path, 'r') as f:
        return f.read()

def write_file(path, content):
    with open(path, 'w') as f:
        f.write(content)

def resolve_file_conflicts(text, conflict_resolutions):
    """
    conflict_resolutions: list of (keep_side, custom_replacement_or_None)
      keep_side: 'head', 'incoming', 'custom'
      custom_replacement: string to replace the entire conflict block, or None
    
    Processes conflicts in order (assumes sequential, non-nested conflicts).
    """
    # Pattern to match conflict blocks
    CONFLICT_RE = re.compile(
        r'<<<<<<< HEAD\n(.*?)=======\n(.*?)>>>>>>> [^\n]+\n',
        re.DOTALL
    )
    
    matches = list(CONFLICT_RE.finditer(text))
    print(f"Found {len(matches)} conflicts")
    
    if len(matches) != len(conflict_resolutions):
        print(f"ERROR: Expected {len(conflict_resolutions)} resolutions, found {len(matches)} conflicts")
        for i, m in enumerate(matches):
            print(f"  Conflict {i+1} at char {m.start()}: head={repr(m.group(1)[:80])}")
        return None
    
    result_parts = []
    last_end = 0
    
    for i, (match, (keep_side, custom)) in enumerate(zip(matches, conflict_resolutions)):
        # Add text before this conflict
        result_parts.append(text[last_end:match.start()])
        
        head_content = match.group(1)
        incoming_content = match.group(2)
        
        if keep_side == 'head':
            result_parts.append(head_content)
        elif keep_side == 'incoming':
            result_parts.append(incoming_content)
        elif keep_side == 'custom':
            result_parts.append(custom)
        elif keep_side == 'empty':
            pass  # Don't add anything
        
        last_end = match.end()
    
    result_parts.append(text[last_end:])
    return ''.join(result_parts)


# ============================================================
# validation.h resolutions
# ============================================================

def resolve_validation_h():
    path = '/home/bluezr/source/repos/dogecoin/src/validation.h'
    text = read_file(path)
    
    # 2 conflicts:
    # C1 (169-173): boost vs std unordered_map -> KEEP HEAD (boost)
    # C2 (524-529): empty vs pcoinsdbview extern -> KEEP HEAD (empty, pcoinsdbview is local to init.cpp)
    
    resolutions = [
        ('head', None),   # C1: keep boost::unordered_map
        ('empty', None),  # C2: don't add extern pcoinsdbview (it's local to init.cpp in Dogecoin)
    ]
    
    result = resolve_file_conflicts(text, resolutions)
    if result:
        write_file(path, result)
        print("validation.h resolved")
    return result


# ============================================================
# validation.cpp resolutions
# ============================================================

# Custom for C3: discard old CChainState class, add nothing here
# (we'll add aliases in the anon namespace separately)
C3_CUSTOM = ""

# Custom for C12: keep LastCommonAncestor, take incoming ReplayBlocks signature
C12_CUSTOM = """/** Find the last common ancestor two blocks have.
 *  Both pa and pb must be non-NULL. */
static const CBlockIndex* LastCommonAncestor(const CBlockIndex* pa, const CBlockIndex* pb) {
    if (pa->nHeight > pb->nHeight) {
        pa = pa->GetAncestor(pb->nHeight);
    } else if (pb->nHeight > pa->nHeight) {
        pb = pb->GetAncestor(pa->nHeight);
    }

    while (pa != pb && pa && pb) {
        pa = pa->pprev;
        pb = pb->pprev;
    }

    // Eventually all chain branches meet at the genesis block.
    assert(pa == pb);
    return pa;
}

bool CChainState::ReplayBlocks(const CChainParams& params, CCoinsView* view)
"""

# Custom for C13: take incoming (RewindBlockIndex wrapper) but fix GetConsensus
C13_CUSTOM = """        CheckBlockIndex(params.GetConsensus(chainActive.Height()));
    }

    return true;
}

bool RewindBlockIndex(const CChainParams& params) {
    if (!g_chainstate.RewindBlockIndex(params)) {
        return false;
    }

    if (chainActive.Tip() != nullptr) {
        // FlushStateToDisk can possibly read chainActive. Be conservative
        // and skip it here, we're about to -reindex-chainstate anyway, so
        // it'll get called a bunch real soon.
        CValidationState state;
        if (!FlushStateToDisk(params, state, FLUSH_STATE_ALWAYS)) {
            return false;
        }
"""

# Custom for C14: take incoming (nullptr) but also clear setBlockIndexCandidates
C14_CUSTOM = """    setBlockIndexCandidates.clear();
    chainActive.SetTip(nullptr);
    pindexBestInvalid = nullptr;
    pindexBestHeader = nullptr;
"""

def resolve_validation_cpp():
    path = '/home/bluezr/source/repos/dogecoin/src/validation.cpp'
    text = read_file(path)
    
    # 17 conflicts in order:
    resolutions = [
        # C1 (171-177): After cs_main, HEAD=pindexBestHeader=NULL, INCOMING=adds refs + nullptr
        # Take INCOMING: adds mapBlockIndex/chainActive refs + nullptr pindexBestHeader
        ('incoming', None),
        
        # C2 (203-212): HEAD=IsSuperMajority+CheckBlockIndex forward decls, INCOMING=empty
        # Take INCOMING: remove the forward declarations (CheckBlockIndex is private member now)
        ('incoming', None),
        
        # C3 (218-280): HEAD=old CChainState class def, INCOMING=anon namespace aliases
        # Take EMPTY: discard the old CChainState class (already defined at top)
        # We'll add aliases separately to the existing anon namespace
        ('empty', None),
        
        # C4 (1979-1986): bool ConnectBlock vs bool CChainState::ConnectBlock + doxygen
        # Take INCOMING: add CChainState:: prefix + doxygen
        ('incoming', None),
        
        # C5 (2442-2457): bool static DisconnectTip(fBare) vs bool CChainState::DisconnectTip(disconnectpool)
        # Take INCOMING: change to CChainState:: member with disconnectpool
        ('incoming', None),
        
        # C6 (2533-2537): bool static ConnectTip vs bool CChainState::ConnectTip(+disconnectpool)
        # Take INCOMING: add CChainState:: prefix + disconnectpool param
        ('incoming', None),
        
        # C7 (3026-3030): bool ReceivedBlockTransactions vs bool CChainState::ReceivedBlockTransactions(+consensusParams)
        # Take INCOMING: add CChainState:: prefix + consensusParams
        ('incoming', None),
        
        # C8 (3515-3521): AcceptBlockHeader(...) vs g_chainstate.AcceptBlockHeader(...) + nullptr
        # Take INCOMING
        ('incoming', None),
        
        # C9 (3534-3559): static bool AcceptBlock vs SaveBlockToDisk + CChainState::AcceptBlock
        # Take INCOMING: adds SaveBlockToDisk helper + changes AcceptBlock to member
        ('incoming', None),
        
        # C10 (3666-3673): AcceptBlock call + CheckBlockIndex vs g_chainstate.AcceptBlock + no CheckBlockIndex
        # Take INCOMING: use g_chainstate.AcceptBlock
        ('incoming', None),
        
        # C11 (3935-3939): LoadBlockIndex body - pblocktree->LoadBlockIndexGuts(InsertBlockIndex) vs lambda
        # Take INCOMING: use blocktree.LoadBlockIndexGuts with lambda
        ('incoming', None),
        
        # C12 (4193-4214): HEAD=LastCommonAncestor + bool ReplayBlocks, INCOMING=bool CChainState::ReplayBlocks
        # CUSTOM: keep LastCommonAncestor + take incoming signature
        ('custom', C12_CUSTOM),
        
        # C13 (4360-4385): HEAD=CheckBlockIndex+FlushStateToDisk, INCOMING=CheckBlockIndex+RewindBlockIndex wrapper
        # CUSTOM: fix GetConsensus(height) + add wrapper
        ('custom', C13_CUSTOM),
        
        # C14 (4401-4410): HEAD=setBlockIndexCandidates.clear()+NULL, INCOMING=nullptr
        # CUSTOM: keep setBlockIndexCandidates.clear() + use nullptr
        ('custom', C14_CUSTOM),
        
        # C15 (4441-4445): bool InitBlockIndex vs bool CChainState::LoadGenesisBlock
        # Take INCOMING: rename function to CChainState::LoadGenesisBlock
        ('incoming', None),
        
        # C16 (4548-4552): AcceptBlock(...NULL...) vs g_chainstate.AcceptBlock(...nullptr...)
        # Take INCOMING: use g_chainstate.AcceptBlock + nullptr
        ('incoming', None),
        
        # C17 (4587-4591): AcceptBlock(...NULL...) vs g_chainstate.AcceptBlock(...nullptr...)
        # Take INCOMING: use g_chainstate.AcceptBlock + nullptr
        ('incoming', None),
    ]
    
    result = resolve_file_conflicts(text, resolutions)
    if result:
        write_file(path, result)
        print("validation.cpp conflicts resolved")
    return result

if __name__ == '__main__':
    print("=== Resolving validation.h ===")
    resolve_validation_h()
    print("=== Resolving validation.cpp ===")
    resolve_validation_cpp()
    print("Done. Check result with grep for conflict markers.")
