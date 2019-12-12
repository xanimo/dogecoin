// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2022-2023 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_VALIDATION_H
#define BITCOIN_VALIDATION_H

#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#endif

#include "amount.h"
#include "chain.h"
#include "coins.h"
#include "fs.h"
#include "txdb.h"
#include "policy/policy.h" // For RECOMMENDED_MIN_TX_FEE
#include "protocol.h" // For CMessageHeader::MessageStartChars
#include "script/script_error.h"
#include "sync.h"
#include "versionbits.h"

#include <algorithm>
#include <exception>
#include <list>
#include <map>
#include <set>
#include <stdint.h>
#include <string>
#include <utility>
#include <vector>

#include <atomic>
#include <optional>

#include <boost/unordered_map.hpp>

#include "consensus/validation.h"

class CBlockIndex;
class CBlockTreeDB;
class CBloomFilter;
class CBlockUndo;
class CChainParams;
class CInv;
class CConnman;
class CScriptCheck;
class CTxMemPool;
class CValidationInterface;
struct ChainTxData;

struct DisconnectedBlockTransactions;
struct PrecomputedTransactionData;
struct LockPoints;

/** Default for DEFAULT_WHITELISTRELAY. */
static const bool DEFAULT_WHITELISTRELAY = true;
/** Default for DEFAULT_WHITELISTFORCERELAY. */
static const bool DEFAULT_WHITELISTFORCERELAY = true;
/** Default for -minrelaytxfee, minimum relay fee for transactions */
static const CAmount DEFAULT_MIN_RELAY_TX_FEE = RECOMMENDED_MIN_TX_FEE / 10;
//! -maxtxfee default
//rnicoll: 8/2021 scaled down as recommended fee is lowered
static const CAmount DEFAULT_TRANSACTION_MAXFEE = RECOMMENDED_MIN_TX_FEE * 10000;

//! Discourage users to set fees higher than this amount (in satoshis) per kB
/* Dogecoin: Set the high tx fee to be higher than the default values
 *           implemented by the wallet.
 */
static const CAmount HIGH_TX_FEE_PER_KB = RECOMMENDED_MIN_TX_FEE * 1000;

//! -maxtxfee will warn if called with a higher fee than this amount (in satoshis)
//mlumin: 5/2021 adjusted max upward in terms of coin
static const CAmount HIGH_MAX_TX_FEE = 100 * HIGH_TX_FEE_PER_KB;
/** Default for -limitancestorcount, max number of in-mempool ancestors */
static const unsigned int DEFAULT_ANCESTOR_LIMIT = 25;
/** Default for -limitancestorsize, maximum kilobytes of tx + all in-mempool ancestors */
static const unsigned int DEFAULT_ANCESTOR_SIZE_LIMIT = 101;
/** Default for -limitdescendantcount, max number of in-mempool descendants */
static const unsigned int DEFAULT_DESCENDANT_LIMIT = 25;
/** Default for -limitdescendantsize, maximum kilobytes of in-mempool descendants */
static const unsigned int DEFAULT_DESCENDANT_SIZE_LIMIT = 101;
/** Default for -mempoolexpiry, expiration time for mempool transactions in hours */
static const unsigned int DEFAULT_MEMPOOL_EXPIRY = 24;
/** The maximum size of a blk?????.dat file (since 0.8) */
static const unsigned int MAX_BLOCKFILE_SIZE = 0x8000000; // 128 MiB
/** The pre-allocation chunk size for blk?????.dat files (since 0.8) */
static const unsigned int BLOCKFILE_CHUNK_SIZE = 0x1000000; // 16 MiB
/** The pre-allocation chunk size for rev?????.dat files (since 0.8) */
static const unsigned int UNDOFILE_CHUNK_SIZE = 0x100000; // 1 MiB

/** Maximum number of script-checking threads allowed */
static const int MAX_SCRIPTCHECK_THREADS = 16;
/** -par default (number of script-checking threads, 0 = auto) */
static const int DEFAULT_SCRIPTCHECK_THREADS = 0;
/** Number of blocks that can be requested at any given time from a single peer. */
static const int MAX_BLOCKS_IN_TRANSIT_PER_PEER = 16;
/** Timeout in seconds during which a peer must stall block download progress before being disconnected. */
static const unsigned int BLOCK_STALLING_TIMEOUT = 2;
/** Number of headers sent in one getheaders result. We rely on the assumption that if a peer sends
 *  less than this number, we reached its tip. Changing this value is a protocol upgrade. */
static const unsigned int MAX_HEADERS_RESULTS = 2000;
/** Maximum depth of blocks we're willing to serve as compact blocks to peers
 *  when requested. For older blocks, a regular BLOCK response will be sent. */
static const int MAX_CMPCTBLOCK_DEPTH = 5;
/** Maximum depth of blocks we're willing to respond to GETBLOCKTXN requests for. */
static const int MAX_BLOCKTXN_DEPTH = 10;
/** Size of the "block download window": how far ahead of our current height do we fetch?
 *  Larger windows tolerate larger download speed differences between peer, but increase the potential
 *  degree of disordering of blocks on disk (which make reindexing and in the future perhaps pruning
 *  harder). We'll probably want to make this a per-peer adaptive value at some point. */
static const unsigned int BLOCK_DOWNLOAD_WINDOW = 1024;
/** Time to wait (in seconds) between writing blocks/block index to disk. */
static const unsigned int DATABASE_WRITE_INTERVAL = 60 * 60;
/** Time to wait (in seconds) between flushing chainstate to disk. */
static const unsigned int DATABASE_FLUSH_INTERVAL = 24 * 60 * 60;
/** Maximum length of reject messages. */
static const unsigned int MAX_REJECT_MESSAGE_LENGTH = 111;
/** Average delay between local address broadcasts in seconds. */
static const unsigned int AVG_LOCAL_ADDRESS_BROADCAST_INTERVAL = 24 * 24 * 60;
/** Average delay between peer address broadcasts in seconds. */
static const unsigned int AVG_ADDRESS_BROADCAST_INTERVAL = 30;
/** Average delay between trickled inventory transmissions in seconds.
 *  Blocks and whitelisted receivers bypass this, outbound peers get half this delay. */
static const unsigned int INVENTORY_BROADCAST_INTERVAL = 5;
/** Maximum number of inventory items to send per transmission.
 *  Limits the impact of low-fee transaction floods. */
static const unsigned int INVENTORY_BROADCAST_MAX = 7 * INVENTORY_BROADCAST_INTERVAL;
/** Average delay between feefilter broadcasts in seconds. */
static const unsigned int AVG_FEEFILTER_BROADCAST_INTERVAL = 10 * 60;
/** Maximum feefilter broadcast delay after significant change. */
static const unsigned int MAX_FEEFILTER_CHANGE_DELAY = 5 * 60;
/** Block download timeout base, expressed in millionths of the block interval (i.e. 5 min) */
static const int64_t BLOCK_DOWNLOAD_TIMEOUT_BASE = 5000000;
/** Additional block download timeout per parallel downloading peer (i.e. 2.5 min) */
static const int64_t BLOCK_DOWNLOAD_TIMEOUT_PER_PEER = 2500000;

static const unsigned int DEFAULT_LIMITFREERELAY = 0;
static const bool DEFAULT_RELAYPRIORITY = true;
static const int64_t DEFAULT_MAX_TIP_AGE = 24 * 60 * 60;
/** Maximum age of our tip in seconds for us to be considered current for fee estimation */
static const int64_t MAX_FEE_ESTIMATION_TIP_AGE = 3 * 60 * 60;

/** Default for -permitbaremultisig */
static const bool DEFAULT_PERMIT_BAREMULTISIG = true;
static const bool DEFAULT_CHECKPOINTS_ENABLED = true;
static const bool DEFAULT_TXINDEX = false;
static const unsigned int DEFAULT_BANSCORE_THRESHOLD = 100;

/** Default for -mempoolreplacement */
static const bool DEFAULT_ENABLE_REPLACEMENT = true;
/** Default for using fee filter */
static const bool DEFAULT_FEEFILTER = true;

/** Maximum number of headers to announce when relaying blocks with headers message.*/
static const unsigned int MAX_BLOCKS_TO_ANNOUNCE = 8;

/** Maximum number of unconnecting headers announcements before DoS score */
static const int MAX_UNCONNECTING_HEADERS = 10;

static const bool DEFAULT_PEERBLOOMFILTERS = true;

struct BlockHasher
{
    size_t operator()(const uint256& hash) const { return hash.GetCheapHash(); }
};

extern CScript COINBASE_FLAGS;
extern CCriticalSection cs_main;
extern CTxMemPool mempool;
typedef boost::unordered_map<uint256, CBlockIndex*, BlockHasher> BlockMap;
extern BlockMap& mapBlockIndex;
extern uint64_t nLastBlockTx;
extern uint64_t nLastBlockSize;
extern uint64_t nLastBlockWeight;
extern const std::string strMessageMagic;
extern CWaitableCriticalSection csBestBlock;
extern CConditionVariable cvBlockChange;
extern std::atomic_bool fImporting;
extern bool fReindex;
extern int nScriptCheckThreads;
extern bool fTxIndex;
extern bool fIsBareMultisigStd;
extern bool fRequireStandard;
extern bool fCheckBlockIndex;
extern bool fCheckpointsEnabled;
extern size_t nCoinCacheUsage;
/** A fee rate smaller than this is considered zero fee (for relaying, mining and transaction creation) */
//mlumin 5/2021: changing variable name to Rate vs Fee because thats what it is.
extern CFeeRate minRelayTxFeeRate;
/** Absolute maximum transaction fee (in satoshis) used by wallet and mempool (rejects high fee in sendrawtransaction) */
extern CAmount maxTxFee;
/** If the tip is older than this (in seconds), the node is considered to be in initial block download. */
extern int64_t nMaxTipAge;
extern bool fEnableReplacement;

/** Block hash whose ancestors we will assume to have valid scripts without checking them. */
extern uint256 hashAssumeValid;

/** Best header we've seen so far (used for getheaders queries' starting points). */
extern CBlockIndex *pindexBestHeader;

/** Minimum disk space required - used in CheckDiskSpace() */
static const uint64_t nMinDiskSpace = 52428800;

/** Pruning-related variables and constants */
/** True if any block files have ever been pruned. */
extern bool fHavePruned;
/** True if we're running in -prune mode. */
extern bool fPruneMode;
/** Number of MiB of block files that we're trying to stay below. */
extern uint64_t nPruneTarget;
/** Block files containing a block-height within MIN_BLOCKS_TO_KEEP of chainActive.Tip() will not be pruned. */
static const unsigned int MIN_BLOCKS_TO_KEEP = 1440;

static const signed int DEFAULT_CHECKBLOCKS = 6;
static const unsigned int DEFAULT_CHECKLEVEL = 3;

// Require that user allocate at least 22,00MB for block & undo files (blk???.dat and rev???.dat)
// At 1MB per block, 1,440 blocks = 1,440MB.
// Add 15% for Undo data = 1,656MB
// Add 20% for Orphan block rate = 1,987MB
// We want the low water mark after pruning to be at least 1987 MB and since we prune in
// full block file chunks, we need the high water mark which triggers the prune to be
// one 128MB block file + added 15% undo data = 147MB greater for a total of 2,134MB
// Setting the target to > than 2200MB will make it likely we can respect the target.
static const uint64_t MIN_DISK_SPACE_FOR_BLOCK_FILES = 2200ULL * 1024 * 1024;

/** 
 * Process an incoming block. This only returns after the best known valid
 * block is made active. Note that it does not, however, guarantee that the
 * specific block passed to it has been checked for validity!
 *
 * If you want to *possibly* get feedback on whether pblock is valid, you must
 * install a CValidationInterface (see validationinterface.h) - this will have
 * its BlockChecked method called whenever *any* block completes validation.
 *
 * Note that we guarantee that either the proof-of-work is valid on pblock, or
 * (and possibly also) BlockChecked will have been called.
 * 
 * Call without cs_main held.
 *
 * @param[in]   pblock  The block we want to process.
 * @param[in]   fForceProcessing Process this block even if unrequested; used for non-network block sources and whitelisted peers.
 * @param[out]  fNewBlock A boolean which is set to indicate if the block was first received via this call
 * @return True if state.IsValid()
 */
bool ProcessNewBlock(const CChainParams& chainparams, const std::shared_ptr<const CBlock> pblock, bool fForceProcessing, bool* fNewBlock);

/**
 * Process incoming block headers.
 *
 * Call without cs_main held.
 *
 * @param[in]  block The block headers themselves
 * @param[out] state This may be set to an Error state if any error occurred processing them
 * @param[in]  chainparams The params for the chain we want to connect to
 * @param[out] ppindex If set, the pointer will be set to point to the last new block index object for the given headers
 */
bool ProcessNewBlockHeaders(const std::vector<CBlockHeader>& block, BlockValidationState& state, const CChainParams& chainparams, const CBlockIndex** ppindex=NULL) LOCKS_EXCLUDED(cs_main);

/** Check whether enough disk space is available for an incoming block */
bool CheckDiskSpace(uint64_t nAdditionalBytes = 0);
/** Open a block file (blk?????.dat) */
FILE* OpenBlockFile(const CDiskBlockPos &pos, bool fReadOnly = false);
/** Translation to a filesystem path */
fs::path GetBlockPosFilename(const CDiskBlockPos &pos, const char *prefix);
/** Import blocks from an external file */
bool LoadExternalBlockFile(const CChainParams& chainparams, FILE* fileIn, CDiskBlockPos *dbp = NULL);
/** Ensures we have a genesis block in the block tree database on disk */
bool LoadGenesisBlock(const CChainParams& chainparams);
/** Load the block tree and coins database from disk */
bool LoadBlockIndex(const CChainParams& chainparams);
/** Update the chain tip based on database information. */
void LoadChainTip(const CChainParams& chainparams);
/** Unload database information */
void UnloadBlockIndex();
/** Run an instance of the script checking thread */
void ThreadScriptCheck();
/** Format a string that describes several potential problems detected by the core.
 * strFor can have three values:
 * - "rpc": get critical warnings, which should put the client in safe mode if non-empty
 * - "statusbar": get all warnings
 * - "gui": get all warnings, translated (where possible) for GUI
 * This function only returns the highest priority warning of the set selected by strFor.
 */
std::string GetWarnings(const std::string& strFor);
/** Retrieve a transaction (from memory pool, or from disk, if possible) */
bool GetTransaction(const uint256 &hash, CTransactionRef &tx, const Consensus::Params& params, uint256 &hashBlock, bool fAllowSlow = false);
/** Find the best known block, and make it the tip of the block chain */
bool ActivateBestChain(BlockValidationState& state, const CChainParams& chainparams, std::shared_ptr<const CBlock> pblock = std::shared_ptr<const CBlock>());

/** Guess verification progress (as a fraction between 0.0=genesis and 1.0=current tip). */
double GuessVerificationProgress(const ChainTxData& data, CBlockIndex* pindex);

/** Calculate the amount of disk space the block & undo files currently use */
uint64_t CalculateCurrentUsage();

/**
 *  Mark one block file as pruned.
 */
void PruneOneBlockFile(const int fileNumber);

/**
 *  Actually unlink the specified files
 */
void UnlinkPrunedFiles(const std::set<int>& setFilesToPrune);

/** Prune block files up to a given height */
void PruneBlockFilesManual(int nPruneUpToHeight);

/** (try to) add transaction to memory pool
 * plTxnReplaced will be appended to with all transactions replaced from mempool **/
bool AcceptToMemoryPool(CTxMemPool& pool, TxValidationState &state, const CTransactionRef &tx, bool fLimitFree,
                        bool* pfMissingInputs, std::list<CTransactionRef>* plTxnReplaced = NULL,
                        bool fOverrideMempoolLimit=false, const CAmount nAbsurdFee=0);

/** Format a ValidationState for human-readable logging */
template<typename Result>
std::string FormatStateMessage(const ValidationState<Result>& state) { return state.ToString(); }

/** Get the BIP9 state for a given deployment at the current tip. */
ThresholdState VersionBitsTipState(const Consensus::Params& params, Consensus::DeploymentPos pos);

/** Get the block height at which the BIP9 deployment switched into the state for the block building on the current tip. */
int VersionBitsTipStateSinceHeight(const Consensus::Params& params, Consensus::DeploymentPos pos);

/** 
 * Count ECDSA signature operations the old-fashioned (pre-0.6) way
 * @return number of sigops this transaction's outputs will produce when spent
 * @see CTransaction::FetchInputs
 */
unsigned int GetLegacySigOpCount(const CTransaction& tx);

/**
 * Count ECDSA signature operations in pay-to-script-hash inputs.
 * 
 * @param[in] mapInputs Map of previous transactions that have outputs we're spending
 * @return maximum number of sigops required to validate this transaction's inputs
 * @see CTransaction::FetchInputs
 */
unsigned int GetP2SHSigOpCount(const CTransaction& tx, const CCoinsViewCache& mapInputs);

/**
 * Compute total signature operation cost of a transaction.
 * @param[in] tx     Transaction for which we are computing the cost
 * @param[in] inputs Map of previous transactions that have outputs we're spending
 * @param[out] flags Script verification flags
 * @return Total signature operation cost of tx
 */
int64_t GetTransactionSigOpCost(const CTransaction& tx, const CCoinsViewCache& inputs, int flags);

/** Apply the effects of this transaction on the UTXO set represented by view */
void UpdateCoins(const CTransaction& tx, CCoinsViewCache& inputs, int nHeight);

/** Transaction validation functions */

/** Context-independent validity checks */
bool CheckTransaction(const CTransaction& tx, TxValidationState& state, bool fCheckDuplicateInputs=true);

namespace Consensus {

/**
 * Check whether all inputs of this transaction are valid (no double spends and amounts)
 * This does not modify the UTXO set. This does not check scripts and sigs.
 * Preconditions: tx.IsCoinBase() is false.
 */
bool CheckTxInputs(const CChainParams& params, const CTransaction& tx, TxValidationState& state, const CCoinsViewCache& inputs, int nSpendHeight);

} // namespace Consensus

/**
 * Check if transaction is final and can be included in a block with the
 * specified height and time. Consensus critical.
 */
bool IsFinalTx(const CTransaction &tx, int nBlockHeight, int64_t nBlockTime);

/**
 * Check if transaction will be final in the next block to be created.
 *
 * Calls IsFinalTx() with current block height and appropriate block time.
 *
 * See consensus/consensus.h for flag definitions.
 */
bool CheckFinalTx(const CTransaction &tx, int flags = -1);

/**
 * Test whether the LockPoints height and time are still valid on the current chain
 */
bool TestLockPointValidity(const LockPoints* lp);

/**
 * Check if transaction is final per BIP 68 sequence numbers and can be included in a block.
 * Consensus critical. Takes as input a list of heights at which tx's inputs (in order) confirmed.
 */
bool SequenceLocks(const CTransaction &tx, int flags, std::vector<int>* prevHeights, const CBlockIndex& block);

/**
 * Check if transaction will be BIP 68 final in the next block to be created.
 *
 * Simulates calling SequenceLocks() with data from the tip of the current active chain.
 * Optionally stores in LockPoints the resulting height and time calculated and the hash
 * of the block needed for calculation or skips the calculation and uses the LockPoints
 * passed in for evaluation.
 * The LockPoints should not be considered valid if CheckSequenceLocks returns false.
 *
 * See consensus/consensus.h for flag definitions.
 */
bool CheckSequenceLocks(const CTransaction &tx, int flags, LockPoints* lp = NULL, bool useExistingLockPoints = false);

/**
 * Closure representing one script verification
 * Note that this stores references to the spending transaction 
 */
class CScriptCheck
{
private:
    CScript scriptPubKey;
    CAmount amount;
    const CTransaction *ptxTo;
    unsigned int nIn;
    unsigned int nFlags;
    bool cacheStore;
    ScriptError error;
    PrecomputedTransactionData *txdata;

public:
    CScriptCheck(): amount(0), ptxTo(0), nIn(0), nFlags(0), cacheStore(false), error(SCRIPT_ERR_UNKNOWN_ERROR) {}
    CScriptCheck(const CScript& scriptPubKeyIn, const CAmount amountIn, const CTransaction& txToIn, unsigned int nInIn, unsigned int nFlagsIn, bool cacheIn, PrecomputedTransactionData* txdataIn) :
        scriptPubKey(scriptPubKeyIn), amount(amountIn),
        ptxTo(&txToIn), nIn(nInIn), nFlags(nFlagsIn), cacheStore(cacheIn), error(SCRIPT_ERR_UNKNOWN_ERROR), txdata(txdataIn) { }

    bool operator()();

    void swap(CScriptCheck &check) {
        scriptPubKey.swap(check.scriptPubKey);
        std::swap(ptxTo, check.ptxTo);
        std::swap(amount, check.amount);
        std::swap(nIn, check.nIn);
        std::swap(nFlags, check.nFlags);
        std::swap(cacheStore, check.cacheStore);
        std::swap(error, check.error);
        std::swap(txdata, check.txdata);
    }

    ScriptError GetScriptError() const { return error; }
};


/** Functions for disk access for blocks */
bool WriteBlockToDisk(const CBlock& block, CDiskBlockPos& pos, const CMessageHeader::MessageStartChars& messageStart);
bool ReadBlockFromDisk(CBlock& block, const CDiskBlockPos& pos, const Consensus::Params& consensusParams, bool fCheckPOW = true);
bool ReadBlockFromDisk(CBlock& block, const CBlockIndex* pindex, const Consensus::Params& consensusParams, bool fCheckPOW = true);
bool ReadBlockHeaderFromDisk(CBlockHeader& block, const CBlockIndex* pindex, const Consensus::Params& consensusParams, bool fCheckPOW = true);

bool UndoReadFromDisk(CBlockUndo& blockundo, const CBlockIndex *pindex);

/** Functions for validating blocks and updating the block tree */

/** Context-independent validity checks */
bool CheckBlockHeader(const CBlockHeader& block, BlockValidationState& state, bool fCheckPOW = true);
bool CheckBlock(const CBlock& block, BlockValidationState& state, bool fCheckPOW = true, bool fCheckMerkleRoot = true);

/** Context-dependent validity checks.
 *  By "context", we mean only the previous block headers, but not the UTXO
 *  set; UTXO-related validity checks are done in ConnectBlock(). */
bool ContextualCheckBlockHeader(const CBlockHeader& block, BlockValidationState& state, const CBlockIndex* pindexPrev, int64_t nAdjustedTime);
bool ContextualCheckBlock(const CBlock& block, BlockValidationState& state, const CBlockIndex* pindexPrev);

/** Apply the effects of this block (with given index) on the UTXO set represented by coins.
 *  Validity checks that depend on the UTXO set are also done; ConnectBlock()
 *  can fail if those validity checks fail (among other reasons). */
bool ConnectBlock(const CBlock& block, BlockValidationState& state, CBlockIndex* pindex, CCoinsViewCache& coins,
                  const CChainParams& chainparams, bool fJustCheck = false);

/** Check a block is completely valid from start to finish (only works on top of our current best block, with cs_main held) */
bool TestBlockValidity(BlockValidationState& state, const CChainParams& chainparams, const CBlock& block, CBlockIndex* pindexPrev, bool fCheckPOW = true, bool fCheckMerkleRoot = true);

/** Check whether witness commitments are required for block. */
bool IsWitnessEnabled(const CBlockIndex* pindexPrev, const Consensus::Params& params);

/** When there are blocks in the active chain with missing data, rewind the chainstate and remove them from the block index */
bool RewindBlockIndex(const CChainParams& params);

/** Update uncommitted block structures (currently: only the witness nonce). This is safe for submitted blocks. */
void UpdateUncommittedBlockStructures(CBlock& block, const CBlockIndex* pindexPrev, const Consensus::Params& consensusParams);

/** Produce the necessary coinbase commitment for a block (modifies the hash, don't call for mined blocks). */
std::vector<unsigned char> GenerateCoinbaseCommitment(CBlock& block, const CBlockIndex* pindexPrev, const Consensus::Params& consensusParams);

/** RAII wrapper for VerifyDB: Verify consistency of the block and coin databases */
class CVerifyDB {
public:
    CVerifyDB();
    ~CVerifyDB();
    bool VerifyDB(const CChainParams& chainparams, CCoinsView *coinsview, int nCheckLevel, int nCheckDepth);
};

/** Replay blocks that aren't fully applied to the database. */
bool ReplayBlocks(const CChainParams& params, CCoinsView* view);

CBlockIndex* LookupBlockIndex(const uint256& hash) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

/** Find the last common block between the parameter chain and a locator. */
CBlockIndex* FindForkInGlobalIndex(const CChain& chain, const CBlockLocator& locator);

enum DisconnectResult
{
    DISCONNECT_OK,      // All good.
    DISCONNECT_UNCLEAN, // Rolled back, but UTXO set was inconsistent with block.
    DISCONNECT_FAILED   // Something else went wrong.
};

class ConnectTrace;

/** @see CChainState::FlushStateToDisk */
enum class FlushStateMode {
    NONE,
    IF_NEEDED,
    PERIODIC,
    ALWAYS
};

struct CBlockIndexWorkComparator
{
    bool operator()(const CBlockIndex *pa, const CBlockIndex *pb) const;
};

/**
 * Maintains a tree of blocks (stored in `m_block_index`) which is consulted
 * to determine where the most-work tip is.
 *
 * This data is used mostly in `CChainState` - information about, e.g.,
 * candidate tips is not maintained here.
 */
class BlockManager {
public:
    BlockMap m_block_index GUARDED_BY(cs_main);

    /** In order to efficiently track invalidity of headers, we keep the set of
      * blocks which we tried to connect and found to be invalid here (ie which
      * were set to BLOCK_FAILED_VALID since the last restart). We can then
      * walk this set and check if a new header is a descendant of something in
      * this set, preventing us from having to walk m_block_index when we try
      * to connect a bad block and fail.
      *
      * While this is more complicated than marking everything which descends
      * from an invalid block as invalid at the time we discover it to be
      * invalid, doing so would require walking all of m_block_index to find all
      * descendants. Since this case should be very rare, keeping track of all
      * BLOCK_FAILED_VALID blocks in a set should be just fine and work just as
      * well.
      *
      * Because we already walk m_block_index in height-order at startup, we go
      * ahead and mark descendants of invalid blocks as FAILED_CHILD at that time,
      * instead of putting things in this set.
      */
    std::set<CBlockIndex*> m_failed_blocks;

    /**
     * All pairs A->B, where A (or one of its ancestors) misses transactions, but B has transactions.
     * Pruned nodes may have entries where B is missing data.
     */
    std::multimap<CBlockIndex*, CBlockIndex*> m_blocks_unlinked;

    /**
     * Load the blocktree off disk and into memory. Populate certain metadata
     * per index entry (nStatus, nChainWork, nTimeMax, etc.) as well as peripheral
     * collections like setDirtyBlockIndex.
     *
     * @param[out] block_index_candidates  Fill this set with any valid blocks for
     *                                     which we've downloaded all transactions.
     */
    bool LoadBlockIndex(
        const Consensus::Params& consensus_params,
        CBlockTreeDB& blocktree,
        std::set<CBlockIndex*, CBlockIndexWorkComparator>& block_index_candidates)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    /** Clear all data members. */
    void Unload() EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    CBlockIndex* AddToBlockIndex(const CBlockHeader& block) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    /** Create a new block index entry for a given block hash */
    CBlockIndex* InsertBlockIndex(const uint256& hash) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    /**
     * If a block header hasn't already been seen, call CheckBlockHeader on it, ensure
     * that it doesn't descend from an invalid block, and then add it to m_block_index.
     */
    bool AcceptBlockHeader(
        const CBlockHeader& block,
        BlockValidationState& state,
        const CChainParams& chainparams,
        CBlockIndex** ppindex) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
};

/**
 * A convenience class for constructing the CCoinsView* hierarchy used
 * to facilitate access to the UTXO set.
 *
 * This class consists of an arrangement of layered CCoinsView objects,
 * preferring to store and retrieve coins in memory via `m_cacheview` but
 * ultimately falling back on cache misses to the canonical store of UTXOs on
 * disk, `m_dbview`.
 */
class CoinsViews {

public:
    //! The lowest level of the CoinsViews cache hierarchy sits in a leveldb database on disk.
    //! All unspent coins reside in this store.
    CCoinsViewDB m_dbview GUARDED_BY(cs_main);

    //! This view wraps access to the leveldb instance and handles read errors gracefully.
    CCoinsViewErrorCatcher m_catcherview GUARDED_BY(cs_main);

    //! This is the top layer of the cache hierarchy - it keeps as many coins in memory as
    //! can fit per the dbcache setting.
    std::unique_ptr<CCoinsViewCache> m_cacheview GUARDED_BY(cs_main);

    //! This constructor initializes CCoinsViewDB and CCoinsViewErrorCatcher instances, but it
    //! *does not* create a CCoinsViewCache instance by default. This is done separately because the
    //! presence of the cache has implications on whether or not we're allowed to flush the cache's
    //! state to disk, which should not be done until the health of the database is verified.
    //!
    //! All arguments forwarded onto CCoinsViewDB.
    CoinsViews(std::string ldb_name, size_t cache_size_bytes, bool in_memory, bool should_wipe);

    //! Initialize the CCoinsViewCache member.
    void InitCache() EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
};

enum class CoinsCacheSizeState
{
    //! The coins cache is in immediate need of a flush.
    CRITICAL = 2,
    //! The cache is at >= 90% capacity.
    LARGE = 1,
    OK = 0
};

// Defined below, but needed for `friend` usage in CChainState.
class ChainstateManager;

/**
 * CChainState stores and provides an API to update our local knowledge of the
 * current best chain.
 *
 * Eventually, the API here is targeted at being exposed externally as a
 * consumable libconsensus library, so any functions added must only call
 * other class member functions, pure functions in other parts of the consensus
 * library, callbacks via the validation interface, or read/write-to-disk
 * functions (eventually this will also be via callbacks).
 *
 * Anything that is contingent on the current tip of the chain is stored here,
 * whereas block information and metadata independent of the current tip is
 * kept in `BlockMetadataManager`.
 */
class CChainState {
private:

    /**
     * Every received block is assigned a unique and increasing identifier, so we
     * know which one to give priority in case of a fork.
     */
    CCriticalSection cs_nBlockSequenceId;
    /** Blocks loaded from disk are assigned id 0, so start the counter at 1. */
    int32_t nBlockSequenceId = 1;
    /** Decreasing counter (used by subsequent preciousblock calls). */
    int32_t nBlockReverseSequenceId = -1;
    /** chainwork for the last block that preciousblock has been applied to. */
    arith_uint256 nLastPreciousChainwork = 0;

    /**
     * the ChainState CriticalSection
     * A lock that must be held when modifying this ChainState - held in ActivateBestChain()
     */
    CCriticalSection m_cs_chainstate;

    /**
     * Whether this chainstate is undergoing initial block download.
     *
     * Mutable because we need to be able to mark IsInitialBlockDownload()
     * const, which latches this for caching purposes.
     */
    mutable std::atomic<bool> m_cached_finished_ibd{false};

    //! Reference to a BlockManager instance which itself is shared across all
    //! CChainState instances. Keeping a local reference allows us to test more
    //! easily as opposed to referencing a global.
    BlockManager& m_blockman;

public:
    const uint256 m_from_snapshot_blockhash{};

    explicit CChainState(BlockManager& blockman, const uint256& snapshot_blockhash = uint256())
        : m_blockman(blockman), m_from_snapshot_blockhash(snapshot_blockhash) { }

    //! The current chain of blockheaders we consult and build on.
    //! @see CChain, CBlockIndex.
    CChain m_chain;
    /**
     * The set of all CBlockIndex entries with BLOCK_VALID_TRANSACTIONS (for itself and all ancestors) and
     * as good as our current tip or better. Entries may be failed, though, and pruning nodes may be
     * missing the data for the block.
     */
    std::set<CBlockIndex*, CBlockIndexWorkComparator> setBlockIndexCandidates;

    /**
     * Update the on-disk chain state.
     * The caches and indexes are flushed depending on the mode we're called with
     * if they're too large, if it's been a while since the last write,
     * or always and in all cases if we're in prune mode and are deleting files.
     *
     * If FlushStateMode::NONE is used, then FlushStateToDisk(...) won't do anything
     * besides checking if we need to prune.
     */
    bool FlushStateToDisk(
        const CChainParams& chainparams,
        BlockValidationState &state,
        FlushStateMode mode,
        int nManualPruneHeight = 0);

    //! Unconditionally flush all changes to disk.
    void ForceFlushStateToDisk();

    //! Prune blockfiles from the disk if necessary and then flush chainstate changes
    //! if we pruned.
    void PruneAndFlush();

    bool ActivateBestChain(BlockValidationState &state, const CChainParams& chainparams, std::shared_ptr<const CBlock> pblock);

    bool AcceptBlock(const std::shared_ptr<const CBlock>& pblock, BlockValidationState& state, const CChainParams& chainparams, CBlockIndex** ppindex, bool fRequested, const CDiskBlockPos* dbp, bool* fNewBlock);

    // Block (dis)connection on a given view:
    DisconnectResult DisconnectBlock(const CBlock& block, const CBlockIndex* pindex, CCoinsViewCache& view);
    bool ConnectBlock(const CBlock& block, BlockValidationState& state, CBlockIndex* pindex,
                    CCoinsViewCache& view, const CChainParams& chainparams, bool fJustCheck = false);

    // Block disconnection on our pcoinsTip:
    bool DisconnectTip(BlockValidationState& state, const CChainParams& chainparams, DisconnectedBlockTransactions *disconnectpool);

    // Manual block validity manipulation:
    bool PreciousBlock(BlockValidationState& state, const CChainParams& params, CBlockIndex *pindex);
    bool InvalidateBlock(BlockValidationState& state, const CChainParams& chainparams, CBlockIndex *pindex);
    bool ResetBlockFailureFlags(CBlockIndex *pindex);

    bool ReplayBlocks(const CChainParams& params, CCoinsView* view);
    bool RewindBlockIndex(const CChainParams& params);
    bool LoadGenesisBlock(const CChainParams& chainparams);

    void PruneBlockIndexCandidates();

    void UnloadBlockIndex();

    /** Check whether we are doing an initial block download (synchronizing from disk or network) */
    bool IsInitialBlockDownload() const;

    /**
     * Make various assertions about the state of the block index.
     *
     * By default this only executes fully when using the Regtest chain; see: fCheckBlockIndex.
     */
    void CheckBlockIndex(const Consensus::Params& consensusParams);

    /** Update the chain tip based on database information, i.e. CoinsTip()'s best block. */
    bool LoadChainTip(const CChainParams& chainparams) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    //! Dictates whether we need to flush the cache to disk or not.
    //!
    //! @return the state of the size of the coins cache.
    CoinsCacheSizeState GetCoinsCacheSizeState(const CTxMemPool& tx_pool)
        EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    CoinsCacheSizeState GetCoinsCacheSizeState(
        const CTxMemPool& tx_pool,
        size_t max_coins_cache_size_bytes,
        size_t max_mempool_size_bytes) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    std::string ToString() EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

private:
    bool ActivateBestChainStep(BlockValidationState& state, const CChainParams& chainparams, CBlockIndex* pindexMostWork, const std::shared_ptr<const CBlock>& pblock, bool& fInvalidFound, ConnectTrace& connectTrace, DisconnectedBlockTransactions &disconnectpool);
    bool ConnectTip(BlockValidationState& state, const CChainParams& chainparams, CBlockIndex* pindexNew, const std::shared_ptr<const CBlock>& pblock, ConnectTrace& connectTrace, DisconnectedBlockTransactions &disconnectpool);

    void EraseBlockData(CBlockIndex* index) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    void InvalidBlockFound(CBlockIndex *pindex, const BlockValidationState &state);
    CBlockIndex* FindMostWorkChain();
    bool ReceivedBlockTransactions(const CBlock &block, BlockValidationState& state, CBlockIndex *pindexNew, const CDiskBlockPos& pos, const Consensus::Params& consensusParams);

    bool RollforwardBlock(const CBlockIndex* pindex, CCoinsViewCache& inputs, const CChainParams& params) EXCLUSIVE_LOCKS_REQUIRED(cs_main);


    friend ChainstateManager;
};

/** Mark a block as precious and reorganize. */
bool PreciousBlock(BlockValidationState& state, const CChainParams& params, CBlockIndex *pindex);
/** Mark a block as invalid. */
bool InvalidateBlock(BlockValidationState& state, const CChainParams& chainparams, CBlockIndex *pindex);

/** Remove invalidity status from a block and its descendants. */
bool ResetBlockFailureFlags(CBlockIndex *pindex);

/** The global chain state. */
extern CChainState g_chainstate;

/**
 * Provides an interface for creating and interacting with one or two
 * chainstates: an IBD chainstate generated by downloading blocks, and
 * an optional snapshot chainstate loaded from a UTXO snapshot. Managed
 * chainstates can be maintained at different heights simultaneously.
 *
 * This class provides abstractions that allow the retrieval of the current
 * most-work chainstate ("Active") as well as chainstates which may be in
 * background use to validate UTXO snapshots.
 *
 * Definitions:
 *
 * *IBD chainstate*: a chainstate whose current state has been "fully"
 *   validated by the initial block download process.
 *
 * *Snapshot chainstate*: a chainstate populated by loading in an
 *    assumeutxo UTXO snapshot.
 *
 * *Active chainstate*: the chainstate containing the current most-work
 *    chain. Consulted by most parts of the system (net_processing,
 *    wallet) as a reflection of the current chain and UTXO set.
 *    This may either be an IBD chainstate or a snapshot chainstate.
 *
 * *Background IBD chainstate*: an IBD chainstate for which the
 *    IBD process is happening in the background while use of the
 *    active (snapshot) chainstate allows the rest of the system to function.
 *
 * *Validated chainstate*: the most-work chainstate which has been validated
 *   locally via initial block download. This will be the snapshot chainstate
 *   if a snapshot was loaded and all blocks up to the snapshot starting point
 *   have been downloaded and validated (via background validation), otherwise
 *   it will be the IBD chainstate.
 */
class ChainstateManager
{
private:
    //! The chainstate used under normal operation (i.e. "regular" IBD) or, if
    //! a snapshot is in use, for background validation.
    //!
    //! Its contents (including on-disk data) will be deleted *upon shutdown*
    //! after background validation of the snapshot has completed. We do not
    //! free the chainstate contents immediately after it finishes validation
    //! to cautiously avoid a case where some other part of the system is still
    //! using this pointer (e.g. net_processing).
    std::unique_ptr<CChainState> m_ibd_chainstate;

    //! A chainstate initialized on the basis of a UTXO snapshot. If this is
    //! non-null, it is always our active chainstate.
    std::unique_ptr<CChainState> m_snapshot_chainstate;

    //! Points to either the ibd or snapshot chainstate; indicates our
    //! most-work chain.
    CChainState* m_active_chainstate{nullptr};

    //! If true, the assumed-valid chainstate has been fully validated
    //! by the background validation chainstate.
    bool m_snapshot_validated{false};

    // For access to m_active_chainstate.
    friend CChain& ChainActive();

public:
    //! Instantiate a new chainstate and assign it based upon whether it is
    //! from a snapshot.
    //!
    //! @param[in] snapshot_blockhash   If given, signify that this chainstate
    //!                                 is based on a snapshot.
    CChainState& InitializeChainstate(const uint256& snapshot_blockhash = uint256())
        EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    //! Get all chainstates currently being used.
    std::vector<CChainState*> GetAll();

    //! The most-work chain.
    CChain& ActiveChain() const;
    int ActiveHeight() const { return ActiveChain().Height(); }
    CBlockIndex* ActiveTip() const { return ActiveChain().Tip(); }

    bool IsSnapshotActive() const;

    std::optional<uint256> SnapshotBlockhash() const;

    //! Is there a snapshot in use and has it been fully validated?
    bool IsSnapshotValidated() const { return m_snapshot_validated; }

    //! @returns true if this chainstate is being used to validate an active
    //!          snapshot in the background.
    bool IsBackgroundIBD(CChainState* chainstate) const;

    //! Return the most-work chainstate that has been fully validated.
    //!
    //! During background validation of a snapshot, this is the IBD chain. After
    //! background validation has completed, this is the snapshot chain.
    CChainState& ValidatedChainstate() const;

    CChain& ValidatedChain() const { return ValidatedChainstate().m_chain; }
    CBlockIndex* ValidatedTip() const { return ValidatedChain().Tip(); }

    //! Unload block index and chain data before shutdown.
    void Unload() EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    //! Clear (deconstruct) chainstate data.
    void Reset();
};

/** @returns the most-work valid chainstate. */
CChainState& ChainstateActive();

/** @returns the most-work chain. */
CChain& ChainActive();

/** The currently-connected chain of blocks (protected by cs_main). */
extern CChain& chainActive;

/** @returns the global block index map. */
BlockMap& BlockIndex();

/** Global variable that points to the active CCoinsView (protected by cs_main) */
extern CCoinsViewCache *pcoinsTip;

/** Global variable that points to the active block tree (protected by cs_main) */
extern CBlockTreeDB *pblocktree;

/**
 * Return the spend height, which is one more than the inputs.GetBestBlock().
 * While checking, GetBestBlock() refers to the parent block. (protected by cs_main)
 * This is also true for mempool checks.
 */
int GetSpendHeight(const CCoinsViewCache& inputs);

extern VersionBitsCache versionbitscache;

/**
 * Determine what nVersion a new block should use.
 */
int32_t ComputeBlockVersion(const CBlockIndex* pindexPrev, const Consensus::Params& params);

/** Reject codes greater or equal to this can be returned by AcceptToMemPool
 * for transactions, to signal internal conditions. They cannot and should not
 * be sent over the P2P network.
 */
static const unsigned int REJECT_INTERNAL = 0x100;
/** Too high fee. Can not be triggered by P2P transactions */
static const unsigned int REJECT_HIGHFEE = 0x100;
/** Transaction is already known (either in mempool or blockchain) */
static const unsigned int REJECT_ALREADY_KNOWN = 0x101;
/** Transaction conflicts with a transaction already known */
static const unsigned int REJECT_CONFLICT = 0x102;

/** Get block file info entry for one block file */
CBlockFileInfo* GetBlockFileInfo(size_t n);

/** Dump the mempool to disk. */
void DumpMempool();

/** Load the mempool from disk. */
bool LoadMempool();

#endif // BITCOIN_VALIDATION_H
