// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2022-2023 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_VALIDATIONINTERFACE_H
#define BITCOIN_VALIDATIONINTERFACE_H

#include <memory>

class CBlock;
class CBlockIndex;
struct CBlockLocator;
class CBlockIndex;
class CConnman;
class CReserveScript;
class CTransaction;
class CValidationInterface;
class CValidationState;
class uint256;

// These functions dispatch to one or all registered wallets

/** Register a wallet to receive updates from core */
void RegisterValidationInterface(CValidationInterface* pwalletIn);
/** Unregister a wallet from core */
void UnregisterValidationInterface(CValidationInterface* pwalletIn);
/** Unregister all wallets from core */
void UnregisterAllValidationInterfaces();

class CValidationInterface {
protected:
    /** Notifies listeners of updated block chain tip */
    virtual void UpdatedBlockTip(const CBlockIndex *pindexNew, const CBlockIndex *pindexFork, bool fInitialDownload) {};
    /** A posInBlock value for SyncTransaction calls for transactions not
     * included in connected blocks such as transactions removed from mempool,
     * accepted to mempool or appearing in disconnected blocks.*/
    static const int SYNC_TRANSACTION_NOT_IN_BLOCK = -1;
    /** Notifies listeners of updated transaction data (transaction, and
     * optionally the block it is found in). Called with block data when
     * transaction is included in a connected block, and without block data when
     * transaction was accepted to mempool, removed from mempool (only when
     * removal was due to conflict from connected block), or appeared in a
     * disconnected block.*/
    virtual void SyncTransaction(const CTransaction &tx, const CBlockIndex *pindex, int posInBlock) {};
    /** Notifies listeners of the new active block chain on-disk. */
    virtual void SetBestChain(const CBlockLocator &locator) {};
    /** Notifies listeners of an updated transaction without new data (for now: a coinbase potentially becoming visible). */
    virtual void UpdatedTransaction(const uint256 &hash) {};
    /** Notifies listeners about an inventory item being seen on the network. */
    virtual void Inventory(const uint256 &hash) {};
    /** Tells listeners to broadcast their data. */
    virtual void ResendWalletTransactions(int64_t nBestBlockTime, CConnman* connman) {};
    /**
     * Notifies listeners of a block validation result.
     * If the provided CValidationState IsValid, the provided block
     * is guaranteed to be the current best block at the time the
     * callback was generated (not necessarily now)
     */
    virtual void BlockChecked(const CBlock& block, const CValidationState& state) {};
    /** Notifies listeners that a key for mining is required (coinbase) */
    virtual void GetScriptForMining(std::shared_ptr<CReserveScript>& script) {};
    virtual void ResetRequestCount(const uint256 &hash) {};
    /**
     * Notifies listeners that a block which builds directly on our current tip
     * has been received and connected to the headers tree, though not validated yet */
    virtual void NewPoWValidBlock(const CBlockIndex *pindex, const std::shared_ptr<const CBlock>& block) {};
    friend void ::RegisterValidationInterface(CValidationInterface*);
    friend void ::UnregisterValidationInterface(CValidationInterface*);
    friend void ::UnregisterAllValidationInterfaces();
};

struct MainSignalsInstance;
class CMainSignals {
private:
    std::unique_ptr<MainSignalsInstance> m_internals;

    friend void ::RegisterValidationInterface(CValidationInterface*);
    friend void ::UnregisterValidationInterface(CValidationInterface*);
    friend void ::UnregisterAllValidationInterfaces();
public:
    CMainSignals();
    void UpdatedBlockTip(const CBlockIndex *, const CBlockIndex *, bool);
    static const int SYNC_TRANSACTION_NOT_IN_BLOCK = -1;
    void SyncTransaction(const CTransaction &, const CBlockIndex *, int);
    void UpdatedTransaction(const uint256 &);
    void SetBestChain(const CBlockLocator &);
    void Inventory(const uint256 &);
    void Broadcast(int64_t, CConnman*);
    void BlockChecked(const CBlock&, const CValidationState&);
    void ScriptForMining(std::shared_ptr<CReserveScript>&);
    void BlockFound(const uint256 &);
    void NewPoWValidBlock(const CBlockIndex *, const std::shared_ptr<const CBlock>&);
};

CMainSignals& GetMainSignals();

#endif // BITCOIN_VALIDATIONINTERFACE_H
