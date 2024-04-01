// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2022 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "validationinterface.h"
#include "init.h"
#include "scheduler.h"

#include <boost/signals2/signal.hpp>

struct MainSignalsInstance {
    boost::signals2::signal<void (const CBlockIndex *, const CBlockIndex *, bool fInitialDownload)> UpdatedBlockTip;
    boost::signals2::signal<void (const CTransactionRef &)> TransactionAddedToMempool;
    boost::signals2::signal<void (const std::shared_ptr<const CBlock> &, const CBlockIndex *, const std::vector<CTransactionRef> &)> BlockConnected;
    boost::signals2::signal<void (const std::shared_ptr<const CBlock> &)> BlockDisconnected;
    boost::signals2::signal<void (const uint256 &)> UpdatedTransaction;
    boost::signals2::signal<void (const CBlockLocator &)> SetBestChain;
    boost::signals2::signal<void (const uint256 &)> Inventory;
    boost::signals2::signal<void (int64_t, CConnman*)> Broadcast;
    boost::signals2::signal<void (const CBlock&, const CValidationState&)> BlockChecked;
    boost::signals2::signal<void (std::shared_ptr<CReserveScript>&)> ScriptForMining;
    boost::signals2::signal<void (const uint256 &)> BlockFound;
    boost::signals2::signal<void (const CBlockIndex *, const std::shared_ptr<const CBlock>&)> NewPoWValidBlock;

    CScheduler *m_scheduler = NULL;
};

static CMainSignals g_signals;

CMainSignals::CMainSignals() {
    m_internals.reset(new MainSignalsInstance());
}

void CMainSignals::RegisterBackgroundSignalScheduler(CScheduler& scheduler) {
    assert(!m_internals->m_scheduler);
    m_internals->m_scheduler = &scheduler;
}

void CMainSignals::UnregisterBackgroundSignalScheduler() {
    m_internals->m_scheduler = NULL;
}

CMainSignals& GetMainSignals()
{
    return g_signals;
}

void RegisterValidationInterface(CValidationInterface* pwalletIn) {
    g_signals.m_internals->UpdatedBlockTip.connect(boost::bind(&CValidationInterface::UpdatedBlockTip, pwalletIn, boost::placeholders::_1, boost::placeholders::_2, boost::placeholders::_3));
    g_signals.m_internals->TransactionAddedToMempool.connect(boost::bind(&CValidationInterface::TransactionAddedToMempool, pwalletIn, boost::placeholders::_1));
    g_signals.m_internals->BlockConnected.connect(boost::bind(&CValidationInterface::BlockConnected, pwalletIn, boost::placeholders::_1, boost::placeholders::_2, boost::placeholders::_3));
    g_signals.m_internals->BlockDisconnected.connect(boost::bind(&CValidationInterface::BlockDisconnected, pwalletIn, boost::placeholders::_1));
    g_signals.m_internals->UpdatedTransaction.connect(boost::bind(&CValidationInterface::UpdatedTransaction, pwalletIn, boost::placeholders::_1));
    g_signals.m_internals->SetBestChain.connect(boost::bind(&CValidationInterface::SetBestChain, pwalletIn, boost::placeholders::_1));
    g_signals.m_internals->Inventory.connect(boost::bind(&CValidationInterface::Inventory, pwalletIn, boost::placeholders::_1));
    g_signals.m_internals->Broadcast.connect(boost::bind(&CValidationInterface::ResendWalletTransactions, pwalletIn, boost::placeholders::_1, boost::placeholders::_2));
    g_signals.m_internals->BlockChecked.connect(boost::bind(&CValidationInterface::BlockChecked, pwalletIn, boost::placeholders::_1, boost::placeholders::_2));
    g_signals.m_internals->ScriptForMining.connect(boost::bind(&CValidationInterface::GetScriptForMining, pwalletIn, boost::placeholders::_1));
    g_signals.m_internals->NewPoWValidBlock.connect(boost::bind(&CValidationInterface::NewPoWValidBlock, pwalletIn, boost::placeholders::_1, boost::placeholders::_2));
}

void UnregisterValidationInterface(CValidationInterface* pwalletIn) {
    g_signals.m_internals->UpdatedBlockTip.disconnect(boost::bind(&CValidationInterface::UpdatedBlockTip, pwalletIn, boost::placeholders::_1, boost::placeholders::_2, boost::placeholders::_3));
    g_signals.m_internals->TransactionAddedToMempool.disconnect(boost::bind(&CValidationInterface::TransactionAddedToMempool, pwalletIn, boost::placeholders::_1));
    g_signals.m_internals->BlockConnected.disconnect(boost::bind(&CValidationInterface::BlockConnected, pwalletIn, boost::placeholders::_1, boost::placeholders::_2, boost::placeholders::_3));
    g_signals.m_internals->BlockDisconnected.disconnect(boost::bind(&CValidationInterface::BlockDisconnected, pwalletIn, boost::placeholders::_1));
    g_signals.m_internals->UpdatedTransaction.disconnect(boost::bind(&CValidationInterface::UpdatedTransaction, pwalletIn, boost::placeholders::_1));
    g_signals.m_internals->SetBestChain.disconnect(boost::bind(&CValidationInterface::SetBestChain, pwalletIn, boost::placeholders::_1));
    g_signals.m_internals->Inventory.disconnect(boost::bind(&CValidationInterface::Inventory, pwalletIn, boost::placeholders::_1));
    g_signals.m_internals->Broadcast.disconnect(boost::bind(&CValidationInterface::ResendWalletTransactions, pwalletIn, boost::placeholders::_1, boost::placeholders::_2));
    g_signals.m_internals->BlockChecked.disconnect(boost::bind(&CValidationInterface::BlockChecked, pwalletIn, boost::placeholders::_1, boost::placeholders::_2));
    g_signals.m_internals->ScriptForMining.disconnect(boost::bind(&CValidationInterface::GetScriptForMining, pwalletIn, boost::placeholders::_1));
    g_signals.m_internals->NewPoWValidBlock.disconnect(boost::bind(&CValidationInterface::NewPoWValidBlock, pwalletIn, boost::placeholders::_1, boost::placeholders::_2));
}

void UnregisterAllValidationInterfaces() {
    g_signals.m_internals->UpdatedBlockTip.disconnect_all_slots();
    g_signals.m_internals->TransactionAddedToMempool.disconnect_all_slots();
    g_signals.m_internals->BlockConnected.disconnect_all_slots();
    g_signals.m_internals->BlockDisconnected.disconnect_all_slots();
    g_signals.m_internals->UpdatedTransaction.disconnect_all_slots();
    g_signals.m_internals->SetBestChain.disconnect_all_slots();
    g_signals.m_internals->Inventory.disconnect_all_slots();
    g_signals.m_internals->Broadcast.disconnect_all_slots();
    g_signals.m_internals->BlockChecked.disconnect_all_slots();
    g_signals.m_internals->ScriptForMining.disconnect_all_slots();
    g_signals.m_internals->NewPoWValidBlock.disconnect_all_slots();
}

void CMainSignals::UpdatedBlockTip(const CBlockIndex *pindexNew, const CBlockIndex *pindexFork, bool fInitialDownload) {
    m_internals->UpdatedBlockTip(pindexNew, pindexFork, fInitialDownload);
}

void CMainSignals::TransactionAddedToMempool(const CTransactionRef &ptxn) {
    m_internals->TransactionAddedToMempool(ptxn);
}

void CMainSignals::BlockConnected(const std::shared_ptr<const CBlock> &block, const CBlockIndex *pindex, const std::vector<CTransactionRef> &txnConflicted) {
    m_internals->BlockConnected(block, pindex, txnConflicted);
}

void CMainSignals::BlockDisconnected(const std::shared_ptr<const CBlock> &block) {
    m_internals->BlockDisconnected(block);
}

void CMainSignals::UpdatedTransaction(const uint256 &hash) {
    m_internals->UpdatedTransaction(hash);
}

void CMainSignals::SetBestChain(const CBlockLocator &locator) {
    m_internals->SetBestChain(locator);
}

void CMainSignals::Inventory(const uint256 &hash) {
    m_internals->Inventory(hash);
}

void CMainSignals::Broadcast(int64_t nBestBlockTime, CConnman* connman) {
    m_internals->Broadcast(nBestBlockTime, connman);
}

void CMainSignals::BlockChecked(const CBlock& block, const CValidationState& state) {
    m_internals->BlockChecked(block, state);
}

void CMainSignals::ScriptForMining(std::shared_ptr<CReserveScript>& script) {
    m_internals->ScriptForMining(script);
}

void CMainSignals::NewPoWValidBlock(const CBlockIndex *pindex, const std::shared_ptr<const CBlock> &block) {
    m_internals->NewPoWValidBlock(pindex, block);
}
