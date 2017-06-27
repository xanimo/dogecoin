// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2022 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "validationinterface.h"

#include <boost/bind/bind.hpp>

static CMainSignals g_signals;

CMainSignals& GetMainSignals()
{
    return g_signals;
}

void RegisterValidationInterface(CValidationInterface* pwalletIn) {
    g_signals.UpdatedBlockTip.connect(boost::bind(&CValidationInterface::UpdatedBlockTip, pwalletIn, boost::placeholders::_1, boost::placeholders::_2, boost::placeholders::_3));
    g_signals.TransactionAddedToMempool.connect(boost::bind(&CValidationInterface::TransactionAddedToMempool, pwalletIn, boost::placeholders::_1));
    g_signals.BlockConnected.connect(boost::bind(&CValidationInterface::BlockConnected, pwalletIn, boost::placeholders::_1, boost::placeholders::_2, boost::placeholders::_3));
    g_signals.BlockDisconnected.connect(boost::bind(&CValidationInterface::BlockDisconnected, pwalletIn, boost::placeholders::_1));
    g_signals.SetBestChain.connect(boost::bind(&CValidationInterface::SetBestChain, pwalletIn, boost::placeholders::_1));
    g_signals.Inventory.connect(boost::bind(&CValidationInterface::Inventory, pwalletIn, boost::placeholders::_1));
    g_signals.Broadcast.connect(boost::bind(&CValidationInterface::ResendWalletTransactions, pwalletIn, boost::placeholders::_1, boost::placeholders::_2));
    g_signals.BlockChecked.connect(boost::bind(&CValidationInterface::BlockChecked, pwalletIn, boost::placeholders::_1, boost::placeholders::_2));
    g_signals.NewPoWValidBlock.connect(boost::bind(&CValidationInterface::NewPoWValidBlock, pwalletIn, boost::placeholders::_1, boost::placeholders::_2));
}

void UnregisterValidationInterface(CValidationInterface* pwalletIn) {
    g_signals.BlockChecked.disconnect(boost::bind(&CValidationInterface::BlockChecked, pwalletIn, boost::placeholders::_1, boost::placeholders::_2));
    g_signals.Broadcast.disconnect(boost::bind(&CValidationInterface::ResendWalletTransactions, pwalletIn, boost::placeholders::_1, boost::placeholders::_2));
    g_signals.Inventory.disconnect(boost::bind(&CValidationInterface::Inventory, pwalletIn, boost::placeholders::_1));
    g_signals.SetBestChain.disconnect(boost::bind(&CValidationInterface::SetBestChain, pwalletIn, boost::placeholders::_1));
    g_signals.TransactionAddedToMempool.disconnect(boost::bind(&CValidationInterface::TransactionAddedToMempool, pwalletIn, boost::placeholders::_1));
    g_signals.BlockConnected.disconnect(boost::bind(&CValidationInterface::BlockConnected, pwalletIn, boost::placeholders::_1, boost::placeholders::_2, boost::placeholders::_3));
    g_signals.BlockDisconnected.disconnect(boost::bind(&CValidationInterface::BlockDisconnected, pwalletIn, boost::placeholders::_1));
    g_signals.UpdatedBlockTip.disconnect(boost::bind(&CValidationInterface::UpdatedBlockTip, pwalletIn, boost::placeholders::_1, boost::placeholders::_2, boost::placeholders::_3));
    g_signals.NewPoWValidBlock.disconnect(boost::bind(&CValidationInterface::NewPoWValidBlock, pwalletIn, boost::placeholders::_1, boost::placeholders::_2));
}

void UnregisterAllValidationInterfaces() {
    g_signals.BlockChecked.disconnect_all_slots();
    g_signals.Broadcast.disconnect_all_slots();
    g_signals.Inventory.disconnect_all_slots();
    g_signals.SetBestChain.disconnect_all_slots();
    g_signals.TransactionAddedToMempool.disconnect_all_slots();
    g_signals.BlockConnected.disconnect_all_slots();
    g_signals.BlockDisconnected.disconnect_all_slots();
    g_signals.UpdatedBlockTip.disconnect_all_slots();
    g_signals.NewPoWValidBlock.disconnect_all_slots();
}
