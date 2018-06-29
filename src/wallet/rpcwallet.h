// Copyright (c) 2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_RPCWALLET_H
#define BITCOIN_WALLET_RPCWALLET_H

class CRPCTable;
class CWallet;
struct PartiallySignedTransaction;
class CTransaction;

void RegisterWalletRPCCommands(CRPCTable &t);

bool FillPSBT(const CWallet* pwallet, PartiallySignedTransaction& psbtx, const CTransaction* txConst, int sighash_type = 1, bool sign = true, bool bip32derivs = false);

#endif //BITCOIN_WALLET_RPCWALLET_H
