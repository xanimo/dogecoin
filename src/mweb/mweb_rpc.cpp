// Copyright (c) 2021 The Litecoin Core developers
// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#endif

#include "amount.h"
#include "net.h"
#include "rpc/server.h"
#include "utilstrencodings.h"
#include "validation.h"

#include "mweb/mweb_wallet.h"
#include "script/standard.h"

#ifdef ENABLE_WALLET
#include "wallet/wallet.h"
#endif

#include <univalue.h>

// The MWEB RPC commands live in the server library rather than the wallet
// library. Building a peg-in needs libmw's transaction builder, which is in the
// server library; a wallet-library RPC calling into it would create a
// wallet -> server archive dependency the single-pass linker cannot resolve.
// Registering here (server -> wallet) is the direction that links cleanly.

//! Default MWEB fee for a peg-in kernel when the caller does not specify one.
static const CAmount DEFAULT_MWEB_FEE = 100000; // 0.001 coin

UniValue pegin(const JSONRPCRequest& request)
{
#ifdef ENABLE_WALLET
    if (!pwalletMain)
        throw JSONRPCError(RPC_METHOD_NOT_FOUND, "Method not found (wallet disabled)");

    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
        throw std::runtime_error(
            "pegin amount ( mwebfee )\n"
            "\nPeg the given amount from the canonical chain into the MWEB, creating one\n"
            "MWEB output worth (amount - mwebfee). The canonical peg-in output is funded\n"
            "and signed by this wallet and the transaction is broadcast.\n"
            "\nNOTE: This is a prototype. The created MWEB output's secret is returned so it\n"
            "can be spent later; the wallet does not yet track MWEB outputs itself.\n"
            "\nArguments:\n"
            "1. \"amount\"   (numeric or string, required) The amount to peg in, e.g. 10.0\n"
            "2. \"mwebfee\"  (numeric or string, optional) The MWEB kernel fee (default 0.001)\n"
            "\nResult:\n"
            "{\n"
            "  \"txid\": \"id\",                (string) The canonical transaction id\n"
            "  \"mweb_output_value\": n,       (numeric) Value of the created MWEB output\n"
            "  \"mweb_output_blind\": \"hex\",   (string) Blinding factor of that output (secret)\n"
            "  \"kernel_id\": \"hex\"            (string) The peg-in kernel id\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("pegin", "10.0")
            + HelpExampleRpc("pegin", "10.0"));

    LOCK2(cs_main, pwalletMain->cs_wallet);

    const CAmount nAmount = AmountFromValue(request.params[0]);
    const CAmount nMwebFee = request.params.size() > 1 ? AmountFromValue(request.params[1]) : DEFAULT_MWEB_FEE;
    if (nAmount <= nMwebFee)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "peg-in amount must exceed the MWEB fee");

    if (pwalletMain->IsLocked())
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Error: Please enter the wallet passphrase with walletpassphrase first.");

    if (pwalletMain->GetBroadcastTransactions() && !g_connman)
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");

    // 1. Build the MWEB side: pegs `nAmount` in and creates one MWEB output.
    MWEB::Wallet::PegInResult peg;
    try {
        peg = MWEB::Wallet::BuildPegIn(nAmount, nMwebFee);
    } catch (const std::exception& e) {
        throw JSONRPCError(RPC_WALLET_ERROR, e.what());
    }
    const mw::Hash kernelID = peg.tx.GetPegIns().front().GetKernelID();

    // 2. Fund and sign the canonical peg-in output paying into that kernel.
    const CScript peginScript = GetScriptForMWEBPegin(kernelID);
    CReserveKey reservekey(pwalletMain);
    CWalletTx wtxNew;
    CAmount nFeeRequired;
    int nChangePosRet = -1;
    std::string strError;
    std::vector<CRecipient> vecSend = {{ peginScript, nAmount, false }};
    if (!pwalletMain->CreateTransaction(vecSend, wtxNew, reservekey, nFeeRequired, nChangePosRet, strError))
        throw JSONRPCError(RPC_WALLET_ERROR, strError);

    // 3. Attach the MWEB transaction. The canonical signature hash excludes MWEB
    //    data (SERIALIZE_NO_MWEB), so the signatures created above stay valid.
    CMutableTransaction mtx(*wtxNew.tx);
    mtx.mweb_tx = MWEB::Tx(std::make_shared<mw::Transaction>(peg.tx));
    CWalletTx wtxFinal(pwalletMain, MakeTransactionRef(std::move(mtx)));

    // 4. Record in the wallet and broadcast (requires MWEB to be active).
    CValidationState state;
    if (!pwalletMain->CommitTransaction(wtxFinal, reservekey, g_connman.get(), state))
        throw JSONRPCError(RPC_WALLET_ERROR,
            strprintf("Error: The transaction was rejected! Reason given: %s", state.GetRejectReason()));

    const std::vector<uint8_t> blindBytes = peg.outputBlind.vec();
    UniValue result(UniValue::VOBJ);
    result.pushKV("txid", wtxFinal.GetHash().GetHex());
    result.pushKV("mweb_output_value", ValueFromAmount(peg.outputValue));
    result.pushKV("mweb_output_blind", HexStr(blindBytes.begin(), blindBytes.end()));
    result.pushKV("kernel_id", kernelID.GetHex());
    return result;
#else
    throw JSONRPCError(RPC_METHOD_NOT_FOUND, "Method not available (wallet support not compiled in)");
#endif
}

static const CRPCCommand commands[] =
{ //  category              name                        actor (function)           okSafeMode
  //  --------------------- --------------------------- -------------------------- ----------
    { "mweb",               "pegin",                    &pegin,                    false,  {"amount","mwebfee"} },
};

void RegisterMWEBRPCCommands(CRPCTable& t)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
