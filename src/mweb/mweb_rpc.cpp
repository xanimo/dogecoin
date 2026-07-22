// Copyright (c) 2021 The Litecoin Core developers
// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#endif

#include "amount.h"
#include "base58.h"
#include "net.h"
#include "rpc/server.h"
#include "utilstrencodings.h"
#include "validation.h"

#include "mweb/mweb_wallet.h"
#include "mweb/mweb_db.h"
#include "script/standard.h"

#ifdef ENABLE_WALLET
#include "wallet/wallet.h"
#endif

#include <univalue.h>
#include <vector>

// The MWEB RPC commands live in the server library rather than the wallet
// library. Building a peg-in needs libmw's transaction builder, which is in the
// server library; a wallet-library RPC calling into it would create a
// wallet -> server archive dependency the single-pass linker cannot resolve.
// Registering here (server -> wallet) is the direction that links cleanly.

//! Default MWEB fee for a peg-in kernel when the caller does not specify one.
static const CAmount DEFAULT_MWEB_FEE = 100000; // 0.001 coin

// Minimal MWEB coin tracking. A real wallet scans each block's extension block
// and recognises its own outputs via its view/spend keys; this prototype instead
// records the outputs it creates itself (peg-ins and spend change), which is
// enough to spend them again. In memory only for now -- lost on restart -- and
// guarded by cs_main, which every MWEB RPC below holds.
struct MWEBWalletCoin {
    mw::Hash outputID;
    CAmount value;
    std::vector<uint8_t> blind;
    bool spent;
};
static std::vector<MWEBWalletCoin> g_mweb_coins;

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

    // 5. Track the created MWEB output so it can be spent once it confirms.
    const mw::Hash newOutputID = peg.tx.GetOutputs().front().GetOutputID();
    const std::vector<uint8_t> blindBytes = peg.outputBlind.vec();
    g_mweb_coins.push_back({ newOutputID, peg.outputValue, blindBytes, false });

    UniValue result(UniValue::VOBJ);
    result.pushKV("txid", wtxFinal.GetHash().GetHex());
    result.pushKV("mweb_output_id", newOutputID.GetHex());
    result.pushKV("mweb_output_value", ValueFromAmount(peg.outputValue));
    result.pushKV("mweb_output_blind", HexStr(blindBytes.begin(), blindBytes.end()));
    result.pushKV("kernel_id", kernelID.GetHex());
    return result;
#else
    throw JSONRPCError(RPC_METHOD_NOT_FOUND, "Method not available (wallet support not compiled in)");
#endif
}

UniValue mwebspend(const JSONRPCRequest& request)
{
#ifdef ENABLE_WALLET
    if (!pwalletMain)
        throw JSONRPCError(RPC_METHOD_NOT_FOUND, "Method not found (wallet disabled)");

    if (request.fHelp || request.params.size() > 1)
        throw std::runtime_error(
            "mwebspend ( mwebfee )\n"
            "\nSpend a tracked MWEB output: consume the first confirmed, unspent MWEB\n"
            "output this wallet owns and create one new MWEB output worth (value - fee),\n"
            "as an MWEB-only transaction. Demonstrates spending inside the MWEB.\n"
            "\nArguments:\n"
            "1. \"mwebfee\"  (numeric or string, optional) The MWEB kernel fee (default 0.001)\n"
            "\nResult:\n"
            "{\n"
            "  \"txid\": \"id\",                (string) The MWEB transaction id (kernel id)\n"
            "  \"spent_output\": \"hex\",        (string) The output ID that was spent\n"
            "  \"new_output\": \"hex\",          (string) The output ID that was created\n"
            "  \"new_output_value\": n,        (numeric) Value of the new output\n"
            "  \"new_output_blind\": \"hex\"     (string) Blinding factor of the new output\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("mwebspend", "")
            + HelpExampleRpc("mwebspend", ""));

    LOCK2(cs_main, pwalletMain->cs_wallet);

    const CAmount nMwebFee = request.params.size() > 0 ? AmountFromValue(request.params[0]) : DEFAULT_MWEB_FEE;
    if (!g_mweb_state)
        throw JSONRPCError(RPC_WALLET_ERROR, "MWEB state database not available");

    // Select a tracked coin that is confirmed (present in the MWEB UTXO set) and
    // large enough to cover the fee.
    MWEBWalletCoin* coin = nullptr;
    for (MWEBWalletCoin& c : g_mweb_coins) {
        if (!c.spent && c.value > nMwebFee && g_mweb_state->HasOutput(c.outputID)) {
            coin = &c;
            break;
        }
    }
    if (coin == nullptr)
        throw JSONRPCError(RPC_WALLET_ERROR,
            "No spendable MWEB output. Peg in with `pegin` and mine a block first.");

    // Build an MWEB-only spend: consume the coin, create one new output.
    std::vector<uint8_t> newBlindBytes(mw::BlindingFactor::SIZE);
    std::vector<uint8_t> offsetBytes(mw::BlindingFactor::SIZE);
    GetStrongRandBytes(newBlindBytes.data(), static_cast<int>(newBlindBytes.size()));
    GetStrongRandBytes(offsetBytes.data(), static_cast<int>(offsetBytes.size()));
    const mw::BlindingFactor newBlind(newBlindBytes);
    const CAmount outValue = coin->value - nMwebFee;

    const mw::wallet::Coin inCoin{ static_cast<uint64_t>(coin->value),
                                   mw::BlindingFactor(coin->blind), coin->outputID };
    const mw::wallet::Coin outCoin{ static_cast<uint64_t>(outValue), newBlind };
    mw::Transaction spend;
    try {
        spend = mw::wallet::TxBuilder::Build({inCoin}, {outCoin},
                                             static_cast<uint64_t>(nMwebFee),
                                             mw::BlindingFactor(offsetBytes));
    } catch (const std::exception& e) {
        throw JSONRPCError(RPC_WALLET_ERROR, e.what());
    }

    // An MWEB-only transaction: no canonical inputs or outputs, just the MWEB body.
    CMutableTransaction mtx;
    mtx.mweb_tx = MWEB::Tx(std::make_shared<mw::Transaction>(spend));
    CTransactionRef tx = MakeTransactionRef(std::move(mtx));

    if (g_connman == nullptr)
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");

    CValidationState state;
    bool fMissingInputs = false;
    if (!AcceptToMemoryPool(mempool, state, tx, false, &fMissingInputs, NULL, false, maxTxFee)) {
        throw JSONRPCError(RPC_WALLET_ERROR,
            strprintf("MWEB spend rejected: %s", state.GetRejectReason()));
    }
    CInv inv(MSG_TX, tx->GetHash());
    g_connman->ForEachNode([&inv](CNode* pnode) { pnode->PushInventory(inv); });

    // Capture what we need before push_back below, which may reallocate
    // g_mweb_coins and invalidate `coin`.
    const mw::Hash spentOutputID = coin->outputID;
    coin->spent = true;

    // Track the new output.
    const mw::Hash newOutID = spend.GetOutputs().front().GetOutputID();
    const std::vector<uint8_t> newBlindVec = newBlind.vec();
    g_mweb_coins.push_back({ newOutID, outValue, newBlindVec, false });

    UniValue result(UniValue::VOBJ);
    result.pushKV("txid", tx->GetHash().GetHex());
    result.pushKV("spent_output", spentOutputID.GetHex());
    result.pushKV("new_output", newOutID.GetHex());
    result.pushKV("new_output_value", ValueFromAmount(outValue));
    result.pushKV("new_output_blind", HexStr(newBlindVec.begin(), newBlindVec.end()));
    return result;
#else
    throw JSONRPCError(RPC_METHOD_NOT_FOUND, "Method not available (wallet support not compiled in)");
#endif
}

UniValue pegout(const JSONRPCRequest& request)
{
#ifdef ENABLE_WALLET
    if (!pwalletMain)
        throw JSONRPCError(RPC_METHOD_NOT_FOUND, "Method not found (wallet disabled)");

    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
        throw std::runtime_error(
            "pegout \"address\" ( mwebfee )\n"
            "\nPeg a tracked MWEB output back out to the canonical chain: consume the\n"
            "first confirmed, unspent MWEB output this wallet owns and pay its value\n"
            "(minus the fee) to \"address\" as a canonical output realised in the block's\n"
            "HogEx. The value leaves the MWEB and becomes a normal spendable UTXO.\n"
            "\nArguments:\n"
            "1. \"address\"  (string, required) The canonical address to peg out to\n"
            "2. \"mwebfee\"  (numeric or string, optional) The MWEB kernel fee (default 0.001)\n"
            "\nResult:\n"
            "{\n"
            "  \"txid\": \"id\",              (string) The MWEB transaction id (kernel id)\n"
            "  \"spent_output\": \"hex\",      (string) The MWEB output ID that was spent\n"
            "  \"pegout_address\": \"addr\",   (string) The canonical destination\n"
            "  \"pegout_amount\": n          (numeric) Value pegged out (value - fee)\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("pegout", "\"mnUs...\"")
            + HelpExampleRpc("pegout", "\"mnUs...\""));

    LOCK2(cs_main, pwalletMain->cs_wallet);

    CBitcoinAddress address(request.params[0].get_str());
    if (!address.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Dogecoin address");
    const CScript destScript = GetScriptForDestination(address.Get());

    const CAmount nMwebFee = request.params.size() > 1 ? AmountFromValue(request.params[1]) : DEFAULT_MWEB_FEE;
    if (!g_mweb_state)
        throw JSONRPCError(RPC_WALLET_ERROR, "MWEB state database not available");

    MWEBWalletCoin* coin = nullptr;
    for (MWEBWalletCoin& c : g_mweb_coins) {
        if (!c.spent && c.value > nMwebFee && g_mweb_state->HasOutput(c.outputID)) {
            coin = &c;
            break;
        }
    }
    if (coin == nullptr)
        throw JSONRPCError(RPC_WALLET_ERROR,
            "No spendable MWEB output. Peg in with `pegin` and mine a block first.");

    const CAmount pegoutAmount = coin->value - nMwebFee;

    std::vector<uint8_t> offsetBytes(mw::BlindingFactor::SIZE);
    GetStrongRandBytes(offsetBytes.data(), static_cast<int>(offsetBytes.size()));

    // Build an MWEB-only transaction: consume the input, peg its value out to the
    // canonical destination (no MWEB output). Balance: input == fee + pegout.
    const mw::wallet::Coin inCoin{ static_cast<uint64_t>(coin->value),
                                   mw::BlindingFactor(coin->blind), coin->outputID };
    const std::vector<mw::wallet::Coin> noOutputs;
    std::vector<mw::PegOutCoin> pegouts = { mw::PegOutCoin(pegoutAmount, destScript) };
    mw::Transaction pegtx;
    try {
        pegtx = mw::wallet::TxBuilder::Build(std::vector<mw::wallet::Coin>{inCoin}, noOutputs,
                                             static_cast<uint64_t>(nMwebFee), /*pegin=*/0,
                                             std::move(pegouts), mw::BlindingFactor(offsetBytes));
    } catch (const std::exception& e) {
        throw JSONRPCError(RPC_WALLET_ERROR, e.what());
    }

    CMutableTransaction mtx;
    mtx.mweb_tx = MWEB::Tx(std::make_shared<mw::Transaction>(pegtx));
    CTransactionRef tx = MakeTransactionRef(std::move(mtx));

    if (g_connman == nullptr)
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");

    CValidationState state;
    bool fMissingInputs = false;
    if (!AcceptToMemoryPool(mempool, state, tx, false, &fMissingInputs, NULL, false, maxTxFee)) {
        throw JSONRPCError(RPC_WALLET_ERROR,
            strprintf("Peg-out rejected: %s", state.GetRejectReason()));
    }
    CInv inv(MSG_TX, tx->GetHash());
    g_connman->ForEachNode([&inv](CNode* pnode) { pnode->PushInventory(inv); });

    const mw::Hash spentOutputID = coin->outputID;
    coin->spent = true;

    UniValue result(UniValue::VOBJ);
    result.pushKV("txid", tx->GetHash().GetHex());
    result.pushKV("spent_output", spentOutputID.GetHex());
    result.pushKV("pegout_address", address.ToString());
    result.pushKV("pegout_amount", ValueFromAmount(pegoutAmount));
    return result;
#else
    throw JSONRPCError(RPC_METHOD_NOT_FOUND, "Method not available (wallet support not compiled in)");
#endif
}

static const CRPCCommand commands[] =
{ //  category              name                        actor (function)           okSafeMode
  //  --------------------- --------------------------- -------------------------- ----------
    { "mweb",               "pegin",                    &pegin,                    false,  {"amount","mwebfee"} },
    { "mweb",               "mwebspend",                &mwebspend,                false,  {"mwebfee"} },
    { "mweb",               "pegout",                   &pegout,                   false,  {"address","mwebfee"} },
};

void RegisterMWEBRPCCommands(CRPCTable& t)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
