// Copyright (c) 2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "script/sign.h"
#include "utilstrencodings.h"
#include "wallet/rpcwallet.h"
#include "wallet/wallet.h"
#include <univalue.h>

#include <boost/test/unit_test.hpp>
#include "test/test_bitcoin.h"
#include "wallet/test/wallet_test_fixture.h"

BOOST_FIXTURE_TEST_SUITE(psbt_wallet_tests, WalletTestingSetup)

BOOST_AUTO_TEST_CASE(psbt_updater_test)
{
    // Create prevtxs and add to wallet
    CDataStream s_prev_tx1(ParseHex("0200000000010158e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd7501000000171600145f275f436b09a8cc9a2eb2a2f528485c68a56323feffffff02d8231f1b0100000017a914aed962d6654f9a2b36608eb9d64d2b260db4f1118700c2eb0b0000000017a914b7f5faf40e3d40a5a459b1db3535f2b72fa921e88702483045022100a22edcc6e5bc511af4cc4ae0de0fcd75c7e04d8c1c3a8aa9d820ed4b967384ec02200642963597b9b1bc22c75e9f3e117284a962188bf5e8a74c895089046a20ad770121035509a48eb623e10aace8bfd0212fdb8a8e5af3c94b0b133b95e114cab89e4f7965000000"), SER_NETWORK, PROTOCOL_VERSION);
    CTransactionRef prev_tx1;
    s_prev_tx1 >> prev_tx1;
    CWalletTx prev_wtx1(pwalletMain, prev_tx1);
    pwalletMain->mapWallet.emplace(prev_wtx1.GetHash(), std::move(prev_wtx1));

    CDataStream s_prev_tx2(ParseHex("0200000001aad73931018bd25f84ae400b68848be09db706eac2ac18298babee71ab656f8b0000000048473044022058f6fc7c6a33e1b31548d481c826c015bd30135aad42cd67790dab66d2ad243b02204a1ced2604c6735b6393e5b41691dd78b00f0c5942fb9f751856faa938157dba01feffffff0280f0fa020000000017a9140fb9463421696b82c833af241c78c17ddbde493487d0f20a270100000017a91429ca74f8a08f81999428185c97b5d852e4063f618765000000"), SER_NETWORK, PROTOCOL_VERSION);
    CTransactionRef prev_tx2;
    s_prev_tx2 >> prev_tx2;
    CWalletTx prev_wtx2(pwalletMain, prev_tx2);
    pwalletMain->mapWallet.emplace(prev_wtx2.GetHash(), std::move(prev_wtx2));

    // Add scripts
    CScript rs1;
    CDataStream s_rs1(ParseHex("475221029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f2102dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d752ae"), SER_NETWORK, PROTOCOL_VERSION);
    s_rs1 >> rs1;
    pwalletMain->AddCScript(rs1);

    CScript rs2;
    CDataStream s_rs2(ParseHex("2200208c2353173743b595dfb4a07b72ba8e42e3797da74e87fe7d9d7497e3b2028903"), SER_NETWORK, PROTOCOL_VERSION);
    s_rs2 >> rs2;
    pwalletMain->AddCScript(rs2);

    CScript ws1;
    CDataStream s_ws1(ParseHex("47522103089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc21023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e7352ae"), SER_NETWORK, PROTOCOL_VERSION);
    s_ws1 >> ws1;
    pwalletMain->AddCScript(ws1);

    // Set HD master key using the BIP174 test vector private key
    // (raw bytes of WIF cUkG8i1RFfWGWy5ziR11zJ5V4U4W3viSFCfyJmZnvQaUsd1xuF3T).
    // Uses v0.14 API: manually set metadata + AddKeyPubKey + SetHDMasterKey,
    // replacing v0.17's DeriveNewSeed(key) + SetHDSeed(pubkey).
    {
        LOCK(pwalletMain->cs_wallet);
        std::vector<unsigned char> privKeyBytes = ParseHex("d5c7a415bc76dcff7cd59299596ab1b569ac6ad84d872cd376c905878eec1384");
        CKey masterKey;
        masterKey.Set(privKeyBytes.begin(), privKeyBytes.end(), true);
        CPubKey masterPubKey = masterKey.GetPubKey();
        BOOST_CHECK(masterKey.VerifyPubKey(masterPubKey));

        int64_t nCreationTime = GetTime();
        CKeyMetadata masterMetadata(nCreationTime);
        masterMetadata.hdKeypath = "m";
        masterMetadata.hdMasterKeyID = masterPubKey.GetID();
        pwalletMain->mapKeyMetadata[masterPubKey.GetID()] = masterMetadata;
        BOOST_CHECK(pwalletMain->AddKeyPubKey(masterKey, masterPubKey));
        BOOST_CHECK(pwalletMain->SetHDMasterKey(masterPubKey));
    }
    pwalletMain->NewKeyPool();

    // Call FillPSBT
    PartiallySignedTransaction psbtx;
    CDataStream ssData(ParseHex("70736274ff01009a020000000258e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd750000000000ffffffff838d0427d0ec650a68aa46bb0b098aea4422c071b2ca78352a077959d07cea1d0100000000ffffffff0270aaf00800000000160014d85c2b71d0060b09c9886aeb815e50991dda124d00e1f5050000000016001400aea9a2e5f0f876a588df5546e8742d1d87008f000000000000000000"), SER_NETWORK, PROTOCOL_VERSION);
    ssData >> psbtx;

    // Use CTransaction for the constant parts of the transaction to avoid rehashing.
    const CTransaction txConst(*psbtx.tx);

    // Fill transaction with our data
    FillPSBT(pwalletMain, psbtx, &txConst, 1, false, true);

    // Get the final tx
    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
    ssTx << psbtx;
    std::string final_hex = HexStr(ssTx.begin(), ssTx.end());
    // The Dogecoin expected hex differs from Bitcoin Core's because Dogecoin
    // uses the m/0'/3'/n' BIP44 derivation path (coin type 3) rather than
    // Bitcoin's m/0'/0'/n'.  The BIP174 test-vector pubkeys in the scripts
    // above were derived at Bitcoin's m/0'/0'/0' and m/0'/0'/1', so they do
    // not appear in Dogecoin's key pool; FillPSBT therefore omits BIP32
    // keypath entries entirely and only populates the UTXOs and redeemscripts.
    BOOST_CHECK_EQUAL(final_hex,
        "70736274ff01009a020000000258e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd750000000000ffffffff838d0427d0ec650a68aa46bb0b098aea4422c071b2ca78352a077959d07cea1d0100000000ffffffff0270aaf00800000000160014d85c2b71d0060b09c9886aeb815e50991dda124d00e1f5050000000016001400aea9a2e5f0f876a588df5546e8742d1d87008f00000000000100bb0200000001aad73931018bd25f84ae400b68848be09db706eac2ac18298babee71ab656f8b0000000048473044022058f6fc7c6a33e1b31548d481c826c015bd30135aad42cd67790dab66d2ad243b02204a1ced2604c6735b6393e5b41691dd78b00f0c5942fb9f751856faa938157dba01feffffff0280f0fa020000000017a9140fb9463421696b82c833af241c78c17ddbde493487d0f20a270100000017a91429ca74f8a08f81999428185c97b5d852e4063f6187650000000104475221029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f2102dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d752ae0001012000c2eb0b0000000017a914b7f5faf40e3d40a5a459b1db3535f2b72fa921e88701042200208c2353173743b595dfb4a07b72ba8e42e3797da74e87fe7d9d7497e3b2028903010547522103089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc21023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e7352ae000000");
}

BOOST_AUTO_TEST_SUITE_END()
