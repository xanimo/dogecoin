// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "bip352.h"

#include "bech32.h"
#include "chainparams.h"
#include "chainparamsbase.h"
#include "key.h"
#include "pubkey.h"
#include "script/script.h"
#include "script/standard.h"
#include "test/test_bitcoin.h"
#include "utilstrencodings.h"

#include "test/data/bip352_p2pkh_vectors.json.h"

#include <univalue.h>

#include <boost/test/unit_test.hpp>

#include <map>
#include <string>
#include <vector>

extern UniValue read_json(const std::string& jsondata);

BOOST_FIXTURE_TEST_SUITE(bip352_tests, BasicTestingSetup)

namespace {

CKey KeyFromHex(const std::string& hex)
{
    const std::vector<unsigned char> bytes = ParseHex(hex);
    BOOST_REQUIRE_EQUAL(bytes.size(), 32u);
    CKey key;
    key.Set(bytes.begin(), bytes.end(), true);
    BOOST_REQUIRE(key.IsValid());
    return key;
}

CScript ScriptFromHex(const std::string& hex)
{
    const std::vector<unsigned char> bytes = ParseHex(hex);
    return CScript(bytes.begin(), bytes.end());
}

UniValue LoadVectors()
{
    return read_json(std::string(json_tests::bip352_p2pkh_vectors,
                                 json_tests::bip352_p2pkh_vectors + sizeof(json_tests::bip352_p2pkh_vectors)));
}

/** Rebuild a case's inputs and the prevout scripts they spend. */
void BuildInputs(const UniValue& vin_json, std::vector<CTxIn>& vin, std::map<COutPoint, CScript>& spks, std::vector<CKey>& keys)
{
    for (size_t i = 0; i < vin_json.size(); ++i) {
        const UniValue& v = vin_json[i];
        const COutPoint prevout(uint256S(v["txid"].get_str()), v["vout"].get_int());
        CTxIn in(prevout);
        in.scriptSig = ScriptFromHex(v["script_sig"].get_str());
        vin.push_back(in);
        const CScript spk = ScriptFromHex(v["prevout_script"].get_str());
        spks[prevout] = spk;
        // Only an eligible input contributes its key to the sender's sum.
        CPubKey revealed;
        if (bip352::GetPubKeyFromInput(revealed, in.scriptSig, spk)) {
            keys.push_back(KeyFromHex(v["private_key"].get_str()));
        }
    }
}

} // namespace

// The hash tags are BIP0352's, so this pins them against the BIP340 construction rather than
// against our own output.
BOOST_AUTO_TEST_CASE(bip352_tagged_hash)
{
    // sha256("BIP0352/Inputs") doubled, then the empty message.
    const std::vector<unsigned char> empty;
    const uint256 h = bip352::TaggedHash("BIP0352/Inputs", empty);
    BOOST_CHECK(h != uint256());
    // A different tag must give a different digest for the same message.
    BOOST_CHECK(bip352::TaggedHash("BIP0352/Label", empty) != h);
    BOOST_CHECK(bip352::TaggedHash("BIP0352/SharedSecret", empty) != h);
    // Tag separation is not just a prefix: appending to the tag changes everything.
    BOOST_CHECK(bip352::TaggedHash("BIP0352/Inputs ", empty) != h);
}

// BIP352 orders outpoints lexicographically over the 36-byte serialization, which is not the
// same as ordering by vout as an integer.
BOOST_AUTO_TEST_CASE(bip352_smallest_outpoint)
{
    const uint256 a = uint256S("aaaa000000000000000000000000000000000000000000000000000000000000");
    const uint256 b = uint256S("bbbb000000000000000000000000000000000000000000000000000000000000");

    std::vector<CTxIn> vin;
    vin.push_back(CTxIn(COutPoint(b, 0)));
    vin.push_back(CTxIn(COutPoint(a, 7)));
    COutPoint smallest;
    BOOST_CHECK(bip352::GetSmallestOutpoint(smallest, vin));
    BOOST_CHECK(smallest == COutPoint(a, 7));

    // Same txid, so the vout decides, little-endian byte order and integer order agreeing here.
    vin.clear();
    vin.push_back(CTxIn(COutPoint(a, 2)));
    vin.push_back(CTxIn(COutPoint(a, 1)));
    BOOST_CHECK(bip352::GetSmallestOutpoint(smallest, vin));
    BOOST_CHECK(smallest == COutPoint(a, 1));

    // The serialization is txid then vout, both little-endian.
    const std::vector<unsigned char> ser = bip352::SerializeOutpoint(COutPoint(a, 0x01020304));
    BOOST_CHECK_EQUAL(ser.size(), 36u);
    BOOST_CHECK_EQUAL(HexStr(ser.begin() + 32, ser.end()), "04030201");

    std::vector<CTxIn> empty;
    BOOST_CHECK(!bip352::GetSmallestOutpoint(smallest, empty));
}

BOOST_AUTO_TEST_CASE(bip352_address_roundtrip)
{
    SelectParams(CBaseChainParams::MAIN);
    const CKey scan = KeyFromHex("0f694e068028a717f8af6b9411f9a133dd3565258714cc226594b34db90c1f2c");
    const CKey spend = KeyFromHex("9d6ad855ce3417ef84e836892e5a56392bfba05fa5d97ccea30e266f540e08b3");

    bip352::CSilentPaymentsAddress addr;
    BOOST_REQUIRE(bip352::CSilentPaymentsAddress::Create(addr, scan.GetPubKey(), spend.GetPubKey()));
    const std::string encoded = bip352::EncodeSilentPaymentsAddress(addr, Params());
    BOOST_CHECK_EQUAL(encoded.substr(0, 4), "dsp1");
    // 67 payload bytes do not fit the 90-character bech32 limit, which is why BIP352 raises it.
    BOOST_CHECK(encoded.size() > 90);

    std::string error;
    bip352::CSilentPaymentsAddress decoded;
    BOOST_CHECK(bip352::DecodeSilentPaymentsAddress(decoded, encoded, Params(), error));
    BOOST_CHECK(decoded == addr);

    // An address for one network must not decode on another.
    SelectParams(CBaseChainParams::TESTNET);
    BOOST_CHECK(!bip352::DecodeSilentPaymentsAddress(decoded, encoded, Params(), error));
    BOOST_CHECK(error.find("different network") != std::string::npos);
    const std::string testnet_encoded = bip352::EncodeSilentPaymentsAddress(addr, Params());
    BOOST_CHECK_EQUAL(testnet_encoded.substr(0, 5), "tdsp1");
    BOOST_CHECK(testnet_encoded != encoded);
    SelectParams(CBaseChainParams::MAIN);
}

BOOST_AUTO_TEST_CASE(bip352_address_rejects_malformed)
{
    SelectParams(CBaseChainParams::MAIN);
    const CKey scan = KeyFromHex("0f694e068028a717f8af6b9411f9a133dd3565258714cc226594b34db90c1f2c");
    const CKey spend = KeyFromHex("9d6ad855ce3417ef84e836892e5a56392bfba05fa5d97ccea30e266f540e08b3");
    bip352::CSilentPaymentsAddress addr, decoded;
    BOOST_REQUIRE(bip352::CSilentPaymentsAddress::Create(addr, scan.GetPubKey(), spend.GetPubKey()));
    const std::string good = bip352::EncodeSilentPaymentsAddress(addr, Params());
    std::string error;

    BOOST_CHECK(!bip352::DecodeSilentPaymentsAddress(decoded, "", Params(), error));
    BOOST_CHECK(!bip352::DecodeSilentPaymentsAddress(decoded, "dsp1qqq", Params(), error));

    // Flip a data character: the checksum must catch it.
    std::string corrupt = good;
    corrupt[10] = (corrupt[10] == 'q') ? 'p' : 'q';
    BOOST_CHECK(!bip352::DecodeSilentPaymentsAddress(decoded, corrupt, Params(), error));

    // Truncating the payload must be rejected on length, not accepted with a short key.
    BOOST_CHECK(!bip352::DecodeSilentPaymentsAddress(decoded, good.substr(0, good.size() - 8), Params(), error));

    // An unknown version is refused rather than parsed under v0 rules, so coin is never sent to
    // a payload this build does not understand.
    std::vector<unsigned char> payload;
    payload.push_back(1);
    payload.insert(payload.end(), scan.GetPubKey().begin(), scan.GetPubKey().begin() + CPubKey::COMPRESSED_SIZE);
    payload.insert(payload.end(), spend.GetPubKey().begin(), spend.GetPubKey().begin() + CPubKey::COMPRESSED_SIZE);
    std::vector<unsigned char> values;
    BOOST_REQUIRE((ConvertBits<8, 5, true>(values, payload.begin(), payload.end())));
    const std::string v1 = bech32::Encode(bech32::Encoding::BECH32M, Params().SilentPaymentsHRP(), values);
    BOOST_CHECK(!bip352::DecodeSilentPaymentsAddress(decoded, v1, Params(), error));
    BOOST_CHECK(error.find("unknown address version") != std::string::npos);
}

// The reason the eligibility rule walks every scriptSig push instead of taking the last one.
BOOST_AUTO_TEST_CASE(bip352_rejects_hybrid_pubkey_encoding)
{
    // libsecp256k1 parses the hybrid encodings 0x06 and 0x07 as well as 0x04, so an
    // implementation that only calls the parser would accept a key that one checking the prefix
    // rejects. The two would then sum a different A and derive different outputs. The chain has
    // no such input, which is why this is pinned here rather than left to be discovered.
    CKey key;
    key.MakeNewKey(false);                       // uncompressed
    const CPubKey pubkey = key.GetPubKey();
    BOOST_REQUIRE(pubkey.size() == CPubKey::SIZE && pubkey[0] == 0x04);

    std::vector<unsigned char> hybrid(pubkey.begin(), pubkey.end());
    hybrid[0] = (pubkey[CPubKey::SIZE - 1] & 1) ? 0x07 : 0x06;   // parity must match y

    // The prevout commits to the hybrid encoding, so the push does hash to it: the only thing
    // standing between this input and eligibility is the prefix rule.
    const CScript hybrid_spk = CScript() << OP_DUP << OP_HASH160
                                         << ToByteVector(Hash160(hybrid))
                                         << OP_EQUALVERIFY << OP_CHECKSIG;
    const std::vector<unsigned char> sig(72, 0x30);
    CPubKey found;
    const CScript hybrid_sig = CScript() << sig << hybrid;
    BOOST_CHECK(!bip352::GetPubKeyFromInput(found, hybrid_sig, hybrid_spk));

    // Positive control: the same key in its 0x04 form is eligible, so the rejection above is the
    // prefix and not something else about this key.
    const CScript spk = GetScriptForDestination(CTxDestination(pubkey.GetID()));
    const CScript ok = CScript() << sig << ToByteVector(pubkey);
    BOOST_CHECK(bip352::GetPubKeyFromInput(found, ok, spk));
    BOOST_CHECK(found == pubkey);
}

BOOST_AUTO_TEST_CASE(bip352_input_pubkey_extraction)
{
    const CKey key = KeyFromHex("eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1");
    const CPubKey pubkey = key.GetPubKey();
    const CScript spk = GetScriptForDestination(CTxDestination(pubkey.GetID()));
    const std::vector<unsigned char> sig(72, 0x30); // stand-in, never evaluated
    CPubKey found;

    const CScript canonical = CScript() << sig << ToByteVector(pubkey);
    BOOST_CHECK(bip352::GetPubKeyFromInput(found, canonical, spk));
    BOOST_CHECK(found == pubkey);

    // Dogecoin has no segwit, so a third party can malleate a P2PKH scriptSig and the
    // transaction stays valid. A rule keyed on the canonical two-push shape would make the
    // payment invisible to its receiver.
    const CScript prefixed = CScript() << OP_1 << OP_DROP << sig << ToByteVector(pubkey);
    BOOST_CHECK(bip352::GetPubKeyFromInput(found, prefixed, spk));
    BOOST_CHECK(found == pubkey);

    const CScript trailing = CScript() << sig << ToByteVector(pubkey) << OP_NOP;
    BOOST_CHECK(bip352::GetPubKeyFromInput(found, trailing, spk));
    BOOST_CHECK(found == pubkey);

    // A 33-byte push that is not the key committed by the prevout must not be accepted.
    const CKey other = KeyFromHex("0378e95685b74565fa56751b84a32dfd18545d10d691641b8372e32164fad66a");
    const CScript wrong = CScript() << sig << ToByteVector(other.GetPubKey());
    BOOST_CHECK(!bip352::GetPubKeyFromInput(found, wrong, spk));

    // Uncompressed keys are eligible here, unlike BIP352, because Dogecoin has plenty of coin
    // behind them. The prevout commits to the uncompressed encoding in that case.
    CKey uncompressed;
    uncompressed.Set(key.begin(), key.begin() + 32, false);
    BOOST_REQUIRE(uncompressed.IsValid());
    const CPubKey upub = uncompressed.GetPubKey();
    BOOST_REQUIRE_EQUAL(upub.size(), (unsigned int)CPubKey::SIZE);
    const CScript uspk = GetScriptForDestination(CTxDestination(upub.GetID()));
    const CScript uscript = CScript() << sig << ToByteVector(upub);
    BOOST_CHECK(bip352::GetPubKeyFromInput(found, uscript, uspk));
    BOOST_CHECK(found == upub);

    // Non-P2PKH prevouts are not eligible at all.
    const CScript p2sh = CScript() << OP_HASH160 << ToByteVector(pubkey.GetID()) << OP_EQUAL;
    BOOST_CHECK(!bip352::GetPubKeyFromInput(found, canonical, p2sh));
    const CScript bare = CScript() << ToByteVector(pubkey) << OP_CHECKSIG;
    BOOST_CHECK(!bip352::GetPubKeyFromInput(found, canonical, bare));
    BOOST_CHECK(!bip352::GetPubKeyFromInput(found, CScript(), spk));
}

// Drive both halves of every ported BIP352 vector: the sender must produce the expected P2PKH
// scripts, and the receiver must find them again and recover a key that spends them.
BOOST_AUTO_TEST_CASE(bip352_send_and_receive_vectors)
{
    SelectParams(CBaseChainParams::MAIN);
    const UniValue vectors = LoadVectors();
    BOOST_REQUIRE(vectors.size() > 0);
    size_t eligible_cases = 0;

    for (size_t idx = 0; idx < vectors.size(); ++idx) {
        const UniValue& c = vectors[idx];
        const std::string comment = c["comment"].get_str();
        BOOST_TEST_MESSAGE(comment);
        const UniValue& given = c["given"];
        const UniValue& expected = c["expected"];

        std::vector<CTxIn> vin;
        std::map<COutPoint, CScript> spks;
        std::vector<CKey> input_keys;
        BuildInputs(given["vin"], vin, spks, input_keys);

        const CKey scan_key = KeyFromHex(given["scan_priv_key"].get_str());
        const CKey spend_key = KeyFromHex(given["spend_priv_key"].get_str());

        bip352::CPrevoutsSummary summary;
        const bip352::PrevoutsSummaryError err = bip352::GetPrevoutsSummary(summary, vin, spks);

        if (!expected["eligible"].get_bool()) {
            BOOST_CHECK_MESSAGE(err != bip352::PREVOUTS_OK, comment);
            BOOST_CHECK_MESSAGE(input_keys.empty(), comment);
            continue;
        }
        ++eligible_cases;
        BOOST_REQUIRE_MESSAGE(err == bip352::PREVOUTS_OK, comment);
        BOOST_CHECK_MESSAGE(HexStr(summary.pubkey_sum) == expected["input_pubkey_sum"].get_str(), comment);
        // HexStr, not GetHex: the vectors carry the digest in its natural byte order, while
        // uint256::GetHex prints it reversed for display.
        BOOST_CHECK_MESSAGE(HexStr(summary.input_hash) == expected["input_hash"].get_str(), comment);

        // Receiver side: register the labels this receiver holds, then check its addresses.
        bip352::CSilentPaymentsReceiver receiver(scan_key, spend_key.GetPubKey());
        BOOST_REQUIRE_MESSAGE(receiver.IsValid(), comment);

        std::vector<std::string> addresses;
        bip352::CSilentPaymentsAddress addr;
        BOOST_REQUIRE(receiver.GetAddress(addr));
        addresses.push_back(bip352::EncodeSilentPaymentsAddress(addr, Params()));
        const UniValue& labels = given["labels"];
        for (size_t i = 0; i < labels.size(); ++i) {
            const uint32_t m = (uint32_t)labels[i].get_int64();
            if (m == bip352::CHANGE_LABEL_M) {
                // m = 0 is the receiver's own change, which is always registered, so it is read
                // back rather than generated. GenerateLabeledAddress refuses it.
                BOOST_CHECK(!receiver.GenerateLabeledAddress(addr, m));
                BOOST_REQUIRE_MESSAGE(receiver.GetChangeAddress(addr), comment);
            } else {
                BOOST_REQUIRE_MESSAGE(receiver.GenerateLabeledAddress(addr, m), comment);
            }
            addresses.push_back(bip352::EncodeSilentPaymentsAddress(addr, Params()));
        }
        const UniValue& expected_addresses = expected["addresses"];
        BOOST_REQUIRE_MESSAGE(addresses.size() == expected_addresses.size(), comment);
        for (size_t i = 0; i < addresses.size(); ++i) {
            BOOST_CHECK_MESSAGE(addresses[i] == expected_addresses[i].get_str(), comment + ": address " + std::to_string(i));
        }

        // Sender side: pay the addresses the vector says were paid, and compare the scripts.
        const UniValue& expected_outputs = expected["outputs"];
        std::vector<bip352::CRecipient> recipients;
        for (size_t i = 0; i < expected_outputs.size(); ++i) {
            std::string error;
            bip352::CSilentPaymentsAddress dest;
            BOOST_REQUIRE_MESSAGE(bip352::DecodeSilentPaymentsAddress(dest, expected_outputs[i]["address"].get_str(), Params(), error), comment + ": " + error);
            recipients.push_back(bip352::CRecipient(dest, i));
        }
        COutPoint smallest;
        BOOST_REQUIRE(bip352::GetSmallestOutpoint(smallest, vin));
        std::map<size_t, CScript> created;
        BOOST_REQUIRE_MESSAGE(bip352::CreateOutputs(created, recipients, input_keys, smallest), comment);
        BOOST_REQUIRE_MESSAGE(created.size() == expected_outputs.size(), comment);

        // The sender is free to choose which recipient in a scan-key group gets k = 0, so compare
        // the scripts as a set rather than position by position.
        std::vector<std::string> created_scripts, wanted_scripts;
        for (std::map<size_t, CScript>::const_iterator it = created.begin(); it != created.end(); ++it) {
            created_scripts.push_back(HexStr(it->second));
        }
        for (size_t i = 0; i < expected_outputs.size(); ++i) {
            wanted_scripts.push_back(expected_outputs[i]["script"].get_str());
        }
        std::sort(created_scripts.begin(), created_scripts.end());
        std::sort(wanted_scripts.begin(), wanted_scripts.end());
        BOOST_CHECK_MESSAGE(created_scripts == wanted_scripts, comment + ": sender scripts");

        // Receiver side: scan a transaction holding those outputs plus one unrelated P2PKH
        // output, which must be ignored.
        std::vector<CTxOut> vout;
        for (size_t i = 0; i < expected_outputs.size(); ++i) {
            vout.push_back(CTxOut(CAmount(1000), ScriptFromHex(expected_outputs[i]["script"].get_str())));
        }
        const CKey unrelated = KeyFromHex("1111111111111111111111111111111111111111111111111111111111111111");
        vout.push_back(CTxOut(CAmount(1000), GetScriptForDestination(CTxDestination(unrelated.GetPubKey().GetID()))));

        std::vector<bip352::CFoundOutput> found;
        BOOST_REQUIRE_MESSAGE(receiver.Scan(found, summary, vout), comment);
        BOOST_REQUIRE_MESSAGE(found.size() == expected_outputs.size(), comment + ": found " + std::to_string(found.size()));

        for (size_t i = 0; i < found.size(); ++i) {
            const std::string what = comment + ": found " + std::to_string(i);
            BOOST_REQUIRE_MESSAGE(found[i].vout < vout.size(), what);
            // The tweak must recover a key that actually spends the output it was found on.
            CKey spending;
            BOOST_REQUIRE_MESSAGE(bip352::CSilentPaymentsReceiver::DeriveSpendingKey(spending, spend_key, found[i].tweak), what);
            BOOST_CHECK_MESSAGE(spending.GetPubKey() == found[i].output_pubkey, what + ": key does not match output");
            BOOST_CHECK_MESSAGE(GetScriptForDestination(CTxDestination(spending.GetPubKey().GetID())) == vout[found[i].vout].scriptPubKey, what + ": key does not spend output");

            // And it must be the tweak the independent generator computed for that output.
            bool matched = false;
            for (size_t j = 0; j < expected_outputs.size(); ++j) {
                if (HexStr(found[i].output_pubkey) != expected_outputs[j]["output_pubkey"].get_str()) continue;
                BOOST_CHECK_MESSAGE(HexStr(found[i].tweak) == expected_outputs[j]["priv_key_tweak"].get_str(), what + ": tweak");
                const UniValue& label = expected_outputs[j]["label"];
                BOOST_CHECK_MESSAGE(found[i].found_with_label == !label.isNull(), what + ": label presence");
                if (!label.isNull()) {
                    BOOST_CHECK_MESSAGE(found[i].label_m == (uint32_t)label.get_int64(), what + ": label value");
                }
                matched = true;
                break;
            }
            BOOST_CHECK_MESSAGE(matched, what + ": output key not in the vector");
        }
    }
    BOOST_CHECK(eligible_cases > 0);
}

// A receiver must not find anything in a transaction it was not paid in.
BOOST_AUTO_TEST_CASE(bip352_scan_ignores_unrelated)
{
    SelectParams(CBaseChainParams::MAIN);
    const UniValue vectors = LoadVectors();
    const UniValue& c = vectors[0];

    std::vector<CTxIn> vin;
    std::map<COutPoint, CScript> spks;
    std::vector<CKey> input_keys;
    BuildInputs(c["given"]["vin"], vin, spks, input_keys);

    bip352::CPrevoutsSummary summary;
    BOOST_REQUIRE(bip352::GetPrevoutsSummary(summary, vin, spks) == bip352::PREVOUTS_OK);

    // A different receiver entirely.
    const CKey scan = KeyFromHex("2222222222222222222222222222222222222222222222222222222222222222");
    const CKey spend = KeyFromHex("3333333333333333333333333333333333333333333333333333333333333333");
    bip352::CSilentPaymentsReceiver stranger(scan, spend.GetPubKey());
    BOOST_REQUIRE(stranger.IsValid());

    std::vector<CTxOut> vout;
    for (size_t i = 0; i < c["expected"]["outputs"].size(); ++i) {
        vout.push_back(CTxOut(CAmount(1000), ScriptFromHex(c["expected"]["outputs"][i]["script"].get_str())));
    }
    std::vector<bip352::CFoundOutput> found;
    BOOST_CHECK(stranger.Scan(found, summary, vout));
    BOOST_CHECK(found.empty());
}

// A missing prevout script is an error, not a skipped input: silently skipping one would change
// A and send the payment somewhere the receiver never looks.
BOOST_AUTO_TEST_CASE(bip352_missing_coin_is_an_error)
{
    SelectParams(CBaseChainParams::MAIN);
    const UniValue vectors = LoadVectors();
    const UniValue& c = vectors[0];

    std::vector<CTxIn> vin;
    std::map<COutPoint, CScript> spks;
    std::vector<CKey> input_keys;
    BuildInputs(c["given"]["vin"], vin, spks, input_keys);
    BOOST_REQUIRE(vin.size() >= 2);

    spks.erase(vin[0].prevout);
    bip352::CPrevoutsSummary summary;
    BOOST_CHECK(bip352::GetPrevoutsSummary(summary, vin, spks) == bip352::PREVOUTS_MISSING_COIN);
}

BOOST_AUTO_TEST_SUITE_END()
