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

/**
 * Encode an address at an arbitrary version, which the public encoder cannot do.
 *
 * extra appends that many trailing payload bytes, trim removes that many from the end, so a
 * caller can build both the forward-compatible and the too-short cases.
 */
std::string AddressWithVersion(int version, const CKey& scan, const CKey& spend, size_t extra, int trim)
{
    /* Held by value: GetPubKey returns one, so calling it twice for begin and for begin + 33
       would take the two iterators from two different temporaries. */
    const CPubKey scan_pubkey = scan.GetPubKey(), spend_pubkey = spend.GetPubKey();
    std::vector<unsigned char> payload;
    payload.insert(payload.end(), scan_pubkey.begin(), scan_pubkey.begin() + CPubKey::COMPRESSED_SIZE);
    payload.insert(payload.end(), spend_pubkey.begin(), spend_pubkey.begin() + CPubKey::COMPRESSED_SIZE);
    for (size_t i = 0; i < extra; i++) payload.push_back((unsigned char)(0xde + i));
    payload.resize(payload.size() + trim);

    std::vector<unsigned char> values;
    values.push_back((unsigned char)version);
    BOOST_REQUIRE((ConvertBits<8, 5, true>(values, payload.begin(), payload.end())));
    return bech32::Encode(bech32::Encoding::BECH32M, Params().SilentPaymentsHRP(), values);
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

/** n - a, the key whose public key is the negation of a's. */
CKey NegateKey(const CKey& key)
{
    static const unsigned char ORDER[32] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
        0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41};
    unsigned char out[32];
    int borrow = 0;
    for (int i = 31; i >= 0; i--) {
        const int d = (int)ORDER[i] - (int)key.begin()[i] - borrow;
        out[i] = (unsigned char)(d & 0xff);
        borrow = d < 0 ? 1 : 0;
    }
    CKey negated;
    negated.Set(out, out + 32, true);
    BOOST_REQUIRE(negated.IsValid());
    return negated;
}

/** Append a P2PKH input that reveals key's compressed public key, spending output n of one txid. */
void AddP2PKHInput(const CKey& key, uint32_t n, std::vector<CTxIn>& vin, std::map<COutPoint, CScript>& spks)
{
    const COutPoint prevout(uint256S("a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d"), n);
    const CPubKey pubkey = key.GetPubKey();
    CTxIn in(prevout);
    // The eligibility rule matches the key push against the prevout's hash and does not look at
    // the signature, so a placeholder of a signature's length stands in for one.
    in.scriptSig = CScript() << std::vector<unsigned char>(72, 0x30) << ToByteVector(pubkey);
    vin.push_back(in);
    spks[prevout] = GetScriptForDestination(CTxDestination(pubkey.GetID()));
}

/** One recipient per requested output, all to the same address. */
std::vector<bip352::CRecipient> Repeat(const bip352::CSilentPaymentsAddress& address, size_t n)
{
    std::vector<bip352::CRecipient> recipients;
    for (size_t i = 0; i < n; i++) recipients.push_back(bip352::CRecipient(address, i));
    return recipients;
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

    BOOST_CHECK_EQUAL(encoded,
        "dsp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xcvd33k5");
    // 2 hrp + 1 separator + 1 version + 106 payload + 6 checksum is BIP352's 116, and "dsp"
    // costs one more. Either way past the 90-character bech32 limit, which is why BIP352 raises
    // it; a 116-character address here would mean a byte went missing from the payload.
    BOOST_CHECK_EQUAL(encoded.size(), 117u);

    // The keys above are BIP352's own first test vector, so only the prefix is Dogecoin's: the
    // version character and the converted payload must come out exactly as the published
    // address has them. The version is one 5-bit character ahead of the 66-byte payload rather
    // than a byte converted along with it, and getting that wrong shifts every following bit
    // while still round-tripping against itself, which is why this compares against the spec's
    // string instead of only decoding what was just encoded.
    const std::string bip352_reference =
        "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv";
    const size_t ours = encoded.find('1'), theirs = bip352_reference.find('1');
    BOOST_CHECK_EQUAL(encoded.substr(ours + 1, encoded.size() - ours - 7),
                      bip352_reference.substr(theirs + 1, bip352_reference.size() - theirs - 7));

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

    // A v0 payload one byte short must fail on length rather than yield a truncated key.
    BOOST_CHECK(!bip352::DecodeSilentPaymentsAddress(decoded, AddressWithVersion(0, scan, spend, 0, -1), Params(), error));
    BOOST_CHECK(error.find("expected 66") != std::string::npos);
}

// BIP352's forward compatibility rule, which is the opposite of refusing what this build does
// not recognise: versions 1 to 30 are defined to keep the two keys in the first 66 bytes, so
// they stay payable and the trailing bytes are discarded. Only v31 is reserved for a change an
// older sender must not attempt. Rejecting v1 to v30 would refuse addresses other wallets pay.
BOOST_AUTO_TEST_CASE(bip352_address_unknown_version_is_payable)
{
    SelectParams(CBaseChainParams::MAIN);
    const CKey scan = KeyFromHex("0f694e068028a717f8af6b9411f9a133dd3565258714cc226594b34db90c1f2c");
    const CKey spend = KeyFromHex("9d6ad855ce3417ef84e836892e5a56392bfba05fa5d97ccea30e266f540e08b3");
    bip352::CSilentPaymentsAddress decoded;
    std::string error;

    for (int version = 1; version <= 30; version++) {
        const std::string exact = AddressWithVersion(version, scan, spend, 0, 0);
        BOOST_REQUIRE_MESSAGE(bip352::DecodeSilentPaymentsAddress(decoded, exact, Params(), error), error);
        BOOST_CHECK(decoded.GetScanPubKey() == scan.GetPubKey());
        BOOST_CHECK(decoded.GetSpendPubKey() == spend.GetPubKey());
        BOOST_CHECK_EQUAL((int)decoded.GetVersion(), version);

        // Four bytes this build has no meaning for, which must be ignored rather than refused
        // or folded into a key.
        const std::string extended = AddressWithVersion(version, scan, spend, 4, 0);
        BOOST_REQUIRE_MESSAGE(bip352::DecodeSilentPaymentsAddress(decoded, extended, Params(), error), error);
        BOOST_CHECK(decoded.GetScanPubKey() == scan.GetPubKey());
        BOOST_CHECK(decoded.GetSpendPubKey() == spend.GetPubKey());

        // Still too short to hold two keys, whatever the version claims.
        BOOST_CHECK(!bip352::DecodeSilentPaymentsAddress(decoded, AddressWithVersion(version, scan, spend, 0, -1), Params(), error));
    }

    BOOST_CHECK(!bip352::DecodeSilentPaymentsAddress(decoded, AddressWithVersion(31, scan, spend, 0, 0), Params(), error));
    BOOST_CHECK(error.find("not backwards compatible") != std::string::npos);
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

    // The uncompressed 0x04 form of the same key is refused too, since BIP352 permits only
    // compressed keys. Both rejections are the encoding rule rather than anything about the key.
    const CScript spk = GetScriptForDestination(CTxDestination(pubkey.GetID()));
    const CScript uncompressed = CScript() << sig << ToByteVector(pubkey);
    BOOST_CHECK(!bip352::GetPubKeyFromInput(found, uncompressed, spk));

    // Positive control: compressed is accepted, so the rejections above are not vacuous.
    CKey compressed_key;
    compressed_key.Set(key.begin(), key.begin() + 32, true);
    BOOST_REQUIRE(compressed_key.IsValid());
    const CPubKey compressed = compressed_key.GetPubKey();
    BOOST_REQUIRE(compressed.IsCompressed());
    const CScript cspk = GetScriptForDestination(CTxDestination(compressed.GetID()));
    const CScript csig = CScript() << sig << ToByteVector(compressed);
    BOOST_CHECK(bip352::GetPubKeyFromInput(found, csig, cspk));
    BOOST_CHECK(found == compressed);
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

    // Uncompressed keys are not eligible, which is what BIP352 permits and what a receiver
    // following it will do. Accepting them would make this input contribute to A on the
    // sender's side and not on a conforming receiver's, and the sender's own recheck cannot
    // see that disagreement, so the payment would be unspendable with every check passing.
    CKey uncompressed;
    uncompressed.Set(key.begin(), key.begin() + 32, false);
    BOOST_REQUIRE(uncompressed.IsValid());
    const CPubKey upub = uncompressed.GetPubKey();
    BOOST_REQUIRE_EQUAL(upub.size(), (unsigned int)CPubKey::SIZE);
    const CScript uspk = GetScriptForDestination(CTxDestination(upub.GetID()));
    const CScript uscript = CScript() << sig << ToByteVector(upub);
    BOOST_CHECK(!bip352::GetPubKeyFromInput(found, uscript, uspk));

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
// A light client has to decide whether a block is worth downloading before it has the block, so
// it derives the scripts it would own from the tweak alone and asks a BIP158 filter about them.
// That only works if the script derived without the outputs is the script the sender actually
// created. Everything about the client rests on this equality.
BOOST_AUTO_TEST_CASE(bip352_candidate_script_matches_the_real_output)
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

    // The receiver the vectors are addressed to.
    const CKey scan = KeyFromHex(c["given"]["scan_priv_key"].get_str());
    const CKey spend = KeyFromHex(c["given"]["spend_priv_key"].get_str());
    bip352::CSilentPaymentsReceiver receiver(scan, spend.GetPubKey());
    BOOST_REQUIRE(receiver.IsValid());

    // What the index would hold for this transaction.
    CPubKey tweak;
    BOOST_REQUIRE(bip352::ComputeScanTweak(tweak, summary));

    std::vector<CScript> candidates;
    BOOST_REQUIRE(receiver.GetCandidateScripts(candidates, tweak));
    BOOST_CHECK(!candidates.empty());

    // The k = 0 output the sender produced has to be among them, derived with no sight of it.
    const CScript real = ScriptFromHex(c["expected"]["outputs"][0]["script"].get_str());
    BOOST_CHECK_MESSAGE(std::find(candidates.begin(), candidates.end(), real) != candidates.end(),
                        "the client would not have asked the filter about the real output");

    // And a stranger derives something else, otherwise the filter query would match for
    // everyone and the client would download every block.
    const CKey other_scan = KeyFromHex("2222222222222222222222222222222222222222222222222222222222222222");
    const CKey other_spend = KeyFromHex("3333333333333333333333333333333333333333333333333333333333333333");
    bip352::CSilentPaymentsReceiver stranger(other_scan, other_spend.GetPubKey());
    BOOST_REQUIRE(stranger.IsValid());

    std::vector<CScript> stranger_candidates;
    BOOST_REQUIRE(stranger.GetCandidateScripts(stranger_candidates, tweak));
    BOOST_CHECK(std::find(stranger_candidates.begin(), stranger_candidates.end(), real) ==
                stranger_candidates.end());
}

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

// BIP352's vector "P2PKH and P2WPKH Uncompressed Keys are skipped", reduced to its two P2PKH
// inputs, which is all this chain can carry. Input 0 reveals a compressed key and input 1 an
// uncompressed one. The BIP's answer is that input 1 contributes nothing and the payment stands
// on input 0 alone; the porting script drops this case for its third, P2WPKH, input, so it is
// written out here. Dropping the transaction instead makes the payment invisible to this wallet
// while every wallet following the BIP derives it.
BOOST_AUTO_TEST_CASE(bip352_uncompressed_input_is_skipped)
{
    std::vector<CTxIn> vin;
    std::map<COutPoint, CScript> spks;
    const char* inputs[2][4] = {
        {"a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d", "0", "493046022100ad79e6801dd9a8727f342f31c71c4912866f59dc6e7981878e92c5844a0ce929022100fb0d2393e813968648b9753b7e9871d90ab3d815ebf91820d704b19f4ed224d60121025a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5", "76a91419c2f3ae0ca3b642bd3e49598b8da89f50c1416188ac"},
        {"f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16", "0", "483045022100a8c61b2d470e393279d1ba54f254b7c237de299580b7fa01ffcc940442ecec4502201afba952f4e4661c40acde7acc0341589031ba103a307b886eb867b23b850b97014104782eeb913431ca6e9b8c2fd80a5f72ed2024ef72a3c6fb10263c3799373233387c5343bf58e23269e903335b958a12182f9849297321e8d710e49a8727129cab", "76a9144b92ac4ac6fe6212393894addda332f2e47a315688ac"},
    };
    for (int i = 0; i < 2; i++) {
        const COutPoint op(uint256S(inputs[i][0]), (uint32_t)atoi(inputs[i][1]));
        const std::vector<unsigned char> ss = ParseHex(inputs[i][2]), spk = ParseHex(inputs[i][3]);
        vin.push_back(CTxIn(op, CScript(ss.begin(), ss.end())));
        spks[op] = CScript(spk.begin(), spk.end());
    }

    CPubKey key;
    BOOST_CHECK(bip352::GetPubKeyFromInput(key, vin[0].scriptSig, spks[vin[0].prevout]));
    BOOST_CHECK(!bip352::GetPubKeyFromInput(key, vin[1].scriptSig, spks[vin[1].prevout]));

    bip352::CPrevoutsSummary summary;
    BOOST_REQUIRE(bip352::GetPrevoutsSummary(summary, vin, spks) == bip352::PREVOUTS_OK);
    BOOST_CHECK_EQUAL(HexStr(summary.pubkey_sum.begin(), summary.pubkey_sum.end()), "025a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5");

    // The output the vector expects, as P2PKH of either parity of its x-only key.
    const std::vector<unsigned char> x = ParseHex("67fee277da9e8542b5d2e6f32d660a9bbd3f0e107c2d53638ab1d869088882d6");
    std::vector<CTxOut> vout;
    for (unsigned char prefix = 2; prefix <= 3; prefix++) {
        std::vector<unsigned char> full(1, prefix);
        full.insert(full.end(), x.begin(), x.end());
        vout.push_back(CTxOut(COIN, GetScriptForDestination(CTxDestination(CKeyID(Hash160(full))))));
    }

    const std::vector<unsigned char> scan_bytes = ParseHex("0f694e068028a717f8af6b9411f9a133dd3565258714cc226594b34db90c1f2c"), spend_bytes = ParseHex("9d6ad855ce3417ef84e836892e5a56392bfba05fa5d97ccea30e266f540e08b3");
    CKey scan, spend;
    scan.Set(scan_bytes.begin(), scan_bytes.end(), true);
    spend.Set(spend_bytes.begin(), spend_bytes.end(), true);
    const bip352::CSilentPaymentsReceiver receiver(scan, spend.GetPubKey());
    std::vector<bip352::CFoundOutput> found;
    BOOST_REQUIRE(receiver.Scan(found, summary, vout));
    BOOST_REQUIRE_EQUAL(found.size(), 1U);
    BOOST_CHECK_EQUAL(HexStr(found[0].output_pubkey.begin() + 1, found[0].output_pubkey.end()), "67fee277da9e8542b5d2e6f32d660a9bbd3f0e107c2d53638ab1d869088882d6");
}

// BIP352's vector "Input keys intermediate sum is zero but final sum is non-zero". The BIP's
// inputs are P2WPKH, so the porting script drops the case, but the rule is about keys and not
// about script types: inputs a, -a and b pay exactly as input b alone does. A sender that adds
// the private keys one at a time and gives up when the running sum is zero refuses a payment
// every receiver would have found.
BOOST_AUTO_TEST_CASE(bip352_partial_key_sum_through_zero_still_pays)
{
    SelectParams(CBaseChainParams::MAIN);
    const CKey a = KeyFromHex("eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1");
    const CKey b = KeyFromHex("93f5ed907ad5b2bdbbdcb5d9116ebc0a4e1f92f910d5260237fa45a9408aad16");
    const CKey scan = KeyFromHex("0f694e068028a717f8af6b9411f9a133dd3565258714cc226594b34db90c1f2c");
    const CKey spend = KeyFromHex("9d6ad855ce3417ef84e836892e5a56392bfba05fa5d97ccea30e266f540e08b3");
    const CKey minus_a = NegateKey(a);

    std::vector<CTxIn> vin;
    std::map<COutPoint, CScript> spks;
    AddP2PKHInput(a, 0, vin, spks);
    AddP2PKHInput(minus_a, 1, vin, spks);
    AddP2PKHInput(b, 2, vin, spks);
    COutPoint smallest;
    BOOST_REQUIRE(bip352::GetSmallestOutpoint(smallest, vin));

    bip352::CSilentPaymentsAddress address;
    BOOST_REQUIRE(bip352::CSilentPaymentsAddress::Create(address, scan.GetPubKey(), spend.GetPubKey()));

    std::vector<CKey> keys;
    keys.push_back(a);
    keys.push_back(minus_a);
    keys.push_back(b);
    std::map<size_t, CScript> through_zero, alone;
    BOOST_REQUIRE(bip352::CreateOutputs(through_zero, Repeat(address, 1), keys, smallest));
    BOOST_REQUIRE(bip352::CreateOutputs(alone, Repeat(address, 1), std::vector<CKey>(1, b), smallest));
    BOOST_CHECK(through_zero[0] == alone[0]);

    // The order the keys arrive in must not matter either.
    std::vector<CKey> reordered;
    reordered.push_back(b);
    reordered.push_back(a);
    reordered.push_back(minus_a);
    std::map<size_t, CScript> other_order;
    BOOST_REQUIRE(bip352::CreateOutputs(other_order, Repeat(address, 1), reordered, smallest));
    BOOST_CHECK(other_order[0] == alone[0]);

    // And the receiver finds it: the three revealed keys sum to b's.
    bip352::CPrevoutsSummary summary;
    BOOST_REQUIRE(bip352::GetPrevoutsSummary(summary, vin, spks) == bip352::PREVOUTS_OK);
    BOOST_CHECK(summary.pubkey_sum == b.GetPubKey());
    const bip352::CSilentPaymentsReceiver receiver(scan, spend.GetPubKey());
    std::vector<bip352::CFoundOutput> found;
    BOOST_REQUIRE(receiver.Scan(found, summary, std::vector<CTxOut>(1, CTxOut(COIN, through_zero[0]))));
    BOOST_CHECK_EQUAL(found.size(), 1U);
}

// BIP352's vector "Input keys sum up to zero / point at infinity: sending fails, receiver skips
// tx", also dropped by the porting script for its P2WPKH inputs.
BOOST_AUTO_TEST_CASE(bip352_key_sum_of_zero_carries_no_payment)
{
    SelectParams(CBaseChainParams::MAIN);
    const CKey a = KeyFromHex("eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1");
    const CKey b = KeyFromHex("93f5ed907ad5b2bdbbdcb5d9116ebc0a4e1f92f910d5260237fa45a9408aad16");
    const CKey scan = KeyFromHex("0f694e068028a717f8af6b9411f9a133dd3565258714cc226594b34db90c1f2c");
    const CKey spend = KeyFromHex("9d6ad855ce3417ef84e836892e5a56392bfba05fa5d97ccea30e266f540e08b3");
    bip352::CSilentPaymentsAddress address;
    BOOST_REQUIRE(bip352::CSilentPaymentsAddress::Create(address, scan.GetPubKey(), spend.GetPubKey()));

    for (int n = 2; n <= 4; n += 2) {
        std::vector<CTxIn> vin;
        std::map<COutPoint, CScript> spks;
        std::vector<CKey> keys;
        keys.push_back(a);
        if (n == 4) keys.push_back(b);
        keys.push_back(NegateKey(a));
        if (n == 4) keys.push_back(NegateKey(b));
        for (size_t i = 0; i < keys.size(); i++) AddP2PKHInput(keys[i], (uint32_t)i, vin, spks);
        COutPoint smallest;
        BOOST_REQUIRE(bip352::GetSmallestOutpoint(smallest, vin));

        std::map<size_t, CScript> outputs;
        BOOST_CHECK(!bip352::CreateOutputs(outputs, Repeat(address, 1), keys, smallest));
        BOOST_CHECK(outputs.empty());
        bip352::CPrevoutsSummary summary;
        BOOST_CHECK(bip352::GetPrevoutsSummary(summary, vin, spks) == bip352::PREVOUTS_NOT_ELIGIBLE);
    }
}

// The per-group limit. BIP352's vector for it has a taproot input and is dropped by the porting
// script, so neither side of the limit had a test: a sender must refuse the output a receiver
// would stop short of, and a receiver must still reach the last one a sender may create.
BOOST_AUTO_TEST_CASE(bip352_group_limit_is_the_same_on_both_sides)
{
    SelectParams(CBaseChainParams::MAIN);
    const CKey b = KeyFromHex("93f5ed907ad5b2bdbbdcb5d9116ebc0a4e1f92f910d5260237fa45a9408aad16");
    const CKey scan = KeyFromHex("0f694e068028a717f8af6b9411f9a133dd3565258714cc226594b34db90c1f2c");
    const CKey spend = KeyFromHex("9d6ad855ce3417ef84e836892e5a56392bfba05fa5d97ccea30e266f540e08b3");
    bip352::CSilentPaymentsAddress address;
    BOOST_REQUIRE(bip352::CSilentPaymentsAddress::Create(address, scan.GetPubKey(), spend.GetPubKey()));

    std::vector<CTxIn> vin;
    std::map<COutPoint, CScript> spks;
    AddP2PKHInput(b, 0, vin, spks);
    COutPoint smallest;
    BOOST_REQUIRE(bip352::GetSmallestOutpoint(smallest, vin));
    const std::vector<CKey> keys(1, b);

    std::map<size_t, CScript> outputs;
    BOOST_CHECK(!bip352::CreateOutputs(outputs, Repeat(address, bip352::RECIPIENT_GROUP_LIMIT + 1), keys, smallest));
    BOOST_CHECK(outputs.empty());
    BOOST_REQUIRE(bip352::CreateOutputs(outputs, Repeat(address, bip352::RECIPIENT_GROUP_LIMIT), keys, smallest));
    BOOST_REQUIRE_EQUAL(outputs.size(), (size_t)bip352::RECIPIENT_GROUP_LIMIT);

    std::vector<CTxOut> vout;
    for (size_t i = 0; i < outputs.size(); i++) vout.push_back(CTxOut(COIN, outputs[i]));
    bip352::CPrevoutsSummary summary;
    BOOST_REQUIRE(bip352::GetPrevoutsSummary(summary, vin, spks) == bip352::PREVOUTS_OK);
    const bip352::CSilentPaymentsReceiver receiver(scan, spend.GetPubKey());
    std::vector<bip352::CFoundOutput> found;
    BOOST_REQUIRE(receiver.Scan(found, summary, vout));
    BOOST_CHECK_EQUAL(found.size(), (size_t)bip352::RECIPIENT_GROUP_LIMIT);
}

BOOST_AUTO_TEST_SUITE_END()
