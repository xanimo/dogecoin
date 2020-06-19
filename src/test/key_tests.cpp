// Copyright (c) 2012-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "key.h"

#include "base58.h"
#include "script/script.h"
#include "uint256.h"
#include "util.h"
#include "utilstrencodings.h"
#include "test/test_bitcoin.h"

#include <string>
#include <vector>

#include <boost/test/unit_test.hpp>

static const std::string strSecret1 = "6JFPe8b4jbpup7petSB98M8tcaqXCigji8fGrC8bEbbDQxQkQ68";
static const std::string strSecret2 = "6KLE6U3w8x3rM7nA1ZQxR4KnyEzeirPEt4YaXWdY4roF7Tt96rq";
static const std::string strSecret1C = "QP8WvtVMV2iU6y7LE27ksRspp4MAJizPWYovx88W71g1nfSdAhkV";
static const std::string strSecret2C = "QTuro8Pwx5yaonvJmU4jbBfwuEmTViyAGNeNyfnG82o7HWJmnrLj";
static const std::string addr1 = "DSpgzjPyfQB6ZzeSbMWpaZiTTxGf2oBCs4";
static const std::string addr2 = "DR9VqfbWgEHZhNst34KQnABQXpPWXeLAJD";
static const std::string addr1C = "D8jZ6R8uuyQwiybupiVs3eDCedKdZ5bYV3";
static const std::string addr2C = "DP7rGcDbpAvMb1dKup981zNt1heWUuVLP7";

static const std::string strAddressBad = "DRjyUS2uuieEPkhZNdQz8hE5YycxVEqSXA";


#ifdef KEY_TESTS_DUMPINFO
void dumpKeyInfo(uint256 privkey)
{
    CKey key;
    key.resize(32);
    memcpy(&secret[0], &privkey, 32);
    std::vector<unsigned char> sec;
    sec.resize(32);
    memcpy(&sec[0], &secret[0], 32);
    printf("  * secret (hex): %s\n", HexStr(sec).c_str());

    for (int nCompressed=0; nCompressed<2; nCompressed++)
    {
        bool fCompressed = nCompressed == 1;
        printf("  * %s:\n", fCompressed ? "compressed" : "uncompressed");
        CBitcoinSecret bsecret;
        bsecret.SetSecret(secret, fCompressed);
        printf("    * secret (base58): %s\n", bsecret.ToString().c_str());
        CKey key;
        key.SetSecret(secret, fCompressed);
        std::vector<unsigned char> vchPubKey = key.GetPubKey();
        printf("    * pubkey (hex): %s\n", HexStr(vchPubKey).c_str());
        printf("    * address (base58): %s\n", CBitcoinAddress(vchPubKey).ToString().c_str());
    }
}
#endif


BOOST_FIXTURE_TEST_SUITE(key_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(key_test1)
{
    CKey key1  = DecodeSecret(strSecret1);
    BOOST_CHECK(key1.IsValid() && !key1.IsCompressed());
    CKey key2  = DecodeSecret(strSecret2);
    BOOST_CHECK(key2.IsValid() && !key2.IsCompressed());
    CKey key1C = DecodeSecret(strSecret1C);
    BOOST_CHECK(key1C.IsValid() && key1C.IsCompressed());
    CKey key2C = DecodeSecret(strSecret2C);
    BOOST_CHECK(key2C.IsValid() && key2C.IsCompressed());
    CKey bad_key = DecodeSecret(strAddressBad);
    BOOST_CHECK(!bad_key.IsValid());

    CPubKey pubkey1  = key1. GetPubKey();
    CPubKey pubkey2  = key2. GetPubKey();
    CPubKey pubkey1C = key1C.GetPubKey();
    CPubKey pubkey2C = key2C.GetPubKey();

    BOOST_CHECK(key1.VerifyPubKey(pubkey1));
    BOOST_CHECK(!key1.VerifyPubKey(pubkey1C));
    BOOST_CHECK(!key1.VerifyPubKey(pubkey2));
    BOOST_CHECK(!key1.VerifyPubKey(pubkey2C));

    BOOST_CHECK(!key1C.VerifyPubKey(pubkey1));
    BOOST_CHECK(key1C.VerifyPubKey(pubkey1C));
    BOOST_CHECK(!key1C.VerifyPubKey(pubkey2));
    BOOST_CHECK(!key1C.VerifyPubKey(pubkey2C));

    BOOST_CHECK(!key2.VerifyPubKey(pubkey1));
    BOOST_CHECK(!key2.VerifyPubKey(pubkey1C));
    BOOST_CHECK(key2.VerifyPubKey(pubkey2));
    BOOST_CHECK(!key2.VerifyPubKey(pubkey2C));

    BOOST_CHECK(!key2C.VerifyPubKey(pubkey1));
    BOOST_CHECK(!key2C.VerifyPubKey(pubkey1C));
    BOOST_CHECK(!key2C.VerifyPubKey(pubkey2));
    BOOST_CHECK(key2C.VerifyPubKey(pubkey2C));

    BOOST_CHECK(DecodeDestination(addr1)  == CTxDestination(pubkey1.GetID()));
    BOOST_CHECK(DecodeDestination(addr2)  == CTxDestination(pubkey2.GetID()));
    BOOST_CHECK(DecodeDestination(addr1C) == CTxDestination(pubkey1C.GetID()));
    BOOST_CHECK(DecodeDestination(addr2C) == CTxDestination(pubkey2C.GetID()));

    for (int n=0; n<16; n++)
    {
        std::string strMsg = strprintf("Very secret message %i: 11", n);
        uint256 hashMsg = Hash(strMsg.begin(), strMsg.end());

        // normal signatures

        std::vector<unsigned char> sign1, sign2, sign1C, sign2C;

        BOOST_CHECK(key1.Sign (hashMsg, sign1));
        BOOST_CHECK(key2.Sign (hashMsg, sign2));
        BOOST_CHECK(key1C.Sign(hashMsg, sign1C));
        BOOST_CHECK(key2C.Sign(hashMsg, sign2C));

        BOOST_CHECK( pubkey1.Verify(hashMsg, sign1));
        BOOST_CHECK(!pubkey1.Verify(hashMsg, sign2));
        BOOST_CHECK( pubkey1.Verify(hashMsg, sign1C));
        BOOST_CHECK(!pubkey1.Verify(hashMsg, sign2C));

        BOOST_CHECK(!pubkey2.Verify(hashMsg, sign1));
        BOOST_CHECK( pubkey2.Verify(hashMsg, sign2));
        BOOST_CHECK(!pubkey2.Verify(hashMsg, sign1C));
        BOOST_CHECK( pubkey2.Verify(hashMsg, sign2C));

        BOOST_CHECK( pubkey1C.Verify(hashMsg, sign1));
        BOOST_CHECK(!pubkey1C.Verify(hashMsg, sign2));
        BOOST_CHECK( pubkey1C.Verify(hashMsg, sign1C));
        BOOST_CHECK(!pubkey1C.Verify(hashMsg, sign2C));

        BOOST_CHECK(!pubkey2C.Verify(hashMsg, sign1));
        BOOST_CHECK( pubkey2C.Verify(hashMsg, sign2));
        BOOST_CHECK(!pubkey2C.Verify(hashMsg, sign1C));
        BOOST_CHECK( pubkey2C.Verify(hashMsg, sign2C));

        // compact signatures (with key recovery)

        std::vector<unsigned char> csign1, csign2, csign1C, csign2C;

        BOOST_CHECK(key1.SignCompact (hashMsg, csign1));
        BOOST_CHECK(key2.SignCompact (hashMsg, csign2));
        BOOST_CHECK(key1C.SignCompact(hashMsg, csign1C));
        BOOST_CHECK(key2C.SignCompact(hashMsg, csign2C));

        CPubKey rkey1, rkey2, rkey1C, rkey2C;

        BOOST_CHECK(rkey1.RecoverCompact (hashMsg, csign1));
        BOOST_CHECK(rkey2.RecoverCompact (hashMsg, csign2));
        BOOST_CHECK(rkey1C.RecoverCompact(hashMsg, csign1C));
        BOOST_CHECK(rkey2C.RecoverCompact(hashMsg, csign2C));

        BOOST_CHECK(rkey1  == pubkey1);
        BOOST_CHECK(rkey2  == pubkey2);
        BOOST_CHECK(rkey1C == pubkey1C);
        BOOST_CHECK(rkey2C == pubkey2C);
    }

    // test deterministic signing

    std::vector<unsigned char> detsig, detsigc;
    std::string strMsg = "Very deterministic message";
    uint256 hashMsg = Hash(strMsg.begin(), strMsg.end());
    BOOST_CHECK(key1.Sign(hashMsg, detsig));
    BOOST_CHECK(key1C.Sign(hashMsg, detsigc));
    BOOST_CHECK(detsig == detsigc);
    BOOST_CHECK(detsig == ParseHex("3044022030475ecf08b2c234a0f1ecfdb65871e4e6a419a995e667ce8bc2c331b916c2df02200b6dffef4a9fb2528a7f65f6e780583ba874618d4a141415dfb65f2f4bb833be"));
    BOOST_CHECK(key2.Sign(hashMsg, detsig));
    BOOST_CHECK(key2C.Sign(hashMsg, detsigc));
    BOOST_CHECK(detsig == detsigc);
    BOOST_CHECK(detsig == ParseHex("3045022100af874275fc12e344969ed4ec89cd1f4974ec816d63391f0e002d3fb81a22c25e022000edcf093fdf460f45d9a3ca918d321a21539dac276f8d81a64818c62e8e9517"));
    BOOST_CHECK(key1.SignCompact(hashMsg, detsig));
    BOOST_CHECK(key1C.SignCompact(hashMsg, detsigc));
    BOOST_CHECK(detsig == ParseHex("1c30475ecf08b2c234a0f1ecfdb65871e4e6a419a995e667ce8bc2c331b916c2df0b6dffef4a9fb2528a7f65f6e780583ba874618d4a141415dfb65f2f4bb833be"));
    BOOST_CHECK(detsigc == ParseHex("2030475ecf08b2c234a0f1ecfdb65871e4e6a419a995e667ce8bc2c331b916c2df0b6dffef4a9fb2528a7f65f6e780583ba874618d4a141415dfb65f2f4bb833be"));
    BOOST_CHECK(key2.SignCompact(hashMsg, detsig));
    BOOST_CHECK(key2C.SignCompact(hashMsg, detsigc));
    BOOST_CHECK(detsig == ParseHex("1caf874275fc12e344969ed4ec89cd1f4974ec816d63391f0e002d3fb81a22c25e00edcf093fdf460f45d9a3ca918d321a21539dac276f8d81a64818c62e8e9517"));
    BOOST_CHECK(detsigc == ParseHex("20af874275fc12e344969ed4ec89cd1f4974ec816d63391f0e002d3fb81a22c25e00edcf093fdf460f45d9a3ca918d321a21539dac276f8d81a64818c62e8e9517"));
}

static CPubKey UnserializePubkey(const std::vector<uint8_t>& data)
{
    CDataStream stream{SER_NETWORK, INIT_PROTO_VERSION};
    stream << data;
    CPubKey pubkey;
    stream >> pubkey;
    return pubkey;
}

static unsigned int GetLen(unsigned char chHeader)
{
    if (chHeader == 2 || chHeader == 3)
        return CPubKey::COMPRESSED_SIZE;
    if (chHeader == 4 || chHeader == 6 || chHeader == 7)
        return CPubKey::SIZE;
    return 0;
}

static void CmpSerializationPubkey(const CPubKey& pubkey)
{
    CDataStream stream{SER_NETWORK, INIT_PROTO_VERSION};
    stream << pubkey;
    CPubKey pubkey2;
    stream >> pubkey2;
    BOOST_CHECK(pubkey == pubkey2);
}

BOOST_AUTO_TEST_CASE(pubkey_unserialize)
{
    for (uint8_t i = 2; i <= 7; ++i) {
        CPubKey key = UnserializePubkey({0x02});
        BOOST_CHECK(!key.IsValid());
        CmpSerializationPubkey(key);
        key = UnserializePubkey(std::vector<uint8_t>(GetLen(i), i));
        CmpSerializationPubkey(key);
        if (i == 5) {
            BOOST_CHECK(!key.IsValid());
        } else {
            BOOST_CHECK(key.IsValid());
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
