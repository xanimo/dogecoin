// Copyright (c) 2017 Pieter Wuille
// Copyright (c) 2021-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "bech32.h"
#include "utilstrencodings.h"
#include "test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(bech32_tests, BasicTestingSetup)

namespace {

bool CaseInsensitiveEqual(const std::string& s1, const std::string& s2)
{
    if (s1.size() != s2.size()) return false;
    for (size_t i = 0; i < s1.size(); ++i) {
        if (ToLower((unsigned char)s1[i]) != ToLower((unsigned char)s2[i])) return false;
    }
    return true;
}

} // namespace

// BIP173 valid vectors.
BOOST_AUTO_TEST_CASE(bech32_testvectors_valid)
{
    static const std::string CASES[] = {
        "A12UEL5L",
        "a12uel5l",
        "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
        "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
        "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
        "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
        "?1ezyfcl",
    };
    for (size_t i = 0; i < ARRAYLEN(CASES); ++i) {
        const std::string& str = CASES[i];
        const bech32::DecodeResult dec = bech32::Decode(str);
        BOOST_CHECK(dec.encoding == bech32::Encoding::BECH32);
        const std::string recode = bech32::Encode(bech32::Encoding::BECH32, dec.hrp, dec.data);
        BOOST_CHECK(!recode.empty());
        BOOST_CHECK(CaseInsensitiveEqual(str, recode));
    }
}

// BIP350 valid vectors.
BOOST_AUTO_TEST_CASE(bech32m_testvectors_valid)
{
    static const std::string CASES[] = {
        "A1LQFN3A",
        "a1lqfn3a",
        "an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6",
        "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
        "11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8",
        "split1checkupstagehandshakeupstreamerranterredcaperredlc445v",
        "?1v759aa",
    };
    for (size_t i = 0; i < ARRAYLEN(CASES); ++i) {
        const std::string& str = CASES[i];
        const bech32::DecodeResult dec = bech32::Decode(str);
        BOOST_CHECK(dec.encoding == bech32::Encoding::BECH32M);
        const std::string recode = bech32::Encode(bech32::Encoding::BECH32M, dec.hrp, dec.data);
        BOOST_CHECK(!recode.empty());
        BOOST_CHECK(CaseInsensitiveEqual(str, recode));
    }
}

// BIP173 invalid vectors. A bech32m string is also invalid as bech32, since the two differ
// only in the checksum constant, so the bech32m valid vectors are folded in here.
BOOST_AUTO_TEST_CASE(bech32_testvectors_invalid)
{
    static const std::string CASES[] = {
        " 1nwldj5",
        "\x7f""1axkwrx",
        "\x80""1eym55h",
        "an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx",
        "pzry9x0s0muk",
        "1pzry9x0s0muk",
        "x1b4n0q5v",
        "li1dgmt3",
        "de1lg7wt\xff",
        "A1G7SGD8",
        "10a06t8",
        "1qzzfhee",
        "a12UEL5L",
        "A12uEL5L",
        "abcdef1qpzrz9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
        "test1zg69w7y6hn0aqy352euf40x77qddq3dc",
    };
    for (size_t i = 0; i < ARRAYLEN(CASES); ++i) {
        const bech32::DecodeResult dec = bech32::Decode(CASES[i]);
        BOOST_CHECK(dec.encoding == bech32::Encoding::INVALID);
    }
    // A 100-character all-'q' string is rejected on length alone.
    BOOST_CHECK(bech32::Decode(std::string(100, 'q')).encoding == bech32::Encoding::INVALID);
}

// BIP350 invalid vectors.
BOOST_AUTO_TEST_CASE(bech32m_testvectors_invalid)
{
    static const std::string CASES[] = {
        " 1xj0phk",
        "\x7f""1g6xzxy",
        "\x80""1vctc34",
        "an84characterslonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11d6pts4",
        "qyrz8wqd2c9m",
        "1qyrz8wqd2c9m",
        "y1b0jsk6g",
        "lt1igcx5c0",
        "in1muywd",
        "mm1crxm3i",
        "au1s5cgom",
        "M1VUXWEZ",
        "16plkw9",
        "1p2gdwpf",
        "abcdef1l7aum6echk45nj2s0wdvt2fg8x9yrzpqzd3ryx",
        "test1zg69v7y60n00qy352euf40x77qcusag6",
    };
    for (size_t i = 0; i < ARRAYLEN(CASES); ++i) {
        const bech32::DecodeResult dec = bech32::Decode(CASES[i]);
        BOOST_CHECK(dec.encoding == bech32::Encoding::INVALID);
    }
}

// The two encodings must never be mistaken for each other: a string valid under one
// must decode as that one, never the other.
BOOST_AUTO_TEST_CASE(bech32_encodings_are_distinct)
{
    BOOST_CHECK(bech32::Decode("a12uel5l").encoding == bech32::Encoding::BECH32);
    BOOST_CHECK(bech32::Decode("a1lqfn3a").encoding == bech32::Encoding::BECH32M);

    const std::vector<uint8_t> values(10, 0);
    const std::string as_bech32 = bech32::Encode(bech32::Encoding::BECH32, "doge", values);
    const std::string as_bech32m = bech32::Encode(bech32::Encoding::BECH32M, "doge", values);
    BOOST_CHECK(as_bech32 != as_bech32m);
    BOOST_CHECK(bech32::Decode(as_bech32).encoding == bech32::Encoding::BECH32);
    BOOST_CHECK(bech32::Decode(as_bech32m).encoding == bech32::Encoding::BECH32M);
}

// The default limit is 90 characters; silent payment addresses need the BIP352 limit of 1023.
BOOST_AUTO_TEST_CASE(bech32m_char_limit)
{
    const std::vector<uint8_t> values(107, 0); // 67 payload bytes in 5-bit groups
    const std::string addr = bech32::Encode(bech32::Encoding::BECH32M, "dsp", values);
    BOOST_CHECK(addr.size() > bech32::CharLimit::BECH32);
    BOOST_CHECK(bech32::Decode(addr).encoding == bech32::Encoding::INVALID);

    const bech32::DecodeResult dec = bech32::Decode(addr, bech32::CharLimit::SILENT_PAYMENTS);
    BOOST_CHECK(dec.encoding == bech32::Encoding::BECH32M);
    BOOST_CHECK_EQUAL(dec.hrp, "dsp");
    BOOST_CHECK(dec.data == values);
}

// Round-trip the 8-to-5 bit regrouping that bech32 payloads are built from.
BOOST_AUTO_TEST_CASE(convertbits_roundtrip)
{
    for (size_t len = 1; len <= 70; ++len) {
        std::vector<unsigned char> in(len);
        for (size_t i = 0; i < len; ++i) in[i] = (unsigned char)(i * 7 + len);

        std::vector<unsigned char> five;
        BOOST_CHECK((ConvertBits<8, 5, true>(five, in.begin(), in.end())));
        BOOST_CHECK_EQUAL(five.size(), (len * 8 + 4) / 5);

        std::vector<unsigned char> out;
        BOOST_CHECK((ConvertBits<5, 8, false>(out, five.begin(), five.end())));
        BOOST_CHECK(out == in);
    }
}

// Unpadded 5-to-8 conversion must reject a trailing group that carries non-zero bits.
BOOST_AUTO_TEST_CASE(convertbits_rejects_nonzero_padding)
{
    std::vector<unsigned char> five;
    std::vector<unsigned char> in(1, 0xff);
    BOOST_CHECK((ConvertBits<8, 5, true>(five, in.begin(), in.end())));
    BOOST_CHECK_EQUAL(five.size(), 2u);
    BOOST_CHECK_EQUAL(five[1], 28); // 0xff padded to 10 bits: 11111 11100

    std::vector<unsigned char> out;
    BOOST_CHECK((ConvertBits<5, 8, false>(out, five.begin(), five.end())));
    BOOST_CHECK(out == in);

    five[1] = 29; // 11101: the pad bits are no longer zero
    out.clear();
    BOOST_CHECK(!(ConvertBits<5, 8, false>(out, five.begin(), five.end())));
}

BOOST_AUTO_TEST_SUITE_END()
