// Copyright (c) 2017, 2021 Pieter Wuille
// Copyright (c) 2021-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Bech32 and Bech32m are string encoding formats. The outputs consist of a
// human-readable part (alphanumeric), a separator character (1), and a base32
// data section, the last 6 characters of which are a checksum.
//
// For more information, see BIP 173 and BIP 350.

#ifndef BITCOIN_BECH32_H
#define BITCOIN_BECH32_H

#include <stdint.h>
#include <stdlib.h>

#include <string>
#include <utility>
#include <vector>

namespace bech32
{

static const size_t CHECKSUM_SIZE = 6;
static const char SEPARATOR = '1';

enum class Encoding {
    INVALID, //!< Failed decoding

    BECH32,  //!< Bech32 encoding as defined in BIP173
    BECH32M, //!< Bech32m encoding as defined in BIP350
};

/** Character limits for Bech32(m) encoded strings. The limit is what bounds the
 *  error-detection guarantee: the BCH code detects up to 4 errors within 89
 *  characters and up to 3 within 1023. */
enum CharLimit : size_t {
    BECH32 = 90,            //!< BIP173/350 limit for addresses
    SILENT_PAYMENTS = 1023, //!< BIP352 limit for silent payment addresses
};

/** Encode a Bech32 or Bech32m string. An uppercase character in hrp asserts.
 *  Encoding must be BECH32 or BECH32M. */
std::string Encode(Encoding encoding, const std::string& hrp, const std::vector<uint8_t>& values);

struct DecodeResult
{
    Encoding encoding;         //!< Encoding detected; Encoding::INVALID if decoding failed
    std::string hrp;           //!< The human readable part
    std::vector<uint8_t> data; //!< The payload (excluding checksum)

    DecodeResult() : encoding(Encoding::INVALID) {}
    DecodeResult(Encoding enc, std::string&& h, std::vector<uint8_t>&& d) : encoding(enc), hrp(std::move(h)), data(std::move(d)) {}
};

/** Decode a Bech32 or Bech32m string. */
DecodeResult Decode(const std::string& str, CharLimit limit = CharLimit::BECH32);

} // namespace bech32

#endif // BITCOIN_BECH32_H
