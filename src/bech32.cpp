// Copyright (c) 2017, 2021 Pieter Wuille
// Copyright (c) 2021-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "bech32.h"

#include <assert.h>

namespace bech32
{

namespace
{

typedef std::vector<uint8_t> data;

/** The Bech32 and Bech32m character set for encoding. */
const char* CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/** The Bech32 and Bech32m character set for decoding. */
const int8_t CHARSET_REV[128] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    15, -1, 10, 17, 21, 20, 26, 30,  7,  5, -1, -1, -1, -1, -1, -1,
    -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
     1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1,
    -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
     1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1
};

/** Determine the final constant to use for the specified encoding. */
uint32_t EncodingConstant(Encoding encoding)
{
    assert(encoding == Encoding::BECH32 || encoding == Encoding::BECH32M);
    return encoding == Encoding::BECH32 ? 1 : 0x2bc830a3;
}

/** This function will compute what 6 5-bit values to XOR into the last 6 input values, in order to
 *  make the checksum 0. These 6 values are packed together in a single 30-bit integer. The higher
 *  bits correspond to earlier values. */
uint32_t PolyMod(const data& v)
{
    // The input is interpreted as a list of coefficients of a polynomial over F = GF(32), with an
    // implicit 1 in front. If the input is [v0,v1,v2,v3,v4], that polynomial is v(x) =
    // 1*x^5 + v0*x^4 + v1*x^3 + v2*x^2 + v3*x + v4. The implicit 1 guarantees that
    // [v0,v1,v2,...] has a distinct checksum from [0,v0,v1,v2,...].

    // The output is a 30-bit integer whose 5-bit groups are the coefficients of the remainder of
    // v(x) mod g(x), where g(x) is the Bech32 generator,
    // x^6 + {29}x^5 + {22}x^4 + {20}x^3 + {21}x^2 + {29}x + {18}. g(x) is chosen in such a way
    // that the resulting code is a BCH code, guaranteeing detection of up to 3 errors within a
    // window of 1023 characters. Among the various possible BCH codes, one was selected to in
    // fact guarantee detection of up to 4 errors within a window of 89 characters.

    // Note that the coefficients are elements of GF(32), here represented as decimal numbers
    // between {}. In this finite field, addition is just XOR of the corresponding numbers. For
    // example, {27} + {13} = {27 ^ 13} = {22}. Multiplication is more complicated, and requires
    // treating the bits of values themselves as coefficients of a polynomial over a smaller field,
    // GF(2), and multiplying those polynomials mod a^5 + a^3 + 1.

    uint32_t c = 1;
    for (size_t i = 0; i < v.size(); ++i) {
        // We want to update `c` to correspond to a polynomial with one extra term. If the initial
        // value of `c` consists of the coefficients of c(x) = f(x) mod g(x), we modify it to
        // correspond to c'(x) = (f(x) * x + v_i) mod g(x), where v_i is the next input to process.
        // If c(x) = c0*x^5 + c1*x^4 + c2*x^3 + c3*x^2 + c4*x + c5, we want to compute
        // c'(x) = (c1*x^5 + c2*x^4 + c3*x^3 + c4*x^2 + c5*x + v_i) + c0*k(x), where k(x) is
        // (x^6 mod g(x)).

        // First, determine the value of c0:
        uint8_t c0 = c >> 25;

        // Then compute c1*x^5 + c2*x^4 + c3*x^3 + c4*x^2 + c5*x + v_i:
        c = ((c & 0x1ffffff) << 5) ^ v[i];

        // Finally, for each set bit n in c0, conditionally add {2^n}k(x).
        if (c0 & 1)  c ^= 0x3b6a57b2; //     k(x) = {29}x^5 + {22}x^4 + {20}x^3 + {21}x^2 + {29}x + {18}
        if (c0 & 2)  c ^= 0x26508e6d; //  {2}k(x) = {19}x^5 +  {5}x^4 +     x^3 +  {3}x^2 + {19}x + {13}
        if (c0 & 4)  c ^= 0x1ea119fa; //  {4}k(x) = {15}x^5 + {10}x^4 +  {2}x^3 +  {6}x^2 + {15}x + {26}
        if (c0 & 8)  c ^= 0x3d4233dd; //  {8}k(x) = {30}x^5 + {20}x^4 +  {4}x^3 + {12}x^2 + {30}x + {29}
        if (c0 & 16) c ^= 0x2a1462b3; // {16}k(x) = {21}x^5 +     x^4 +  {8}x^3 + {24}x^2 + {21}x + {19}
    }
    return c;
}

/** Convert to lower case. */
inline unsigned char LowerCase(unsigned char c)
{
    return (c >= 'A' && c <= 'Z') ? (c - 'A') + 'a' : c;
}

/** Reject strings with invalid characters or mixed case. */
bool CheckCharacters(const std::string& str)
{
    bool lower = false, upper = false;
    for (size_t i = 0; i < str.size(); ++i) {
        unsigned char c = (unsigned char)str[i];
        if (c >= 'a' && c <= 'z') {
            if (upper) return false;
            lower = true;
        } else if (c >= 'A' && c <= 'Z') {
            if (lower) return false;
            upper = true;
        } else if (c < 33 || c > 126) {
            return false;
        }
    }
    return true;
}

/** Expand the HRP and append the values, giving the polynomial coefficients. */
data PreparePolynomialCoefficients(const std::string& hrp, const data& values)
{
    data ret;
    ret.reserve(hrp.size() + 1 + hrp.size() + values.size() + CHECKSUM_SIZE);

    for (size_t i = 0; i < hrp.size(); ++i) ret.push_back(hrp[i] >> 5);
    ret.push_back(0);
    for (size_t i = 0; i < hrp.size(); ++i) ret.push_back(hrp[i] & 0x1f);

    ret.insert(ret.end(), values.begin(), values.end());

    return ret;
}

/** Verify a checksum, returning which encoding it matches. */
Encoding VerifyChecksum(const std::string& hrp, const data& values)
{
    // PolyMod computes what value to xor into the final values to make the checksum 0. However,
    // if we required that the checksum was 0, it would be the case that appending a 0 to a valid
    // list of values would result in a new valid list. For that reason, Bech32 requires the
    // resulting checksum to be 1 instead. In Bech32m, this constant was amended.
    const data enc = PreparePolynomialCoefficients(hrp, values);
    const uint32_t check = PolyMod(enc);
    if (check == EncodingConstant(Encoding::BECH32)) return Encoding::BECH32;
    if (check == EncodingConstant(Encoding::BECH32M)) return Encoding::BECH32M;
    return Encoding::INVALID;
}

/** Create a checksum. */
data CreateChecksum(Encoding encoding, const std::string& hrp, const data& values)
{
    data enc = PreparePolynomialCoefficients(hrp, values);
    enc.insert(enc.end(), CHECKSUM_SIZE, 0x00);
    uint32_t mod = PolyMod(enc) ^ EncodingConstant(encoding); // Determine what to XOR into those 6 zeroes.
    data ret(CHECKSUM_SIZE);
    for (size_t i = 0; i < CHECKSUM_SIZE; ++i) {
        // Convert the 5-bit groups in mod to checksum values.
        ret[i] = (mod >> (5 * (5 - i))) & 31;
    }
    return ret;
}

} // namespace

std::string Encode(Encoding encoding, const std::string& hrp, const data& values)
{
    // BIP173 and BIP350 require an encoder to return a lowercase string; an uppercase HRP would
    // always produce an invalid result, so reject it rather than emit one.
    for (size_t i = 0; i < hrp.size(); ++i) assert(hrp[i] < 'A' || hrp[i] > 'Z');

    std::string ret;
    ret.reserve(hrp.size() + 1 + values.size() + CHECKSUM_SIZE);
    ret += hrp;
    ret += SEPARATOR;
    for (size_t i = 0; i < values.size(); ++i) ret += CHARSET[values[i]];
    const data checksum = CreateChecksum(encoding, hrp, values);
    for (size_t i = 0; i < checksum.size(); ++i) ret += CHARSET[checksum[i]];
    return ret;
}

DecodeResult Decode(const std::string& str, CharLimit limit)
{
    if (!CheckCharacters(str)) return DecodeResult();
    if (str.size() > limit) return DecodeResult();
    const size_t pos = str.rfind(SEPARATOR);
    if (pos == str.npos || pos == 0 || pos + CHECKSUM_SIZE >= str.size()) {
        return DecodeResult();
    }
    data values(str.size() - 1 - pos);
    for (size_t i = 0; i < str.size() - 1 - pos; ++i) {
        const unsigned char c = str[i + pos + 1];
        const int8_t rev = CHARSET_REV[c];
        if (rev == -1) return DecodeResult();
        values[i] = rev;
    }
    std::string hrp;
    hrp.reserve(pos);
    for (size_t i = 0; i < pos; ++i) {
        hrp += LowerCase(str[i]);
    }
    const Encoding result = VerifyChecksum(hrp, values);
    if (result == Encoding::INVALID) return DecodeResult();
    return DecodeResult(result, std::move(hrp), data(values.begin(), values.end() - CHECKSUM_SIZE));
}

} // namespace bech32
