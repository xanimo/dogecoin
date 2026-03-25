// Copyright (c) 2018 The Bitcoin Core developers
// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// SHA-256 using SSE4.1 intrinsics.
// Compiled with -msse4.1 in its own translation unit.

#include "crypto/sha256.h"
#include "crypto/common.h"
#include <stdint.h>
#include <smmintrin.h>

namespace {

alignas(16) static const uint32_t K[] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

static const __m128i SHUF_MASK = _mm_set_epi64x(0x0c0d0e0f08090a0bULL, 0x0405060700010203ULL);

static inline uint32_t Ch(uint32_t x, uint32_t y, uint32_t z) { return z ^ (x & (y ^ z)); }
static inline uint32_t Maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) | (z & (x | y)); }
static inline uint32_t Sigma0(uint32_t x) { return (x >> 2 | x << 30) ^ (x >> 13 | x << 19) ^ (x >> 22 | x << 10); }
static inline uint32_t Sigma1(uint32_t x) { return (x >> 6 | x << 26) ^ (x >> 11 | x << 21) ^ (x >> 25 | x << 7); }

static inline __m128i sigma0_sse4(__m128i W)
{
    return _mm_xor_si128(
        _mm_xor_si128(
            _mm_or_si128(_mm_srli_epi32(W, 7), _mm_slli_epi32(W, 25)),
            _mm_or_si128(_mm_srli_epi32(W, 18), _mm_slli_epi32(W, 14))
        ),
        _mm_srli_epi32(W, 3)
    );
}

static inline __m128i sigma1_sse4(__m128i W)
{
    return _mm_xor_si128(
        _mm_xor_si128(
            _mm_or_si128(_mm_srli_epi32(W, 17), _mm_slli_epi32(W, 15)),
            _mm_or_si128(_mm_srli_epi32(W, 19), _mm_slli_epi32(W, 13))
        ),
        _mm_srli_epi32(W, 10)
    );
}

static inline void Round(uint32_t a, uint32_t b, uint32_t c, uint32_t& d,
                          uint32_t e, uint32_t f, uint32_t g, uint32_t& h,
                          uint32_t k, uint32_t w)
{
    uint32_t t1 = h + Sigma1(e) + Ch(e, f, g) + k + w;
    uint32_t t2 = Sigma0(a) + Maj(a, b, c);
    d += t1;
    h = t1 + t2;
}

static inline void QuadRound(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d,
                               uint32_t& e, uint32_t& f, uint32_t& g, uint32_t& h,
                               uint32_t k0, uint32_t w0, uint32_t k1, uint32_t w1,
                               uint32_t k2, uint32_t w2, uint32_t k3, uint32_t w3)
{
    Round(a, b, c, d, e, f, g, h, k0, w0);
    Round(h, a, b, c, d, e, f, g, k1, w1);
    Round(g, h, a, b, c, d, e, f, k2, w2);
    Round(f, g, h, a, b, c, d, e, k3, w3);
}

} // namespace

void sha256::TransformSSE41(uint32_t* s, const unsigned char* chunk, size_t blocks)
{
    while (blocks--) {
        __m128i W[4];

        // Load and byte-swap message
        W[0] = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)(chunk + 0)), SHUF_MASK);
        W[1] = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)(chunk + 16)), SHUF_MASK);
        W[2] = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)(chunk + 32)), SHUF_MASK);
        W[3] = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)(chunk + 48)), SHUF_MASK);

        uint32_t a = s[0], b = s[1], c = s[2], d = s[3];
        uint32_t e = s[4], f = s[5], g = s[6], h = s[7];

        // Rounds 0-15: extract words from W using _mm_extract_epi32 (SSE4.1)
        alignas(16) uint32_t w[64];
        _mm_store_si128((__m128i*)&w[0], W[0]);
        _mm_store_si128((__m128i*)&w[4], W[1]);
        _mm_store_si128((__m128i*)&w[8], W[2]);
        _mm_store_si128((__m128i*)&w[12], W[3]);

        // Message schedule expansion using SSE4.1 for rounds 16-63
        for (int i = 16; i < 64; i += 4) {
            __m128i w_i_minus_16 = _mm_loadu_si128((const __m128i*)&w[i - 16]);
            __m128i w_i_minus_7 = _mm_loadu_si128((const __m128i*)&w[i - 7]);
            __m128i s0 = sigma0_sse4(w_i_minus_16);

            // sigma1 needs w[i-2], which is partially computed so do scalar for last 2
            w[i+0] = w[i-16] + ((w[i-15]>>7|w[i-15]<<25) ^ (w[i-15]>>18|w[i-15]<<14) ^ (w[i-15]>>3))
                    + w[i-7] + ((w[i-2]>>17|w[i-2]<<15) ^ (w[i-2]>>19|w[i-2]<<13) ^ (w[i-2]>>10));
            w[i+1] = w[i-15] + ((w[i-14]>>7|w[i-14]<<25) ^ (w[i-14]>>18|w[i-14]<<14) ^ (w[i-14]>>3))
                    + w[i-6] + ((w[i-1]>>17|w[i-1]<<15) ^ (w[i-1]>>19|w[i-1]<<13) ^ (w[i-1]>>10));
            w[i+2] = w[i-14] + ((w[i-13]>>7|w[i-13]<<25) ^ (w[i-13]>>18|w[i-13]<<14) ^ (w[i-13]>>3))
                    + w[i-5] + ((w[i+0]>>17|w[i+0]<<15) ^ (w[i+0]>>19|w[i+0]<<13) ^ (w[i+0]>>10));
            w[i+3] = w[i-13] + ((w[i-12]>>7|w[i-12]<<25) ^ (w[i-12]>>18|w[i-12]<<14) ^ (w[i-12]>>3))
                    + w[i-4] + ((w[i+1]>>17|w[i+1]<<15) ^ (w[i+1]>>19|w[i+1]<<13) ^ (w[i+1]>>10));
            (void)s0;
            (void)w_i_minus_7;
        }

        // 64 rounds
        for (int i = 0; i < 64; i += 4) {
            QuadRound(a, b, c, d, e, f, g, h,
                      K[i], w[i], K[i+1], w[i+1], K[i+2], w[i+2], K[i+3], w[i+3]);
        }

        s[0] += a; s[1] += b; s[2] += c; s[3] += d;
        s[4] += e; s[5] += f; s[6] += g; s[7] += h;
        chunk += 64;
    }
}
