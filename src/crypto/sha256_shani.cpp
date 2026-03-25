// Copyright (c) 2018 The Bitcoin Core developers
// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// SHA-256 using Intel SHA-NI (SHA Extensions) intrinsics.
// Compiled with -msse4.1 -msha in its own translation unit.

#include "crypto/sha256.h"
#include <stdint.h>
#include <immintrin.h>

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

static const __m128i SHUF_MASK = _mm_set_epi64x(
    0x0c0d0e0f08090a0bULL, 0x0405060700010203ULL);

} // namespace

void sha256::TransformSHANI(uint32_t* s, const unsigned char* chunk, size_t blocks)
{
    __m128i STATE0, STATE1, ABEF_SAVE, CDGH_SAVE;
    __m128i MSG, MSG0, MSG1, MSG2, MSG3;
    __m128i TMP;

    // Load initial state: s[0..3] = ABCD, s[4..7] = EFGH
    // SHA-NI wants ABEF in one reg, CDGH in other
    TMP    = _mm_loadu_si128((const __m128i*)&s[0]);
    STATE1 = _mm_loadu_si128((const __m128i*)&s[4]);

    // Rearrange: TMP = [A B C D], STATE1 = [E F G H]
    // We need STATE0 = [C D A B] -> _mm_shuffle_epi32(TMP, 0xB1) -> [B A D C]
    // Actually the SHA-NI instructions expect CDAB, EFGH → let's use the
    // shuffle pattern from Bitcoin Core's implementation
    TMP    = _mm_shuffle_epi32(TMP, 0xB1);    // BADC
    STATE1 = _mm_shuffle_epi32(STATE1, 0x1B);  // HGFE
    STATE0 = _mm_alignr_epi8(TMP, STATE1, 8);  // ABEF
    STATE1 = _mm_blend_epi16(STATE1, TMP, 0xF0); // CDGH

    while (blocks--) {
        ABEF_SAVE = STATE0;
        CDGH_SAVE = STATE1;

        // Load and byte-swap message
        MSG0 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)(chunk + 0)), SHUF_MASK);
        MSG1 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)(chunk + 16)), SHUF_MASK);
        MSG2 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)(chunk + 32)), SHUF_MASK);
        MSG3 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)(chunk + 48)), SHUF_MASK);

        // Rounds 0-3
        MSG = _mm_add_epi32(MSG0, _mm_load_si128((const __m128i*)&K[0]));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

        // Rounds 4-7
        MSG0 = _mm_sha256msg1_epu32(MSG0, MSG1);
        MSG = _mm_add_epi32(MSG1, _mm_load_si128((const __m128i*)&K[4]));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

        // Rounds 8-11
        MSG1 = _mm_sha256msg1_epu32(MSG1, MSG2);
        MSG = _mm_add_epi32(MSG2, _mm_load_si128((const __m128i*)&K[8]));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        MSG0 = _mm_add_epi32(MSG0, _mm_alignr_epi8(MSG2, MSG1, 4));
        MSG0 = _mm_sha256msg2_epu32(MSG0, MSG2);

        // Rounds 12-15
        MSG2 = _mm_sha256msg1_epu32(MSG2, MSG3);
        MSG = _mm_add_epi32(MSG3, _mm_load_si128((const __m128i*)&K[12]));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        MSG1 = _mm_add_epi32(MSG1, _mm_alignr_epi8(MSG3, MSG2, 4));
        MSG1 = _mm_sha256msg2_epu32(MSG1, MSG3);

        // Rounds 16-19
        MSG3 = _mm_sha256msg1_epu32(MSG3, MSG0);
        MSG = _mm_add_epi32(MSG0, _mm_load_si128((const __m128i*)&K[16]));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        MSG2 = _mm_add_epi32(MSG2, _mm_alignr_epi8(MSG0, MSG3, 4));
        MSG2 = _mm_sha256msg2_epu32(MSG2, MSG0);

        // Rounds 20-23
        MSG0 = _mm_sha256msg1_epu32(MSG0, MSG1);
        MSG = _mm_add_epi32(MSG1, _mm_load_si128((const __m128i*)&K[20]));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        MSG3 = _mm_add_epi32(MSG3, _mm_alignr_epi8(MSG1, MSG0, 4));
        MSG3 = _mm_sha256msg2_epu32(MSG3, MSG1);

        // Rounds 24-27
        MSG1 = _mm_sha256msg1_epu32(MSG1, MSG2);
        MSG = _mm_add_epi32(MSG2, _mm_load_si128((const __m128i*)&K[24]));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        MSG0 = _mm_add_epi32(MSG0, _mm_alignr_epi8(MSG2, MSG1, 4));
        MSG0 = _mm_sha256msg2_epu32(MSG0, MSG2);

        // Rounds 28-31
        MSG2 = _mm_sha256msg1_epu32(MSG2, MSG3);
        MSG = _mm_add_epi32(MSG3, _mm_load_si128((const __m128i*)&K[28]));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        MSG1 = _mm_add_epi32(MSG1, _mm_alignr_epi8(MSG3, MSG2, 4));
        MSG1 = _mm_sha256msg2_epu32(MSG1, MSG3);

        // Rounds 32-35
        MSG3 = _mm_sha256msg1_epu32(MSG3, MSG0);
        MSG = _mm_add_epi32(MSG0, _mm_load_si128((const __m128i*)&K[32]));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        MSG2 = _mm_add_epi32(MSG2, _mm_alignr_epi8(MSG0, MSG3, 4));
        MSG2 = _mm_sha256msg2_epu32(MSG2, MSG0);

        // Rounds 36-39
        MSG0 = _mm_sha256msg1_epu32(MSG0, MSG1);
        MSG = _mm_add_epi32(MSG1, _mm_load_si128((const __m128i*)&K[36]));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        MSG3 = _mm_add_epi32(MSG3, _mm_alignr_epi8(MSG1, MSG0, 4));
        MSG3 = _mm_sha256msg2_epu32(MSG3, MSG1);

        // Rounds 40-43
        MSG1 = _mm_sha256msg1_epu32(MSG1, MSG2);
        MSG = _mm_add_epi32(MSG2, _mm_load_si128((const __m128i*)&K[40]));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        MSG0 = _mm_add_epi32(MSG0, _mm_alignr_epi8(MSG2, MSG1, 4));
        MSG0 = _mm_sha256msg2_epu32(MSG0, MSG2);

        // Rounds 44-47
        MSG2 = _mm_sha256msg1_epu32(MSG2, MSG3);
        MSG = _mm_add_epi32(MSG3, _mm_load_si128((const __m128i*)&K[44]));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        MSG1 = _mm_add_epi32(MSG1, _mm_alignr_epi8(MSG3, MSG2, 4));
        MSG1 = _mm_sha256msg2_epu32(MSG1, MSG3);

        // Rounds 48-51
        MSG = _mm_add_epi32(MSG0, _mm_load_si128((const __m128i*)&K[48]));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

        // Rounds 52-55
        MSG = _mm_add_epi32(MSG1, _mm_load_si128((const __m128i*)&K[52]));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

        // Rounds 56-59
        MSG = _mm_add_epi32(MSG2, _mm_load_si128((const __m128i*)&K[56]));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

        // Rounds 60-63
        MSG = _mm_add_epi32(MSG3, _mm_load_si128((const __m128i*)&K[60]));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

        // Add saved state
        STATE0 = _mm_add_epi32(STATE0, ABEF_SAVE);
        STATE1 = _mm_add_epi32(STATE1, CDGH_SAVE);

        chunk += 64;
    }

    // Rearrange state back to s[0..7]
    TMP    = _mm_shuffle_epi32(STATE0, 0x1B);  // FEBA
    STATE1 = _mm_shuffle_epi32(STATE1, 0xB1);  // GHCD
    STATE0 = _mm_blend_epi16(TMP, STATE1, 0xF0); // ABCD
    STATE1 = _mm_alignr_epi8(STATE1, TMP, 8);    // EFGH

    _mm_storeu_si128((__m128i*)&s[0], STATE0);
    _mm_storeu_si128((__m128i*)&s[4], STATE1);
}
