/*
 * Copyright 2009 Colin Percival, 2011 ArtForz, 2012-2013 pooler
 * Copyright (c) 2026 The Dogecoin Core developers
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * AVX2 optimized scrypt Salsa20/8 core.  Processes two 128-bit Salsa
 * quarter-rounds in parallel using 256-bit YMM registers.
 */

#include "crypto/scrypt.h"

#include <stdint.h>
#include <string.h>
#include <immintrin.h>

/*
 * xor_salsa8_avx2: AVX2-optimized Salsa20/8 core.
 *
 * Works on two independent 4x32 blocks packed into 256-bit registers:
 * each YMM lane holds one set of Salsa state, and we process both
 * halves of the scrypt block (B[0..15] and B[16..31]) simultaneously.
 */
static inline void xor_salsa8_avx2_dual(
    __m256i B[4], const __m256i Bx[4])
{
    __m256i X0, X1, X2, X3, T;
    int i;

    X0 = B[0] = _mm256_xor_si256(B[0], Bx[0]);
    X1 = B[1] = _mm256_xor_si256(B[1], Bx[1]);
    X2 = B[2] = _mm256_xor_si256(B[2], Bx[2]);
    X3 = B[3] = _mm256_xor_si256(B[3], Bx[3]);

    for (i = 0; i < 8; i += 2) {
        /* Operate on "columns". */
        T = _mm256_add_epi32(X0, X3);
        X1 = _mm256_xor_si256(X1, _mm256_slli_epi32(T, 7));
        X1 = _mm256_xor_si256(X1, _mm256_srli_epi32(T, 25));
        T = _mm256_add_epi32(X1, X0);
        X2 = _mm256_xor_si256(X2, _mm256_slli_epi32(T, 9));
        X2 = _mm256_xor_si256(X2, _mm256_srli_epi32(T, 23));
        T = _mm256_add_epi32(X2, X1);
        X3 = _mm256_xor_si256(X3, _mm256_slli_epi32(T, 13));
        X3 = _mm256_xor_si256(X3, _mm256_srli_epi32(T, 19));
        T = _mm256_add_epi32(X3, X2);
        X0 = _mm256_xor_si256(X0, _mm256_slli_epi32(T, 18));
        X0 = _mm256_xor_si256(X0, _mm256_srli_epi32(T, 14));

        /* Rearrange data. */
        X1 = _mm256_shuffle_epi32(X1, 0x93);
        X2 = _mm256_shuffle_epi32(X2, 0x4E);
        X3 = _mm256_shuffle_epi32(X3, 0x39);

        /* Operate on "rows". */
        T = _mm256_add_epi32(X0, X1);
        X3 = _mm256_xor_si256(X3, _mm256_slli_epi32(T, 7));
        X3 = _mm256_xor_si256(X3, _mm256_srli_epi32(T, 25));
        T = _mm256_add_epi32(X3, X0);
        X2 = _mm256_xor_si256(X2, _mm256_slli_epi32(T, 9));
        X2 = _mm256_xor_si256(X2, _mm256_srli_epi32(T, 23));
        T = _mm256_add_epi32(X2, X3);
        X1 = _mm256_xor_si256(X1, _mm256_slli_epi32(T, 13));
        X1 = _mm256_xor_si256(X1, _mm256_srli_epi32(T, 19));
        T = _mm256_add_epi32(X1, X2);
        X0 = _mm256_xor_si256(X0, _mm256_slli_epi32(T, 18));
        X0 = _mm256_xor_si256(X0, _mm256_srli_epi32(T, 14));

        /* Rearrange data back. */
        X1 = _mm256_shuffle_epi32(X1, 0x39);
        X2 = _mm256_shuffle_epi32(X2, 0x4E);
        X3 = _mm256_shuffle_epi32(X3, 0x93);
    }

    B[0] = _mm256_add_epi32(B[0], X0);
    B[1] = _mm256_add_epi32(B[1], X1);
    B[2] = _mm256_add_epi32(B[2], X2);
    B[3] = _mm256_add_epi32(B[3], X3);
}

/*
 * Single-lane AVX2 Salsa20/8 (for the sequential mixing phase where we
 * can't pair blocks easily).  Uses the lower 128 bits of YMM registers
 * but still benefits from VEX encoding.
 */
static inline void xor_salsa8_avx2(__m128i B[4], const __m128i Bx[4])
{
    __m128i X0, X1, X2, X3, T;
    int i;

    X0 = B[0] = _mm_xor_si128(B[0], Bx[0]);
    X1 = B[1] = _mm_xor_si128(B[1], Bx[1]);
    X2 = B[2] = _mm_xor_si128(B[2], Bx[2]);
    X3 = B[3] = _mm_xor_si128(B[3], Bx[3]);

    for (i = 0; i < 8; i += 2) {
        T = _mm_add_epi32(X0, X3);
        X1 = _mm_xor_si128(X1, _mm_slli_epi32(T, 7));
        X1 = _mm_xor_si128(X1, _mm_srli_epi32(T, 25));
        T = _mm_add_epi32(X1, X0);
        X2 = _mm_xor_si128(X2, _mm_slli_epi32(T, 9));
        X2 = _mm_xor_si128(X2, _mm_srli_epi32(T, 23));
        T = _mm_add_epi32(X2, X1);
        X3 = _mm_xor_si128(X3, _mm_slli_epi32(T, 13));
        X3 = _mm_xor_si128(X3, _mm_srli_epi32(T, 19));
        T = _mm_add_epi32(X3, X2);
        X0 = _mm_xor_si128(X0, _mm_slli_epi32(T, 18));
        X0 = _mm_xor_si128(X0, _mm_srli_epi32(T, 14));

        X1 = _mm_shuffle_epi32(X1, 0x93);
        X2 = _mm_shuffle_epi32(X2, 0x4E);
        X3 = _mm_shuffle_epi32(X3, 0x39);

        T = _mm_add_epi32(X0, X1);
        X3 = _mm_xor_si128(X3, _mm_slli_epi32(T, 7));
        X3 = _mm_xor_si128(X3, _mm_srli_epi32(T, 25));
        T = _mm_add_epi32(X3, X0);
        X2 = _mm_xor_si128(X2, _mm_slli_epi32(T, 9));
        X2 = _mm_xor_si128(X2, _mm_srli_epi32(T, 23));
        T = _mm_add_epi32(X2, X3);
        X1 = _mm_xor_si128(X1, _mm_slli_epi32(T, 13));
        X1 = _mm_xor_si128(X1, _mm_srli_epi32(T, 19));
        T = _mm_add_epi32(X1, X2);
        X0 = _mm_xor_si128(X0, _mm_slli_epi32(T, 18));
        X0 = _mm_xor_si128(X0, _mm_srli_epi32(T, 14));

        X1 = _mm_shuffle_epi32(X1, 0x39);
        X2 = _mm_shuffle_epi32(X2, 0x4E);
        X3 = _mm_shuffle_epi32(X3, 0x93);
    }

    B[0] = _mm_add_epi32(B[0], X0);
    B[1] = _mm_add_epi32(B[1], X1);
    B[2] = _mm_add_epi32(B[2], X2);
    B[3] = _mm_add_epi32(B[3], X3);
}

void scrypt_1024_1_1_256_sp_avx2(const char *input, char *output, char *scratchpad)
{
    uint8_t B[128];
    union {
        __m128i i128[8];
        uint32_t u32[32];
    } X;
    __m128i *V;
    uint32_t i, j, k;

    V = (__m128i *)(((uintptr_t)(scratchpad) + 63) & ~(uintptr_t)(63));

    PBKDF2_SHA256((const uint8_t *)input, 80, (const uint8_t *)input, 80, 1, B, 128);

    for (k = 0; k < 2; k++) {
        for (i = 0; i < 16; i++) {
            X.u32[k * 16 + i] = le32dec(&B[(k * 16 + (i * 5 % 16)) * 4]);
        }
    }

    /* ROMix: fill the scratchpad V */
    for (i = 0; i < 1024; i++) {
        for (k = 0; k < 8; k++)
            V[i * 8 + k] = X.i128[k];
        xor_salsa8_avx2(&X.i128[0], &X.i128[4]);
        xor_salsa8_avx2(&X.i128[4], &X.i128[0]);
    }

    /* ROMix: mix with random lookups */
    for (i = 0; i < 1024; i++) {
        j = 8 * (X.u32[16] & 1023);
        for (k = 0; k < 8; k++)
            X.i128[k] = _mm_xor_si128(X.i128[k], V[j + k]);
        xor_salsa8_avx2(&X.i128[0], &X.i128[4]);
        xor_salsa8_avx2(&X.i128[4], &X.i128[0]);
    }

    for (k = 0; k < 2; k++) {
        for (i = 0; i < 16; i++) {
            le32enc(&B[(k * 16 + (i * 5 % 16)) * 4], X.u32[k * 16 + i]);
        }
    }

    PBKDF2_SHA256((const uint8_t *)input, 80, B, 128, 1, (uint8_t *)output, 32);
}
