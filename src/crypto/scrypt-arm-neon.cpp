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
 * ARM NEON optimized scrypt Salsa20/8 core.
 */

#include "crypto/scrypt.h"

#include <stdint.h>
#include <string.h>
#include <arm_neon.h>

static inline void xor_salsa8_neon(uint32x4_t B[4], const uint32x4_t Bx[4])
{
    uint32x4_t X0, X1, X2, X3, T;
    int i;

    X0 = B[0] = veorq_u32(B[0], Bx[0]);
    X1 = B[1] = veorq_u32(B[1], Bx[1]);
    X2 = B[2] = veorq_u32(B[2], Bx[2]);
    X3 = B[3] = veorq_u32(B[3], Bx[3]);

    for (i = 0; i < 8; i += 2) {
        /* Operate on "columns". */
        T = vaddq_u32(X0, X3);
        X1 = veorq_u32(X1, vsriq_n_u32(vshlq_n_u32(T, 7), T, 25));
        T = vaddq_u32(X1, X0);
        X2 = veorq_u32(X2, vsriq_n_u32(vshlq_n_u32(T, 9), T, 23));
        T = vaddq_u32(X2, X1);
        X3 = veorq_u32(X3, vsriq_n_u32(vshlq_n_u32(T, 13), T, 19));
        T = vaddq_u32(X3, X2);
        X0 = veorq_u32(X0, vsriq_n_u32(vshlq_n_u32(T, 18), T, 14));

        /* Rearrange data. */
        X1 = vextq_u32(X1, X1, 3);
        X2 = vextq_u32(X2, X2, 2);
        X3 = vextq_u32(X3, X3, 1);

        /* Operate on "rows". */
        T = vaddq_u32(X0, X1);
        X3 = veorq_u32(X3, vsriq_n_u32(vshlq_n_u32(T, 7), T, 25));
        T = vaddq_u32(X3, X0);
        X2 = veorq_u32(X2, vsriq_n_u32(vshlq_n_u32(T, 9), T, 23));
        T = vaddq_u32(X2, X3);
        X1 = veorq_u32(X1, vsriq_n_u32(vshlq_n_u32(T, 13), T, 19));
        T = vaddq_u32(X1, X2);
        X0 = veorq_u32(X0, vsriq_n_u32(vshlq_n_u32(T, 18), T, 14));

        /* Rearrange data back. */
        X1 = vextq_u32(X1, X1, 1);
        X2 = vextq_u32(X2, X2, 2);
        X3 = vextq_u32(X3, X3, 3);
    }

    B[0] = vaddq_u32(B[0], X0);
    B[1] = vaddq_u32(B[1], X1);
    B[2] = vaddq_u32(B[2], X2);
    B[3] = vaddq_u32(B[3], X3);
}

void scrypt_1024_1_1_256_sp_neon(const char *input, char *output, char *scratchpad)
{
    uint8_t B[128];
    union {
        uint32x4_t q[8];
        uint32_t u32[32];
    } X;
    uint32x4_t *V;
    uint32_t i, j, k;

    V = (uint32x4_t *)(((uintptr_t)(scratchpad) + 63) & ~(uintptr_t)(63));

    PBKDF2_SHA256((const uint8_t *)input, 80, (const uint8_t *)input, 80, 1, B, 128);

    for (k = 0; k < 2; k++) {
        for (i = 0; i < 16; i++) {
            X.u32[k * 16 + i] = le32dec(&B[(k * 16 + (i * 5 % 16)) * 4]);
        }
    }

    /* ROMix: fill the scratchpad V */
    for (i = 0; i < 1024; i++) {
        for (k = 0; k < 8; k++)
            V[i * 8 + k] = X.q[k];
        xor_salsa8_neon(&X.q[0], &X.q[4]);
        xor_salsa8_neon(&X.q[4], &X.q[0]);
    }

    /* ROMix: mix with random lookups */
    for (i = 0; i < 1024; i++) {
        j = 8 * (X.u32[16] & 1023);
        for (k = 0; k < 8; k++)
            X.q[k] = veorq_u32(X.q[k], V[j + k]);
        xor_salsa8_neon(&X.q[0], &X.q[4]);
        xor_salsa8_neon(&X.q[4], &X.q[0]);
    }

    for (k = 0; k < 2; k++) {
        for (i = 0; i < 16; i++) {
            le32enc(&B[(k * 16 + (i * 5 % 16)) * 4], X.u32[k * 16 + i]);
        }
    }

    PBKDF2_SHA256((const uint8_t *)input, 80, B, 128, 1, (uint8_t *)output, 32);
}
