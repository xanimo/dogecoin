// Copyright (c) 2011-2012 The Litecoin Core developers
// Copyright (c) 2013-2021 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CRYPTO_SCRYPT_H
#define BITCOIN_CRYPTO_SCRYPT_H
#include <stdlib.h>
#include <stdint.h>

#if defined(HAVE_CONFIG_H)
#include "bitcoin-config.h" // for USE_SSE2, USE_SCRYPT_AVX2, USE_SCRYPT_ARM_NEON
#endif

static const int SCRYPT_SCRATCHPAD_SIZE = 131072 + 63;

void scrypt_1024_1_1_256(const char *input, char *output);
void scrypt_1024_1_1_256_sp_generic(const char *input, char *output, char *scratchpad);

/* Backend declarations */
#if defined(USE_SSE2)
void scrypt_1024_1_1_256_sp_sse2(const char *input, char *output, char *scratchpad);
#endif

#if defined(USE_SCRYPT_AVX2)
void scrypt_1024_1_1_256_sp_avx2(const char *input, char *output, char *scratchpad);
#endif

#if defined(USE_SCRYPT_ARM_NEON)
void scrypt_1024_1_1_256_sp_neon(const char *input, char *output, char *scratchpad);
#endif

/*
 * Runtime dispatch: on x86_64, AVX2 > SSE2 > generic.
 * On ARM with NEON, use NEON directly. Otherwise, generic.
 */
#if defined(BUILD_BITCOIN_INTERNAL)
/* Consensus library: always use generic implementation */
#define scrypt_1024_1_1_256_sp(input, output, scratchpad) scrypt_1024_1_1_256_sp_generic((input), (output), (scratchpad))

#elif defined(USE_SCRYPT_AVX2) || (defined(USE_SSE2) && !defined(USE_SSE2_ALWAYS))
/* Runtime CPUID dispatch needed */
extern void (*scrypt_1024_1_1_256_sp_detected)(const char *input, char *output, char *scratchpad);
void scrypt_detect_best();
#define scrypt_1024_1_1_256_sp(input, output, scratchpad) scrypt_1024_1_1_256_sp_detected((input), (output), (scratchpad))

#elif defined(USE_SSE2) && (defined(_M_X64) || defined(__x86_64__) || defined(_M_AMD64) || (defined(MAC_OSX) && defined(__i386__)))
/* x86_64 with SSE2 always available, but no AVX2 compiled in — use SSE2 directly */
#define USE_SSE2_ALWAYS 1
#define scrypt_1024_1_1_256_sp(input, output, scratchpad) scrypt_1024_1_1_256_sp_sse2((input), (output), (scratchpad))

#elif defined(USE_SCRYPT_ARM_NEON)
/* ARM with NEON — use NEON directly */
#define scrypt_1024_1_1_256_sp(input, output, scratchpad) scrypt_1024_1_1_256_sp_neon((input), (output), (scratchpad))

#else
/* Fallback to generic */
#define scrypt_1024_1_1_256_sp(input, output, scratchpad) scrypt_1024_1_1_256_sp_generic((input), (output), (scratchpad))
#endif

void
PBKDF2_SHA256(const uint8_t *passwd, size_t passwdlen, const uint8_t *salt,
    size_t saltlen, uint64_t c, uint8_t *buf, size_t dkLen);

#ifndef __FreeBSD__
static inline uint32_t le32dec(const void *pp)
{
        const uint8_t *p = (uint8_t const *)pp;
        return ((uint32_t)(p[0]) + ((uint32_t)(p[1]) << 8) +
            ((uint32_t)(p[2]) << 16) + ((uint32_t)(p[3]) << 24));
}

static inline void le32enc(void *pp, uint32_t x)
{
        uint8_t *p = (uint8_t *)pp;
        p[0] = x & 0xff;
        p[1] = (x >> 8) & 0xff;
        p[2] = (x >> 16) & 0xff;
        p[3] = (x >> 24) & 0xff;
}
#endif
#endif // BITCOIN_CRYPTO_SCRYPT_H
