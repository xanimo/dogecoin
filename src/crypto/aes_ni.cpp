// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// AES-NI accelerated AES-128/256 helpers.
// Compiled with -maes in its own translation unit.

#include "crypto/aes_ni.h"
#include <wmmintrin.h>
#include <smmintrin.h>
#include <string.h>

// ======== AES-128 Key Expansion ========

static inline __m128i aes128_key_expand_assist(__m128i key, __m128i keygen)
{
    keygen = _mm_shuffle_epi32(keygen, 0xFF);
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    return _mm_xor_si128(key, keygen);
}

void aes128_expand_key_ni(const unsigned char key[16], unsigned char round_keys[176])
{
    __m128i* rk = (__m128i*)round_keys;
    rk[0] = _mm_loadu_si128((const __m128i*)key);
    rk[1] = aes128_key_expand_assist(rk[0], _mm_aeskeygenassist_si128(rk[0], 0x01));
    rk[2] = aes128_key_expand_assist(rk[1], _mm_aeskeygenassist_si128(rk[1], 0x02));
    rk[3] = aes128_key_expand_assist(rk[2], _mm_aeskeygenassist_si128(rk[2], 0x04));
    rk[4] = aes128_key_expand_assist(rk[3], _mm_aeskeygenassist_si128(rk[3], 0x08));
    rk[5] = aes128_key_expand_assist(rk[4], _mm_aeskeygenassist_si128(rk[4], 0x10));
    rk[6] = aes128_key_expand_assist(rk[5], _mm_aeskeygenassist_si128(rk[5], 0x20));
    rk[7] = aes128_key_expand_assist(rk[6], _mm_aeskeygenassist_si128(rk[6], 0x40));
    rk[8] = aes128_key_expand_assist(rk[7], _mm_aeskeygenassist_si128(rk[7], 0x80));
    rk[9] = aes128_key_expand_assist(rk[8], _mm_aeskeygenassist_si128(rk[8], 0x1B));
    rk[10] = aes128_key_expand_assist(rk[9], _mm_aeskeygenassist_si128(rk[9], 0x36));
}

void aes128_encrypt_ni(const unsigned char* round_keys, const unsigned char* plaintext, unsigned char* ciphertext)
{
    const __m128i* rk = (const __m128i*)round_keys;
    __m128i block = _mm_loadu_si128((const __m128i*)plaintext);

    block = _mm_xor_si128(block, rk[0]);
    block = _mm_aesenc_si128(block, rk[1]);
    block = _mm_aesenc_si128(block, rk[2]);
    block = _mm_aesenc_si128(block, rk[3]);
    block = _mm_aesenc_si128(block, rk[4]);
    block = _mm_aesenc_si128(block, rk[5]);
    block = _mm_aesenc_si128(block, rk[6]);
    block = _mm_aesenc_si128(block, rk[7]);
    block = _mm_aesenc_si128(block, rk[8]);
    block = _mm_aesenc_si128(block, rk[9]);
    block = _mm_aesenclast_si128(block, rk[10]);

    _mm_storeu_si128((__m128i*)ciphertext, block);
}

void aes128_decrypt_ni(const unsigned char* round_keys, const unsigned char* ciphertext, unsigned char* plaintext)
{
    const __m128i* rk = (const __m128i*)round_keys;
    __m128i block = _mm_loadu_si128((const __m128i*)ciphertext);

    block = _mm_xor_si128(block, rk[10]);
    block = _mm_aesdec_si128(block, _mm_aesimc_si128(rk[9]));
    block = _mm_aesdec_si128(block, _mm_aesimc_si128(rk[8]));
    block = _mm_aesdec_si128(block, _mm_aesimc_si128(rk[7]));
    block = _mm_aesdec_si128(block, _mm_aesimc_si128(rk[6]));
    block = _mm_aesdec_si128(block, _mm_aesimc_si128(rk[5]));
    block = _mm_aesdec_si128(block, _mm_aesimc_si128(rk[4]));
    block = _mm_aesdec_si128(block, _mm_aesimc_si128(rk[3]));
    block = _mm_aesdec_si128(block, _mm_aesimc_si128(rk[2]));
    block = _mm_aesdec_si128(block, _mm_aesimc_si128(rk[1]));
    block = _mm_aesdeclast_si128(block, rk[0]);

    _mm_storeu_si128((__m128i*)plaintext, block);
}

// ======== AES-256 Key Expansion ========

static inline __m128i aes256_key_expand_1(__m128i key, __m128i keygen)
{
    keygen = _mm_shuffle_epi32(keygen, 0xFF);
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    return _mm_xor_si128(key, keygen);
}

static inline __m128i aes256_key_expand_2(__m128i key, __m128i keygen)
{
    keygen = _mm_shuffle_epi32(_mm_aeskeygenassist_si128(keygen, 0x00), 0xAA);
    __m128i tmp = _mm_slli_si128(key, 4);
    key = _mm_xor_si128(key, tmp);
    tmp = _mm_slli_si128(tmp, 4);
    key = _mm_xor_si128(key, tmp);
    tmp = _mm_slli_si128(tmp, 4);
    key = _mm_xor_si128(key, tmp);
    return _mm_xor_si128(key, keygen);
}

void aes256_expand_key_ni(const unsigned char key[32], unsigned char round_keys[240])
{
    __m128i* rk = (__m128i*)round_keys;
    rk[0] = _mm_loadu_si128((const __m128i*)key);
    rk[1] = _mm_loadu_si128((const __m128i*)(key + 16));

    rk[2] = aes256_key_expand_1(rk[0], _mm_aeskeygenassist_si128(rk[1], 0x01));
    rk[3] = aes256_key_expand_2(rk[1], rk[2]);
    rk[4] = aes256_key_expand_1(rk[2], _mm_aeskeygenassist_si128(rk[3], 0x02));
    rk[5] = aes256_key_expand_2(rk[3], rk[4]);
    rk[6] = aes256_key_expand_1(rk[4], _mm_aeskeygenassist_si128(rk[5], 0x04));
    rk[7] = aes256_key_expand_2(rk[5], rk[6]);
    rk[8] = aes256_key_expand_1(rk[6], _mm_aeskeygenassist_si128(rk[7], 0x08));
    rk[9] = aes256_key_expand_2(rk[7], rk[8]);
    rk[10] = aes256_key_expand_1(rk[8], _mm_aeskeygenassist_si128(rk[9], 0x10));
    rk[11] = aes256_key_expand_2(rk[9], rk[10]);
    rk[12] = aes256_key_expand_1(rk[10], _mm_aeskeygenassist_si128(rk[11], 0x20));
    rk[13] = aes256_key_expand_2(rk[11], rk[12]);
    rk[14] = aes256_key_expand_1(rk[12], _mm_aeskeygenassist_si128(rk[13], 0x40));
}

void aes256_encrypt_ni(const unsigned char* round_keys, const unsigned char* plaintext, unsigned char* ciphertext)
{
    const __m128i* rk = (const __m128i*)round_keys;
    __m128i block = _mm_loadu_si128((const __m128i*)plaintext);

    block = _mm_xor_si128(block, rk[0]);
    block = _mm_aesenc_si128(block, rk[1]);
    block = _mm_aesenc_si128(block, rk[2]);
    block = _mm_aesenc_si128(block, rk[3]);
    block = _mm_aesenc_si128(block, rk[4]);
    block = _mm_aesenc_si128(block, rk[5]);
    block = _mm_aesenc_si128(block, rk[6]);
    block = _mm_aesenc_si128(block, rk[7]);
    block = _mm_aesenc_si128(block, rk[8]);
    block = _mm_aesenc_si128(block, rk[9]);
    block = _mm_aesenc_si128(block, rk[10]);
    block = _mm_aesenc_si128(block, rk[11]);
    block = _mm_aesenc_si128(block, rk[12]);
    block = _mm_aesenc_si128(block, rk[13]);
    block = _mm_aesenclast_si128(block, rk[14]);

    _mm_storeu_si128((__m128i*)ciphertext, block);
}

void aes256_decrypt_ni(const unsigned char* round_keys, const unsigned char* ciphertext, unsigned char* plaintext)
{
    const __m128i* rk = (const __m128i*)round_keys;
    __m128i block = _mm_loadu_si128((const __m128i*)ciphertext);

    block = _mm_xor_si128(block, rk[14]);
    block = _mm_aesdec_si128(block, _mm_aesimc_si128(rk[13]));
    block = _mm_aesdec_si128(block, _mm_aesimc_si128(rk[12]));
    block = _mm_aesdec_si128(block, _mm_aesimc_si128(rk[11]));
    block = _mm_aesdec_si128(block, _mm_aesimc_si128(rk[10]));
    block = _mm_aesdec_si128(block, _mm_aesimc_si128(rk[9]));
    block = _mm_aesdec_si128(block, _mm_aesimc_si128(rk[8]));
    block = _mm_aesdec_si128(block, _mm_aesimc_si128(rk[7]));
    block = _mm_aesdec_si128(block, _mm_aesimc_si128(rk[6]));
    block = _mm_aesdec_si128(block, _mm_aesimc_si128(rk[5]));
    block = _mm_aesdec_si128(block, _mm_aesimc_si128(rk[4]));
    block = _mm_aesdec_si128(block, _mm_aesimc_si128(rk[3]));
    block = _mm_aesdec_si128(block, _mm_aesimc_si128(rk[2]));
    block = _mm_aesdec_si128(block, _mm_aesimc_si128(rk[1]));
    block = _mm_aesdeclast_si128(block, rk[0]);

    _mm_storeu_si128((__m128i*)plaintext, block);
}
