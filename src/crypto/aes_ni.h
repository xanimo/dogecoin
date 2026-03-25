// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// AES-NI accelerated AES-128/256 encrypt/decrypt helpers.
// Compiled with -maes in its own translation unit.

#ifndef BITCOIN_CRYPTO_AES_NI_H
#define BITCOIN_CRYPTO_AES_NI_H

#include <stdint.h>

/** Encrypt a single 16-byte block with AES-256 using AES-NI.
 *  round_keys must point to 15 x 16 bytes of expanded key schedule. */
void aes256_encrypt_ni(const unsigned char* round_keys, const unsigned char* plaintext, unsigned char* ciphertext);

/** Decrypt a single 16-byte block with AES-256 using AES-NI.
 *  round_keys must point to 15 x 16 bytes of expanded key schedule (encryption order). */
void aes256_decrypt_ni(const unsigned char* round_keys, const unsigned char* ciphertext, unsigned char* plaintext);

/** Encrypt a single 16-byte block with AES-128 using AES-NI.
 *  round_keys must point to 11 x 16 bytes of expanded key schedule. */
void aes128_encrypt_ni(const unsigned char* round_keys, const unsigned char* plaintext, unsigned char* ciphertext);

/** Decrypt a single 16-byte block with AES-128 using AES-NI.
 *  round_keys must point to 11 x 16 bytes of expanded key schedule (encryption order). */
void aes128_decrypt_ni(const unsigned char* round_keys, const unsigned char* ciphertext, unsigned char* plaintext);

/** Expand a 256-bit key into 15 round keys for AES-NI.
 *  round_keys must point to 15 x 16 = 240 bytes. */
void aes256_expand_key_ni(const unsigned char key[32], unsigned char round_keys[240]);

/** Expand a 128-bit key into 11 round keys for AES-NI.
 *  round_keys must point to 11 x 16 = 176 bytes. */
void aes128_expand_key_ni(const unsigned char key[16], unsigned char round_keys[176]);

#endif // BITCOIN_CRYPTO_AES_NI_H
