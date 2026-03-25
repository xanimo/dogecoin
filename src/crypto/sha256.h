// Copyright (c) 2014-2016 The Bitcoin Core developers
// Copyright (c) 2022 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CRYPTO_SHA256_H
#define BITCOIN_CRYPTO_SHA256_H

#include <stdint.h>
#include <stdlib.h>
#include <string>

/** A hasher class for SHA-256. */
class CSHA256
{
private:
    uint32_t s[8];
    unsigned char buf[64];
    uint64_t bytes;

public:
    static const size_t OUTPUT_SIZE = 32;

    CSHA256();
    CSHA256& Write(const unsigned char* data, size_t len);
    void Finalize(unsigned char hash[OUTPUT_SIZE]);
    CSHA256& Reset();

    /** Detect the best available SHA-256 implementation. Returns a string
     *  describing the selected backend (e.g. "sse4", "avx2", "shani", "armv8", "generic").
     *  Must be called once at startup before any hashing. */
    static std::string AutoDetect();
};

/** SHA-256 Transform function type. Processes one 64-byte block. */
typedef void (*TransformType)(uint32_t* s, const unsigned char* chunk, size_t blocks);

/** Implementations in separate translation units. */
namespace sha256 {
void TransformGeneric(uint32_t* s, const unsigned char* chunk, size_t blocks);
void TransformSSE41(uint32_t* s, const unsigned char* chunk, size_t blocks);
void TransformAVX2(uint32_t* s, const unsigned char* chunk, size_t blocks);
void TransformSHANI(uint32_t* s, const unsigned char* chunk, size_t blocks);
void TransformARMv8(uint32_t* s, const unsigned char* chunk, size_t blocks);
}

#endif // BITCOIN_CRYPTO_SHA256_H
