// Copyright (c) 2014 The Bitcoin Core developers
// Copyright (c) 2022 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include "bitcoin-config.h"
#endif

#include "crypto/sha256.h"

#include "crypto/common.h"
#include "support/experimental.h"

#include <string.h>
#include <string>

#if (defined(__ia64__) || defined(__x86_64__)) && \
    !defined(__APPLE__) && \
    (defined(USE_AVX2))
#include <intel-ipsec-mb.h>
#endif

#if !defined(BUILD_BITCOIN_INTERNAL)
#if defined(USE_SHA256_SSE41) || defined(USE_SHA256_AVX2) || defined(USE_SHA256_SHANI) || defined(USE_AVX2)
#if defined(_MSC_VER)
#include <intrin.h>
#elif defined(__GNUC__) || defined(__clang__)
#include <cpuid.h>
#endif
#endif
#endif // !BUILD_BITCOIN_INTERNAL

// Internal implementation code.
namespace
{

uint32_t inline Ch(uint32_t x, uint32_t y, uint32_t z) { return z ^ (x & (y ^ z)); }
uint32_t inline Maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) | (z & (x | y)); }
uint32_t inline Sigma0(uint32_t x) { return (x >> 2 | x << 30) ^ (x >> 13 | x << 19) ^ (x >> 22 | x << 10); }
uint32_t inline Sigma1(uint32_t x) { return (x >> 6 | x << 26) ^ (x >> 11 | x << 21) ^ (x >> 25 | x << 7); }
uint32_t inline sigma0(uint32_t x) { return (x >> 7 | x << 25) ^ (x >> 18 | x << 14) ^ (x >> 3); }
uint32_t inline sigma1(uint32_t x) { return (x >> 17 | x << 15) ^ (x >> 19 | x << 13) ^ (x >> 10); }

/** One round of SHA-256. */
void inline Round(uint32_t a, uint32_t b, uint32_t c, uint32_t& d, uint32_t e, uint32_t f, uint32_t g, uint32_t& h, uint32_t k, uint32_t w)
{
    uint32_t t1 = h + Sigma1(e) + Ch(e, f, g) + k + w;
    uint32_t t2 = Sigma0(a) + Maj(a, b, c);
    d += t1;
    h = t1 + t2;
}

void inline Initialize(uint32_t* s)
{
    s[0] = 0x6a09e667ul;
    s[1] = 0xbb67ae85ul;
    s[2] = 0x3c6ef372ul;
    s[3] = 0xa54ff53aul;
    s[4] = 0x510e527ful;
    s[5] = 0x9b05688cul;
    s[6] = 0x1f83d9abul;
    s[7] = 0x5be0cd19ul;
}

} // namespace

void sha256::TransformGeneric(uint32_t* s, const unsigned char* chunk, size_t blocks)
{
    while (blocks--) {
        uint32_t a = s[0], b = s[1], c = s[2], d = s[3], e = s[4], f = s[5], g = s[6], h = s[7];
        uint32_t w0, w1, w2, w3, w4, w5, w6, w7, w8, w9, w10, w11, w12, w13, w14, w15;

        Round(a, b, c, d, e, f, g, h, 0x428a2f98, w0 = ReadBE32(chunk + 0));
        Round(h, a, b, c, d, e, f, g, 0x71374491, w1 = ReadBE32(chunk + 4));
        Round(g, h, a, b, c, d, e, f, 0xb5c0fbcf, w2 = ReadBE32(chunk + 8));
        Round(f, g, h, a, b, c, d, e, 0xe9b5dba5, w3 = ReadBE32(chunk + 12));
        Round(e, f, g, h, a, b, c, d, 0x3956c25b, w4 = ReadBE32(chunk + 16));
        Round(d, e, f, g, h, a, b, c, 0x59f111f1, w5 = ReadBE32(chunk + 20));
        Round(c, d, e, f, g, h, a, b, 0x923f82a4, w6 = ReadBE32(chunk + 24));
        Round(b, c, d, e, f, g, h, a, 0xab1c5ed5, w7 = ReadBE32(chunk + 28));
        Round(a, b, c, d, e, f, g, h, 0xd807aa98, w8 = ReadBE32(chunk + 32));
        Round(h, a, b, c, d, e, f, g, 0x12835b01, w9 = ReadBE32(chunk + 36));
        Round(g, h, a, b, c, d, e, f, 0x243185be, w10 = ReadBE32(chunk + 40));
        Round(f, g, h, a, b, c, d, e, 0x550c7dc3, w11 = ReadBE32(chunk + 44));
        Round(e, f, g, h, a, b, c, d, 0x72be5d74, w12 = ReadBE32(chunk + 48));
        Round(d, e, f, g, h, a, b, c, 0x80deb1fe, w13 = ReadBE32(chunk + 52));
        Round(c, d, e, f, g, h, a, b, 0x9bdc06a7, w14 = ReadBE32(chunk + 56));
        Round(b, c, d, e, f, g, h, a, 0xc19bf174, w15 = ReadBE32(chunk + 60));

        Round(a, b, c, d, e, f, g, h, 0xe49b69c1, w0 += sigma1(w14) + w9 + sigma0(w1));
        Round(h, a, b, c, d, e, f, g, 0xefbe4786, w1 += sigma1(w15) + w10 + sigma0(w2));
        Round(g, h, a, b, c, d, e, f, 0x0fc19dc6, w2 += sigma1(w0) + w11 + sigma0(w3));
        Round(f, g, h, a, b, c, d, e, 0x240ca1cc, w3 += sigma1(w1) + w12 + sigma0(w4));
        Round(e, f, g, h, a, b, c, d, 0x2de92c6f, w4 += sigma1(w2) + w13 + sigma0(w5));
        Round(d, e, f, g, h, a, b, c, 0x4a7484aa, w5 += sigma1(w3) + w14 + sigma0(w6));
        Round(c, d, e, f, g, h, a, b, 0x5cb0a9dc, w6 += sigma1(w4) + w15 + sigma0(w7));
        Round(b, c, d, e, f, g, h, a, 0x76f988da, w7 += sigma1(w5) + w0 + sigma0(w8));
        Round(a, b, c, d, e, f, g, h, 0x983e5152, w8 += sigma1(w6) + w1 + sigma0(w9));
        Round(h, a, b, c, d, e, f, g, 0xa831c66d, w9 += sigma1(w7) + w2 + sigma0(w10));
        Round(g, h, a, b, c, d, e, f, 0xb00327c8, w10 += sigma1(w8) + w3 + sigma0(w11));
        Round(f, g, h, a, b, c, d, e, 0xbf597fc7, w11 += sigma1(w9) + w4 + sigma0(w12));
        Round(e, f, g, h, a, b, c, d, 0xc6e00bf3, w12 += sigma1(w10) + w5 + sigma0(w13));
        Round(d, e, f, g, h, a, b, c, 0xd5a79147, w13 += sigma1(w11) + w6 + sigma0(w14));
        Round(c, d, e, f, g, h, a, b, 0x06ca6351, w14 += sigma1(w12) + w7 + sigma0(w15));
        Round(b, c, d, e, f, g, h, a, 0x14292967, w15 += sigma1(w13) + w8 + sigma0(w0));

        Round(a, b, c, d, e, f, g, h, 0x27b70a85, w0 += sigma1(w14) + w9 + sigma0(w1));
        Round(h, a, b, c, d, e, f, g, 0x2e1b2138, w1 += sigma1(w15) + w10 + sigma0(w2));
        Round(g, h, a, b, c, d, e, f, 0x4d2c6dfc, w2 += sigma1(w0) + w11 + sigma0(w3));
        Round(f, g, h, a, b, c, d, e, 0x53380d13, w3 += sigma1(w1) + w12 + sigma0(w4));
        Round(e, f, g, h, a, b, c, d, 0x650a7354, w4 += sigma1(w2) + w13 + sigma0(w5));
        Round(d, e, f, g, h, a, b, c, 0x766a0abb, w5 += sigma1(w3) + w14 + sigma0(w6));
        Round(c, d, e, f, g, h, a, b, 0x81c2c92e, w6 += sigma1(w4) + w15 + sigma0(w7));
        Round(b, c, d, e, f, g, h, a, 0x92722c85, w7 += sigma1(w5) + w0 + sigma0(w8));
        Round(a, b, c, d, e, f, g, h, 0xa2bfe8a1, w8 += sigma1(w6) + w1 + sigma0(w9));
        Round(h, a, b, c, d, e, f, g, 0xa81a664b, w9 += sigma1(w7) + w2 + sigma0(w10));
        Round(g, h, a, b, c, d, e, f, 0xc24b8b70, w10 += sigma1(w8) + w3 + sigma0(w11));
        Round(f, g, h, a, b, c, d, e, 0xc76c51a3, w11 += sigma1(w9) + w4 + sigma0(w12));
        Round(e, f, g, h, a, b, c, d, 0xd192e819, w12 += sigma1(w10) + w5 + sigma0(w13));
        Round(d, e, f, g, h, a, b, c, 0xd6990624, w13 += sigma1(w11) + w6 + sigma0(w14));
        Round(c, d, e, f, g, h, a, b, 0xf40e3585, w14 += sigma1(w12) + w7 + sigma0(w15));
        Round(b, c, d, e, f, g, h, a, 0x106aa070, w15 += sigma1(w13) + w8 + sigma0(w0));

        Round(a, b, c, d, e, f, g, h, 0x19a4c116, w0 += sigma1(w14) + w9 + sigma0(w1));
        Round(h, a, b, c, d, e, f, g, 0x1e376c08, w1 += sigma1(w15) + w10 + sigma0(w2));
        Round(g, h, a, b, c, d, e, f, 0x2748774c, w2 += sigma1(w0) + w11 + sigma0(w3));
        Round(f, g, h, a, b, c, d, e, 0x34b0bcb5, w3 += sigma1(w1) + w12 + sigma0(w4));
        Round(e, f, g, h, a, b, c, d, 0x391c0cb3, w4 += sigma1(w2) + w13 + sigma0(w5));
        Round(d, e, f, g, h, a, b, c, 0x4ed8aa4a, w5 += sigma1(w3) + w14 + sigma0(w6));
        Round(c, d, e, f, g, h, a, b, 0x5b9cca4f, w6 += sigma1(w4) + w15 + sigma0(w7));
        Round(b, c, d, e, f, g, h, a, 0x682e6ff3, w7 += sigma1(w5) + w0 + sigma0(w8));
        Round(a, b, c, d, e, f, g, h, 0x748f82ee, w8 += sigma1(w6) + w1 + sigma0(w9));
        Round(h, a, b, c, d, e, f, g, 0x78a5636f, w9 += sigma1(w7) + w2 + sigma0(w10));
        Round(g, h, a, b, c, d, e, f, 0x84c87814, w10 += sigma1(w8) + w3 + sigma0(w11));
        Round(f, g, h, a, b, c, d, e, 0x8cc70208, w11 += sigma1(w9) + w4 + sigma0(w12));
        Round(e, f, g, h, a, b, c, d, 0x90befffa, w12 += sigma1(w10) + w5 + sigma0(w13));
        Round(d, e, f, g, h, a, b, c, 0xa4506ceb, w13 += sigma1(w11) + w6 + sigma0(w14));
        Round(c, d, e, f, g, h, a, b, 0xbef9a3f7, w14 += sigma1(w12) + w7 + sigma0(w15));
        Round(b, c, d, e, f, g, h, a, 0xc67178f2, w15 += sigma1(w13) + w8 + sigma0(w0));

        s[0] += a;
        s[1] += b;
        s[2] += c;
        s[3] += d;
        s[4] += e;
        s[5] += f;
        s[6] += g;
        s[7] += h;
        chunk += 64;
    }
}

/** The selected Transform function pointer, initialized to generic. */
TransformType sha256_transform = sha256::TransformGeneric;

#if !defined(BUILD_BITCOIN_INTERNAL)
#if defined(USE_SHA256_SSE41) || defined(USE_SHA256_AVX2) || defined(USE_SHA256_SHANI) || defined(USE_AVX2)
static inline void GetCPUID(uint32_t leaf, uint32_t subleaf, uint32_t& eax, uint32_t& ebx, uint32_t& ecx, uint32_t& edx)
{
#if defined(_MSC_VER)
    int cpuinfo[4];
    __cpuidex(cpuinfo, (int)leaf, (int)subleaf);
    eax = (uint32_t)cpuinfo[0];
    ebx = (uint32_t)cpuinfo[1];
    ecx = (uint32_t)cpuinfo[2];
    edx = (uint32_t)cpuinfo[3];
#else
    __cpuid_count(leaf, subleaf, eax, ebx, ecx, edx);
#endif
}
#endif

// Intel IPSec_MB AVX2 wrapper (experimental: --with-intel-avx2)
#if (defined(__ia64__) || defined(__x86_64__)) && \
    !defined(__APPLE__) && defined(USE_AVX2)
static void TransformIPSecMBAVX2(uint32_t* s, const unsigned char* chunk, size_t blocks)
{
    EXPERIMENTAL_FEATURE
    while (blocks--) {
        sha256_one_block_avx2(chunk, s);
        chunk += 64;
    }
}
#endif

#endif // !BUILD_BITCOIN_INTERNAL

std::string CSHA256::AutoDetect()
{
#if !defined(BUILD_BITCOIN_INTERNAL)
#if defined(USE_SHA256_SSE41) || defined(USE_SHA256_AVX2) || defined(USE_SHA256_SHANI) || defined(USE_AVX2)
    uint32_t eax, ebx, ecx, edx;
    GetCPUID(1, 0, eax, ebx, ecx, edx);
    bool have_sse41 = (ecx >> 19) & 1;
    bool have_xsave = (ecx >> 27) & 1;
    bool have_avx = (ecx >> 28) & 1;
    (void)have_sse41;
    (void)have_xsave;
    (void)have_avx;

    uint32_t eax7 = 0, ebx7 = 0, ecx7 = 0, edx7 = 0;
    GetCPUID(7, 0, eax7, ebx7, ecx7, edx7);
    bool have_avx2 = (ebx7 >> 5) & 1;
    bool have_shani = (ebx7 >> 29) & 1;
    (void)have_avx2;
    (void)have_shani;

#if defined(USE_SHA256_SHANI)
    if (have_shani) {
        sha256_transform = sha256::TransformSHANI;
        return "shani";
    }
#endif
#if (defined(__ia64__) || defined(__x86_64__)) && !defined(__APPLE__) && defined(USE_AVX2)
    if (have_avx2 && have_avx && have_xsave) {
        sha256_transform = TransformIPSecMBAVX2;
        return "avx2 (intel-ipsec-mb)";
    }
#endif
#if defined(USE_SHA256_AVX2)
    if (have_avx2 && have_avx && have_xsave) {
        sha256_transform = sha256::TransformAVX2;
        return "avx2";
    }
#endif
#if defined(USE_SHA256_SSE41)
    if (have_sse41) {
        sha256_transform = sha256::TransformSSE41;
        return "sse4";
    }
#endif
#endif // x86 SIMD checks

#if defined(USE_ARMV8) || defined(USE_ARMV82)
    EXPERIMENTAL_FEATURE
    sha256_transform = sha256::TransformARMv8;
    return "armv8";
#endif
#endif // !BUILD_BITCOIN_INTERNAL

    sha256_transform = sha256::TransformGeneric;
    return "generic";
}


////// SHA-256

CSHA256::CSHA256() : bytes(0)
{
    Initialize(s);
}

CSHA256& CSHA256::Write(const unsigned char* data, size_t len)
{
    const unsigned char* end = data + len;
    size_t bufsize = bytes % 64;
    if (bufsize && bufsize + len >= 64) {
        // Fill the buffer, and process it.
        memcpy(buf + bufsize, data, 64 - bufsize);
        bytes += 64 - bufsize;
        data += 64 - bufsize;
        sha256_transform(s, buf, 1);
        bufsize = 0;
    }
    if (end - data >= 64) {
        size_t nblocks = (end - data) / 64;
        sha256_transform(s, data, nblocks);
        data += 64 * nblocks;
        bytes += 64 * nblocks;
    }
    if (end > data) {
        // Fill the buffer with what remains.
        memcpy(buf + bufsize, data, end - data);
        bytes += end - data;
    }
    return *this;
}

void CSHA256::Finalize(unsigned char hash[OUTPUT_SIZE])
{
    static const unsigned char pad[64] = {0x80};
    unsigned char sizedesc[8];
    WriteBE64(sizedesc, bytes << 3);
    Write(pad, 1 + ((119 - (bytes % 64)) % 64));
    Write(sizedesc, 8);
    WriteBE32(hash, s[0]);
    WriteBE32(hash + 4, s[1]);
    WriteBE32(hash + 8, s[2]);
    WriteBE32(hash + 12, s[3]);
    WriteBE32(hash + 16, s[4]);
    WriteBE32(hash + 20, s[5]);
    WriteBE32(hash + 24, s[6]);
    WriteBE32(hash + 28, s[7]);
}

CSHA256& CSHA256::Reset()
{
    bytes = 0;
    Initialize(s);
    return *this;
}
