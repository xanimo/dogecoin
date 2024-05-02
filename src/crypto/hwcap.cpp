// Copyright (c) 2024 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "crypto/hwcap.h"
#include "support/experimental.h"

#if defined(HAVE_CONFIG_H)
#include "bitcoin-config.h" // for USE_SSE2
#endif
#include <cstdint>

#if defined(USE_ASM) && (defined(__x86_64__) || defined(__amd64__) || defined(__i386__))
/** Check whether the OS has enabled AVX registers. */
bool AVXEnabled()
{
    uint32_t a, d;
    __asm__("xgetbv" : "=a"(a), "=d"(d) : "c"(0));
    return (a & 6) == 6;
}
#endif

HardwareCapabilities DetectHWCapabilities()
{
    HardwareCapabilities capabilities;
    capabilities.have_sse4 = false;
    capabilities.have_xsave = false;
    capabilities.have_avx = false;
    capabilities.has_sse2 = false;
    capabilities.have_avx2 = false;
    capabilities.have_arm_shani = false;
    capabilities.have_x86_shani = false;
    capabilities.enabled_avx = false;

// generic x86_64 and i686 detection
#if defined(HAVE_GETCPUID)
    uint32_t eax, ebx, ecx, edx=0;
    // 32bit x86 Linux or Windows, detect cpuid features
#if defined(_MSC_VER)
    // MSVC
    int x86cpuid[4];
    __cpuid(x86cpuid, 1);
    edx = (unsigned int)buffer[3];
#else // _MSC_VER
    // Linux or i686-w64-mingw32 (gcc-4.6.3)
    GetCPUID(1, 0, eax, ebx, ecx, edx);
#endif // _MSC_VER

// detect SSE2
#if defined(USE_SSE2)
    EXPERIMENTAL_FEATURE
    capabilities.has_sse2 = (edx & 1<<26);
#endif // USE_SSE2

#if defined(USE_ASM) && (defined(__x86_64__) || defined(__amd64__) || defined(__i386__))
    capabilities.have_sse4 = (ecx >> 19) & 1;
    capabilities.have_xsave = (ecx >> 27) & 1;
    capabilities.have_avx = (ecx >> 28) & 1;
    if (capabilities.have_xsave && capabilities.have_avx) {
        capabilities.enabled_avx = AVXEnabled();
    }

    if (capabilities.have_sse4) {
        GetCPUID(7, 0, eax, ebx, ecx, edx);
        capabilities.have_avx2 = (ebx >> 5) & 1;
        capabilities.have_x86_shani = (ebx >> 29) & 1;
    }
#if defined(ENABLE_X86_SHANI) && !defined(BUILD_BITCOIN_INTERNAL)
    if (capabilities.have_x86_shani) {
        capabilities.have_sse4 = false; // Disable SSE4/AVX2;
        capabilities.have_avx2 = false;
    }
#endif
#endif // defined(USE_ASM) && defined(HAVE_GETCPUID)

#if defined(ENABLE_ARM_SHANI) && !defined(BUILD_BITCOIN_INTERNAL)
#if defined(__linux__)
#if defined(__arm__) // 32-bit
    if (getauxval(AT_HWCAP2) & HWCAP2_SHA2) {
        capabilities.have_arm_shani = true;
    }
#endif
#if defined(__aarch64__) // 64-bit
    if (getauxval(AT_HWCAP) & HWCAP_SHA2) {
        capabilities.have_arm_shani = true;
    }
#endif
#endif

#if defined(MAC_OSX)
    int val = 0;
    size_t len = sizeof(val);
    if (sysctlbyname("hw.optional.arm.FEAT_SHA256", &val, &len, nullptr, 0) == 0) {
        capabilities.have_arm_shani = val != 0;
    }
#endif
#endif

#endif // HAVE_GETCPUID
    return capabilities;
}
