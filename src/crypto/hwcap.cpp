// Copyright (c) 2024 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "crypto/hwcap.h"
#include "support/experimental.h"

#if defined(HAVE_CONFIG_H)
#include "bitcoin-config.h" // for USE_SSE2
#endif

HardwareCapabilities DetectHWCapabilities()
{
 HardwareCapabilities capabilities;
 capabilities.has_sse2 = false;

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
    GetCPUID(1, 0, &eax, &ebx, &ecx, &edx);
#endif // _MSC_VER

// detect SSE2
#if defined(USE_SSE2)
    EXPERIMENTAL_FEATURE
    capabilities.has_sse2 = (edx & 1<<26);
#endif // USE_SSE2
#endif // HAVE_GETCPUID
    return capabilities;

}
