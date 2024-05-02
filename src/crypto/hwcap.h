// Copyright (c) 2024 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CRYPTO_HWCAP_H
#define BITCOIN_CRYPTO_HWCAP_H

#if defined(USE_SSE2) && !defined(USE_SSE2_ALWAYS)
#ifdef _MSC_VER
// MSVC 64bit is unable to use inline asm
#include <intrin.h>
#else
// GCC Linux or i686-w64-mingw32
#include <compat/cpuid.h>
#endif
#endif

struct HardwareCapabilities {
  bool have_sse4;
  bool have_xsave;
  bool have_avx;
  bool has_sse2;
  bool have_avx2;
  bool have_arm_shani;
  bool have_x86_shani;
  bool enabled_avx;
};

HardwareCapabilities DetectHWCapabilities();

#endif // BITCOIN_CRYPTO_HWCAP_H
