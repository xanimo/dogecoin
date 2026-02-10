// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "random.h"

#include "crypto/sha256.h"
#include "crypto/sha512.h"
#include "support/cleanse.h"
#include "sync.h"
#ifdef WIN32
#include "compat.h" // for Windows API
#include <wincrypt.h>
#endif
#include "util.h"             // for LogPrint()
#include "utilstrencodings.h" // for GetTime()

#include <stdlib.h>
#include <limits>
#include <chrono>
#include <mutex>
#include <thread>

#ifndef WIN32
#include <sys/time.h>
#endif

#ifdef HAVE_SYS_GETRANDOM
#include <sys/syscall.h>
#include <linux/random.h>
#endif
#if defined(HAVE_GETENTROPY)
#include <unistd.h>
#endif
#if defined(HAVE_GETENTROPY_RAND) && defined(MAC_OSX)
#include <sys/random.h>
#endif
#ifdef HAVE_SYSCTL_ARND
#include <sys/sysctl.h>
#endif

#if defined(__x86_64__) || defined(__amd64__) || defined(__i386__)
#include <cpuid.h>
#endif

static void RandFailure()
{
    LogPrintf("Failed to read randomness, aborting\n");
    abort();
}

static inline int64_t GetPerformanceCounter()
{
    // Read the hardware time stamp counter when available.
    // See https://en.wikipedia.org/wiki/Time_Stamp_Counter for more information.
#if defined(_MSC_VER) && (defined(_M_IX86) || defined(_M_X64))
    return __rdtsc();
#elif !defined(_MSC_VER) && defined(__i386__)
    uint64_t r = 0;
    __asm__ volatile ("rdtsc" : "=A"(r)); // Constrain the r variable to the eax:edx pair.
    return r;
#elif !defined(_MSC_VER) && (defined(__x86_64__) || defined(__amd64__))
    uint64_t r1 = 0, r2 = 0;
    __asm__ volatile ("rdtsc" : "=a"(r1), "=d"(r2)); // Constrain r1 to rax and r2 to rdx.
    return (r2 << 32) | r1;
#else
    // Fall back to using C++11 clock (usually microsecond or nanosecond precision)
    return std::chrono::high_resolution_clock::now().time_since_epoch().count();
#endif
}


#if defined(__x86_64__) || defined(__amd64__) || defined(__i386__)
static std::atomic<bool> hwrand_initialized{false};
static bool rdrand_supported = false;
static constexpr uint32_t CPUID_F1_ECX_RDRAND = 0x40000000;
static void RDRandInit()
{
    uint32_t eax, ebx, ecx, edx;
    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx) && (ecx & CPUID_F1_ECX_RDRAND)) {
        LogPrintf("Using RdRand as an additional entropy source\n");
        rdrand_supported = true;
    }
    hwrand_initialized.store(true);
}
#else
static void RDRandInit() {}
#endif

static bool GetHWRand(unsigned char* ent32) {
#if defined(__x86_64__) || defined(__amd64__) || defined(__i386__)
    assert(hwrand_initialized.load(std::memory_order_relaxed));
    if (rdrand_supported) {
        uint8_t ok;
        // Not all assemblers support the rdrand instruction, write it in hex.
#ifdef __i386__
        for (int iter = 0; iter < 4; ++iter) {
            uint32_t r1, r2;
            __asm__ volatile (".byte 0x0f, 0xc7, 0xf0;" // rdrand %eax
                              ".byte 0x0f, 0xc7, 0xf2;" // rdrand %edx
                              "setc %2" :
                              "=a"(r1), "=d"(r2), "=q"(ok) :: "cc");
            if (!ok) return false;
            WriteLE32(ent32 + 8 * iter, r1);
            WriteLE32(ent32 + 8 * iter + 4, r2);
        }
#else
        uint64_t r1, r2, r3, r4;
        __asm__ volatile (".byte 0x48, 0x0f, 0xc7, 0xf0, " // rdrand %rax
                                "0x48, 0x0f, 0xc7, 0xf3, " // rdrand %rbx
                                "0x48, 0x0f, 0xc7, 0xf1, " // rdrand %rcx
                                "0x48, 0x0f, 0xc7, 0xf2; " // rdrand %rdx
                          "setc %4" :
                          "=a"(r1), "=b"(r2), "=c"(r3), "=d"(r4), "=q"(ok) :: "cc");
        if (!ok) return false;
        WriteLE64(ent32, r1);
        WriteLE64(ent32 + 8, r2);
        WriteLE64(ent32 + 16, r3);
        WriteLE64(ent32 + 24, r4);
#endif
        return true;
    }
#endif
    return false;
}

static inline void SeedTimestamp(CSHA512& hasher)
{
    int64_t perfcounter = GetPerformanceCounter();
    hasher.Write((const unsigned char*)&perfcounter, sizeof(perfcounter));
}

static inline void SeedHWRand(CSHA512& hasher)
{
    unsigned char buf[32];
    if (GetHWRand(buf)) {
        hasher.Write(buf, sizeof(buf));
    }
}

// Forward declaration — defined after RNGState
static void InitHardwareRand();

/**
 * The RNG state class. This manages a global 256-bit state from which all
 * random output is derived. State transitions use SHA-512:
 *
 *   SHA-512(entropy || state || counter) => first 32 bytes = output
 *                                          last 32 bytes  = new state
 *
 * An event hasher (SHA-256) continuously accumulates entropy from P2P
 * message timestamps and other events, which is periodically drained
 * into the main state.
 */
class RNGState {
    CCriticalSection m_mutex;
    unsigned char m_state[32] GUARDED_BY(m_mutex) = {0};
    uint64_t m_counter GUARDED_BY(m_mutex) = 0;
    bool m_strongly_seeded GUARDED_BY(m_mutex) = false;

    CCriticalSection m_events_mutex;
    CSHA256 m_events_hasher GUARDED_BY(m_events_mutex);

public:
    RNGState() { InitHardwareRand(); }

    /** Accumulate entropy from an event (e.g. P2P message timing). */
    void AddEvent(uint32_t event_info)
    {
        LOCK(m_events_mutex);
        m_events_hasher.Write((const unsigned char*)&event_info, sizeof(event_info));
        // Also add a high-resolution timestamp — the precise timing of
        // each event is itself entropy.
        int64_t perfcounter = GetPerformanceCounter();
        m_events_hasher.Write((const unsigned char*)&perfcounter, sizeof(perfcounter));
    }

    /** Drain accumulated events entropy into an SHA-512 hasher. */
    void SeedEvents(CSHA512& hasher)
    {
        LOCK(m_events_mutex);
        unsigned char events_hash[32];
        m_events_hasher.Finalize(events_hash);
        hasher.Write(events_hash, 32);
        // Re-initialize hasher with finalized state for forward secrecy
        m_events_hasher.Reset();
        m_events_hasher.Write(events_hash, 32);
        memory_cleanse(events_hash, sizeof(events_hash));
    }

    /**
     * Mix entropy into the state and extract output.
     *
     * @param out        Pointer to output buffer (can be nullptr if num == 0)
     * @param num        Number of output bytes (must be <= 32)
     * @param hasher     SHA-512 hasher pre-loaded with entropy from various sources
     * @param strong_seed Whether the entropy included strong (OS-level) randomness
     * @return           Whether the RNG has ever been strongly seeded
     */
    bool MixExtract(unsigned char* out, size_t num, CSHA512&& hasher, bool strong_seed)
    {
        assert(num <= 32);
        unsigned char buf[64];
        bool ret;
        {
            LOCK(m_mutex);
            ret = (m_strongly_seeded |= strong_seed);
            // Mix current state into the hasher
            hasher.Write(m_state, 32);
            // Mix counter into the hasher
            hasher.Write((const unsigned char*)&m_counter, sizeof(m_counter));
            ++m_counter;
            // Finalize: 64 bytes of SHA-512 output
            hasher.Finalize(buf);
            // Last 32 bytes become new state
            memcpy(m_state, buf + 32, 32);
        }
        // First bytes are the output
        if (num) {
            assert(out != nullptr);
            memcpy(out, buf, num);
        }
        // Clean up
        memory_cleanse(buf, 64);
        return ret;
    }
};

static void InitHardwareRand()
{
    RDRandInit();
}

static RNGState& GetRNGState()
{
    static RNGState rng_state;
    return rng_state;
}

/** Seeding level for ProcRand. */
enum class RNGLevel {
    FAST,     //!< Automatically called by GetRandBytes; cheap, sub-microsecond
    SLOW,     //!< Automatically called by GetStrongRandBytes; includes OS entropy
    PERIODIC, //!< Called by RandAddPeriodic; includes environment and strengthening
};

/** FAST seeding: stack pointer + RDRAND + RDTSC. Very cheap. */
static void SeedFast(CSHA512& hasher)
{
    unsigned char buffer[32];
    // Use stack address as a source of per-call uniqueness
    const unsigned char* ptr = buffer;
    hasher.Write((const unsigned char*)&ptr, sizeof(ptr));
    SeedHWRand(hasher);
    SeedTimestamp(hasher);
}

/** SLOW seeding: everything from FAST plus OS entropy and accumulated events. */
static void SeedSlow(CSHA512& hasher, RNGState& rng)
{
    SeedFast(hasher);
    // 32 bytes from the OS CSPRNG (getrandom/CryptGenRandom/etc.)
    unsigned char buf[32];
    GetOSRand(buf);
    hasher.Write(buf, sizeof(buf));
    memory_cleanse(buf, sizeof(buf));
    // Drain accumulated event entropy
    rng.SeedEvents(hasher);
    SeedTimestamp(hasher);
}

/**
 * STARTUP seeding: heavy one-time seeding on first RNG use.
 * Mixes all available entropy sources and does key strengthening.
 */
static void SeedStartup(CSHA512& hasher, RNGState& rng)
{
#if defined(__x86_64__) || defined(__amd64__) || defined(__i386__)
    // Try to gather 256 bits from RDRAND with XOR folding for defense in depth
    if (rdrand_supported) {
        unsigned char hwbuf[32];
        for (int i = 0; i < 4; ++i) {
            unsigned char chunk[32];
            if (GetHWRand(chunk)) {
                for (int j = 0; j < 32; ++j) hwbuf[j] ^= chunk[j];
            }
        }
        hasher.Write(hwbuf, sizeof(hwbuf));
        memory_cleanse(hwbuf, sizeof(hwbuf));
    }
#endif
    // Full slow seed (OS + events + HW + timing)
    SeedSlow(hasher, rng);

    // Strengthen: repeatedly hash for ~100ms to make brute-forcing the seed expensive
    int64_t stop = GetPerformanceCounter();
    hasher.Write((const unsigned char*)&stop, sizeof(stop));

    CSHA512 inner_hasher;
    unsigned char inner_buf[64];
    auto start_time = std::chrono::steady_clock::now();
    do {
        for (int i = 0; i < 1000; ++i) {
            inner_hasher.Finalize(inner_buf);
            inner_hasher.Reset();
            inner_hasher.Write(inner_buf, sizeof(inner_buf));
        }
        // Mix in timestamps along the way
        int64_t perf = GetPerformanceCounter();
        hasher.Write((const unsigned char*)&perf, sizeof(perf));
    } while (std::chrono::steady_clock::now() < start_time + std::chrono::milliseconds(100));
    inner_hasher.Finalize(inner_buf);
    hasher.Write(inner_buf, sizeof(inner_buf));
    memory_cleanse(inner_buf, sizeof(inner_buf));
}

/**
 * PERIODIC seeding: called every ~60 seconds by the scheduler.
 * Mixes OS entropy, events, and does moderate strengthening.
 */
static void SeedPeriodic(CSHA512& hasher, RNGState& rng)
{
    SeedSlow(hasher, rng);

    // Strengthen: repeatedly hash for ~10ms
    CSHA512 inner_hasher;
    unsigned char inner_buf[64];
    auto start_time = std::chrono::steady_clock::now();
    do {
        for (int i = 0; i < 1000; ++i) {
            inner_hasher.Finalize(inner_buf);
            inner_hasher.Reset();
            inner_hasher.Write(inner_buf, sizeof(inner_buf));
        }
        int64_t perf = GetPerformanceCounter();
        hasher.Write((const unsigned char*)&perf, sizeof(perf));
    } while (std::chrono::steady_clock::now() < start_time + std::chrono::milliseconds(10));
    inner_hasher.Finalize(inner_buf);
    hasher.Write(inner_buf, sizeof(inner_buf));
    memory_cleanse(inner_buf, sizeof(inner_buf));
}

/**
 * Core RNG processing function. Gathers entropy at the requested level,
 * mixes it into the global state, and extracts output bytes.
 */
static void ProcRand(unsigned char* out, int num, RNGLevel level)
{
    RNGState& rng = GetRNGState();
    assert(num <= 32);

    CSHA512 hasher;
    switch (level) {
    case RNGLevel::FAST:
        SeedFast(hasher);
        break;
    case RNGLevel::SLOW:
        SeedSlow(hasher, rng);
        break;
    case RNGLevel::PERIODIC:
        SeedPeriodic(hasher, rng);
        break;
    }

    // Mix and extract; if this is the first call ever, also do startup seeding
    if (!rng.MixExtract(out, num, std::move(hasher), level == RNGLevel::SLOW)) {
        // Not yet strongly seeded — do heavy startup seeding
        CSHA512 startup_hasher;
        SeedStartup(startup_hasher, rng);
        rng.MixExtract(out, num, std::move(startup_hasher), /*strong_seed=*/true);
    }
}

#ifndef WIN32
/** Fallback: get 32 bytes of system entropy from /dev/urandom. The most
 * compatible way to get cryptographic randomness on UNIX-ish platforms.
 */
void GetDevURandom(unsigned char *ent32)
{
    int f = open("/dev/urandom", O_RDONLY);
    if (f == -1) {
        RandFailure();
    }
    int have = 0;
    do {
        ssize_t n = read(f, ent32 + have, NUM_OS_RANDOM_BYTES - have);
        if (n <= 0 || n + have > NUM_OS_RANDOM_BYTES) {
            close(f);
            RandFailure();
        }
        have += n;
    } while (have < NUM_OS_RANDOM_BYTES);
    close(f);
}
#endif

/** Get 32 bytes of system entropy. */
void GetOSRand(unsigned char *ent32)
{
#if defined(WIN32)
    HCRYPTPROV hProvider;
    int ret = CryptAcquireContextW(&hProvider, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
    if (!ret) {
        RandFailure();
    }
    ret = CryptGenRandom(hProvider, NUM_OS_RANDOM_BYTES, ent32);
    if (!ret) {
        RandFailure();
    }
    CryptReleaseContext(hProvider, 0);
#elif defined(HAVE_SYS_GETRANDOM)
    /* Linux. From the getrandom(2) man page:
     * "If the urandom source has been initialized, reads of up to 256 bytes
     * will always return as many bytes as requested and will not be
     * interrupted by signals."
     */
    int rv = syscall(SYS_getrandom, ent32, NUM_OS_RANDOM_BYTES, 0);
    if (rv != NUM_OS_RANDOM_BYTES) {
        if (rv < 0 && errno == ENOSYS) {
            /* Fallback for kernel <3.17: the return value will be -1 and errno
             * ENOSYS if the syscall is not available, in that case fall back
             * to /dev/urandom.
             */
            GetDevURandom(ent32);
        } else {
            RandFailure();
        }
    }
#elif defined(HAVE_GETENTROPY)
    /* On OpenBSD this can return up to 256 bytes of entropy, will return an
     * error if more are requested.
     * The call cannot return less than the requested number of bytes.
     */
    if (getentropy(ent32, NUM_OS_RANDOM_BYTES) != 0) {
        RandFailure();
    }
#elif defined(HAVE_GETENTROPY_RAND) && defined(MAC_OSX)
    // We need a fallback for OSX < 10.12
    if (&getentropy != nullptr) {
        if (getentropy(ent32, NUM_OS_RANDOM_BYTES) != 0) {
            RandFailure();
        }
    } else {
        GetDevURandom(ent32);
    }
#elif defined(HAVE_SYSCTL_ARND)
    /* FreeBSD and similar. It is possible for the call to return less
     * bytes than requested, so need to read in a loop.
     */
    static const int name[2] = {CTL_KERN, KERN_ARND};
    int have = 0;
    do {
        size_t len = NUM_OS_RANDOM_BYTES - have;
        if (sysctl(name, ARRAYLEN(name), ent32 + have, &len, NULL, 0) != 0) {
            RandFailure();
        }
        have += len;
    } while (have < NUM_OS_RANDOM_BYTES);
#else
    /* Fall back to /dev/urandom if there is no specific method implemented to
     * get system entropy for this OS.
     */
    GetDevURandom(ent32);
#endif
}

void GetRandBytes(unsigned char* buf, int num)
{
    // Fill in 32-byte chunks from the fast-seeded CSPRNG
    while (num > 0) {
        int now = std::min(num, 32);
        ProcRand(buf, now, RNGLevel::FAST);
        buf += now;
        num -= now;
    }
}

void GetStrongRandBytes(unsigned char* out, int num)
{
    assert(num <= 32);
    ProcRand(out, num, RNGLevel::SLOW);
}

void RandAddEvent(const uint32_t event_info)
{
    GetRNGState().AddEvent(event_info);
}

void RandAddPeriodic()
{
    ProcRand(nullptr, 0, RNGLevel::PERIODIC);
}

uint64_t GetRand(uint64_t nMax)
{
    if (nMax == 0)
        return 0;

    // The range of the random source must be a multiple of the modulus
    // to give every possible output value an equal possibility
    uint64_t nRange = (std::numeric_limits<uint64_t>::max() / nMax) * nMax;
    uint64_t nRand = 0;
    do {
        GetRandBytes((unsigned char*)&nRand, sizeof(nRand));
    } while (nRand >= nRange);
    return (nRand % nMax);
}

int GetRandInt(int nMax)
{
    return GetRand(nMax);
}

uint256 GetRandHash()
{
    uint256 hash;
    GetRandBytes((unsigned char*)&hash, sizeof(hash));
    return hash;
}

void FastRandomContext::RandomSeed()
{
    uint256 seed = GetRandHash();
    rng.SetKey(seed.begin(), 32);
    requires_seed = false;
}

uint256 FastRandomContext::rand256()
{
    if (bytebuf_size < 32) {
        FillByteBuffer();
    }
    uint256 ret;
    memcpy(ret.begin(), bytebuf + 64 - bytebuf_size, 32);
    bytebuf_size -= 32;
    return ret;
}

std::vector<unsigned char> FastRandomContext::randbytes(size_t len)
{
    std::vector<unsigned char> ret(len);
    if (len > 0) {
        rng.Output(&ret[0], len);
    }
    return ret;
}

FastRandomContext::FastRandomContext(const uint256& seed) : requires_seed(false), bytebuf_size(0), bitbuf_size(0)
{
    rng.SetKey(seed.begin(), 32);
}

bool Random_SanityCheck()
{
    uint64_t start = GetPerformanceCounter();

    /* This does not measure the quality of randomness, but it does test that
     * OSRandom() overwrites all 32 bytes of the output given a maximum
     * number of tries.
     */
    static const ssize_t MAX_TRIES = 1024;
    uint8_t data[NUM_OS_RANDOM_BYTES];
    bool overwritten[NUM_OS_RANDOM_BYTES] = {}; /* Tracks which bytes have been overwritten at least once */
    int num_overwritten;
    int tries = 0;
    /* Loop until all bytes have been overwritten at least once, or max number tries reached */
    do {
        memset(data, 0, NUM_OS_RANDOM_BYTES);
        GetOSRand(data);
        for (int x=0; x < NUM_OS_RANDOM_BYTES; ++x) {
            overwritten[x] |= (data[x] != 0);
        }

        num_overwritten = 0;
        for (int x=0; x < NUM_OS_RANDOM_BYTES; ++x) {
            if (overwritten[x]) {
                num_overwritten += 1;
            }
        }

        tries += 1;
    } while (num_overwritten < NUM_OS_RANDOM_BYTES && tries < MAX_TRIES);
    if (num_overwritten != NUM_OS_RANDOM_BYTES) return false; /* If this failed, bailed out after too many tries */

    // Check that GetPerformanceCounter increases at least during a GetOSRand() call + 1ms sleep.
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
    uint64_t stop = GetPerformanceCounter();
    if (stop == start) return false;

    // We called GetPerformanceCounter. Use it as entropy.
    CSHA512 hasher;
    hasher.Write((const unsigned char*)&start, sizeof(start));
    hasher.Write((const unsigned char*)&stop, sizeof(stop));
    GetRNGState().MixExtract(nullptr, 0, std::move(hasher), false);

    return true;
}

FastRandomContext::FastRandomContext(bool fDeterministic) : requires_seed(!fDeterministic), bytebuf_size(0), bitbuf_size(0)
{
    if (!fDeterministic) {
        return;
    }
    uint256 seed;
    rng.SetKey(seed.begin(), 32);
}

void RandomInit()
{
    // Trigger construction of the global RNGState (which calls RDRandInit)
    GetRNGState();
}
