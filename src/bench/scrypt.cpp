#include <iostream>
#include <vector>

#include "bench.h"
#include "crypto/scrypt.h"
#include "uint256.h"
#include "utiltime.h"
#include "utilstrencodings.h"

// 80 bytes input, size of CPureBlockHeader
static const uint64_t BUFFER_SIZE = 80;

static void Scrypt(benchmark::State& state)
{
    uint256 output;
    std::vector<char> in(BUFFER_SIZE, 0);

#if defined(USE_SCRYPT_AVX2) || (defined(USE_SSE2) && !defined(USE_SSE2_ALWAYS))
    scrypt_detect_best();
#endif

    while (state.KeepRunning())
    {
        scrypt_1024_1_1_256(in.data(), BEGIN(output));
    }
}

BENCHMARK(Scrypt);
