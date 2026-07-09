// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2021-2022 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "amount.h"

#include "tinyformat.h"

#include <limits>

const std::string CURRENCY_UNIT = "DOGE";

namespace {

// Compute num * mul / div for int64_t operands without overflowing the num*mul
// intermediate, saturating to the int64_t range. Exact whenever the true result
// fits in int64_t (which covers every realistic fee/size); only inputs whose
// result genuinely exceeds int64_t saturate.
//
// Dogecoin needs this where Bitcoin does not: Bitcoin's 21e6-coin cap keeps
// MAX_MONEY at 2.1e15 sat, so fee*1000 <= 2.1e18 < INT64_MAX. Dogecoin's
// MAX_MONEY is 1e18 sat, so fee*1000 (up to 1e21) overflows int64_t. __int128 is
// unavailable on the 32-bit targets we build (i686/armhf), so stay in int64_t.
int64_t MulDivSaturate(int64_t num, int64_t mul, int64_t div)
{
    assert(div > 0 && mul > 0);
    const int64_t kMax = std::numeric_limits<int64_t>::max();
    const int64_t kMin = std::numeric_limits<int64_t>::min();

    // Fast path: num*mul cannot overflow -> exact, bit-identical to the old code.
    if (num <= kMax / mul && num >= kMin / mul)
        return num * mul / div;

    // num*mul would overflow. num*mul/div == (num/div)*mul + (num%div)*mul/div,
    // which avoids forming num*mul.
    const int64_t quot = num / div;
    const int64_t rem = num % div;
    if (quot > kMax / mul) return kMax;   // result exceeds int64_t range
    if (quot < kMin / mul) return kMin;

    // rem*mul is safe unless an operand is enormous (only synthetic inputs, e.g.
    // a size near SIZE_MAX). When div >= mul (our reachable callers), then
    // rem*mul/div == rem / (div/mul) with div/mul >= 1. The div < mul case is
    // unreachable for both callers; return 0 there rather than risk a div-by-zero.
    int64_t remPart = 0;
    if (rem <= kMax / mul && rem >= kMin / mul)
        remPart = rem * mul / div;
    else if (div >= mul)
        remPart = rem / (div / mul);
    return quot * mul + remPart;
}

} // namespace

CFeeRate::CFeeRate(const CAmount& nFeePaid, size_t nBytes_)
{
    assert(nBytes_ <= uint64_t(std::numeric_limits<int64_t>::max()));
    int64_t nSize = int64_t(nBytes_);

    if (nSize > 0)
        nSatoshisPerK = MulDivSaturate(nFeePaid, 1000, nSize);
    else
        nSatoshisPerK = 0;
}

CAmount CFeeRate::GetFee(size_t nBytes_) const
{
    assert(nBytes_ <= uint64_t(std::numeric_limits<int64_t>::max()));
    int64_t nSize = int64_t(nBytes_);

    CAmount nFee = (nSize > 0) ? MulDivSaturate(nSatoshisPerK, nSize, 1000) : 0;

    if (nFee == 0 && nSize != 0) {
        if (nSatoshisPerK > 0)
            nFee = CAmount(1);
        if (nSatoshisPerK < 0)
            nFee = CAmount(-1);
    }

    return nFee;
}

std::string CFeeRate::ToString() const
{
    return strprintf("%d.%08d %s/kB", nSatoshisPerK / COIN, nSatoshisPerK % COIN, CURRENCY_UNIT);
}
