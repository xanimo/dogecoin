// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2021-2022 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "amount.h"

#include "tinyformat.h"

const std::string CURRENCY_UNIT = "DOGE";

CFeeRate::CFeeRate(const CAmount& nFeePaid, size_t nBytes_)
{
    assert(nBytes_ <= uint64_t(std::numeric_limits<int64_t>::max()));
    int64_t nSize = int64_t(nBytes_);

    if (nSize <= 0) {
        nSatoshisPerK = 0;
    } else if (nFeePaid <= std::numeric_limits<int64_t>::max() / 1000) {
        nSatoshisPerK = nFeePaid * 1000 / nSize;
    } else {
        /* A fee this side of MAX_MONEY does not survive being multiplied by
         * 1000, so divide first and saturate, losing under a koinu per kB. */
        int64_t nPerByte = nFeePaid / nSize;
        nSatoshisPerK = nPerByte > std::numeric_limits<int64_t>::max() / 1000
            ? std::numeric_limits<int64_t>::max()
            : nPerByte * 1000;
    }
}

CAmount CFeeRate::GetFee(size_t nBytes_) const
{
    assert(nBytes_ <= uint64_t(std::numeric_limits<int64_t>::max()));
    int64_t nSize = int64_t(nBytes_);

    CAmount nFee;
    if (nSize > 0 && (nSatoshisPerK > std::numeric_limits<int64_t>::max() / nSize ||
                      nSatoshisPerK < std::numeric_limits<int64_t>::min() / nSize)) {
        /* Same reach, from the other side: this rate over this many bytes does
         * not fit, so stop at the end of the range instead of wrapping past it. */
        nFee = nSatoshisPerK > 0 ? std::numeric_limits<int64_t>::max()
                                 : std::numeric_limits<int64_t>::min();
    } else {
        nFee = nSatoshisPerK * nSize / 1000;
    }

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
