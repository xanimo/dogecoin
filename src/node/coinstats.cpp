// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2020 The Bitcoin Core developers
// Copyright (c) 2022 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "node/coinstats.h"

#include "coins.h"
#include "hash.h"
#include "serialize.h"
#include "sync.h"
#include "uint256.h"
#include "validation.h"

#include <map>

#include <boost/thread.hpp>

static void ApplyStats(CCoinsStats& stats, CHashWriter& ss, const uint256& hash, const std::map<uint32_t, Coin>& outputs)
{
    assert(!outputs.empty());
    ss << hash;
    ss << VARINT(uint32_t(outputs.begin()->second.nHeight * 2 + outputs.begin()->second.fCoinBase));
    stats.nTransactions++;
    for (const auto& output : outputs) {
        ss << VARINT(output.first + 1);
        ss << *(const CScriptBase*)(&output.second.out.scriptPubKey);
        ss << VARINT_MODE(output.second.out.nValue, VarIntMode::NONNEGATIVE_SIGNED);
        stats.nTransactionOutputs++;
        stats.nTotalAmount += output.second.out.nValue;
    }
    ss << VARINT(0u);
}

static bool GetUTXOStatsHashSerialized(CCoinsView* view, CCoinsStats& stats,
    const std::function<void()>& interruption_point)
{
    std::unique_ptr<CCoinsViewCursor> pcursor(view->Cursor());

    CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
    stats.hashBlock = pcursor->GetBestBlock();
    {
        LOCK(cs_main);
        stats.nHeight = mapBlockIndex.find(stats.hashBlock)->second->nHeight;
    }
    ss << stats.hashBlock;
    uint256 prevkey;
    std::map<uint32_t, Coin> outputs;
    while (pcursor->Valid()) {
        if (interruption_point) {
            interruption_point();
        } else {
            boost::this_thread::interruption_point();
        }
        COutPoint key;
        Coin coin;
        if (pcursor->GetKey(key) && pcursor->GetValue(coin)) {
            if (!outputs.empty() && key.hash != prevkey) {
                ApplyStats(stats, ss, prevkey, outputs);
                outputs.clear();
            }
            prevkey = key.hash;
            outputs[key.n] = std::move(coin);
            stats.coins_count++;
        } else {
            return error("%s: unable to read value", __func__);
        }
        pcursor->Next();
    }
    if (!outputs.empty()) {
        ApplyStats(stats, ss, prevkey, outputs);
    }
    stats.hashSerialized = ss.GetHash();
    stats.nDiskSize = view->EstimateSize();
    return true;
}

static bool GetUTXOStatsNone(CCoinsView* view, CCoinsStats& stats,
    const std::function<void()>& interruption_point)
{
    std::unique_ptr<CCoinsViewCursor> pcursor(view->Cursor());

    stats.hashBlock = pcursor->GetBestBlock();
    {
        LOCK(cs_main);
        stats.nHeight = mapBlockIndex.find(stats.hashBlock)->second->nHeight;
    }
    while (pcursor->Valid()) {
        if (interruption_point) {
            interruption_point();
        } else {
            boost::this_thread::interruption_point();
        }
        COutPoint key;
        Coin coin;
        if (pcursor->GetKey(key) && pcursor->GetValue(coin)) {
            stats.nTransactionOutputs++;
            stats.coins_count++;
            stats.nTotalAmount += coin.out.nValue;
        } else {
            return error("%s: unable to read value", __func__);
        }
        pcursor->Next();
    }
    stats.nDiskSize = view->EstimateSize();
    return true;
}

bool GetUTXOStats(CCoinsView* view, CCoinsStats& stats,
    CoinStatsHashType hash_type,
    const std::function<void()>& interruption_point)
{
    switch (hash_type) {
    case CoinStatsHashType::HASH_SERIALIZED:
        return GetUTXOStatsHashSerialized(view, stats, interruption_point);
    case CoinStatsHashType::NONE:
        return GetUTXOStatsNone(view, stats, interruption_point);
    case CoinStatsHashType::MUHASH:
        return error("%s: MuHash not supported", __func__);
    }
    assert(false);
}
