// Copyright (c) 2014-2016 The Bitcoin Core developers
// Copyright (c) 2021-2023 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_RPCMINING_H
#define BITCOIN_RPCMINING_H

#include "arith_uint256.h"
#include "consensus/validation.h"
#include "primitives/block.h"
#include "validation.h"
#include "validationinterface.h"

#include <univalue.h>

class submitblock_StateCatcher : public CValidationInterface
{
public:
    uint256 hash;
    bool found;
    BlockValidationState state;

    submitblock_StateCatcher(const uint256 &hashIn) : hash(hashIn), found(false), state() {}

protected:
    virtual void BlockChecked(const CBlock& block, const BlockValidationState& stateIn) {
        if (block.GetHash() != hash)
            return;
        found = true;
        state = stateIn;
    }
};

UniValue BIP22ValidationResult(const BlockValidationState& state);

#endif //BITCOIN_RPCMINING_H
