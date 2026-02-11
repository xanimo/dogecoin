// Copyright (c) 2021 The Litecoin Core developers
// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef MW_MODELS_TX_PEGOUTCOIN_H
#define MW_MODELS_TX_PEGOUTCOIN_H

#include <mw/common/Traits.h>
#include <amount.h>
#include <script/script.h>
#include <serialize.h>

MW_NAMESPACE

/// Represents a peg-out from the MWEB back to the canonical UTXO set
class PegOutCoin {
public:
    PegOutCoin() : m_amount(0) {}
    PegOutCoin(CAmount amount, const std::vector<uint8_t>& scriptPubKey)
        : m_amount(amount), m_scriptPubKey(scriptPubKey.begin(), scriptPubKey.end()) {}
    PegOutCoin(CAmount amount, const CScript& script)
        : m_amount(amount), m_scriptPubKey(script) {}

    CAmount GetAmount() const { return m_amount; }
    const CScript& GetScriptPubKey() const { return m_scriptPubKey; }

    bool operator==(const PegOutCoin& rhs) const {
        return m_amount == rhs.m_amount && m_scriptPubKey == rhs.m_scriptPubKey;
    }

    template<typename Stream>
    void Serialize(Stream& s) const {
        ser_writedata64(s, m_amount);
        s << *(const CScriptBase*)(&m_scriptPubKey);
    }

    template<typename Stream>
    void Unserialize(Stream& s) {
        m_amount = ser_readdata64(s);
        s >> *(CScriptBase*)(&m_scriptPubKey);
        if (m_scriptPubKey.empty()) {
            throw std::ios_base::failure("PegOutCoin scriptPubKey is empty");
        }
    }

private:
    CAmount m_amount;
    CScript m_scriptPubKey;
};

END_NAMESPACE

#endif // MW_MODELS_TX_PEGOUTCOIN_H
