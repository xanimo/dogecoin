// Copyright (c) 2021 The Litecoin Core developers
// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef MW_MODELS_TX_PEGINCOIN_H
#define MW_MODELS_TX_PEGINCOIN_H

#include <mw/common/Traits.h>
#include <amount.h>
#include <serialize.h>

MW_NAMESPACE

/// Represents a peg-in from the canonical UTXO set into the MWEB
class PegInCoin {
public:
    PegInCoin() : m_amount(0) {}
    PegInCoin(CAmount amount, const mw::Hash& kernelID)
        : m_amount(amount), m_kernelID(kernelID) {}
    PegInCoin(CAmount amount, mw::Hash&& kernelID)
        : m_amount(amount), m_kernelID(std::move(kernelID)) {}

    CAmount GetAmount() const { return m_amount; }
    const mw::Hash& GetKernelID() const { return m_kernelID; }

    bool operator==(const PegInCoin& rhs) const {
        return m_amount == rhs.m_amount && m_kernelID == rhs.m_kernelID;
    }

    template<typename Stream>
    void Serialize(Stream& s) const {
        ser_writedata64(s, m_amount);
        s << m_kernelID;
    }

    template<typename Stream>
    void Unserialize(Stream& s) {
        m_amount = ser_readdata64(s);
        s >> m_kernelID;
    }

private:
    CAmount m_amount;
    mw::Hash m_kernelID;
};

END_NAMESPACE

#endif // MW_MODELS_TX_PEGINCOIN_H
